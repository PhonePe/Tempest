// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{HashMap, HashSet, VecDeque};
use std::convert::TryInto;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::{Notify, OnceCell, Semaphore};
use tracing::info;

use crate::artifact_root::{ArtifactRoot, lexical_artifact_path};
use crate::error::{ProtocolError, TempestError};

pub(crate) mod deletion;

/// Process-local release version identifier.
pub type VersionId = u64;

/// Lowercase hexadecimal SHA-256 content hash.
pub type ContentHash = String;

/// Backwards-compatible profile used when no orchestration profile is supplied.
pub const DEFAULT_BOOT_PROFILE: &str = "default";

/// Returns whether a profile is 1-64 ASCII alphanumeric, dash, underscore, or dot bytes.
pub fn is_valid_boot_profile(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

/// Returns whether a release group identifier is bounded and log-safe.
pub fn is_valid_group_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Returns whether an artifact name is a bounded relative path of normal components.
pub fn is_valid_logical_name(name: &str) -> bool {
    name.len() <= 255 && is_canonical_artifact_name(name)
}

/// Lexical identity shared by release keys, ownership fences and filesystem reads.
/// Keep the HTTP compatibility length limit separate from managed-name limits.
pub(crate) fn is_canonical_artifact_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains('\\')
        && !name.chars().any(char::is_control)
        && name.split('/').all(|part| !matches!(part, "" | "." | ".."))
        && Path::new(name)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

/// Applies the default profile and validates the resulting name.
fn normalize_boot_profile(boot_profile: Option<&str>) -> Result<&str, TempestError> {
    let profile = boot_profile.unwrap_or(DEFAULT_BOOT_PROFILE);
    if is_valid_boot_profile(profile) {
        Ok(profile)
    } else {
        Err(TempestError::Version(format!(
            "Invalid boot profile: {profile}"
        )))
    }
}

/// Compound key for one profile-scoped logical artifact.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct VersionKey {
    boot_profile: String,
    logical_name: String,
}

impl VersionKey {
    /// Creates an owned profile and artifact key.
    fn new(boot_profile: &str, logical_name: &str) -> Self {
        Self {
            boot_profile: boot_profile.to_string(),
            logical_name: logical_name.to_string(),
        }
    }
}

/// One managed artifact version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileVersion {
    /// Profile namespace in which the logical artifact is active.
    pub boot_profile: String,
    /// Client-visible relative artifact name.
    pub logical_name: String,
    /// Canonical or operator-supplied filesystem path containing the bytes.
    pub path: PathBuf,
    /// Monotonic process-local release version identifier.
    pub version_id: VersionId,
    /// Lowercase hexadecimal SHA-256 digest of the file bytes.
    pub content_hash: ContentHash,
    /// File length in bytes at registration time.
    pub size: u64,
}

/// Version identity pinned for one in-flight transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedVersion {
    /// Profile namespace owning the pinned release.
    pub boot_profile: String,
    /// Client-visible artifact name used as the pin key.
    pub logical_name: String,
    /// Release version held alive by the transfer.
    pub version_id: VersionId,
    /// Expected lowercase hexadecimal SHA-256 digest.
    pub content_hash: ContentHash,
    /// Expected file length in bytes.
    pub size: u64,
}

/// Boot-chain release identity pinned for one PXE boot session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootChainPin {
    /// Profile namespace selected for the boot session.
    pub boot_profile: String,
    /// Operator-supplied release group identifier.
    pub group_id: String,
    /// Process-local version identifier shared by all group artifacts.
    pub version_id: VersionId,
    /// SHA-256 digest binding the release manifest payload.
    pub manifest_digest: String,
}

/// Result of resolving a TFTP filename for a transfer.
#[derive(Debug, Clone)]
pub struct ResolvedFile {
    /// SQL admission retained through the actual transfer or HTTP body lifetime.
    /// Compositions must preserve it alongside the selected artifact; never drop
    /// it before delivery finishes. SQL-free resolution initializes this to None.
    pub durable_reader: Option<Arc<crate::persistence::ReaderRegistration>>,
    /// Filesystem path selected for opening by the transfer engine.
    pub path: PathBuf,
    /// Managed artifact pin; callers must unpin it after transfer completion.
    pub pinned_version: Option<PinnedVersion>,
    /// Expected SHA-256 digest when the artifact is release-managed.
    pub content_hash: Option<ContentHash>,
    /// Release identity attached to audit and cross-transport session state.
    pub boot_chain: Option<BootChainPin>,
}

/// A single artifact entry within a signed boot-chain manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestArtifact {
    /// Client-visible relative artifact name.
    pub logical_name: String,
    /// Filesystem path serialized when the release was registered.
    pub path: String,
    /// Lowercase hexadecimal SHA-256 digest of the artifact bytes.
    pub content_hash: ContentHash,
    /// Artifact length in bytes.
    pub size: u64,
}

/// Canonical serializable fields used to authenticate a release manifest.
#[derive(Debug, Serialize)]
struct ManifestPayload<'a> {
    boot_profile: &'a str,
    group_id: &'a str,
    version_id: VersionId,
    created_at: String,
    artifacts: &'a [ManifestArtifact],
}

/// Signed identity for a coordinated boot release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootChainManifest {
    /// Profile namespace to which the release belongs.
    pub boot_profile: String,
    /// Operator-supplied release group identifier.
    pub group_id: String,
    /// Shared version ID for all artifacts in the release.
    pub version_id: VersionId,
    /// UTC registration timestamp included in the authenticated payload.
    /// Canonical encoding preserves the existing RFC3339 precision and UTC offset.
    pub created_at: jiff::Timestamp,
    /// Ordered release artifact metadata included in the authenticated payload.
    pub artifacts: Vec<ManifestArtifact>,
    /// Lowercase hexadecimal SHA-256 digest of the canonical JSON payload.
    pub manifest_digest: String,
    /// Optional hex-encoded Ed25519 signature over the canonical JSON payload.
    pub signature: Option<String>,
}

impl BootChainManifest {
    /// Serializes canonical manifest fields for digesting and signing.
    fn payload_bytes(
        boot_profile: &str,
        group_id: &str,
        version_id: VersionId,
        created_at: jiff::Timestamp,
        artifacts: &[ManifestArtifact],
    ) -> Result<Vec<u8>, TempestError> {
        let payload = ManifestPayload {
            boot_profile,
            group_id,
            version_id,
            created_at: crate::timestamp::to_rfc3339(created_at),
            artifacts,
        };

        serde_json::to_vec(&payload)
            .map_err(|e| TempestError::Version(format!("Failed to serialize manifest: {e}")))
    }

    /// Reconstructs the canonical bytes authenticated by this manifest.
    fn signed_bytes(&self) -> Result<Vec<u8>, TempestError> {
        Self::payload_bytes(
            &self.boot_profile,
            &self.group_id,
            self.version_id,
            self.created_at,
            &self.artifacts,
        )
    }

    /// Recomputes and compares the manifest SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns a version error if canonical payload serialization fails.
    pub fn verify_digest(&self) -> Result<bool, TempestError> {
        Ok(hex::encode(Sha256::digest(self.signed_bytes()?)) == self.manifest_digest)
    }

    /// Verifies both digest integrity and the Ed25519 signature with `verifying_key`.
    ///
    /// Returns `false` for absent or cryptographically invalid signatures.
    ///
    /// # Errors
    ///
    /// Returns a version error for malformed signature hex or length, or if
    /// canonical payload serialization fails.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<bool, TempestError> {
        let payload = self.signed_bytes()?;
        let computed_digest = hex::encode(Sha256::digest(&payload));
        if computed_digest != self.manifest_digest {
            return Ok(false);
        }

        let Some(signature_hex) = &self.signature else {
            return Ok(false);
        };

        let signature_bytes = hex::decode(signature_hex)
            .map_err(|e| TempestError::Version(format!("Invalid manifest signature hex: {e}")))?;
        let signature_array: [u8; 64] = signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| TempestError::Version("Invalid manifest signature length".to_string()))?;
        let signature = Signature::from_bytes(&signature_array);

        Ok(verifying_key.verify(&payload, &signature).is_ok())
    }
}

/// A set of artifact mappings activated as one process-local snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionGroup {
    /// Profile namespace switched by this group.
    pub boot_profile: String,
    /// Operator-supplied release identifier, unique within retained profile history.
    pub group_id: String,
    /// Shared process-local version identifier.
    pub version_id: VersionId,
    /// Registered artifact versions switched as one snapshot.
    pub files: Vec<FileVersion>,
    /// UTC registration timestamp.
    /// Uses the same instant type as the signed manifest.
    pub created_at: jiff::Timestamp,
    /// Digest and optional signature binding the complete release.
    pub manifest: BootChainManifest,
}

/// Blocks replacement versions while a profile cutover drains selected pins.
#[derive(Debug, Clone)]
struct CutoverGate {
    boot_profile: String,
    group_id: String,
    blocked_versions: HashMap<VersionKey, VersionId>,
}

#[derive(Clone, Default)]
struct ActiveReleaseState {
    versions: HashMap<VersionKey, FileVersion>,
    chains: HashMap<String, BootChainPin>,
    owned_names: HashSet<VersionKey>,
}

/// Owns release snapshots, history, transfer pins, and boot-session pins.
pub struct VersionStore {
    /// Atomically published active versions, release identities, and ownership index.
    active_releases: ArcSwap<ActiveReleaseState>,
    /// Retained release groups, subject to live-pin-aware pruning.
    groups: RwLock<Vec<VersionGroup>>,
    /// One bounded, previously authenticated durable manifest snapshot.
    validated_persistent_groups: Mutex<Option<Arc<ValidatedPersistentGroups>>>,
    /// Reference counts held by in-flight transfers.
    pinned_versions: DashMap<(String, String, VersionId), usize>,
    /// Reference counts for releases pinned by live boot sessions.
    pinned_boot_chains: DashMap<String, usize>,
    /// Wakes cutovers after any relevant pin count decreases.
    pin_notify: Notify,
    /// Versions that are draining during a release cutover, keyed by boot profile.
    cutover_gates: RwLock<HashMap<String, CutoverGate>>,
    /// Next process-local version identifier.
    next_version: std::sync::atomic::AtomicU64,
    /// Content hashes with insertion times for TTL expiry.
    hash_cache: DashMap<PathBuf, (ContentHash, Instant)>,
    /// Serializes exact-capacity admission and eviction for the hash cache.
    hash_cache_admission: Mutex<()>,
    verified_artifacts: DashMap<String, Arc<OnceCell<ContentHash>>>,
    /// Serializes bounded verification-cache admission; hits need no global lock.
    verification_order: Mutex<VecDeque<String>>,
    /// Shared by transfer verification and control-plane hashing workers.
    pub(crate) artifact_hash_budget: Arc<Semaphore>,
    /// Optional signing key for boot-chain manifests.
    manifest_signing_key: Option<SigningKey>,
    manifest_verifying_key: Option<VerifyingKey>,
    require_signed_manifests: bool,
}

/// Fully validated durable release snapshot awaiting one atomic hot-state swap.
pub(crate) struct ValidatedPersistentGroups(Vec<(VersionGroup, bool)>);

impl ValidatedPersistentGroups {
    pub(crate) fn matches(&self, groups: &[(VersionGroup, bool)]) -> bool {
        self.0 == groups
    }
}

/// Historical release whose complete artifact set was verified for rollback.
pub(crate) struct VerifiedRollback(VersionGroup);

/// Prepared release whose cutover gate is cleared unless it is handed off or activated.
pub(crate) struct PreparedGroupReservation<'a> {
    store: &'a VersionStore,
    group: Option<VersionGroup>,
}

impl PreparedGroupReservation<'_> {
    pub(crate) fn group(&self) -> &VersionGroup {
        self.group
            .as_ref()
            .expect("prepared group reservation is consumed only once")
    }

    fn into_group(mut self) -> VersionGroup {
        self.group
            .take()
            .expect("prepared group reservation is consumed only once")
    }

    pub(crate) fn activate(mut self) -> Result<VersionGroup, TempestError> {
        let group = self
            .group
            .take()
            .expect("prepared group reservation is consumed only once");
        self.store.activate_prepared_group(group)
    }
}

impl Drop for PreparedGroupReservation<'_> {
    fn drop(&mut self) {
        if let Some(group) = &self.group {
            self.store
                .clear_cutover_gate(&group.boot_profile, &group.group_id);
        }
    }
}

/// Cutover reservation that clears itself if a rollback request is cancelled.
pub(crate) struct VerifiedRollbackReservation<'a> {
    store: &'a VersionStore,
    rollback: Option<VerifiedRollback>,
}

impl VerifiedRollbackReservation<'_> {
    /// Atomically publishes the verified historical release.
    pub(crate) fn activate(mut self) {
        if let Some(rollback) = self.rollback.take() {
            self.store.activate_verified_rollback(rollback);
        }
    }
}

impl Drop for VerifiedRollbackReservation<'_> {
    fn drop(&mut self) {
        if let Some(rollback) = &self.rollback {
            self.store
                .clear_cutover_gate(&rollback.0.boot_profile, &rollback.0.group_id);
        }
    }
}

/// One coherent view of active versions and retained release history.
pub(crate) struct ReleaseSnapshot {
    pub active_versions: Vec<FileVersion>,
    pub active_groups: Vec<BootChainPin>,
    pub groups: Vec<VersionGroup>,
}

/// Non-disclosing outcome classes for the retained-artifact verification API.
pub(crate) enum GroupVerificationError {
    /// The requested retained group does not exist.
    NotFound,
    /// The caller selected duplicate or unknown logical artifacts.
    InvalidRequest,
    /// Verification could not complete because trusted state or I/O failed.
    Internal,
}

/// Hard retained-history bound shared with the coherent snapshot contract.
const MAX_GROUP_HISTORY: usize = 100;
const MAX_GROUP_ARTIFACTS: usize = 100;
const MAX_RELEASE_SNAPSHOT_GROUPS: usize = MAX_GROUP_HISTORY;
const MAX_RELEASE_SNAPSHOT_ARTIFACTS: usize = 10_000;
/// Hash-cache freshness interval in seconds.
const HASH_CACHE_TTL_SECS: u64 = 300;
/// Hash-cache cleanup threshold.
const MAX_HASH_CACHE_ENTRIES: usize = 10_000;
const MAX_VERIFIED_ARTIFACTS: usize = 10_000;

impl Default for VersionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl VersionStore {
    /// Creates an unsigned store that accepts unsigned persisted manifests.
    pub fn new() -> Self {
        Self::new_with_manifest_keys(None, None, false)
    }

    /// Creates a store that signs new manifests and requires signed manifests.
    pub fn new_with_manifest_signing_key(signing_key_bytes: &[u8; 32]) -> Self {
        Self::new_with_manifest_keys(Some(signing_key_bytes), None, true)
    }

    /// Creates a store with independent manifest signing and verification policy.
    ///
    /// `require_signed_manifests` makes release activation fail closed when no
    /// signing key is available and rejects unsigned state during hydration.
    pub fn new_with_manifest_keys(
        signing_key_bytes: Option<&[u8; 32]>,
        manifest_verifying_key: Option<VerifyingKey>,
        require_signed_manifests: bool,
    ) -> Self {
        Self {
            active_releases: ArcSwap::new(Arc::new(ActiveReleaseState::default())),
            groups: RwLock::new(Vec::new()),
            validated_persistent_groups: Mutex::new(None),
            pinned_versions: DashMap::new(),
            pinned_boot_chains: DashMap::new(),
            pin_notify: Notify::new(),
            cutover_gates: RwLock::new(HashMap::new()),
            next_version: std::sync::atomic::AtomicU64::new(1),
            hash_cache: DashMap::new(),
            hash_cache_admission: Mutex::new(()),
            verified_artifacts: DashMap::new(),
            verification_order: Mutex::new(VecDeque::new()),
            artifact_hash_budget: Arc::new(Semaphore::new(4)),
            manifest_signing_key: signing_key_bytes.map(SigningKey::from_bytes),
            manifest_verifying_key,
            require_signed_manifests,
        }
    }

    /// Returns the explicit verifier or the public half of the signing key.
    pub fn manifest_verifying_key(&self) -> Option<VerifyingKey> {
        self.manifest_verifying_key.or_else(|| {
            self.manifest_signing_key
                .as_ref()
                .map(|key| key.verifying_key())
        })
    }

    /// Sign one domain-separated control message with the manifest identity.
    pub(crate) fn sign_manifest_message(&self, message: &[u8]) -> Result<String, TempestError> {
        let signing_key = self.manifest_signing_key.as_ref().ok_or_else(|| {
            TempestError::Config("signed redirect requires audit.manifest_signing_key_path".into())
        })?;
        Ok(hex::encode(signing_key.sign(message).to_bytes()))
    }

    /// Resolve a validated filename to its pinned physical path.
    ///
    /// Unmanaged names are selected lexically; the transfer layer validates
    /// existence and file type while opening through its artifact capability.
    pub fn resolve_file(&self, filename: &str, root: &Path) -> Result<PathBuf, TempestError> {
        self.resolve_file_for_transfer(filename, root)
            .map(|resolved| resolved.path)
    }

    /// Resolves and pins an artifact in `boot_profile`, returning its path only.
    ///
    /// The compatibility API does not expose the pin token; prefer
    /// [`Self::resolve_file_for_transfer_in_profile`] for explicit ownership.
    pub fn resolve_file_in_profile(
        &self,
        boot_profile: &str,
        filename: &str,
        root: &Path,
    ) -> Result<PathBuf, TempestError> {
        self.resolve_file_for_transfer_in_profile(boot_profile, filename, root)
            .map(|resolved| resolved.path)
    }

    /// Resolve a validated filename and return its version identity when pinned.
    pub fn resolve_file_for_transfer(
        &self,
        filename: &str,
        root: &Path,
    ) -> Result<ResolvedFile, TempestError> {
        self.resolve_file_for_transfer_in_profile(DEFAULT_BOOT_PROFILE, filename, root)
    }

    /// Resolves an artifact and returns managed identity needed to release its pin.
    ///
    /// Names longer than 1,024 bytes and root traversal are rejected. A name
    /// present in release history cannot fall back to an unmanaged root file.
    pub fn resolve_file_for_transfer_in_profile(
        &self,
        boot_profile: &str,
        filename: &str,
        root: &Path,
    ) -> Result<ResolvedFile, TempestError> {
        self.resolve_file_for_transfer_in_profile_with_boot_chain(boot_profile, filename, root)
            .map(|(resolved, _)| resolved)
    }

    /// Resolves an artifact and separately returns the active release pin.
    ///
    /// Successful managed resolution increments the artifact pin count; the
    /// caller owns that pin and must call [`Self::unpin_version_for_profile`].
    pub fn resolve_file_for_transfer_in_profile_with_boot_chain(
        &self,
        boot_profile: &str,
        filename: &str,
        root: &Path,
    ) -> Result<(ResolvedFile, Option<BootChainPin>), TempestError> {
        self.resolve_active_file(boot_profile, filename, root, true)
    }

    /// Resolves only a managed member of the profile's active release.
    ///
    /// The artifact and release identity come from the same atomic snapshot.
    /// No direct-root fallback is allowed; the caller owns the transfer pin.
    pub(crate) fn resolve_managed_file_for_transfer_in_profile(
        &self,
        boot_profile: &str,
        filename: &str,
        root: &Path,
    ) -> Result<(ResolvedFile, Option<BootChainPin>), TempestError> {
        self.resolve_active_file(boot_profile, filename, root, false)
    }

    fn resolve_active_file(
        &self,
        boot_profile: &str,
        filename: &str,
        root: &Path,
        allow_direct: bool,
    ) -> Result<(ResolvedFile, Option<BootChainPin>), TempestError> {
        let boot_profile = normalize_boot_profile(Some(boot_profile))?;
        if filename.len() > 1024 || !is_canonical_artifact_name(filename) {
            let reason = if filename.len() > 1024 {
                "filename too long"
            } else {
                "noncanonical filename"
            };
            return Err(TempestError::Protocol(
                crate::error::ProtocolError::AccessViolation(reason.to_string()),
            ));
        }
        // Serialize snapshot selection and pin acquisition with retained deletion.
        // Otherwise a reader could hold an outgoing snapshot across withdrawal
        // and acquire its first pin after the group was removed.
        let _groups = self.groups.read();
        let active = self.active_releases.load();
        if allow_direct && active.versions.is_empty() && active.owned_names.is_empty() {
            drop(active);
            return Ok((self.resolve_direct_file(filename, root)?, None));
        }

        let gates = self.cutover_gates.read();
        let key = VersionKey::new(boot_profile, filename);

        if let Some(version) = active.versions.get(&key) {
            if gates
                .get(boot_profile)
                .and_then(|g| g.blocked_versions.get(&key))
                .is_some_and(|blocked_version_id| *blocked_version_id == version.version_id)
            {
                return Err(TempestError::Protocol(
                    crate::error::ProtocolError::AccessViolation(
                        "release cutover in progress".to_string(),
                    ),
                ));
            }

            let boot_chain = Some(active.chains.get(boot_profile).cloned().ok_or_else(|| {
                TempestError::Version(format!(
                    "Active release identity missing for profile {boot_profile}"
                ))
            })?);
            // Validate identity before acquiring the caller-owned transfer pin.
            self.pin_version(boot_profile, filename, version.version_id);
            return Ok((
                ResolvedFile {
                    durable_reader: None,
                    path: version.path.clone(),
                    pinned_version: Some(PinnedVersion {
                        boot_profile: version.boot_profile.clone(),
                        logical_name: version.logical_name.clone(),
                        version_id: version.version_id,
                        content_hash: version.content_hash.clone(),
                        size: version.size,
                    }),
                    content_hash: Some(version.content_hash.clone()),
                    boot_chain: boot_chain.clone(),
                },
                boot_chain,
            ));
        }

        if !allow_direct || active.owned_names.contains(&key) {
            return Err(TempestError::Protocol(
                crate::error::ProtocolError::FileNotFound(filename.to_string()),
            ));
        }
        drop(active);
        drop(gates);

        Ok((self.resolve_direct_file(filename, root)?, None))
    }

    /// Resolves strictly within an already pinned release manifest.
    ///
    /// No unmanaged fallback is permitted. Successful resolution creates an
    /// artifact pin that the caller must release after use.
    pub fn resolve_file_for_transfer_in_boot_chain(
        &self,
        pin: &BootChainPin,
        filename: &str,
        _root: &Path,
    ) -> Result<ResolvedFile, TempestError> {
        let boot_profile = normalize_boot_profile(Some(&pin.boot_profile))?;
        if filename.len() > 1024 || !is_canonical_artifact_name(filename) {
            let reason = if filename.len() > 1024 {
                "filename too long"
            } else {
                "noncanonical filename"
            };
            return Err(TempestError::Protocol(
                crate::error::ProtocolError::AccessViolation(reason.to_string()),
            ));
        }

        let groups = self.groups.read();
        let group = groups
            .iter()
            .find(|group| {
                group.boot_profile == boot_profile
                    && group.group_id == pin.group_id
                    && group.version_id == pin.version_id
                    && group.manifest.manifest_digest == pin.manifest_digest
            })
            .ok_or_else(|| {
                TempestError::Version(format!(
                    "Pinned boot chain not found for profile {} group {} version {}",
                    pin.boot_profile, pin.group_id, pin.version_id
                ))
            })?;

        if let Some(version) = group
            .files
            .iter()
            .find(|file| file.logical_name == filename)
        {
            self.pin_version(boot_profile, filename, version.version_id);
            return Ok(ResolvedFile {
                durable_reader: None,
                path: version.path.clone(),
                pinned_version: Some(PinnedVersion {
                    boot_profile: version.boot_profile.clone(),
                    logical_name: version.logical_name.clone(),
                    version_id: version.version_id,
                    content_hash: version.content_hash.clone(),
                    size: version.size,
                }),
                content_hash: Some(version.content_hash.clone()),
                boot_chain: Some(pin.clone()),
            });
        }

        Err(TempestError::Protocol(
            crate::error::ProtocolError::FileNotFound(filename.to_string()),
        ))
    }

    /// Returns the fully active release identity for a profile.
    ///
    /// # Errors
    ///
    /// Returns an access violation while that profile has a cutover gate.
    pub fn active_boot_chain_for_profile(
        &self,
        boot_profile: &str,
    ) -> Result<Option<BootChainPin>, TempestError> {
        let boot_profile = normalize_boot_profile(Some(boot_profile))?;
        if self.cutover_in_progress(boot_profile) {
            return Err(TempestError::Protocol(
                crate::error::ProtocolError::AccessViolation(
                    "release cutover in progress".to_string(),
                ),
            ));
        }
        Ok(self
            .active_releases
            .load()
            .chains
            .get(boot_profile)
            .cloned())
    }

    /// Returns whether new bindings are gated for `boot_profile` during cutover.
    pub fn cutover_in_progress(&self, boot_profile: &str) -> bool {
        self.cutover_gates.read().contains_key(boot_profile)
    }

    /// Returns active release groups containing the comparable filesystem path.
    pub fn active_groups_for_path(&self, failed_path: &Path) -> Vec<VersionGroup> {
        let failed_path = comparable_path(failed_path);
        let active = self.active_releases.load();
        self.groups
            .read()
            .iter()
            .filter(|group| {
                group.files.iter().all(|file| {
                    active
                        .versions
                        .get(&VersionKey::new(&group.boot_profile, &file.logical_name))
                        .is_some_and(|current| current.version_id == group.version_id)
                }) && group
                    .files
                    .iter()
                    .any(|file| comparable_path(&file.path) == failed_path)
            })
            .cloned()
            .collect()
    }

    /// Atomically removes all active mappings for a profile without deleting history.
    pub fn withdraw_profile(&self, boot_profile: &str) -> Result<(), TempestError> {
        let boot_profile = normalize_boot_profile(Some(boot_profile))?;
        // The groups lock is also the release-snapshot serialization lock.
        let _groups = self.groups.write();
        let active = self.active_releases.load();
        let mut next = (**active).clone();
        next.versions
            .retain(|key, _| key.boot_profile != boot_profile);
        next.chains.remove(boot_profile);
        self.active_releases.store(Arc::new(next));
        Ok(())
    }

    /// Lists older groups in reverse chronological order before `before_version`.
    pub fn prior_groups_for_profile(
        &self,
        boot_profile: &str,
        before_version: VersionId,
    ) -> Result<Vec<VersionGroup>, TempestError> {
        let boot_profile = normalize_boot_profile(Some(boot_profile))?;
        Ok(self
            .groups
            .read()
            .iter()
            .rev()
            .filter(|group| group.boot_profile == boot_profile && group.version_id < before_version)
            .cloned()
            .collect())
    }

    /// Resolves an unmanaged compatibility file directly beneath the TFTP root.
    fn resolve_direct_file(
        &self,
        filename: &str,
        root: &Path,
    ) -> Result<ResolvedFile, TempestError> {
        Ok(ResolvedFile {
            durable_reader: None,
            path: lexical_artifact_path(root, Path::new(filename))?,
            pinned_version: None,
            content_hash: None,
            boot_chain: None,
        })
    }

    /// Compute or retrieve a cached content hash for a file with bounded TTL storage.
    pub fn content_hash(&self, path: &Path) -> Result<ContentHash, TempestError> {
        if let Some(cached) = self.hash_cache.get(path) {
            let (hash, timestamp) = cached.value();
            if timestamp.elapsed().as_secs() < HASH_CACHE_TTL_SECS {
                return Ok(hash.clone());
            }
            // Expired — will recompute below
        }

        let hash = compute_sha256(path)?;
        self.cache_content_hash(path.to_path_buf(), hash.clone());
        Ok(hash)
    }

    /// Inserts one hash while enforcing the cache's exact cardinality bound.
    fn cache_content_hash(&self, path: PathBuf, hash: ContentHash) {
        let _admission = self.hash_cache_admission.lock();
        if !self.hash_cache.contains_key(&path) && self.hash_cache.len() >= MAX_HASH_CACHE_ENTRIES {
            if let Some(cutoff) =
                Instant::now().checked_sub(std::time::Duration::from_secs(HASH_CACHE_TTL_SECS))
            {
                self.hash_cache
                    .retain(|_, (_, timestamp)| *timestamp > cutoff);
            }
        }
        while !self.hash_cache.contains_key(&path)
            && self.hash_cache.len() >= MAX_HASH_CACHE_ENTRIES
        {
            let oldest = self
                .hash_cache
                .iter()
                .min_by_key(|entry| entry.value().1)
                .map(|entry| entry.key().clone());
            let Some(oldest) = oldest else { break };
            self.hash_cache.remove(&oldest);
        }
        self.hash_cache.insert(path, (hash, Instant::now()));
    }

    /// Invalidate hash cache for a file
    pub fn invalidate_hash(&self, path: &Path) {
        self.hash_cache.remove(path);
    }

    /// Returns the single-flight verification cell for one file identity and hash.
    pub(crate) fn artifact_verification(
        &self,
        path: &Path,
        metadata: &fs::Metadata,
        expected_hash: &str,
    ) -> Arc<OnceCell<ContentHash>> {
        let key = format!("{}:{expected_hash}", artifact_identity(path, metadata));
        if let Some(cell) = self.verified_artifacts.get(&key) {
            return cell.clone();
        }
        let mut order = self.verification_order.lock();
        if let Some(cell) = self.verified_artifacts.get(&key) {
            return cell.clone();
        }
        // Running and waiting verifiers own an Arc. Never evict their shared cell.
        // Bound the scan when every candidate is busy; the next miss resumes here.
        for _ in 0..order.len().min(64) {
            if self.verified_artifacts.len() < MAX_VERIFIED_ARTIFACTS {
                break;
            }
            let oldest = order.pop_front().unwrap();
            if self
                .verified_artifacts
                .remove_if(&oldest, |_, cell| Arc::strong_count(cell) == 1)
                .is_none()
            {
                order.push_back(oldest);
            }
        }
        let cell = Arc::new(OnceCell::new());
        if self.verified_artifacts.len() < MAX_VERIFIED_ARTIFACTS {
            order.push_back(key.clone());
            self.verified_artifacts.insert(key, cell.clone());
        }
        cell
    }

    /// Seeds the bounded verification cache for an already hashed artifact.
    pub(crate) fn cache_verified_artifact(&self, path: &Path, metadata: &fs::Metadata, hash: &str) {
        let cell = self.artifact_verification(path, metadata, hash);
        let _ = cell.set(hash.to_string());
    }

    /// Compares stable file identity before and after content verification.
    pub(crate) fn artifact_unchanged(
        &self,
        path: &Path,
        before: &fs::Metadata,
        after: &fs::Metadata,
    ) -> bool {
        artifact_identity(path, before) == artifact_identity(path, after)
    }

    /// Retain one artifact version for the lifetime of an in-flight transfer.
    fn pin_version(&self, boot_profile: &str, filename: &str, version_id: VersionId) {
        self.pinned_versions
            .entry((boot_profile.to_string(), filename.to_string(), version_id))
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    /// Release the default-profile pin held by a completed transfer.
    pub fn unpin_version(&self, filename: &str, version_id: VersionId) {
        self.unpin_version_for_profile(DEFAULT_BOOT_PROFILE, filename, version_id);
    }

    /// Releases one transfer-owned artifact pin and permits history collection.
    pub fn unpin_version_for_profile(
        &self,
        boot_profile: &str,
        filename: &str,
        version_id: VersionId,
    ) {
        let key = (boot_profile.to_string(), filename.to_string(), version_id);
        let mut removed = false;
        if let dashmap::mapref::entry::Entry::Occupied(mut entry) = self.pinned_versions.entry(key)
        {
            if *entry.get() > 1 {
                *entry.get_mut() -= 1;
            } else {
                entry.remove();
                removed = true;
            }
        }
        if removed {
            self.gc_versions(boot_profile, filename);
        }
        self.pin_notify.notify_waiters();
    }

    /// Adds a live boot-session reference to a release manifest.
    pub fn pin_boot_chain(&self, pin: &BootChainPin) {
        self.pinned_boot_chains
            .entry(pin.manifest_digest.clone())
            .and_modify(|count| *count += 1)
            .or_insert(1);
    }

    /// Releases one boot-session reference to a release manifest.
    pub fn unpin_boot_chain(&self, pin: &BootChainPin) {
        let mut changed = false;
        if let dashmap::mapref::entry::Entry::Occupied(mut entry) =
            self.pinned_boot_chains.entry(pin.manifest_digest.clone())
        {
            if *entry.get() > 1 {
                *entry.get_mut() -= 1;
                changed = true;
            } else {
                entry.remove();
                changed = true;
            }
        }
        if changed {
            self.pin_notify.notify_waiters();
        }
    }

    /// Returns the number of live session references to this manifest digest.
    pub fn pinned_boot_chain_count(&self, pin: &BootChainPin) -> usize {
        self.pinned_boot_chains
            .get(&pin.manifest_digest)
            .map(|count| *count)
            .unwrap_or(0)
    }

    /// Atomically switch a group of files to new versions
    pub fn atomic_switch(
        &self,
        group_id: String,
        files: Vec<(String, PathBuf)>,
    ) -> Result<VersionGroup, TempestError> {
        self.atomic_switch_for_profile(DEFAULT_BOOT_PROFILE.to_string(), group_id, files)
    }

    /// Hashes, manifests, and atomically activates one profile-scoped release.
    ///
    /// Existing in-flight pins continue to refer to prior versions.
    pub fn atomic_switch_for_profile(
        &self,
        boot_profile: String,
        group_id: String,
        files: Vec<(String, PathBuf)>,
    ) -> Result<VersionGroup, TempestError> {
        let group = self.prepare_group(&boot_profile, group_id, files)?;
        self.activate_group(group.clone())?;

        info!(
            boot_profile = %group.boot_profile,
            group_id = %group.group_id,
            version_id = group.version_id,
            file_count = group.files.len(),
            "Atomic version switch completed"
        );

        Ok(group)
    }

    /// Activate a new version group after preventing new requests from binding
    /// to any replaced old versions and waiting for existing pins to drain.
    pub async fn drain_gated_switch(
        &self,
        group_id: String,
        files: Vec<(String, PathBuf)>,
        timeout: Duration,
    ) -> Result<VersionGroup, TempestError> {
        self.drain_gated_switch_for_profile(
            DEFAULT_BOOT_PROFILE.to_string(),
            group_id,
            files,
            timeout,
            true,
        )
        .await
    }

    /// Gates old bindings, waits for selected pins, then activates a release.
    ///
    /// When `drain_sessions` is false, only transfer pins drain; existing boot
    /// sessions may retain their old release across the cutover.
    pub async fn drain_gated_switch_for_profile(
        &self,
        boot_profile: String,
        group_id: String,
        files: Vec<(String, PathBuf)>,
        timeout: Duration,
        drain_sessions: bool,
    ) -> Result<VersionGroup, TempestError> {
        let group = self.prepare_group(&boot_profile, group_id, files)?;
        self.prepare_drain_gated_group(group, timeout, drain_sessions)
            .await?
            .activate()
    }

    /// Builds a release and holds its cutover gate after the requested pins drain.
    ///
    /// The caller must invoke [`Self::activate_prepared_group`] or
    /// [`Self::abort_prepared_group`] to clear the gate. Timeout also clears it.
    pub async fn prepare_drain_gated_group_for_profile(
        &self,
        boot_profile: String,
        group_id: String,
        files: Vec<(String, PathBuf)>,
        timeout: Duration,
        drain_sessions: bool,
    ) -> Result<VersionGroup, TempestError> {
        let group = self.prepare_group(&boot_profile, group_id, files)?;
        self.prepare_drain_gated_group(group, timeout, drain_sessions)
            .await
            .map(PreparedGroupReservation::into_group)
    }

    /// Install a cutover gate for an already hashed release and wait for pins.
    pub(crate) async fn prepare_drain_gated_group(
        &self,
        group: VersionGroup,
        timeout: Duration,
        drain_sessions: bool,
    ) -> Result<PreparedGroupReservation<'_>, TempestError> {
        let blocked_versions = self.begin_cutover_gate(&group)?;
        let reservation = PreparedGroupReservation {
            store: self,
            group: Some(group),
        };
        let boot_profile = reservation.group().boot_profile.clone();
        let blocked_version_ids: HashSet<_> = blocked_versions.values().copied().collect();
        let blocked_manifests: Vec<_> = self
            .groups
            .read()
            .iter()
            .filter(|candidate| {
                candidate.boot_profile == boot_profile
                    && blocked_version_ids.contains(&candidate.version_id)
            })
            .map(|candidate| candidate.manifest.manifest_digest.clone())
            .collect();

        if !blocked_versions.is_empty() {
            let start = Instant::now();
            loop {
                let notified = self.pin_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let pinned_total = blocked_versions
                    .iter()
                    .map(|(key, version_id)| {
                        self.pinned_count_for_profile(
                            &key.boot_profile,
                            &key.logical_name,
                            *version_id,
                        )
                    })
                    .sum::<usize>()
                    + usize::from(drain_sessions)
                        * blocked_manifests
                            .iter()
                            .map(|digest| {
                                self.pinned_boot_chains
                                    .get(digest)
                                    .map(|count| *count)
                                    .unwrap_or(0)
                            })
                            .sum::<usize>();

                if pinned_total == 0 {
                    break;
                }

                let Some(remaining) = timeout.checked_sub(start.elapsed()) else {
                    return Err(TempestError::Version(format!(
                        "Drain-gated cutover timed out waiting for {pinned_total} pinned transfer(s)"
                    )));
                };

                if tokio::time::timeout(remaining, notified).await.is_err() {
                    return Err(TempestError::Version(format!(
                        "Drain-gated cutover timed out waiting for {pinned_total} pinned transfer(s)"
                    )));
                }
            }
        }

        Ok(reservation)
    }

    /// Atomically activates a prepared group and always clears its cutover gate.
    pub fn activate_prepared_group(
        &self,
        group: VersionGroup,
    ) -> Result<VersionGroup, TempestError> {
        let activation = self.activate_group(group.clone());
        self.clear_cutover_gate(&group.boot_profile, &group.group_id);
        activation?;

        info!(
            boot_profile = %group.boot_profile,
            group_id = %group.group_id,
            version_id = group.version_id,
            file_count = group.files.len(),
            "Drain-gated version switch completed"
        );

        Ok(group)
    }

    /// Clears the matching prepared cutover gate without changing active versions.
    pub fn abort_prepared_group(&self, boot_profile: &str, group_id: &str) {
        self.clear_cutover_gate(boot_profile, group_id);
    }

    /// Validates and hashes release files without changing active mappings.
    pub(crate) fn prepare_group(
        &self,
        boot_profile: &str,
        group_id: String,
        files: Vec<(String, PathBuf)>,
    ) -> Result<VersionGroup, TempestError> {
        self.prepare_group_inner(None, boot_profile, group_id, files)
    }

    /// Validates and hashes release files through one capability-confined open.
    pub(crate) fn prepare_group_from_artifact_root(
        &self,
        artifact_root: &ArtifactRoot,
        boot_profile: &str,
        group_id: String,
        files: Vec<(String, PathBuf)>,
    ) -> Result<VersionGroup, TempestError> {
        self.prepare_group_inner(Some(artifact_root), boot_profile, group_id, files)
    }

    fn prepare_group_inner(
        &self,
        artifact_root: Option<&ArtifactRoot>,
        boot_profile: &str,
        group_id: String,
        files: Vec<(String, PathBuf)>,
    ) -> Result<VersionGroup, TempestError> {
        let boot_profile = normalize_boot_profile(Some(boot_profile))?.to_string();
        if files.is_empty() {
            return Err(TempestError::Version(
                "Version group must contain at least one file".into(),
            ));
        }
        if files.len() > MAX_GROUP_ARTIFACTS {
            return Err(TempestError::Version(format!(
                "Version group may contain at most {MAX_GROUP_ARTIFACTS} files"
            )));
        }
        let mut names = HashSet::with_capacity(files.len());
        if files.iter().any(|(name, _)| !is_valid_logical_name(name)) {
            return Err(TempestError::Version(
                "Invalid logical artifact name".into(),
            ));
        }
        if let Some((name, _)) = files.iter().find(|(name, _)| !names.insert(name)) {
            return Err(TempestError::Version(format!(
                "Duplicate logical artifact name: {name}"
            )));
        }
        // A retained group identifier must never acquire a second manifest.
        {
            let groups = self.groups.read();
            if groups
                .iter()
                .any(|g| g.boot_profile == boot_profile && g.group_id == group_id)
            {
                return Err(TempestError::Version(format!(
                    "Group ID already registered for profile {boot_profile}: {group_id}"
                )));
            }
        }
        let version_id = self
            .next_version
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let mut file_versions = Vec::new();
        for (name, path) in &files {
            let (hash, metadata, stored_path) = if let Some(root) = artifact_root {
                hash_stable_artifact(root, path, Some(4 * 1024 * 1024 * 1024))?
            } else {
                let (hash, metadata) = hash_stable_file(path, Some(4 * 1024 * 1024 * 1024))?;
                (hash, metadata, path.clone())
            };
            let size = metadata.len();
            self.cache_verified_artifact(&stored_path, &metadata, &hash);

            file_versions.push(FileVersion {
                boot_profile: boot_profile.clone(),
                logical_name: name.clone(),
                path: stored_path,
                version_id,
                content_hash: hash,
                size,
            });
        }

        let created_at = jiff::Timestamp::now();
        let manifest = self.build_manifest(
            &boot_profile,
            &group_id,
            version_id,
            created_at,
            &file_versions,
        )?;

        let group = VersionGroup {
            boot_profile,
            group_id: group_id.clone(),
            version_id,
            files: file_versions.clone(),
            created_at,
            manifest,
        };

        Ok(group)
    }

    /// Publishes a prepared group as the profile's active atomic snapshot.
    fn activate_group(&self, group: VersionGroup) -> Result<(), TempestError> {
        let mut groups = self.groups.write();
        if groups
            .iter()
            .any(|g| g.boot_profile == group.boot_profile && g.group_id == group.group_id)
        {
            return Err(TempestError::Version(format!(
                "Group ID already registered for profile {}: {}",
                group.boot_profile, group.group_id
            )));
        }

        self.check_group_capacity(&groups, &group)?;

        let old = self.active_releases.load();
        let mut next = (**old).clone();
        next.versions
            .retain(|key, _| key.boot_profile != group.boot_profile);
        for file_version in &group.files {
            let key = VersionKey::new(&file_version.boot_profile, &file_version.logical_name);
            next.owned_names.insert(key.clone());
            next.versions.insert(key, file_version.clone());
            self.cache_content_hash(file_version.path.clone(), file_version.content_hash.clone());
        }
        next.chains.insert(
            group.boot_profile.clone(),
            BootChainPin {
                boot_profile: group.boot_profile.clone(),
                group_id: group.group_id.clone(),
                version_id: group.version_id,
                manifest_digest: group.manifest.manifest_digest.clone(),
            },
        );
        // Store group history (bounded to MAX_GROUP_HISTORY)
        let activated_profile = group.boot_profile.clone();
        let activated_version = group.version_id;
        groups.push(group);
        self.prune_groups(&mut groups, Some((&activated_profile, activated_version)));
        next.owned_names = Self::owned_names_for_groups(&groups);
        self.active_releases.store(Arc::new(next));

        Ok(())
    }

    /// Installs a profile gate for active versions replaced by a prepared group.
    fn begin_cutover_gate(
        &self,
        group: &VersionGroup,
    ) -> Result<HashMap<VersionKey, VersionId>, TempestError> {
        let mut gates = self.cutover_gates.write();
        if let Some(active_gate) = gates.get(&group.boot_profile) {
            return Err(TempestError::Version(format!(
                "Cutover already in progress for profile {}: {}",
                active_gate.boot_profile, active_gate.group_id
            )));
        }

        let active = self.active_releases.load();
        let blocked_versions: HashMap<VersionKey, VersionId> = active
            .versions
            .iter()
            .filter(|(key, _)| key.boot_profile == group.boot_profile)
            .map(|(key, old)| (key.clone(), old.version_id))
            .collect();

        // Reserve the profile even when it has no active release. This makes
        // preparation mutually exclusive with rollback and keeps the final
        // control-plane transition single-writer.
        gates.insert(
            group.boot_profile.clone(),
            CutoverGate {
                boot_profile: group.boot_profile.clone(),
                group_id: group.group_id.clone(),
                blocked_versions: blocked_versions.clone(),
            },
        );

        Ok(blocked_versions)
    }

    /// Removes the matching profile cutover gate.
    fn clear_cutover_gate(&self, boot_profile: &str, group_id: &str) {
        let mut gates = self.cutover_gates.write();
        if gates
            .get(boot_profile)
            .is_some_and(|g| g.group_id == group_id)
        {
            gates.remove(boot_profile);
        }
    }

    /// Test-only helper using the group's parent as a capability root.
    #[cfg(test)]
    pub fn rollback(&self, group_id: &str) -> Result<(), TempestError> {
        let root_path = self
            .groups
            .read()
            .iter()
            .find(|group| group.group_id == group_id)
            .and_then(|group| group.files.first())
            .and_then(|file| file.path.parent())
            .ok_or_else(|| TempestError::Version("rollback group has no artifact root".into()))?
            .to_path_buf();
        let artifact_root = ArtifactRoot::open(&root_path)?;
        self.rollback_for_profile(&artifact_root, DEFAULT_BOOT_PROFILE, group_id)
    }

    /// Verifies every artifact in a historical release without changing live state.
    pub(crate) fn prepare_rollback_for_profile(
        &self,
        artifact_root: &ArtifactRoot,
        boot_profile: &str,
        group_id: &str,
        manifest_digest: Option<&str>,
    ) -> Result<VerifiedRollback, TempestError> {
        let boot_profile = normalize_boot_profile(Some(boot_profile))?;
        if self.cutover_in_progress(boot_profile) {
            return Err(TempestError::Conflict(format!(
                "cutover already in progress for profile {boot_profile}"
            )));
        }
        let groups = self.groups.read();
        let group = groups
            .iter()
            .rev()
            .find(|g| g.boot_profile == boot_profile && g.group_id == group_id)
            .ok_or_else(|| {
                TempestError::Version(format!(
                    "Group not found for profile {boot_profile}: {group_id}"
                ))
            })?
            .clone();
        drop(groups);
        if manifest_digest.is_some_and(|digest| digest != group.manifest.manifest_digest) {
            return Err(TempestError::Conflict(
                "rollback target manifest changed; refresh the release snapshot".into(),
            ));
        }

        // Activation is committed only after every byte stream has been checked.
        for fv in &group.files {
            if !self.verify_file_integrity(artifact_root, fv, true)? {
                return Err(TempestError::Version(format!(
                    "Rollback artifact integrity mismatch: {}",
                    fv.logical_name
                )));
            }
        }

        Ok(VerifiedRollback(group))
    }

    /// Reserves the profile cutover gate for an already verified rollback.
    pub(crate) fn reserve_verified_rollback(
        &self,
        rollback: VerifiedRollback,
    ) -> Result<VerifiedRollbackReservation<'_>, TempestError> {
        self.begin_cutover_gate(&rollback.0)?;
        let retained = self.groups.read().iter().any(|group| {
            group.boot_profile == rollback.0.boot_profile
                && group.group_id == rollback.0.group_id
                && group.version_id == rollback.0.version_id
                && group.manifest.manifest_digest == rollback.0.manifest.manifest_digest
        });
        if !retained {
            self.clear_cutover_gate(&rollback.0.boot_profile, &rollback.0.group_id);
            return Err(TempestError::Conflict(
                "rollback target was pruned while it was being verified".into(),
            ));
        }
        Ok(VerifiedRollbackReservation {
            store: self,
            rollback: Some(rollback),
        })
    }

    /// Publishes a verified rollback while its profile cutover gate is held.
    pub(crate) fn activate_verified_rollback(&self, rollback: VerifiedRollback) {
        let group = rollback.0;
        let boot_profile = group.boot_profile.clone();
        let group_id = group.group_id.clone();
        // Serialize this swap with coherent control-plane snapshots and pruning.
        let _groups = self.groups.write();

        let old = self.active_releases.load();
        let mut next = (**old).clone();
        next.versions
            .retain(|key, _| key.boot_profile != boot_profile);
        for fv in &group.files {
            // Use the original logical artifact name recorded with the version.
            next.versions.insert(
                VersionKey::new(&fv.boot_profile, &fv.logical_name),
                fv.clone(),
            );
        }
        next.chains.insert(
            boot_profile.to_string(),
            BootChainPin {
                boot_profile: boot_profile.to_string(),
                group_id: group.group_id.clone(),
                version_id: group.version_id,
                manifest_digest: group.manifest.manifest_digest.clone(),
            },
        );
        self.active_releases.store(Arc::new(next));
        drop(_groups);
        self.clear_cutover_gate(&boot_profile, &group_id);

        info!(boot_profile = %boot_profile, group_id = %group_id, "Rolled back to group");
    }

    /// Reactivates a historical group after verifying capability-opened bytes.
    #[cfg(test)]
    pub(crate) fn rollback_for_profile(
        &self,
        artifact_root: &ArtifactRoot,
        boot_profile: &str,
        group_id: &str,
    ) -> Result<(), TempestError> {
        let rollback =
            self.prepare_rollback_for_profile(artifact_root, boot_profile, group_id, None)?;
        self.reserve_verified_rollback(rollback)?.activate();
        Ok(())
    }

    /// Garbage collect old versions that are no longer pinned
    fn gc_versions(&self, _boot_profile: &str, _filename: &str) {
        // Old versions are automatically freed when Arc<File> handles drop
        // and pinned_versions entries are removed.
    }

    /// List all active versions
    /// Pre-allocate Vec with known size
    pub fn list_versions(&self) -> Vec<FileVersion> {
        let active = self.active_releases.load();
        let mut result = Vec::with_capacity(active.versions.len());
        result.extend(active.versions.values().cloned());
        result
    }

    /// Clone at most `limit + 1` active versions for cursor pagination.
    pub fn list_versions_page(&self, start: usize, limit: usize) -> (Vec<FileVersion>, bool) {
        let active = self.active_releases.load();
        let mut page: Vec<_> = active
            .versions
            .values()
            .skip(start)
            .take(limit.saturating_add(1))
            .cloned()
            .collect();
        let has_more = page.len() > limit;
        page.truncate(limit);
        (page, has_more)
    }

    /// List all version groups
    /// Returns count and allows pagination instead of cloning entire Vec
    pub fn list_groups(&self) -> Vec<VersionGroup> {
        self.groups.read().clone()
    }

    /// Clone at most `limit + 1` release groups for cursor pagination.
    pub fn list_groups_page(&self, start: usize, limit: usize) -> (Vec<VersionGroup>, bool) {
        let groups = self.groups.read();
        let mut page: Vec<_> = groups
            .iter()
            .skip(start)
            .take(limit.saturating_add(1))
            .cloned()
            .collect();
        let has_more = page.len() > limit;
        page.truncate(limit);
        (page, has_more)
    }

    /// Clones active versions and retained groups under one serialization lock.
    pub(crate) fn release_snapshot(&self) -> Result<ReleaseSnapshot, TempestError> {
        let groups = self.groups.read();
        let active = self.active_releases.load();
        if groups.len() > MAX_RELEASE_SNAPSHOT_GROUPS
            || active.versions.len() > MAX_RELEASE_SNAPSHOT_ARTIFACTS
        {
            return Err(TempestError::Version(
                "release snapshot exceeds integrity-controller bounds".into(),
            ));
        }
        let historical_artifacts = groups
            .iter()
            .try_fold(0usize, |total, group| total.checked_add(group.files.len()));
        if historical_artifacts.is_none_or(|total| total > MAX_RELEASE_SNAPSHOT_ARTIFACTS) {
            return Err(TempestError::Version(
                "release snapshot exceeds integrity-controller bounds".into(),
            ));
        }
        Ok(ReleaseSnapshot {
            active_versions: active.versions.values().cloned().collect(),
            active_groups: active.chains.values().cloned().collect(),
            groups: groups.clone(),
        })
    }

    /// Rehashes one retained release through the capability root.
    pub(crate) fn verify_group_artifacts(
        &self,
        artifact_root: &ArtifactRoot,
        boot_profile: &str,
        group_id: &str,
        manifest_digest: &str,
        logical_names: &[String],
    ) -> Result<bool, GroupVerificationError> {
        const MAX_VERIFY_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
        const MAX_VERIFY_GROUP_BYTES: u64 = 64 * 1024 * 1024 * 1024;

        let boot_profile = normalize_boot_profile(Some(boot_profile))
            .map_err(|_| GroupVerificationError::InvalidRequest)?;
        let group = self
            .groups
            .read()
            .iter()
            .find(|group| {
                group.boot_profile == boot_profile
                    && group.group_id == group_id
                    && group.manifest.manifest_digest == manifest_digest
            })
            .cloned()
            .ok_or(GroupVerificationError::NotFound)?;
        let requested: HashSet<&str> = logical_names.iter().map(String::as_str).collect();
        if requested.len() != logical_names.len() {
            return Err(GroupVerificationError::InvalidRequest);
        }
        let files: Vec<_> = group
            .files
            .iter()
            .filter(|file| requested.contains(file.logical_name.as_str()))
            .collect();
        if files.len() != requested.len() {
            return Err(GroupVerificationError::InvalidRequest);
        }
        let total_bytes = files.iter().try_fold(0u64, |total, file| {
            if file.size > MAX_VERIFY_FILE_BYTES {
                return Err(GroupVerificationError::Internal);
            }
            total
                .checked_add(file.size)
                .ok_or(GroupVerificationError::Internal)
        })?;
        if total_bytes > MAX_VERIFY_GROUP_BYTES {
            return Err(GroupVerificationError::Internal);
        }
        for file in files {
            if !self
                .verify_file_integrity(artifact_root, file, false)
                .map_err(|_| GroupVerificationError::Internal)?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Returns groups whose complete artifact set is currently active.
    pub fn list_active_groups(&self) -> Vec<VersionGroup> {
        let active = self.active_releases.load();
        self.groups
            .read()
            .iter()
            .filter(|group| {
                group.files.iter().all(|file| {
                    active
                        .versions
                        .get(&VersionKey::new(&group.boot_profile, &file.logical_name))
                        .is_some_and(|current| current.version_id == group.version_id)
                })
            })
            .cloned()
            .collect()
    }

    /// Replace in-process hot state from the durable repository.
    /// The repository remains authoritative; this map is the fast transfer path cache.
    #[cfg(test)]
    pub fn replace_from_persistent(
        &self,
        persisted_groups: Vec<(VersionGroup, bool)>,
    ) -> Result<(), TempestError> {
        let root_path = persisted_groups
            .iter()
            .flat_map(|(group, _)| &group.files)
            .next()
            .and_then(|file| file.path.parent())
            .ok_or_else(|| {
                TempestError::Version("persistent snapshot has no artifact root".into())
            })?;
        let artifact_root = ArtifactRoot::open(root_path)?;
        let validated = self.validate_persistent_groups(&artifact_root, persisted_groups)?;
        self.commit_persistent_groups(validated);
        Ok(())
    }

    /// Validate a complete durable group snapshot without mutating live state.
    pub(crate) fn validate_persistent_groups(
        &self,
        artifact_root: &ArtifactRoot,
        persisted_groups: Vec<(VersionGroup, bool)>,
    ) -> Result<Arc<ValidatedPersistentGroups>, TempestError> {
        if persisted_groups.len() > MAX_GROUP_HISTORY {
            return Err(TempestError::Version(
                "Persistent release history exceeds capacity".into(),
            ));
        }
        let cached = self
            .validated_persistent_groups
            .lock()
            .clone()
            .filter(|cached| cached.matches(&persisted_groups));
        for (group, _) in &persisted_groups {
            if cached.is_none() {
                self.validate_group(group)?;
            }
            for file in &group.files {
                artifact_root.validate_candidate(&file.path)?;
            }
        }
        // Session-only churn can reuse authenticated metadata, but never skips
        // capability opens or changed-file verification of active artifacts.
        for (group, active) in &persisted_groups {
            if *active {
                for file in &group.files {
                    self.verify_persisted_file(artifact_root, file)?;
                }
            }
        }
        let validated =
            cached.unwrap_or_else(|| Arc::new(ValidatedPersistentGroups(persisted_groups)));
        *self.validated_persistent_groups.lock() = Some(validated.clone());
        Ok(validated)
    }

    /// Commit a snapshot only after groups and boot sessions have all validated.
    pub(crate) fn commit_persistent_groups(&self, validated: Arc<ValidatedPersistentGroups>) {
        let persisted_groups = &validated.0;
        {
            let groups = self.groups.read();
            let active = self.active_releases.load();
            if groups
                .iter()
                .eq(persisted_groups.iter().map(|(group, _)| group))
                && persisted_groups.iter().all(|(group, expected_active)| {
                    let is_active = active.chains.get(&group.boot_profile).is_some_and(|pin| {
                        pin.group_id == group.group_id
                            && pin.version_id == group.version_id
                            && pin.manifest_digest == group.manifest.manifest_digest
                    });
                    is_active == *expected_active
                })
            {
                return; // Session-only refresh must not rebuild or republish release maps.
            }
        }
        let mut active_versions = HashMap::new();
        let mut active_chains = HashMap::new();
        let mut owned_names = HashSet::new();
        let mut groups = Vec::with_capacity(persisted_groups.len());
        let mut max_version_id = 0;

        for (group, active) in persisted_groups {
            max_version_id = max_version_id.max(group.version_id);
            for file_version in &group.files {
                owned_names.insert(VersionKey::new(
                    &file_version.boot_profile,
                    &file_version.logical_name,
                ));
            }
            if *active {
                for file_version in &group.files {
                    active_versions.insert(
                        VersionKey::new(&file_version.boot_profile, &file_version.logical_name),
                        file_version.clone(),
                    );
                    self.cache_content_hash(
                        file_version.path.clone(),
                        file_version.content_hash.clone(),
                    );
                }
                active_chains.insert(
                    group.boot_profile.clone(),
                    BootChainPin {
                        boot_profile: group.boot_profile.clone(),
                        group_id: group.group_id.clone(),
                        version_id: group.version_id,
                        manifest_digest: group.manifest.manifest_digest.clone(),
                    },
                );
            }
            groups.push(group.clone());
        }

        let mut live_groups = self.groups.write();
        *live_groups = groups;
        self.active_releases.store(Arc::new(ActiveReleaseState {
            versions: active_versions,
            chains: active_chains,
            owned_names,
        }));
        self.next_version.store(
            max_version_id.saturating_add(1).max(1),
            std::sync::atomic::Ordering::SeqCst,
        );
        drop(live_groups);
    }

    /// Verifies persisted artifact metadata and content before hydration.
    fn verify_persisted_file(
        &self,
        artifact_root: &ArtifactRoot,
        file: &FileVersion,
    ) -> Result<(), TempestError> {
        if !self.verify_file_integrity(artifact_root, file, true)? {
            return Err(TempestError::Version(format!(
                "Persisted artifact integrity mismatch: {}",
                file.path.display()
            )));
        }
        Ok(())
    }

    fn verify_file_integrity(
        &self,
        artifact_root: &ArtifactRoot,
        file: &FileVersion,
        allow_cached: bool,
    ) -> Result<bool, TempestError> {
        let (mut opened, opened_path) = match artifact_root.open_read(&file.path) {
            Ok(opened) => opened,
            Err(TempestError::Protocol(
                ProtocolError::FileNotFound(_) | ProtocolError::AccessViolation(_),
            )) => return Ok(false),
            Err(error) => return Err(error),
        };
        let metadata = opened.metadata().map_err(|error| {
            TempestError::Version(format!("Cannot inspect {}: {error}", file.path.display()))
        })?;
        if !metadata.is_file() || metadata.len() != file.size {
            return Ok(false);
        }
        if allow_cached
            && self
                .artifact_verification(&opened_path, &metadata, &file.content_hash)
                .get()
                .map(String::as_str)
                == Some(file.content_hash.as_str())
        {
            return Ok(true);
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 256 * 1024];
        let mut total = 0u64;
        loop {
            let read = opened.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            total = total.saturating_add(read as u64);
            if total > file.size {
                return Ok(false);
            }
            hasher.update(&buffer[..read]);
        }
        let hash = hex::encode(hasher.finalize());
        let after = opened.metadata()?;
        if total != file.size
            || !self.artifact_unchanged(&opened_path, &metadata, &after)
            || hash != file.content_hash
        {
            return Ok(false);
        }
        self.cache_verified_artifact(&opened_path, &after, &hash);
        Ok(true)
    }

    /// Validates persisted group structure, digest, and signature policy.
    fn validate_group(&self, group: &VersionGroup) -> Result<(), TempestError> {
        let mut names = HashSet::with_capacity(group.files.len());
        let artifacts: Vec<_> = group
            .files
            .iter()
            .map(|file| ManifestArtifact {
                logical_name: file.logical_name.clone(),
                path: file.path.display().to_string(),
                content_hash: file.content_hash.clone(),
                size: file.size,
            })
            .collect();
        let valid = !group.files.is_empty()
            && is_valid_boot_profile(&group.boot_profile)
            && is_valid_group_id(&group.group_id)
            && group.files.len() <= MAX_GROUP_ARTIFACTS
            && group.files.iter().all(|file| {
                file.boot_profile == group.boot_profile
                    && file.version_id == group.version_id
                    && is_valid_logical_name(&file.logical_name)
                    && names.insert(&file.logical_name)
                    && file.content_hash.len() == 64
                    && file
                        .content_hash
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit())
            })
            && group.manifest.boot_profile == group.boot_profile
            && group.manifest.group_id == group.group_id
            && group.manifest.version_id == group.version_id
            && group.manifest.created_at == group.created_at
            && group.manifest.artifacts == artifacts
            && group.manifest.verify_digest()?
            && match (
                group.manifest.signature.is_some(),
                self.manifest_verifying_key(),
            ) {
                (true, Some(key)) => group.manifest.verify(&key).unwrap_or(false),
                (true, None) => false,
                (false, _) => !self.require_signed_manifests,
            };
        if valid {
            Ok(())
        } else {
            Err(TempestError::Version(format!(
                "Invalid persisted manifest for profile {} group {}",
                group.boot_profile, group.group_id
            )))
        }
    }

    /// Check under the control-plane lock before committing a durable deployment.
    pub(crate) fn ensure_group_capacity(
        &self,
        incoming: &VersionGroup,
    ) -> Result<(), TempestError> {
        self.check_group_capacity(&self.groups.read(), incoming)
    }

    fn check_group_capacity(
        &self,
        groups: &[VersionGroup],
        incoming: &VersionGroup,
    ) -> Result<(), TempestError> {
        if groups.len() < MAX_GROUP_HISTORY {
            return Ok(());
        }
        let active = self.active_releases.load();
        let gates = self.cutover_gates.read();
        let retained = groups
            .iter()
            .filter(|group| {
                self.group_is_protected(
                    group,
                    &active,
                    &gates,
                    Some((&incoming.boot_profile, incoming.version_id)),
                )
            })
            .count();
        if retained >= MAX_GROUP_HISTORY {
            return Err(TempestError::Conflict(
                "Active or pinned release history is at capacity".into(),
            ));
        }
        Ok(())
    }

    fn group_is_protected(
        &self,
        group: &VersionGroup,
        active: &ActiveReleaseState,
        gates: &HashMap<String, CutoverGate>,
        pending_active: Option<(&str, VersionId)>,
    ) -> bool {
        self.pinned_boot_chains
            .contains_key(&group.manifest.manifest_digest)
            || gates
                .get(&group.boot_profile)
                .is_some_and(|gate| gate.group_id == group.group_id)
            || match pending_active {
                // The outgoing release becomes evictable at this same atomic swap.
                Some((profile, version_id)) if profile == group.boot_profile => {
                    group.version_id == version_id
                }
                _ => active
                    .chains
                    .get(&group.boot_profile)
                    .is_some_and(|pin| pin.manifest_digest == group.manifest.manifest_digest),
            }
    }

    /// Removes oldest inactive, unpinned groups beyond the history bound.
    fn prune_groups(
        &self,
        groups: &mut Vec<VersionGroup>,
        pending_active: Option<(&str, VersionId)>,
    ) {
        let mut excess = groups.len().saturating_sub(MAX_GROUP_HISTORY);
        if excess == 0 {
            return;
        }
        let active = self.active_releases.load();
        let gates = self.cutover_gates.read();
        groups.retain(|group| {
            let protected = self.group_is_protected(group, &active, &gates, pending_active);
            if excess > 0 && !protected {
                excess -= 1;
                false
            } else {
                true
            }
        });
    }

    /// Prunes unpinned inactive history toward the 100-group memory bound.
    pub fn prune_group_history(&self) {
        let mut groups = self.groups.write();
        self.prune_groups(&mut groups, None);
        let active = self.active_releases.load();
        let owned_names = Self::owned_names_for_groups(&groups);
        if active.owned_names == owned_names {
            return;
        }
        let mut next = (**active).clone();
        next.owned_names = owned_names;
        self.active_releases.store(Arc::new(next));
    }

    fn owned_names_for_groups(groups: &[VersionGroup]) -> HashSet<VersionKey> {
        groups
            .iter()
            .flat_map(|group| {
                group
                    .files
                    .iter()
                    .map(|file| VersionKey::new(&file.boot_profile, &file.logical_name))
            })
            .collect()
    }

    /// Get the count of version groups without cloning
    pub fn group_count(&self) -> usize {
        self.groups.read().len()
    }

    /// Get active transfer count on a version
    pub fn pinned_count(&self, filename: &str, version_id: VersionId) -> usize {
        self.pinned_count_for_profile(DEFAULT_BOOT_PROFILE, filename, version_id)
    }

    /// Returns active transfer references for one profile/name/version tuple.
    pub fn pinned_count_for_profile(
        &self,
        boot_profile: &str,
        filename: &str,
        version_id: VersionId,
    ) -> usize {
        self.pinned_versions
            .get(&(boot_profile.to_string(), filename.to_string(), version_id))
            .map(|c| *c)
            .unwrap_or(0)
    }

    /// Builds and optionally signs the canonical manifest for a prepared group.
    fn build_manifest(
        &self,
        boot_profile: &str,
        group_id: &str,
        version_id: VersionId,
        created_at: jiff::Timestamp,
        file_versions: &[FileVersion],
    ) -> Result<BootChainManifest, TempestError> {
        if self.require_signed_manifests && self.manifest_signing_key.is_none() {
            return Err(TempestError::Version(
                "Manifest signing key required to activate a release".into(),
            ));
        }
        let artifacts: Vec<ManifestArtifact> = file_versions
            .iter()
            .map(|file| ManifestArtifact {
                logical_name: file.logical_name.clone(),
                path: file.path.display().to_string(),
                content_hash: file.content_hash.clone(),
                size: file.size,
            })
            .collect();

        let payload = BootChainManifest::payload_bytes(
            boot_profile,
            group_id,
            version_id,
            created_at,
            &artifacts,
        )?;
        let manifest_digest = hex::encode(Sha256::digest(&payload));
        let signature = self
            .manifest_signing_key
            .as_ref()
            .map(|key| hex::encode(key.sign(&payload).to_bytes()));

        Ok(BootChainManifest {
            boot_profile: boot_profile.to_string(),
            group_id: group_id.to_string(),
            version_id,
            created_at,
            artifacts,
            manifest_digest,
            signature,
        })
    }
}

/// Produces a stable comparable path even when the final file is absent.
fn comparable_path(path: &Path) -> PathBuf {
    path.canonicalize()
        .or_else(|_| {
            Ok::<_, std::io::Error>(
                path.parent()
                    .ok_or_else(|| std::io::Error::other("path has no parent"))?
                    .canonicalize()?
                    .join(
                        path.file_name()
                            .ok_or_else(|| std::io::Error::other("path has no file name"))?,
                    ),
            )
        })
        .unwrap_or_else(|_| path.to_path_buf())
}

/// Builds a platform-specific identity for detecting file replacement or mutation.
fn artifact_identity(path: &Path, metadata: &fs::Metadata) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            path.display(),
            metadata.dev(),
            metadata.ino(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec()
        )
    }
    #[cfg(not(unix))]
    format!(
        "{}:{}:{:?}",
        path.display(),
        metadata.len(),
        metadata.modified().ok()
    )
}

/// Stream SHA-256 with the default 4 GiB work limit.
pub fn compute_sha256(path: &Path) -> Result<String, TempestError> {
    compute_sha256_with_limit(path, Some(4 * 1024 * 1024 * 1024)) // Default 4GB limit
}

/// Streaming SHA-256 with an optional file size limit.
pub fn compute_sha256_with_limit(
    path: &Path,
    max_file_size: Option<u64>,
) -> Result<String, TempestError> {
    hash_stable_file(path, max_file_size).map(|(hash, _)| hash)
}

fn hash_stable_file(
    path: &Path,
    max_file_size: Option<u64>,
) -> Result<(String, fs::Metadata), TempestError> {
    let file = fs::File::open(path)
        .map_err(|e| TempestError::Version(format!("Failed to open {}: {e}", path.display())))?;
    let before = file
        .metadata()
        .map_err(|e| TempestError::Version(format!("Failed to stat {}: {e}", path.display())))?;
    hash_stable_open_file(file, path, before, max_file_size)
}

fn hash_stable_artifact(
    artifact_root: &ArtifactRoot,
    path: &Path,
    max_file_size: Option<u64>,
) -> Result<(String, fs::Metadata, PathBuf), TempestError> {
    let opened = artifact_root.open_release_source_with_metadata(path)?;
    let stored_path = opened.path;
    let (hash, metadata) =
        hash_stable_open_file(opened.file, &stored_path, opened.metadata, max_file_size)?;
    Ok((hash, metadata, stored_path))
}

pub(crate) fn hash_stable_open_file(
    mut file: fs::File,
    path: &Path,
    before: fs::Metadata,
    max_file_size: Option<u64>,
) -> Result<(String, fs::Metadata), TempestError> {
    if !before.is_file() {
        return Err(TempestError::Version(format!(
            "Artifact is not a regular file: {}",
            path.display()
        )));
    }
    if max_file_size.is_some_and(|limit| before.len() > limit) {
        return Err(TempestError::Version(format!(
            "File too large for hashing: {} bytes (limit {})",
            before.len(),
            max_file_size.unwrap_or_default()
        )));
    }
    let (hash, total) = hash_reader_with_limit(&mut file, max_file_size)?;
    let after = file
        .metadata()
        .map_err(|e| TempestError::Version(format!("Failed to re-stat {}: {e}", path.display())))?;
    if total != before.len() || artifact_identity(path, &before) != artifact_identity(path, &after)
    {
        return Err(TempestError::Version(format!(
            "File changed while hashing: {}",
            path.display()
        )));
    }
    Ok((hash, after))
}

fn hash_reader_with_limit(
    reader: &mut impl Read,
    max_bytes: Option<u64>,
) -> Result<(String, u64), TempestError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(|| {
            TempestError::Version("Hash byte count overflowed while reading artifact".into())
        })?;
        if max_bytes.is_some_and(|limit| total > limit) {
            return Err(TempestError::Version(format!(
                "Artifact stream exceeded hashing limit: {total} bytes (limit {})",
                max_bytes.unwrap_or_default()
            )));
        }
        hasher.update(&buffer[..read]);
    }
    Ok((hex::encode(hasher.finalize()), total))
}

#[cfg(test)]
mod tests;
