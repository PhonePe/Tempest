// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashSet;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::error::TempestError;
use crate::features::versioning::{
    DEFAULT_BOOT_PROFILE, GroupVerificationError, is_valid_boot_profile, is_valid_group_id,
    is_valid_logical_name,
};
use crate::server::ServerState;
use axum::extract::{Json, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use tracing::warn;

const DEFAULT_CUTOVER_TIMEOUT_MS: u64 = 30_000;
const MAX_CUTOVER_TIMEOUT_MS: u64 = 300_000;

/// Selects which existing pins a release cutover waits to drain.
#[derive(Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CutoverPolicy {
    #[default]
    DrainAll,
    PreserveSessions,
}

/// JSON representation of one artifact version.
#[derive(Serialize)]
struct VersionInfo {
    boot_profile: String,
    name: String,
    version_id: u64,
    content_hash: String,
    size: u64,
}

/// JSON representation of one coordinated release group.
#[derive(Serialize)]
struct GroupInfo {
    boot_profile: String,
    group_id: String,
    version_id: u64,
    files: Vec<VersionInfo>,
    created_at: String,
    manifest_digest: String,
    manifest_signature: Option<String>,
}

/// Coherent active-release and history view used by integrity controllers.
#[derive(Serialize)]
struct ReleaseSnapshot {
    versions: Vec<VersionInfo>,
    /// Exact identities for the active profile releases.
    active_groups: Vec<ActiveGroupInfo>,
    groups: Vec<GroupInfo>,
}

#[derive(Serialize)]
struct ActiveGroupInfo {
    boot_profile: String,
    group_id: String,
    version_id: u64,
    manifest_digest: String,
}

#[derive(Deserialize)]
/// Identifies one retained release for server-side integrity verification.
pub struct VerifyGroupRequest {
    /// Boot-profile namespace.
    pub(crate) boot_profile: String,
    /// Retained release identifier.
    pub(crate) group_id: String,
    /// Manifest digest binding the exact retained release.
    pub(crate) manifest_digest: String,
    /// Logical artifacts to verify in one bounded batch.
    pub(crate) files: Vec<String>,
}

#[derive(Serialize)]
struct VerifyGroupResponse {
    verified: bool,
}

/// Converts internal artifact metadata into its API representation.
fn version_info(v: crate::features::versioning::FileVersion) -> VersionInfo {
    VersionInfo {
        boot_profile: v.boot_profile,
        name: v.logical_name,
        version_id: v.version_id,
        content_hash: v.content_hash,
        size: v.size,
    }
}

fn group_info(group: crate::features::versioning::VersionGroup) -> GroupInfo {
    GroupInfo {
        boot_profile: group.boot_profile,
        group_id: group.group_id,
        version_id: group.version_id,
        files: group.files.into_iter().map(version_info).collect(),
        created_at: crate::timestamp::to_rfc3339(group.created_at),
        manifest_digest: group.manifest.manifest_digest,
        manifest_signature: group.manifest.signature,
    }
}

fn is_valid_manifest_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Bounded cursor request accepted by version and group list endpoints.
#[derive(Default, Deserialize)]
pub struct PageQuery {
    cursor: Option<usize>,
    limit: Option<usize>,
}

/// One bounded page of control-plane results.
#[derive(Serialize)]
pub struct Page<T> {
    items: Vec<T>,
    next_cursor: Option<String>,
}

fn page_bounds(query: PageQuery) -> (usize, usize) {
    const DEFAULT_LIMIT: usize = 50;
    const MAX_LIMIT: usize = 100;
    let start = query.cursor.unwrap_or(0);
    let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    (start, limit)
}

fn page<T>(items: Vec<T>, start: usize, has_more: bool) -> Page<T> {
    Page {
        next_cursor: has_more.then(|| start.saturating_add(items.len()).to_string()),
        items,
    }
}

/// Lists one bounded page of active artifact versions.
pub async fn list_versions(
    State(state): State<Arc<ServerState>>,
    Query(query): Query<PageQuery>,
) -> impl IntoResponse {
    let (start, limit) = page_bounds(query);
    let (versions, has_more) = state.version_store.list_versions_page(start, limit);
    let versions = versions.into_iter().map(version_info).collect();

    Json(page(versions, start, has_more))
}

/// Lists one bounded page of release groups and manifest identities.
pub async fn list_groups(
    State(state): State<Arc<ServerState>>,
    Query(query): Query<PageQuery>,
) -> impl IntoResponse {
    let (start, limit) = page_bounds(query);
    let (groups, has_more) = state.version_store.list_groups_page(start, limit);
    let groups = groups.into_iter().map(group_info).collect();

    Json(page(groups, start, has_more))
}

/// Returns active versions and retained history from one atomic release snapshot.
pub async fn release_snapshot(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    match state.version_store.release_snapshot() {
        Ok(snapshot) => Json(ReleaseSnapshot {
            versions: snapshot
                .active_versions
                .into_iter()
                .map(version_info)
                .collect(),
            active_groups: snapshot
                .active_groups
                .into_iter()
                .map(|pin| ActiveGroupInfo {
                    boot_profile: pin.boot_profile,
                    group_id: pin.group_id,
                    version_id: pin.version_id,
                    manifest_digest: pin.manifest_digest,
                })
                .collect(),
            groups: snapshot.groups.into_iter().map(group_info).collect(),
        })
        .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Release snapshot exceeds integrity-controller bounds",
        )
            .into_response(),
    }
}

/// Rehashes one retained release through Tempest's capability-confined root.
pub async fn verify_group(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<VerifyGroupRequest>,
) -> impl IntoResponse {
    if !is_valid_boot_profile(&req.boot_profile)
        || !is_valid_group_id(&req.group_id)
        || !is_valid_manifest_digest(&req.manifest_digest)
        || req.files.is_empty()
        || req.files.len() > 100
    {
        return (StatusCode::BAD_REQUEST, "Invalid release identity").into_response();
    }
    let mut unique_files = HashSet::with_capacity(req.files.len());
    if req
        .files
        .iter()
        .any(|name| !is_valid_logical_name(name) || !unique_files.insert(name.as_str()))
    {
        return (StatusCode::BAD_REQUEST, "Invalid release identity").into_response();
    }
    let permit = match state.artifact_hash_budget.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Artifact verification is unavailable",
            )
                .into_response();
        }
    };
    let verify_state = state.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let artifact_root = verify_state
            .artifact_root()
            .map_err(|_| GroupVerificationError::Internal)?;
        verify_state.version_store.verify_group_artifacts(
            &artifact_root,
            &req.boot_profile,
            &req.group_id,
            &req.manifest_digest,
            &req.files,
        )
    })
    .await;
    match result {
        Ok(Ok(verified)) => Json(VerifyGroupResponse { verified }).into_response(),
        Ok(Err(GroupVerificationError::NotFound)) => {
            (StatusCode::NOT_FOUND, "Release group not found").into_response()
        }
        Ok(Err(GroupVerificationError::InvalidRequest)) => {
            (StatusCode::BAD_REQUEST, "Invalid artifact selection").into_response()
        }
        Ok(Err(GroupVerificationError::Internal)) | Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Artifact verification failed",
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
/// JSON request for atomically registering and activating a release group.
///
/// File paths must resolve to regular files beneath the configured artifact
/// root. At most 100 files are accepted and cutover waits at most 300 seconds.
pub struct DeployRequest {
    #[serde(default)]
    boot_profile: Option<String>,
    group_id: String,
    files: Vec<FileMapping>,
    #[serde(default)]
    drain_timeout_ms: Option<u64>,
    #[serde(default)]
    cutover_policy: CutoverPolicy,
}

/// Maps a logical artifact name to its source path during deployment.
#[derive(Deserialize)]
struct FileMapping {
    name: String,
    path: String,
}

/// Validates, manifests, optionally persists, and activates a release group.
///
/// Returns `400` for invalid identifiers or paths, `409` when pin draining or a
/// durable compare-and-swap conflicts, and `500` for non-disclosed internal errors.
pub async fn deploy_version(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<DeployRequest>,
) -> impl IntoResponse {
    // Validate group_id format
    if !is_valid_group_id(&req.group_id) {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid group_id: must be 1-128 alphanumeric/dash/underscore/dot characters"
                .to_string(),
        )
            .into_response();
    }

    let boot_profile = req
        .boot_profile
        .unwrap_or_else(|| DEFAULT_BOOT_PROFILE.to_string());
    if !is_valid_boot_profile(&boot_profile) {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid boot_profile: must be 1-64 alphanumeric/dash/underscore/dot characters"
                .to_string(),
        )
            .into_response();
    }

    // Bound hashing and manifest construction before touching the filesystem.
    const MAX_FILES_PER_DEPLOY: usize = 100;
    if req.files.is_empty() || req.files.len() > MAX_FILES_PER_DEPLOY {
        return (
            StatusCode::BAD_REQUEST,
            format!("Deploy requires 1-{MAX_FILES_PER_DEPLOY} files"),
        )
            .into_response();
    }

    // Validate logical names are safe relative TFTP paths.
    let mut logical_names = HashSet::with_capacity(req.files.len());
    for f in &req.files {
        if !is_valid_logical_name(&f.name) || !logical_names.insert(f.name.as_str()) {
            return (
                StatusCode::BAD_REQUEST,
                "File names must be unique safe relative TFTP paths".to_string(),
            )
                .into_response();
        }
        if f.path.contains('\0') {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid file path: must not contain null bytes".to_string(),
            )
                .into_response();
        }
    }

    // Preserve the operator-supplied candidates for one capability-confined
    // open-and-hash operation in the blocking worker below. Validating an
    // ambient path here and reopening it later would permit a symlink race.
    let mut files: Vec<(String, PathBuf)> = Vec::with_capacity(req.files.len());
    for f in &req.files {
        let path = PathBuf::from(&f.path);
        files.push((f.name.clone(), path));
    }

    let timeout_ms = req
        .drain_timeout_ms
        .unwrap_or(DEFAULT_CUTOVER_TIMEOUT_MS)
        .min(MAX_CUTOVER_TIMEOUT_MS);
    let cutover_timeout = Duration::from_millis(timeout_ms);
    let drain_sessions = matches!(req.cutover_policy, CutoverPolicy::DrainAll);
    let cutover_started = Instant::now();
    state.metrics.release_event("cutover_attempt");
    let hash_permit = match state.artifact_hash_budget.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
            state
                .metrics
                .cutover_finished(cutover_started, "cutover_failure");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Deploy preparation is unavailable".to_string(),
            )
                .into_response();
        }
    };
    let prepare_state = state.clone();
    let prepare_profile = boot_profile.clone();
    let rejected_file_count = files.len();
    let rejected_group_id = req.group_id.clone();
    let prepare_group_id = req.group_id;
    let prepared = match tokio::task::spawn_blocking(move || {
        let _hash_permit = hash_permit;
        let artifact_root = prepare_state.artifact_root()?;
        prepare_state
            .version_store
            .prepare_group_from_artifact_root(
                &artifact_root,
                &prepare_profile,
                prepare_group_id,
                files,
            )
    })
    .await
    {
        Ok(Ok(group)) => group,
        Ok(Err(
            error @ TempestError::Protocol(
                crate::error::ProtocolError::AccessViolation(_)
                | crate::error::ProtocolError::FileNotFound(_),
            ),
        )) => {
            warn!(
                root = %state.config.server.root.display(),
                boot_profile = %boot_profile,
                group_id = %rejected_group_id,
                file_count = rejected_file_count,
                error = %error,
                "Rejected unsafe deploy file path"
            );
            state
                .metrics
                .cutover_finished(cutover_started, "cutover_failure");
            return (
                StatusCode::BAD_REQUEST,
                "File path is outside TFTP root, not a regular file, or does not exist".to_string(),
            )
                .into_response();
        }
        Ok(Err(_)) | Err(_) => {
            state
                .metrics
                .cutover_finished(cutover_started, "cutover_failure");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Deploy failed: artifact preparation error".to_string(),
            )
                .into_response();
        }
    };

    // Gate installation and pin waiting use VersionStore's own synchronization;
    // the global control lock is reacquired only for the final CAS/activation.
    let gated = state
        .version_store
        .prepare_drain_gated_group(prepared, cutover_timeout, drain_sessions)
        .await;
    let switch_result = match gated {
        Err(error) => Err(error),
        Ok(prepared) => {
            let _control_guard = state.control_plane_lock.lock().await;
            if state.ensure_persistence_admission().await.is_err() {
                state
                    .metrics
                    .cutover_finished(cutover_started, "persistence_failure");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Deploy failed: persistence unavailable",
                )
                    .into_response();
            }
            // Reject before durable state changes; activation also checks in-memory callers.
            if state
                .version_store
                .ensure_group_capacity(prepared.group())
                .is_err()
            {
                state
                    .metrics
                    .cutover_finished(cutover_started, "cutover_conflict");
                return (
                    StatusCode::CONFLICT,
                    "Active or pinned release history is at capacity",
                )
                    .into_response();
            }
            if let Some(persistence) = &state.persistence {
                let revision = match persistence.version_revision(&boot_profile).await {
                    Ok(revision) => revision,
                    Err(_) => {
                        state
                            .metrics
                            .cutover_finished(cutover_started, "cutover_failure");
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Deploy failed: durable persistence error".to_string(),
                        )
                            .into_response();
                    }
                };
                if let Err(error) = persistence
                    .persist_version_group(prepared.group(), revision)
                    .await
                {
                    let conflict = matches!(error, TempestError::Conflict(_));
                    state.metrics.cutover_finished(
                        cutover_started,
                        if conflict {
                            "cutover_conflict"
                        } else {
                            "cutover_failure"
                        },
                    );
                    return (
                        if conflict {
                            StatusCode::CONFLICT
                        } else {
                            StatusCode::INTERNAL_SERVER_ERROR
                        },
                        if conflict {
                            "Deploy conflicted with another version mutation; retry".to_string()
                        } else {
                            "Deploy failed: durable persistence error".to_string()
                        },
                    )
                        .into_response();
                }
            }
            prepared.activate()
        }
    };

    match switch_result {
        Ok(group) => {
            state
                .metrics
                .cutover_finished(cutover_started, "cutover_success");
            let response = group_info(group);
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(crate::error::TempestError::Version(message))
            if message.contains("Cutover already in progress") || message.contains("timed out") =>
        {
            state.metrics.cutover_finished(
                cutover_started,
                if message.contains("timed out") {
                    "cutover_timeout"
                } else {
                    "cutover_conflict"
                },
            );
            (
                StatusCode::CONFLICT,
                "Deploy cutover is waiting for existing release pins to drain".to_string(),
            )
                .into_response()
        }
        // Don't expose internal error details to API clients
        Err(_e) => {
            state
                .metrics
                .cutover_finished(cutover_started, "cutover_failure");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Deploy failed: internal error".to_string(),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
/// JSON request selecting a previously registered group for rollback.
pub struct RollbackRequest {
    #[serde(default)]
    boot_profile: Option<String>,
    group_id: String,
    #[serde(default)]
    manifest_digest: Option<String>,
    #[serde(default)]
    expected_active_group: Option<String>,
    #[serde(default)]
    expected_active_manifest_digest: Option<String>,
}

#[derive(Deserialize)]
/// JSON request withdrawing the currently active group from a boot profile.
pub struct WithdrawRequest {
    #[serde(default)]
    boot_profile: Option<String>,
    group_id: String,
    #[serde(default)]
    manifest_digest: Option<String>,
}

/// Removes the matching active release after optional durable CAS persistence.
///
/// Returns `404` without an active release and `409` if the requested group is
/// stale, a cutover is active, or another durable mutation won the race.
pub async fn withdraw_version(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<WithdrawRequest>,
) -> impl IntoResponse {
    if !is_valid_group_id(&req.group_id)
        || req
            .manifest_digest
            .as_deref()
            .is_some_and(|digest| !is_valid_manifest_digest(digest))
    {
        return (StatusCode::BAD_REQUEST, "Invalid group_id format").into_response();
    }
    let boot_profile = req
        .boot_profile
        .unwrap_or_else(|| DEFAULT_BOOT_PROFILE.to_string());
    if !is_valid_boot_profile(&boot_profile) {
        return (StatusCode::BAD_REQUEST, "Invalid boot_profile format").into_response();
    }

    let _control_guard = state.control_plane_lock.lock().await;
    if state.ensure_persistence_admission().await.is_err() {
        state.metrics.release_event("withdrawal_failure");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Withdrawal failed: persistence unavailable",
        )
            .into_response();
    }
    let active = match state
        .version_store
        .active_boot_chain_for_profile(&boot_profile)
    {
        Ok(Some(active)) => active,
        Ok(None) => return (StatusCode::NOT_FOUND, "No active release").into_response(),
        Err(_) => {
            return (StatusCode::CONFLICT, "Release cutover is in progress").into_response();
        }
    };
    if active.group_id != req.group_id
        || req
            .manifest_digest
            .as_deref()
            .is_some_and(|digest| digest != active.manifest_digest)
    {
        return (
            StatusCode::CONFLICT,
            "Requested group is not the active release",
        )
            .into_response();
    }

    let result = if let Some(persistence) = &state.persistence {
        match persistence.version_revision(&boot_profile).await {
            Ok(revision) => persistence
                .withdraw_version_group(
                    &boot_profile,
                    &req.group_id,
                    req.manifest_digest.as_deref(),
                    revision,
                )
                .await
                .and_then(|_| state.version_store.withdraw_profile(&boot_profile)),
            Err(error) => Err(error),
        }
    } else {
        state.version_store.withdraw_profile(&boot_profile)
    };

    match result {
        Ok(()) => {
            state.metrics.release_event("withdrawal_success");
            (StatusCode::OK, "Release withdrawn").into_response()
        }
        Err(TempestError::Conflict(_)) => {
            state.metrics.release_event("withdrawal_failure");
            (
                StatusCode::CONFLICT,
                "Withdrawal conflicted with another version mutation",
            )
                .into_response()
        }
        Err(_) => {
            state.metrics.release_event("withdrawal_failure");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Withdrawal failed: internal error",
            )
                .into_response()
        }
    }
}

/// Requires the digest-bound withdrawal contract introduced with API v2.
pub async fn withdraw_version_exact(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<WithdrawRequest>,
) -> impl IntoResponse {
    if req.manifest_digest.is_none() {
        return (StatusCode::BAD_REQUEST, "manifest_digest is required").into_response();
    }
    withdraw_version(State(state), Json(req))
        .await
        .into_response()
}

/// Reactivates a registered group for a profile using durable-first ordering.
///
/// Returns `400` for malformed identifiers, `409` for concurrent durable
/// mutation, and `500` without exposing persistence or filesystem details.
pub async fn rollback_version(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<RollbackRequest>,
) -> impl IntoResponse {
    // Validate group_id format
    if !is_valid_group_id(&req.group_id) {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid group_id format".to_string(),
        )
            .into_response();
    }

    let boot_profile = req
        .boot_profile
        .unwrap_or_else(|| DEFAULT_BOOT_PROFILE.to_string());
    if !is_valid_boot_profile(&boot_profile) {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid boot_profile format".to_string(),
        )
            .into_response();
    }
    if req
        .expected_active_group
        .as_deref()
        .is_some_and(|group| !is_valid_group_id(group))
        || req
            .manifest_digest
            .as_deref()
            .is_some_and(|digest| !is_valid_manifest_digest(digest))
        || req
            .expected_active_manifest_digest
            .as_deref()
            .is_some_and(|digest| !is_valid_manifest_digest(digest))
        || (req.expected_active_group.is_none() && req.expected_active_manifest_digest.is_some())
    {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid rollback identity".to_string(),
        )
            .into_response();
    }

    let active = match state
        .version_store
        .active_boot_chain_for_profile(&boot_profile)
    {
        Ok(active) => active,
        Err(_) => {
            state.metrics.release_event("rollback_failure");
            return (
                StatusCode::CONFLICT,
                "Release cutover is in progress".to_string(),
            )
                .into_response();
        }
    };
    if let Some(expected_group) = req.expected_active_group.as_deref() {
        let matches = active.as_ref().is_some_and(|current| {
            current.group_id == expected_group
                && req
                    .expected_active_manifest_digest
                    .as_deref()
                    .is_none_or(|digest| digest == current.manifest_digest)
        });
        if !matches {
            state.metrics.release_event("rollback_failure");
            return (
                StatusCode::CONFLICT,
                "Active release changed; rollback request is stale".to_string(),
            )
                .into_response();
        }
    }

    let hash_permit = match state.artifact_hash_budget.clone().acquire_owned().await {
        Ok(permit) => permit,
        Err(_) => {
            state.metrics.release_event("rollback_failure");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Rollback verification is unavailable".to_string(),
            )
                .into_response();
        }
    };
    let prepare_state = state.clone();
    let prepare_profile = boot_profile.clone();
    let prepare_group = req.group_id.clone();
    let prepare_digest = req.manifest_digest.clone();
    let rollback = match tokio::task::spawn_blocking(move || {
        let _hash_permit = hash_permit;
        let artifact_root = prepare_state.artifact_root()?;
        prepare_state.version_store.prepare_rollback_for_profile(
            &artifact_root,
            &prepare_profile,
            &prepare_group,
            prepare_digest.as_deref(),
        )
    })
    .await
    {
        Ok(Ok(rollback)) => rollback,
        Ok(Err(TempestError::Conflict(_))) => {
            state.metrics.release_event("rollback_failure");
            return (
                StatusCode::CONFLICT,
                "Rollback request conflicts with current release state".to_string(),
            )
                .into_response();
        }
        Ok(Err(_)) | Err(_) => {
            state.metrics.release_event("rollback_failure");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Rollback failed: artifact verification error".to_string(),
            )
                .into_response();
        }
    };

    let _control_guard = state.control_plane_lock.lock().await;
    if state.ensure_persistence_admission().await.is_err() {
        state.metrics.release_event("rollback_failure");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Rollback failed: persistence unavailable",
        )
            .into_response();
    }
    if let Some(expected_active_group) = req.expected_active_group.as_deref() {
        let active_group = state
            .version_store
            .active_boot_chain_for_profile(&boot_profile)
            .ok()
            .flatten();
        let matches = active_group.as_ref().is_some_and(|active| {
            active.group_id == expected_active_group
                && req
                    .expected_active_manifest_digest
                    .as_deref()
                    .is_none_or(|digest| digest == active.manifest_digest)
        });
        if !matches {
            state.metrics.release_event("rollback_failure");
            return (
                StatusCode::CONFLICT,
                "Active release changed; rollback request is stale".to_string(),
            )
                .into_response();
        }
    }
    let rollback = match state.version_store.reserve_verified_rollback(rollback) {
        Ok(rollback) => rollback,
        Err(_) => {
            state.metrics.release_event("rollback_failure");
            return (
                StatusCode::CONFLICT,
                "Release cutover is in progress".to_string(),
            )
                .into_response();
        }
    };
    let rollback_result = if let Some(persistence) = &state.persistence {
        match persistence.version_revision(&boot_profile).await {
            Ok(revision) => {
                persistence
                    .rollback_version_group(
                        &boot_profile,
                        &req.group_id,
                        req.manifest_digest.as_deref(),
                        revision,
                        req.expected_active_group.as_deref(),
                        req.expected_active_manifest_digest.as_deref(),
                    )
                    .await
            }
            Err(error) => Err(error),
        }
    } else {
        Ok(())
    };

    match rollback_result {
        Ok(()) => {
            rollback.activate();
            state.metrics.release_event("rollback_success");
            (StatusCode::OK, "Rollback successful").into_response()
        }
        Err(TempestError::Conflict(_)) => {
            state.metrics.release_event("rollback_failure");
            (
                StatusCode::CONFLICT,
                "Rollback conflicted with another version mutation; retry".to_string(),
            )
                .into_response()
        }
        // Don't expose internal error details
        Err(_e) => {
            state.metrics.release_event("rollback_failure");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Rollback failed: internal error".to_string(),
            )
                .into_response()
        }
    }
}

/// Requires the digest-bound rollback target introduced with API v2.
pub async fn rollback_version_exact(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<RollbackRequest>,
) -> impl IntoResponse {
    if req.manifest_digest.is_none() {
        return (StatusCode::BAD_REQUEST, "manifest_digest is required").into_response();
    }
    rollback_version(State(state), Json(req))
        .await
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn concurrent_deployments_cannot_overfill_release_history() {
        let directory = tempfile::tempdir().unwrap();
        let artifact = directory.path().join("kernel");
        std::fs::write(&artifact, b"kernel").unwrap();
        let mut config = crate::config::TempestConfig::default();
        config.server.root = directory.path().to_path_buf();
        let state = crate::server::TftpServer::new(config).state();
        for index in 0..99 {
            state
                .version_store
                .atomic_switch_for_profile(
                    format!("profile-{index}"),
                    "release".into(),
                    vec![("kernel".into(), artifact.clone())],
                )
                .unwrap();
        }
        let request = |profile: &str| {
            Json(DeployRequest {
                boot_profile: Some(profile.into()),
                group_id: "release".into(),
                files: vec![FileMapping {
                    name: "kernel".into(),
                    path: artifact.display().to_string(),
                }],
                drain_timeout_ms: Some(1000),
                cutover_policy: CutoverPolicy::PreserveSessions,
            })
        };
        let (left, right) = tokio::join!(
            deploy_version(State(state.clone()), request("left")),
            deploy_version(State(state.clone()), request("right")),
        );
        let mut statuses = [
            left.into_response().status(),
            right.into_response().status(),
        ];
        statuses.sort();
        assert_eq!(statuses, [StatusCode::OK, StatusCode::CONFLICT]);
        assert_eq!(
            state.version_store.release_snapshot().unwrap().groups.len(),
            100
        );
        assert!(!state.version_store.cutover_in_progress("left"));
        assert!(!state.version_store.cutover_in_progress("right"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn deploy_rejects_a_symlink_that_escapes_the_artifact_root() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_artifact = outside.path().join("kernel");
        std::fs::write(&outside_artifact, b"outside kernel").unwrap();
        let candidate = directory.path().join("kernel");
        symlink(&outside_artifact, &candidate).unwrap();

        let mut config = crate::config::TempestConfig::default();
        config.server.root = directory.path().to_path_buf();
        let state = crate::server::TftpServer::new(config).state();
        let response = deploy_version(
            State(state.clone()),
            Json(DeployRequest {
                boot_profile: None,
                group_id: "release-escape".into(),
                files: vec![FileMapping {
                    name: "kernel".into(),
                    path: candidate.display().to_string(),
                }],
                drain_timeout_ms: None,
                cutover_policy: CutoverPolicy::DrainAll,
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            body.as_ref(),
            b"File path is outside TFTP root, not a regular file, or does not exist"
        );
        assert!(state.version_store.list_groups().is_empty());
    }

    #[tokio::test]
    async fn deploy_accepts_parent_components_that_remain_inside_the_artifact_root() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::create_dir(directory.path().join("images")).unwrap();
        std::fs::write(directory.path().join("kernel"), b"kernel").unwrap();
        let mut config = crate::config::TempestConfig::default();
        config.server.root = directory.path().to_path_buf();
        let state = crate::server::TftpServer::new(config).state();
        let response = deploy_version(
            State(state.clone()),
            Json(DeployRequest {
                boot_profile: None,
                group_id: "release-confined-parent".into(),
                files: vec![FileMapping {
                    name: "kernel".into(),
                    path: directory
                        .path()
                        .join("images/../kernel")
                        .display()
                        .to_string(),
                }],
                drain_timeout_ms: None,
                cutover_policy: CutoverPolicy::DrainAll,
            }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.version_store.list_groups().len(), 1);
    }

    #[tokio::test]
    async fn exact_mutation_routes_require_digest_identity() {
        let state = crate::server::TftpServer::new(crate::config::TempestConfig::default()).state();
        let withdraw = withdraw_version_exact(
            State(state.clone()),
            Json(WithdrawRequest {
                boot_profile: None,
                group_id: "release-a".into(),
                manifest_digest: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(withdraw.status(), StatusCode::BAD_REQUEST);

        let rollback = rollback_version_exact(
            State(state),
            Json(RollbackRequest {
                boot_profile: None,
                group_id: "release-a".into(),
                manifest_digest: None,
                expected_active_group: Some("release-b".into()),
                expected_active_manifest_digest: Some("b".repeat(64)),
            }),
        )
        .await
        .into_response();
        assert_eq!(rollback.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn verify_rejects_file_count_before_processing_members() {
        let state = crate::server::TftpServer::new(crate::config::TempestConfig::default()).state();
        let response = verify_group(
            State(state),
            Json(VerifyGroupRequest {
                boot_profile: DEFAULT_BOOT_PROFILE.into(),
                group_id: "release-a".into(),
                manifest_digest: "a".repeat(64),
                files: vec!["kernel".into(); 101],
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_withdraw_requires_matching_active_group() {
        let directory = tempfile::tempdir().unwrap();
        let artifact = directory.path().join("kernel");
        std::fs::write(&artifact, b"kernel").unwrap();
        let mut config = crate::config::TempestConfig::default();
        config.server.root = directory.path().to_path_buf();
        let state = crate::server::TftpServer::new(config).state();
        state
            .version_store
            .atomic_switch("release-a".into(), vec![("kernel".into(), artifact)])
            .unwrap();

        let stale = withdraw_version(
            State(state.clone()),
            Json(WithdrawRequest {
                boot_profile: None,
                group_id: "release-b".into(),
                manifest_digest: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        assert!(
            state
                .version_store
                .active_boot_chain_for_profile(DEFAULT_BOOT_PROFILE)
                .unwrap()
                .is_some()
        );

        let active_digest = state
            .version_store
            .active_boot_chain_for_profile(DEFAULT_BOOT_PROFILE)
            .unwrap()
            .unwrap()
            .manifest_digest;
        let stale_manifest = withdraw_version(
            State(state.clone()),
            Json(WithdrawRequest {
                boot_profile: None,
                group_id: "release-a".into(),
                manifest_digest: Some("0".repeat(64)),
            }),
        )
        .await
        .into_response();
        assert_eq!(stale_manifest.status(), StatusCode::CONFLICT);

        let withdrawn = withdraw_version(
            State(state.clone()),
            Json(WithdrawRequest {
                boot_profile: None,
                group_id: "release-a".into(),
                manifest_digest: Some(active_digest),
            }),
        )
        .await
        .into_response();
        assert_eq!(withdrawn.status(), StatusCode::OK);
        assert!(
            state
                .version_store
                .active_boot_chain_for_profile(DEFAULT_BOOT_PROFILE)
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn rollback_rejects_a_stale_expected_active_group() {
        let directory = tempfile::tempdir().unwrap();
        let first = directory.path().join("kernel-1");
        let second = directory.path().join("kernel-2");
        std::fs::write(&first, b"kernel-1").unwrap();
        std::fs::write(&second, b"kernel-2").unwrap();
        let mut config = crate::config::TempestConfig::default();
        config.server.root = directory.path().to_path_buf();
        let state = crate::server::TftpServer::new(config).state();
        state
            .version_store
            .atomic_switch("release-a".into(), vec![("kernel".into(), first)])
            .unwrap();
        state
            .version_store
            .atomic_switch("release-b".into(), vec![("kernel".into(), second)])
            .unwrap();

        let hash_permits = state
            .artifact_hash_budget
            .clone()
            .acquire_many_owned(4)
            .await
            .unwrap();
        let stale = tokio::time::timeout(
            Duration::from_millis(100),
            rollback_version(
                State(state.clone()),
                Json(RollbackRequest {
                    boot_profile: None,
                    group_id: "release-a".into(),
                    manifest_digest: None,
                    expected_active_group: Some("release-c".into()),
                    expected_active_manifest_digest: None,
                }),
            ),
        )
        .await
        .expect("known-stale rollback must not wait for a hash worker")
        .into_response();
        assert_eq!(stale.status(), StatusCode::CONFLICT);
        drop(hash_permits);

        let stale_target = rollback_version(
            State(state.clone()),
            Json(RollbackRequest {
                boot_profile: None,
                group_id: "release-a".into(),
                manifest_digest: Some("0".repeat(64)),
                expected_active_group: Some("release-b".into()),
                expected_active_manifest_digest: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(stale_target.status(), StatusCode::CONFLICT);

        let applied = rollback_version(
            State(state.clone()),
            Json(RollbackRequest {
                boot_profile: None,
                group_id: "release-a".into(),
                manifest_digest: None,
                expected_active_group: Some("release-b".into()),
                expected_active_manifest_digest: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(applied.status(), StatusCode::OK);
        assert_eq!(
            state
                .version_store
                .active_boot_chain_for_profile(DEFAULT_BOOT_PROFILE)
                .unwrap()
                .unwrap()
                .group_id,
            "release-a"
        );
    }

    #[test]
    fn test_logical_name_validation_allows_safe_relative_paths() {
        assert!(is_valid_logical_name("vmlinuz"));
        assert!(is_valid_logical_name("pxelinux.cfg/default"));
        assert!(!is_valid_logical_name("../vmlinuz"));
        assert!(!is_valid_logical_name("/vmlinuz"));
        assert!(!is_valid_logical_name("boot\\vmlinuz"));
        assert!(!is_valid_logical_name(""));
    }

    #[tokio::test]
    async fn test_deploy_cutover_policies_honor_session_pins() {
        let dir = tempfile::tempdir().unwrap();
        let paths: Vec<_> = (1..=3)
            .map(|version| {
                let path = dir.path().join(format!("kernel-{version}"));
                std::fs::write(&path, format!("kernel-{version}")).unwrap();
                path
            })
            .collect();
        let mut config = crate::config::TempestConfig::default();
        config.server.root = dir.path().to_path_buf();
        let state = crate::server::TftpServer::new(config).state();
        state
            .version_store
            .atomic_switch(
                "release-1".into(),
                vec![("kernel".into(), paths[0].clone())],
            )
            .unwrap();
        let client_ip = std::net::IpAddr::from([10, 0, 0, 1]);
        let session = |pin| crate::server::BootSessionEntry {
            trace_id: None,
            boot_profile: DEFAULT_BOOT_PROFILE.into(),
            client_mac: None,
            serial: None,
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: Some(pin),
            expires_at: Instant::now() + Duration::from_secs(60),
        };
        state.insert_boot_session(
            client_ip,
            session(
                state
                    .version_store
                    .active_boot_chain_for_profile(DEFAULT_BOOT_PROFILE)
                    .unwrap()
                    .unwrap(),
            ),
        );

        let deploy = |group_id: &str, path: &Path, cutover_policy: CutoverPolicy| DeployRequest {
            boot_profile: None,
            group_id: group_id.into(),
            files: vec![FileMapping {
                name: "kernel".into(),
                path: path.display().to_string(),
            }],
            drain_timeout_ms: Some(1),
            cutover_policy,
        };
        let response = deploy_version(
            State(state.clone()),
            Json(deploy(
                "release-2",
                &paths[1],
                CutoverPolicy::PreserveSessions,
            )),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);

        let release_2 = state
            .version_store
            .active_boot_chain_for_profile(DEFAULT_BOOT_PROFILE)
            .unwrap()
            .unwrap();
        assert_eq!(release_2.group_id, "release-2");
        state.insert_boot_session(client_ip, session(release_2));
        let response = deploy_version(
            State(state.clone()),
            Json(deploy("release-3", &paths[2], CutoverPolicy::DrainAll)),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            state
                .version_store
                .active_boot_chain_for_profile(DEFAULT_BOOT_PROFILE)
                .unwrap()
                .unwrap()
                .group_id,
            "release-2"
        );
    }
}
