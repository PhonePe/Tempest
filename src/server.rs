// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::collections::{BinaryHeap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::{DashMap, DashSet};
use ed25519_dalek::{SigningKey, VerifyingKey};
use subtle::ConstantTimeEq;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{debug, error, info, warn};

use crate::artifact_cache::HotArtifactCache;
use crate::artifact_root::ArtifactRoot;
use crate::config::{TempestConfig, validate_tftp_performance_config};
use crate::error::{ProtocolError, TempestError, TftpErrorCode};
use crate::extension::{
    AdmissionContext, AdmissionPolicy, EXTENSION_PROTOCOL_VERSION,
    EXTENSION_PROTOCOL_VERSION_OPTION, ProvisioningPriorityProvider, ROUTE_ARTIFACT_VERSION_OPTION,
    ROUTE_BOOT_PROFILE_OPTION, ROUTE_CONTENT_HASH_OPTION, ROUTE_GROUP_OPTION,
    ROUTE_MANIFEST_DIGEST_OPTION, ReadProtocolExtension, ReadRequestRouter, SharedBlockCache,
    TransferPacing, TransferScheduler,
};
use crate::features::audit::{
    AuditLog, AuditRecord, AuditReservation, AuditWriter, TransferOutcome,
};
use crate::features::bandwidth_governor::{self, BandwidthGovernor};
use crate::features::boot_phase::{PhaseClassifier, TransferProfile};
use crate::features::dscp::DscpManager;
use crate::features::versioning::{
    BootChainPin, DEFAULT_BOOT_PROFILE, VersionStore, is_valid_boot_profile,
};
use crate::persistence::PersistenceStore;
use crate::protocol::options::{
    OptionDefaults, OptionRequestKind, negotiate_options_only_for_request,
};
use crate::protocol::packet::TftpPacket;
use crate::protocol::transfer::{
    PinnedVersionGuard, TransferId, TransferMetrics, run_read_transfer_for_phase,
    run_write_transfer_with_duplicate_request, supported_transfer_mode,
};
use crate::rate_limit::PerIpRateLimiter;

mod client_limit;
mod metrics;

pub(crate) use client_limit::TftpClientLimits;
use client_limit::TftpClientPermit;
pub(crate) use metrics::ExtensionFailure;
#[cfg(test)]
use metrics::MAX_PROFILE_METRICS;
pub use metrics::{DURATION_BUCKETS, DurationHistogram, ServerMetrics};

/// Stable metrics and audit label for UDP TFTP delivery.
pub const TRANSPORT_TFTP: &str = "TFTP";
/// Stable metrics and audit label for HTTP artifact delivery.
pub const TRANSPORT_HTTP: &str = "HTTP";
/// Stable metrics and audit label for native UEFI HTTP Boot delivery.
pub const TRANSPORT_HTTP_NATIVE: &str = "HTTP_NATIVE";

/// Maximum number of audit-log scans allowed to occupy blocking workers at once.
pub(crate) const MAX_CONCURRENT_AUDIT_READS: usize = 4;
/// Maximum integrity-failure entries retained by Tempest core.
pub(crate) const MAX_QUARANTINED_FILES: usize = 10_000;

fn bind_tftp_listener(bind_addr: SocketAddr, reuse_port: bool) -> std::io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(bind_addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    if reuse_port {
        #[cfg(target_os = "linux")]
        {
            socket.set_reuse_port(true)?;
        }
        #[cfg(not(target_os = "linux"))]
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "SO_REUSEPORT listener sharding requires Linux",
            ));
        }
    }
    socket.set_nonblocking(true)?;
    socket.bind(&bind_addr.into())?;
    let socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(socket)
}

fn configure_udp_socket_buffers(
    socket: &UdpSocket,
    receive_bytes: usize,
    send_bytes: Option<usize>,
) -> std::io::Result<()> {
    let socket = socket2::SockRef::from(socket);
    socket.set_recv_buffer_size(receive_bytes)?;
    if let Some(send_bytes) = send_bytes {
        socket.set_send_buffer_size(send_bytes)?;
    }
    Ok(())
}

fn configure_transfer_socket_buffers(socket: &UdpSocket, bytes: usize) -> std::io::Result<()> {
    if bytes == 0 {
        return Ok(());
    }
    configure_udp_socket_buffers(socket, bytes, Some(bytes))
}

fn option_defaults_for_profile(
    state: &ServerState,
    profile: Option<&TransferProfile>,
) -> OptionDefaults {
    if let Some(profile) = profile {
        OptionDefaults {
            max_block_size: profile.block_size,
            max_window_size: profile.max_window_size,
            retransmit_interval_ms: profile.retransmit_interval_ms,
            min_retransmit_interval_ms: profile.min_retransmit_interval_ms,
            max_retransmit_interval_ms: profile.max_retransmit_interval_ms,
            max_retries: profile.max_retries,
        }
    } else {
        OptionDefaults {
            max_block_size: state.config.server.default_block_size,
            max_window_size: state.config.server.max_window_size,
            retransmit_interval_ms: state.config.server.retransmit_interval_ms,
            min_retransmit_interval_ms: state.config.server.min_retransmit_interval_ms,
            max_retransmit_interval_ms: state.config.server.max_retransmit_interval_ms,
            max_retries: state.config.server.max_retries,
        }
    }
}

/// Decrements the active-transfer count without underflow and returns its prior value.
pub(crate) fn release_active_transfer_counter(active_transfers: &AtomicUsize) -> usize {
    let mut current = active_transfers.load(Ordering::Acquire);
    loop {
        if current == 0 {
            return 0;
        }
        match active_transfers.compare_exchange_weak(
            current,
            current - 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return current,
            Err(actual) => current = actual,
        }
    }
}

/// Releases a reserved transfer slot on early return until ownership is handed off.
pub(crate) struct ReservedTransferSlotGuard<'a> {
    state: &'a ServerState,
    released: bool,
}

#[derive(Debug)]
struct InflightTftpTidGuard {
    client_addr: SocketAddr,
    duplicate_request: Arc<tokio::sync::Notify>,
    inflight: Arc<DashMap<SocketAddr, Arc<tokio::sync::Notify>>>,
    client_limit: Option<TftpClientPermit>,
}

impl InflightTftpTidGuard {
    fn claim(
        inflight: Arc<DashMap<SocketAddr, Arc<tokio::sync::Notify>>>,
        client_addr: SocketAddr,
    ) -> Option<InflightTftpTidGuard> {
        use dashmap::mapref::entry::Entry;

        match inflight.entry(client_addr) {
            Entry::Vacant(entry) => {
                let duplicate_request = Arc::new(tokio::sync::Notify::new());
                entry.insert(duplicate_request.clone());
                Some(Self {
                    client_addr,
                    duplicate_request,
                    inflight: inflight.clone(),
                    client_limit: None,
                })
            }
            Entry::Occupied(entry) => {
                entry.get().notify_one();
                None
            }
        }
    }

    fn duplicate_request(&self) -> Arc<tokio::sync::Notify> {
        self.duplicate_request.clone()
    }
}

impl Drop for InflightTftpTidGuard {
    fn drop(&mut self) {
        // Re-admission after releasing this TID must see the returned quota.
        drop(self.client_limit.take());
        // A late drop must not remove a newer owner after client-port reuse.
        self.inflight.remove_if(&self.client_addr, |_, signal| {
            Arc::ptr_eq(signal, &self.duplicate_request)
        });
    }
}

const TRANSFER_ID_SEQUENCE_MASK: u64 = (1_u64 << 62) - 1;

#[derive(Debug)]
pub(crate) struct TransferIdGenerator {
    process_prefix: u64,
    sequence: AtomicU64,
}

impl TransferIdGenerator {
    pub(crate) fn new() -> Self {
        Self {
            // A process nonce keeps IDs distinct across restarts. Per-transfer
            // uniqueness is then exact and does not require an entropy syscall.
            process_prefix: (TransferId::new_v4().as_u128() >> 64) as u64,
            sequence: AtomicU64::new(0),
        }
    }

    fn next(&self) -> Result<TransferId, TempestError> {
        #[allow(
            deprecated,
            reason = "try_update requires Rust 1.95; retain fetch_update for MSRV 1.85"
        )]
        let reservation =
            self.sequence
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    (current < TRANSFER_ID_SEQUENCE_MASK).then_some(current + 1)
                });
        let sequence = reservation.map_err(|_| {
            TempestError::Io(std::io::Error::other(
                "process transfer ID sequence exhausted",
            ))
        })? + 1;
        let variant_and_sequence = 0x8000_0000_0000_0000_u64 | sequence;
        Ok(TransferId::from_u128(
            (u128::from(self.process_prefix) << 64) | u128::from(variant_and_sequence),
        ))
    }
}

impl<'a> ReservedTransferSlotGuard<'a> {
    /// Arms a guard for a slot already counted as active.
    pub(crate) fn new(state: &'a ServerState) -> Self {
        Self {
            state,
            released: false,
        }
    }

    /// Leaves slot release to the transfer engine's terminal metrics path.
    pub(crate) fn hand_off(&mut self) {
        self.released = true;
    }
}

impl Drop for ReservedTransferSlotGuard<'_> {
    fn drop(&mut self) {
        if !self.released {
            self.state.release_reserved_transfer_slot();
        }
    }
}

/// A boot session registered by the provisioning layer ahead of a TFTP boot.
/// It is keyed by client IP because ordinary PXE/TFTP packets do not carry
/// authenticated MAC or serial identity.
#[derive(Clone)]
pub struct BootSessionEntry {
    /// Optional provisioning trace identifier propagated into audit records.
    pub trace_id: Option<String>,
    /// Profile namespace used for release resolution.
    pub boot_profile: String,
    /// Optional provisioning-supplied client MAC address; TFTP does not authenticate it.
    pub client_mac: Option<String>,
    /// Optional hardware serial used by provisioning-priority extensions.
    pub serial: Option<String>,
    /// Monotonic provisioning generation used to reject stale durable pin updates.
    pub boot_epoch: u64,
    /// SHA-256 digest of the one-time HTTP artifact bearer token.
    pub artifact_token_hash: Option<[u8; 32]>,
    /// Release fixed by the session's first managed artifact resolution.
    pub pinned_boot_chain: Option<BootChainPin>,
    /// Wall-clock deadline after which this entry is discarded during cleanup.
    pub expires_at: Instant,
}

/// A TFTP request held under entry and byte permits while capacity is exhausted.
#[derive(Debug)]
pub struct PendingTransfer {
    /// Transfer peer and destination for replies.
    pub client_addr: SocketAddr,
    /// Parsed RRQ or WRQ fields owned by the queue until admission.
    pub request: crate::protocol::packet::RequestPacket,
    /// Whether the queued request is a write rather than a read.
    pub is_write: bool,
    /// Monotonic enqueue time used for expiry and FIFO tie-breaking.
    pub arrived_at: Instant,
    /// Phase weight governs dequeue priority (higher = dequeued first).
    pub phase_weight: f64,
    /// Entry reservation retained while this request is queued in any stage.
    queue_entry_permit: OwnedSemaphorePermit,
    /// Byte reservation matching the received request datagram.
    queue_byte_permit: OwnedSemaphorePermit,
    /// Capacity retained for the transfer's terminal audit record.
    audit_reservation: Option<AuditReservation>,
    /// Exclusive ownership of the client TID while this request is queued.
    client_tid_guard: InflightTftpTidGuard,
    /// Counts accepted queue work until it becomes an active transfer or is dropped.
    queue_count_guard: QueuedTransferGuard,
}

struct QueuedTransferGuard {
    counter: Arc<AtomicUsize>,
    metrics: Arc<ServerMetrics>,
}

impl QueuedTransferGuard {
    fn new(counter: Arc<AtomicUsize>, metrics: Arc<ServerMetrics>) -> Self {
        counter.fetch_add(1, Ordering::AcqRel);
        Self { counter, metrics }
    }
}

impl std::fmt::Debug for QueuedTransferGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("QueuedTransferGuard")
    }
}

impl Drop for QueuedTransferGuard {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
        self.metrics.drain_notify.notify_waiters();
    }
}

impl PartialEq for PendingTransfer {
    fn eq(&self, other: &Self) -> bool {
        self.phase_weight == other.phase_weight && self.arrived_at == other.arrived_at
    }
}
impl Eq for PendingTransfer {}

impl PartialOrd for PendingTransfer {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PendingTransfer {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher phase_weight = higher priority; ties broken by earlier arrival.
        self.phase_weight
            .partial_cmp(&other.phase_weight)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| other.arrived_at.cmp(&self.arrived_at))
    }
}

/// Shared release, policy, capacity, and lifecycle state.
pub struct ServerState {
    /// Immutable validated runtime configuration shared by all tasks.
    pub config: Arc<TempestConfig>,
    /// In-memory release registry, resolver, and pin accounting.
    pub version_store: VersionStore,
    /// Precompiled artifact-path to boot-phase classifier.
    pub phase_classifier: PhaseClassifier,
    /// Optional shared-block provider supplied by the current composition.
    pub shared_blocks: Option<Arc<dyn SharedBlockCache>>,
    /// Optional ACK-driven pacing provider supplied by the current composition.
    pub transfer_pacing: Option<Arc<dyn TransferPacing>>,
    /// Optional custom wire-protocol pack supplied by the current composition.
    pub read_protocol: Option<Arc<dyn ReadProtocolExtension>>,
    /// Optional externally owned signed-redirect selector.
    pub read_request_router: Option<Arc<dyn ReadRequestRouter>>,
    /// Optional externally supplied bounded admission and stagger policy.
    pub admission_policy: Option<Arc<dyn AdmissionPolicy>>,
    /// Process-wide counters and histograms shared across transports.
    pub metrics: Arc<ServerMetrics>,
    /// Number of reserved or running transfers; lifecycle completion decrements it.
    pub active_transfers: Arc<AtomicUsize>,
    /// Number of accepted requests retained by the bounded admission queue.
    pub(crate) queued_transfers: Arc<AtomicUsize>,
    /// Client transfer IDs reserved by queued requests and initial handshakes.
    pub(crate) inflight_tftp_tids: Arc<DashMap<SocketAddr, Arc<tokio::sync::Notify>>>,
    /// Per-source TFTP quota, independent of HTTP and the global transfer slots.
    pub(crate) tftp_client_limits: Arc<TftpClientLimits>,
    /// Process-scoped UUID generator used only for transfer correlation.
    pub(crate) transfer_ids: TransferIdGenerator,
    /// When set, new transfer admission is rejected while existing work drains.
    pub drain_mode: AtomicBool,
    /// Whether the UDP listener is currently bound and serving.
    pub tftp_ready: AtomicBool,
    /// Actual UDP port, including an ephemeral port selected for configured port zero.
    pub tftp_bound_port: AtomicU16,
    /// Aggregate readiness flag for required background dependencies.
    pub critical_services_healthy: Arc<AtomicBool>,
    /// Timestamp when the server was constructed — used for uptime metrics
    pub start_time: Instant,
    /// Per-IP rate limiter for the TFTP UDP loop
    pub tftp_rate_limiter: Arc<PerIpRateLimiter>,
    /// Per-client warning budget for malformed TFTP datagrams.
    pub(crate) malformed_log_limiter: Arc<PerIpRateLimiter>,
    /// Per-client warning budget for unexpected TFTP opcodes.
    pub(crate) unexpected_log_limiter: Arc<PerIpRateLimiter>,
    /// Per-IP rate limiter for the HTTP API (shared with api/mod.rs middleware)
    pub http_rate_limiter: Arc<PerIpRateLimiter>,
    /// Optional read-only observer of HTTP response production.
    pub(crate) http_observer: Option<HttpObserverCallback>,
    /// DSCP/QoS manager — applies TOS byte marking per boot phase
    pub dscp_manager: Arc<DscpManager>,
    /// Durable delivery audit log — None if audit is not configured.
    pub audit_log: Option<Arc<AuditLog>>,
    /// Bounded dedicated terminal-record writer for the configured audit log.
    pub(crate) audit_writer: Option<Arc<AuditWriter>>,
    /// Bounds concurrent audit-log scans on the blocking worker pool.
    pub(crate) audit_read_budget: Arc<Semaphore>,
    /// Files quarantined by an external integrity controller.
    pub quarantined_files: Arc<DashSet<String>>,
    /// Serializes exact-capacity admission for quarantine entries created by core.
    pub(crate) quarantine_admission: parking_lot::Mutex<()>,
    /// Optional packet scheduler supplied by the current server composition.
    pub scheduler: Option<Arc<dyn TransferScheduler>>,
    /// Optional vendor-neutral source of provisioning-priority weights.
    pub provisioning_priority: Option<Arc<dyn ProvisioningPriorityProvider>>,
    /// Boot sessions registered by the provisioning layer via POST /api/v1/sessions.
    pub boot_sessions: Arc<DashMap<IpAddr, BootSessionEntry>>,
    /// Digest-to-session index used only by authenticated HTTP artifact requests.
    pub http_session_tokens: Arc<DashMap<[u8; 32], IpAddr>>,
    /// Durable control-plane repository. When configured, database state is
    /// authoritative and in-process maps are hot-path caches hydrated from it.
    pub persistence: Option<Arc<PersistenceStore>>,
    /// Last complete durable snapshot installed in the hot-path caches.
    pub(crate) persistence_revision: AtomicI64,
    /// Monotonic time of the last successful durable snapshot validation.
    pub(crate) persistence_snapshot_validated_at: parking_lot::Mutex<Option<Instant>>,
    /// Lazily started, bounded SQL session group-commit queue.
    pub(crate) session_registration_queue:
        std::sync::OnceLock<tokio::sync::mpsc::Sender<crate::api::sessions::Command>>,
    /// Serializes durable mutations with cache refresh on this node.
    pub control_plane_lock: Arc<tokio::sync::Mutex<()>>,
    /// Global bandwidth governor — caps aggregate TFTP/HTTP artifact output to the server NIC ceiling.
    /// None when bandwidth_governor_enabled = false.
    pub bandwidth_governor: Option<Arc<BandwidthGovernor>>,
    /// Bounds blocking artifact hashing shared by control-plane operations.
    pub(crate) artifact_hash_budget: Arc<Semaphore>,
    /// Bounds foreground filesystem work even after its request is cancelled.
    pub(crate) artifact_io_budget: Arc<Semaphore>,
    /// Lazily opened capability root shared by every artifact operation.
    pub(crate) artifact_root: std::sync::OnceLock<Result<Arc<ArtifactRoot>, String>>,
    /// Identity-validated, byte-bounded snapshots of frequently read small artifacts.
    pub(crate) hot_artifact_cache: Arc<HotArtifactCache>,
    /// HTTP-only verified snapshots, isolated from TFTP cache capacity and eviction.
    pub(crate) http_artifact_cache: Arc<HotArtifactCache>,
}

impl ServerState {
    /// Admission bounds waiters; the closure retains its permit through cancellation.
    pub(crate) async fn artifact_io<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T, TempestError> + Send + 'static,
    ) -> Result<T, TempestError> {
        let permit = self
            .artifact_io_budget
            .clone()
            .acquire_owned()
            .await
            .map_err(|error| TempestError::Io(std::io::Error::other(error)))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await
        .map_err(|error| TempestError::Io(std::io::Error::other(error)))?
    }

    /// Releases admission before transport metrics take ownership of the slot.
    pub(crate) fn release_reserved_transfer_slot(&self) {
        let previous = release_active_transfer_counter(&self.active_transfers);
        self.metrics.admission_notify.notify_one();
        if previous == 1 {
            self.metrics.drain_notify.notify_waiters();
        }
    }

    /// Records a core-detected integrity failure for fast rejection on later requests.
    pub(crate) fn quarantine_artifact(&self, key: String) {
        let _admission = self.quarantine_admission.lock();
        if self.quarantined_files.contains(&key)
            || self.quarantined_files.len() >= MAX_QUARANTINED_FILES
        {
            return;
        }
        self.quarantined_files.insert(key);
    }

    /// Returns the process-lifetime artifact capability, opening it at most once.
    pub(crate) fn artifact_root(&self) -> Result<Arc<ArtifactRoot>, TempestError> {
        match self.artifact_root.get_or_init(|| {
            ArtifactRoot::open(&self.config.server.root)
                .map(Arc::new)
                .map_err(|error| error.to_string())
        }) {
            Ok(root) => Ok(root.clone()),
            Err(error) => Err(TempestError::Config(error.clone())),
        }
    }

    /// Inserts a boot session and transfers any boot-chain pin to the live map.
    pub(crate) fn insert_boot_session(&self, client_ip: IpAddr, session: BootSessionEntry) {
        let token_hash = session.artifact_token_hash;
        if let Some(pin) = &session.pinned_boot_chain {
            self.version_store.pin_boot_chain(pin);
        }
        if let Some(previous) = self.boot_sessions.insert(client_ip, session) {
            if let Some(hash) = previous
                .artifact_token_hash
                .filter(|previous| Some(*previous) != token_hash)
            {
                self.http_session_tokens.remove(&hash);
            }
            if let Some(pin) = &previous.pinned_boot_chain {
                self.version_store.unpin_boot_chain(pin);
            }
        }
        if let Some(hash) = token_hash {
            self.http_session_tokens.insert(hash, client_ip);
        }
    }

    /// Removes a boot session and releases its boot-chain pin.
    pub(crate) fn remove_boot_session(&self, client_ip: IpAddr) -> Option<BootSessionEntry> {
        self.remove_boot_session_if(client_ip, |_, _| true)
    }

    /// Conditionally removes the current session without deleting a replacement.
    fn remove_boot_session_if(
        &self,
        client_ip: IpAddr,
        predicate: impl FnOnce(&IpAddr, &BootSessionEntry) -> bool,
    ) -> Option<BootSessionEntry> {
        let session = self
            .boot_sessions
            .remove_if(&client_ip, predicate)
            .map(|(_, session)| session);
        if let Some(pin) = session
            .as_ref()
            .and_then(|session| session.pinned_boot_chain.as_ref())
        {
            self.version_store.unpin_boot_chain(pin);
        }
        if let Some(hash) = session
            .as_ref()
            .and_then(|session| session.artifact_token_hash)
        {
            self.http_session_tokens.remove(&hash);
        }
        session
    }

    /// Resolves an unexpired HTTP session by bearer-token digest.
    pub(crate) fn boot_session_for_artifact_token(
        &self,
        token_hash: &[u8; 32],
    ) -> Option<(IpAddr, BootSessionEntry)> {
        let client_ip = self
            .http_session_tokens
            .get(token_hash)
            .map(|entry| *entry)?;
        let session = active_boot_session(self, client_ip)?;
        // Harden the authorization recheck; the preceding index lookup is not constant-time.
        session
            .artifact_token_hash
            .as_ref()
            .is_some_and(|stored| bool::from(stored.ct_eq(token_hash)))
            .then_some((client_ip, session))
    }

    /// Reconciles persisted sessions with the live map while preserving pin counts.
    fn reconcile_boot_sessions(&self, sessions: Vec<(IpAddr, BootSessionEntry)>) {
        let retained: HashSet<_> = sessions.iter().map(|(ip, _)| *ip).collect();
        for (client_ip, session) in sessions {
            if let Some(mut current) = self.boot_sessions.get_mut(&client_ip) {
                if current.artifact_token_hash == session.artifact_token_hash
                    && current.pinned_boot_chain == session.pinned_boot_chain
                {
                    // Refresh identity/TTL without churning unchanged pin and token indexes.
                    *current = session;
                    continue;
                }
            }
            self.insert_boot_session(client_ip, session);
        }
        let stale: Vec<_> = self
            .boot_sessions
            .iter()
            .filter_map(|entry| (!retained.contains(entry.key())).then_some(*entry.key()))
            .collect();
        for client_ip in stale {
            self.remove_boot_session(client_ip);
        }
    }

    /// Removes expired sessions and releases their boot-chain pins.
    fn prune_expired_boot_sessions(&self, now: Instant) {
        let expired: Vec<_> = self
            .boot_sessions
            .iter()
            .filter_map(|entry| (entry.expires_at <= now).then_some(*entry.key()))
            .collect();
        for client_ip in expired {
            self.remove_boot_session_if(client_ip, |_, session| session.expires_at <= now);
        }
    }

    /// Validate SQL admission for every entry point, including custom states.
    pub(crate) async fn ensure_persistence_admission(&self) -> Result<(), TempestError> {
        if let Some(store) = &self.persistence {
            store
                .ensure_serving_admission(self.config.persistence.coordinated_deletion)
                .await
        } else if self.config.persistence.enabled || self.config.persistence.coordinated_deletion {
            Err(TempestError::Persistence(
                "configured persistence is unavailable; an attached SQL store is required".into(),
            ))
        } else {
            Ok(())
        }
    }

    pub(crate) fn ensure_persistence_snapshot_fresh(&self) -> Result<(), TempestError> {
        if self.persistence.is_none() || self.config.persistence.coordinated_deletion {
            return Ok(());
        }
        let fresh = self
            .persistence_snapshot_validated_at
            .lock()
            .is_some_and(|validated| {
                validated.elapsed()
                    < Duration::from_secs(self.config.persistence.max_snapshot_age_secs)
            });
        if fresh {
            Ok(())
        } else {
            Err(TempestError::PersistenceSnapshotStale)
        }
    }

    fn record_persistence_snapshot_validation(&self, validated_at: Instant) {
        let mut last = self.persistence_snapshot_validated_at.lock();
        if last.is_none_or(|previous| previous < validated_at) {
            *last = Some(validated_at);
        }
    }

    /// Reconciles durable groups and live sessions into in-process hot state.
    ///
    /// Slow snapshot loading and artifact hashing run outside the control lock;
    /// the final revision check and hot-state publication serialize with
    /// mutations. Invalid manifests, missing active files, or malformed sessions
    /// fail closed.
    pub async fn sync_persistent_state(self: &Arc<Self>) -> Result<(), TempestError> {
        self.ensure_persistence_admission().await?;
        let Some(persistence) = &self.persistence else {
            return Ok(());
        };

        persistence.prune_expired_boot_sessions().await?;
        for _ in 0..3 {
            let validated_at = Instant::now();
            let revision = persistence.state_revision().await?;
            if revision == self.persistence_revision.load(Ordering::Acquire) {
                self.record_persistence_snapshot_validation(validated_at);
                return Ok(());
            }

            let groups = persistence.load_version_groups().await?;
            let permit = self
                .artifact_hash_budget
                .clone()
                .acquire_owned()
                .await
                .map_err(|_| {
                    TempestError::Version("Artifact verification workers are unavailable".into())
                })?;
            let validation_state = self.clone();
            let groups = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let artifact_root = validation_state.artifact_root()?;
                validation_state
                    .version_store
                    .validate_persistent_groups(&artifact_root, groups)
            })
            .await
            .map_err(|error| {
                TempestError::Version(format!(
                    "Persistent artifact verification task failed: {error}"
                ))
            })??;

            // Hashing can be slow, so serialize only the final revision check and
            // atomic hot-state publication with other control-plane mutations.
            let _guard = self.control_plane_lock.lock().await;
            if revision == self.persistence_revision.load(Ordering::Acquire) {
                self.record_persistence_snapshot_validation(validated_at);
                return Ok(());
            }
            // Read sessions and groups at one committed revision. Session churn
            // cannot invalidate artifact verification or exhaust snapshot retries.
            let validated_at = Instant::now();
            let snapshot = persistence
                .load_control_snapshot(self.config.server.max_boot_sessions)
                .await?;
            if !groups.matches(&snapshot.groups) {
                continue;
            }

            // No live state changes until the complete stable snapshot validates.
            self.version_store.commit_persistent_groups(groups);
            self.reconcile_boot_sessions(snapshot.sessions);
            self.version_store.prune_group_history();
            self.persistence_revision
                .store(snapshot.revision, Ordering::Release);
            self.record_persistence_snapshot_validation(validated_at);
            return Ok(());
        }

        Err(TempestError::Conflict(
            "durable state changed repeatedly while building a snapshot; retry refresh".into(),
        ))
    }

    /// Resolves a managed TFTP artifact for a source-IP session or public default release.
    ///
    /// The fallback profile argument is retained for source compatibility but
    /// is not authorization: without a live session only `default` is public.
    /// Unmanaged root files are never served by this resolver.
    /// The first managed resolution pins the release into the session. The
    /// returned artifact pin remains caller-owned and must be released.
    pub async fn resolve_file_for_boot_session(
        &self,
        client_ip: IpAddr,
        _fallback_boot_profile: &str,
        filename: &str,
    ) -> Result<crate::features::versioning::ResolvedFile, TempestError> {
        self.resolve_file_for_boot_session_inner(
            client_ip,
            Some(DEFAULT_BOOT_PROFILE),
            None,
            filename,
            true,
        )
        .await
    }

    /// Resolves only when an unexpired source-IP boot session exists.
    ///
    /// Missing sessions return an access violation rather than serving an
    /// unmanaged artifact, which protects authenticated HTTP artifact routes.
    pub async fn resolve_file_for_required_boot_session(
        &self,
        client_ip: IpAddr,
        filename: &str,
    ) -> Result<crate::features::versioning::ResolvedFile, TempestError> {
        self.resolve_file_for_boot_session_inner(client_ip, None, None, filename, false)
            .await
    }

    /// Resolves only for the exact boot session authorized by a bearer token.
    pub(crate) async fn resolve_file_for_authorized_boot_session(
        &self,
        client_ip: IpAddr,
        token_hash: &[u8; 32],
        filename: &str,
    ) -> Result<crate::features::versioning::ResolvedFile, TempestError> {
        self.resolve_file_for_boot_session_inner(client_ip, None, Some(token_hash), filename, false)
            .await
    }

    /// Resolves an artifact and pins the session's first managed boot chain.
    async fn resolve_file_for_boot_session_inner(
        &self,
        client_ip: IpAddr,
        fallback_boot_profile: Option<&str>,
        expected_token_hash: Option<&[u8; 32]>,
        filename: &str,
        managed_only: bool,
    ) -> Result<crate::features::versioning::ResolvedFile, TempestError> {
        if let Some(store) = &self.persistence {
            store
                .ensure_serving_mode(self.config.persistence.coordinated_deletion)
                .await?;
        } else {
            self.ensure_persistence_admission().await?;
        }
        self.ensure_persistence_snapshot_fresh()?;
        let mut resolved = self
            .resolve_file_for_boot_session_local(
                client_ip,
                fallback_boot_profile,
                expected_token_hash,
                filename,
                managed_only,
            )
            .await?;
        // Local resolution owns a pin already. Retain its cancellation guard
        // while durable admission waits; no artifact opening precedes admission.
        let version_guard =
            PinnedVersionGuard::new(&self.version_store, resolved.pinned_version.take());
        self.ensure_persistence_snapshot_fresh()?;
        // Nested rather than a let chain: the crate's MSRV (1.85) predates them.
        if let Some(store) = &self.persistence {
            if self.config.persistence.coordinated_deletion {
                if let Some(pin) = &resolved.boot_chain {
                    resolved.durable_reader = Some(store.register_reader(pin).await?);
                } else {
                    let profile = active_boot_session(self, client_ip)
                        .map(|session| session.boot_profile)
                        .unwrap_or_else(|| DEFAULT_BOOT_PROFILE.into());
                    store.check_unmanaged_admission(&profile, filename).await?;
                }
            }
        }
        resolved.pinned_version = version_guard.hand_off();
        Ok(resolved)
    }

    async fn resolve_file_for_boot_session_local(
        &self,
        client_ip: IpAddr,
        fallback_boot_profile: Option<&str>,
        expected_token_hash: Option<&[u8; 32]>,
        filename: &str,
        managed_only: bool,
    ) -> Result<crate::features::versioning::ResolvedFile, TempestError> {
        let Some(session) = active_boot_session(self, client_ip) else {
            return self.resolve_without_boot_session(fallback_boot_profile, filename);
        };
        if expected_token_hash.is_some_and(|hash| {
            session
                .artifact_token_hash
                .as_ref()
                .is_none_or(|stored| !bool::from(stored.ct_eq(hash)))
        }) {
            return self.resolve_without_boot_session(None, filename);
        }
        if let Some(pin) = session.pinned_boot_chain {
            return self.version_store.resolve_file_for_transfer_in_boot_chain(
                &pin,
                filename,
                &self.config.server.root,
            );
        }

        let _guard = self.control_plane_lock.lock().await;
        let Some(session) = active_boot_session(self, client_ip) else {
            return self.resolve_without_boot_session(fallback_boot_profile, filename);
        };
        if expected_token_hash.is_some_and(|hash| {
            session
                .artifact_token_hash
                .as_ref()
                .is_none_or(|stored| !bool::from(stored.ct_eq(hash)))
        }) {
            return self.resolve_without_boot_session(None, filename);
        }
        if let Some(pin) = session.pinned_boot_chain {
            return self.version_store.resolve_file_for_transfer_in_boot_chain(
                &pin,
                filename,
                &self.config.server.root,
            );
        }
        let (mut resolved, pin) = if managed_only {
            self.version_store
                .resolve_managed_file_for_transfer_in_profile(
                    &session.boot_profile,
                    filename,
                    &self.config.server.root,
                )?
        } else {
            self.version_store
                .resolve_file_for_transfer_in_profile_with_boot_chain(
                    &session.boot_profile,
                    filename,
                    &self.config.server.root,
                )?
        };
        let Some(pin) = pin else { return Ok(resolved) };
        // Cancellation during durable pinning must also release the transfer pin.
        let version_guard =
            PinnedVersionGuard::new(&self.version_store, resolved.pinned_version.take());
        let claimed = match &self.persistence {
            Some(store) => {
                store
                    .pin_boot_session(client_ip, session.boot_epoch, &pin)
                    .await?
            }
            None => true,
        };
        let current = self.boot_sessions.get_mut(&client_ip);
        if !claimed
            || current.as_ref().is_none_or(|entry| {
                entry.boot_epoch != session.boot_epoch
                    || entry.boot_profile != session.boot_profile
                    || expected_token_hash.is_some_and(|hash| {
                        entry
                            .artifact_token_hash
                            .as_ref()
                            .is_none_or(|stored| !bool::from(stored.ct_eq(hash)))
                    })
                    || entry.pinned_boot_chain.is_some()
            })
        {
            return Err(TempestError::Conflict(
                "boot session changed during pinning".into(),
            ));
        }
        self.version_store.pin_boot_chain(&pin);
        current.unwrap().pinned_boot_chain = Some(pin);
        resolved.pinned_version = version_guard.hand_off();
        Ok(resolved)
    }

    /// Uses a managed fallback profile or rejects requests requiring an active session.
    fn resolve_without_boot_session(
        &self,
        fallback_boot_profile: Option<&str>,
        filename: &str,
    ) -> Result<crate::features::versioning::ResolvedFile, TempestError> {
        match fallback_boot_profile {
            Some(profile) => self
                .version_store
                .resolve_managed_file_for_transfer_in_profile(
                    profile,
                    filename,
                    &self.config.server.root,
                )
                .map(|(resolved, _)| resolved),
            None => Err(TempestError::Protocol(
                crate::error::ProtocolError::AccessViolation("active boot session required".into()),
            )),
        }
    }
}

/// Main server handle for release-aware TFTP serving.
#[derive(Clone)]
pub struct TftpServer {
    state: Arc<ServerState>,
}

type HttpObserverCallback = Arc<dyn Fn(crate::extension::HttpObservation) + Send + Sync>;

/// Builder for composing the Tempest server with optional extension crates.
///
/// The default composition uses only capabilities configured in
/// [`TempestConfig`]. Downstream composition binaries can inject extension
/// implementations without modifying Tempest's protocol or release-resolution
/// code. The builder retains one implementation of each extension contract;
/// calling the same `with_*` method again replaces the previous implementation.
pub struct TftpServerBuilder {
    config: TempestConfig,
    meter: Option<opentelemetry::metrics::Meter>,
    http_observer: Option<HttpObserverCallback>,
    quarantined_files: Arc<DashSet<String>>,
    persistence: Option<Arc<PersistenceStore>>,
    scheduler: Option<Arc<dyn TransferScheduler>>,
    provisioning_priority: Option<Arc<dyn ProvisioningPriorityProvider>>,
    shared_blocks: Option<Arc<dyn SharedBlockCache>>,
    transfer_pacing: Option<Arc<dyn TransferPacing>>,
    read_protocol: Option<Arc<dyn ReadProtocolExtension>>,
    read_request_router: Option<Arc<dyn ReadRequestRouter>>,
    admission_policy: Option<Arc<dyn AdmissionPolicy>>,
}

/// Internal component bundle consumed when constructing shared server state.
struct TftpServerComponents {
    meter: Option<opentelemetry::metrics::Meter>,
    http_observer: Option<HttpObserverCallback>,
    quarantined_files: Arc<DashSet<String>>,
    persistence: Option<Arc<PersistenceStore>>,
    scheduler: Option<Arc<dyn TransferScheduler>>,
    provisioning_priority: Option<Arc<dyn ProvisioningPriorityProvider>>,
    shared_blocks: Option<Arc<dyn SharedBlockCache>>,
    transfer_pacing: Option<Arc<dyn TransferPacing>>,
    read_protocol: Option<Arc<dyn ReadProtocolExtension>>,
    read_request_router: Option<Arc<dyn ReadRequestRouter>>,
    admission_policy: Option<Arc<dyn AdmissionPolicy>>,
}

impl TftpServerComponents {
    /// Creates the core component set with no optional integrations installed.
    fn core(quarantined_files: Arc<DashSet<String>>) -> Self {
        Self {
            meter: None,
            http_observer: None,
            quarantined_files,
            persistence: None,
            scheduler: None,
            provisioning_priority: None,
            shared_blocks: None,
            transfer_pacing: None,
            read_protocol: None,
            read_request_router: None,
            admission_policy: None,
        }
    }
}

impl TftpServerBuilder {
    /// Create a builder for the supplied server configuration.
    pub fn new(config: TempestConfig) -> Self {
        Self {
            config,
            meter: None,
            http_observer: None,
            quarantined_files: Arc::new(DashSet::new()),
            persistence: None,
            scheduler: None,
            provisioning_priority: None,
            shared_blocks: None,
            transfer_pacing: None,
            read_protocol: None,
            read_request_router: None,
            admission_policy: None,
        }
    }

    /// Also export native metrics through this OpenTelemetry 0.32 meter.
    ///
    /// The standalone Prometheus reader remains active. No global provider is
    /// installed. The caller owns external provider export/flush/shutdown and
    /// must configure cardinality views (see EXTENSIONS.md). Replaces any
    /// previously supplied meter. Construct inside the serving Tokio runtime
    /// to include runtime metrics; callbacks never require an entered runtime.
    ///
    /// ```no_run
    /// use opentelemetry::metrics::MeterProvider;
    /// use opentelemetry_sdk::metrics::{Instrument, SdkMeterProvider, Stream};
    /// use tempest::{config::TempestConfig, server::TftpServer};
    ///
    /// let config = TempestConfig::default();
    /// // SDK gauge labels can overlap across two consecutive collections.
    /// let session_limit = config.server.max_boot_sessions * 2;
    /// // Add the composition's OTLP reader/exporter to this provider builder.
    /// let provider = SdkMeterProvider::builder()
    ///     .with_view(move |instrument: &Instrument| {
    ///         instrument.name().starts_with("tempest_").then(|| {
    ///             let limit = if instrument.name() == "tempest_active_boot_sessions" {
    ///                 session_limit
    ///             } else {
    ///                 60_007
    ///             };
    ///             Stream::builder().with_cardinality_limit(limit).build().unwrap()
    ///         })
    ///     })
    ///     .build();
    /// let server = TftpServer::builder(config)
    ///     .with_meter(provider.meter("boot-server"))
    ///     .build()?;
    /// // Run the server, stop its work, then flush/shut down the owned provider.
    /// # drop(server);
    /// # provider.shutdown()?;
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn with_meter(mut self, meter: opentelemetry::metrics::Meter) -> Self {
        self.meter = Some(meter);
        self
    }

    /// Observe HTTP response production without access to routing or security state.
    ///
    /// See [`crate::extension::HttpObservation`] for lifecycle and resource rules.
    ///
    /// ```no_run
    /// use tempest::{config::TempestConfig, server::TftpServer};
    /// let server = TftpServer::builder(TempestConfig::default())
    ///     .with_http_observer(|event| {
    ///         // Submit to a bounded, nonblocking composition-owned exporter.
    ///         let _ = (event.method, event.route, event.status, event.elapsed);
    ///     })
    ///     .build()?;
    /// # Ok::<(), tempest::error::TempestError>(())
    /// ```
    pub fn with_http_observer(
        mut self,
        observer: impl Fn(crate::extension::HttpObservation) + Send + Sync + 'static,
    ) -> Self {
        self.http_observer = Some(Arc::new(observer));
        self
    }

    /// Share an externally managed quarantine set with the transfer path.
    pub fn with_quarantined_files(mut self, files: Arc<DashSet<String>>) -> Self {
        self.quarantined_files = files;
        self
    }

    /// Use an externally constructed durable control-state store.
    pub fn with_persistence(mut self, persistence: Arc<PersistenceStore>) -> Self {
        self.persistence = Some(persistence);
        self
    }

    /// Install a packet scheduler supplied by an extension crate.
    pub fn with_scheduler(mut self, scheduler: Arc<dyn TransferScheduler>) -> Self {
        self.scheduler = Some(scheduler);
        self
    }

    /// Install a vendor-neutral source of provisioning-priority weights.
    pub fn with_provisioning_priority(
        mut self,
        provider: Arc<dyn ProvisioningPriorityProvider>,
    ) -> Self {
        self.provisioning_priority = Some(provider);
        self
    }

    /// Install shared block storage supplied by an extension crate.
    pub fn with_shared_blocks(mut self, provider: Arc<dyn SharedBlockCache>) -> Self {
        self.shared_blocks = Some(provider);
        self
    }

    /// Install ACK-driven transfer pacing supplied by an extension crate.
    pub fn with_transfer_pacing(mut self, provider: Arc<dyn TransferPacing>) -> Self {
        self.transfer_pacing = Some(provider);
        self
    }

    /// Install a versioned custom TFTP protocol pack.
    pub fn with_read_protocol(mut self, protocol: Arc<dyn ReadProtocolExtension>) -> Self {
        self.read_protocol = Some(protocol);
        self
    }

    /// Install an externally owned RRQ redirect or proxy handler.
    pub fn with_read_request_router(mut self, router: Arc<dyn ReadRequestRouter>) -> Self {
        self.read_request_router = Some(router);
        self
    }

    /// Install bounded queue, priority, expiry, and stagger policy.
    pub fn with_admission_policy(mut self, policy: Arc<dyn AdmissionPolicy>) -> Self {
        self.admission_policy = Some(policy);
        self
    }

    /// Validate the composition and construct the server.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when cryptographic keys are missing,
    /// malformed, or inconsistent, or resource limits are invalid. In particular,
    /// `server.max_boot_sessions` must be in `1..=1_000_000`.
    pub fn build(self) -> Result<TftpServer, TempestError> {
        let components = TftpServerComponents {
            meter: self.meter,
            http_observer: self.http_observer,
            quarantined_files: self.quarantined_files,
            persistence: self.persistence,
            scheduler: self.scheduler,
            provisioning_priority: self.provisioning_priority,
            shared_blocks: self.shared_blocks,
            transfer_pacing: self.transfer_pacing,
            read_protocol: self.read_protocol,
            read_request_router: self.read_request_router,
            admission_policy: self.admission_policy,
        };
        TftpServer::try_new_with_components(self.config, components)
    }
}

/// Clears listener readiness when the TFTP run loop exits or is cancelled.
struct TftpReadinessGuard(Arc<ServerState>);

struct BackgroundTaskGuard(tokio::task::JoinHandle<()>);

/// Loads an optional raw 32-byte Ed25519 signing key for the named role.
fn load_signing_key(path: Option<&Path>, role: &str) -> Result<Option<[u8; 32]>, TempestError> {
    path.map(|path| {
        let bytes = crate::config::read_secure_file(path, &format!("{role} key"), 32, true)?;
        <[u8; 32]>::try_from(bytes.as_slice())
            .map_err(|_| TempestError::Config(format!("{role} key must contain exactly 32 bytes")))
    })
    .transpose()
}

/// Parses an optional hex-encoded Ed25519 verifying key for the named role.
fn parse_verifying_key(
    value: Option<&str>,
    role: &str,
) -> Result<Option<VerifyingKey>, TempestError> {
    value
        .map(|value| {
            let bytes =
                hex::decode(value.strip_prefix("ed25519:").unwrap_or(value)).map_err(|error| {
                    TempestError::Config(format!("Invalid {role} key hex: {error}"))
                })?;
            let bytes = <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
                TempestError::Config(format!("{role} key must decode to exactly 32 bytes"))
            })?;
            VerifyingKey::from_bytes(&bytes)
                .map_err(|error| TempestError::Config(format!("Invalid {role} key: {error}")))
        })
        .transpose()
}

impl Drop for TftpReadinessGuard {
    fn drop(&mut self) {
        self.0.tftp_ready.store(false, Ordering::Release);
        self.0.tftp_bound_port.store(0, Ordering::Release);
    }
}

impl Drop for BackgroundTaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Clone)]
struct AdmissionQueue {
    sender: mpsc::Sender<PendingTransfer>,
    entry_budget: Arc<Semaphore>,
    byte_budget: Arc<Semaphore>,
}

impl TftpServer {
    /// Start a composable server builder.
    pub fn builder(config: TempestConfig) -> TftpServerBuilder {
        TftpServerBuilder::new(config)
    }

    /// Constructs the core server with an empty quarantine set and no persistence.
    ///
    /// # Panics
    ///
    /// Panics when configured keys or resource limits are invalid; use
    /// [`Self::try_new_with_quarantine_and_persistence`] for recoverable startup.
    pub fn new(config: TempestConfig) -> Self {
        Self::new_with_quarantine(config, Arc::new(DashSet::new()))
    }

    /// Construct with an externally provided quarantine set.
    pub fn new_with_quarantine(
        config: TempestConfig,
        quarantined_files: Arc<DashSet<String>>,
    ) -> Self {
        Self::new_with_quarantine_and_persistence(config, quarantined_files, None)
    }

    /// Constructs a server sharing external quarantine and persistence state.
    ///
    /// # Panics
    ///
    /// Panics when cryptographic configuration or resource limits are invalid.
    pub fn new_with_quarantine_and_persistence(
        config: TempestConfig,
        quarantined_files: Arc<DashSet<String>>,
        persistence: Option<Arc<PersistenceStore>>,
    ) -> Self {
        Self::try_new_with_quarantine_and_persistence(config, quarantined_files, persistence)
            .expect("valid Tempest configuration")
    }

    /// Constructs a server with recoverable configuration errors.
    ///
    /// This reads configured 32-byte signing keys and validates that explicit
    /// Ed25519 verifiers match their signing keys.
    pub fn try_new_with_quarantine_and_persistence(
        config: TempestConfig,
        quarantined_files: Arc<DashSet<String>>,
        persistence: Option<Arc<PersistenceStore>>,
    ) -> Result<Self, TempestError> {
        let mut components = TftpServerComponents::core(quarantined_files);
        components.persistence = persistence;
        Self::try_new_with_components(config, components)
    }

    /// Validates configuration and assembles shared state from core and optional components.
    fn try_new_with_components(
        config: TempestConfig,
        components: TftpServerComponents,
    ) -> Result<Self, TempestError> {
        crate::config::validate_boot_session_capacity(config.server.max_boot_sessions)?;
        validate_tftp_performance_config(&config)?;
        config.persistence.validate_snapshot_age()?;
        config.validate_coordinated_reader_capacity()?;
        #[cfg(target_os = "linux")]
        if config.server.udp_segmentation_offload {
            crate::protocol::transfer::initialize_udp_segmentation(config.server.bind).map_err(
                |error| TempestError::Config(format!("server.udp_segmentation_offload: {error}")),
            )?;
        }
        let hot_artifact_cache_max_bytes =
            usize::try_from(config.server.hot_artifact_cache_max_bytes).map_err(|_| {
                TempestError::Config(
                    "server.hot_artifact_cache_max_bytes does not fit this platform".into(),
                )
            })?;
        let hot_artifact_cache_max_file_bytes =
            usize::try_from(config.server.hot_artifact_cache_max_file_bytes).map_err(|_| {
                TempestError::Config(
                    "server.hot_artifact_cache_max_file_bytes does not fit this platform".into(),
                )
            })?;
        let http_artifact_cache_max_bytes = usize::try_from(config.api.artifact_cache_max_bytes)
            .map_err(|_| {
                TempestError::Config(
                    "api.artifact_cache_max_bytes does not fit this platform".into(),
                )
            })?;
        let http_artifact_cache_max_file_bytes =
            usize::try_from(config.api.artifact_cache_max_file_bytes).map_err(|_| {
                TempestError::Config(
                    "api.artifact_cache_max_file_bytes does not fit this platform".into(),
                )
            })?;
        let TftpServerComponents {
            meter,
            http_observer,
            quarantined_files,
            persistence,
            scheduler,
            provisioning_priority,
            shared_blocks,
            transfer_pacing,
            read_protocol,
            read_request_router,
            admission_policy,
        } = components;
        if config.persistence.coordinated_deletion && persistence.is_none() {
            return Err(TempestError::Config(
                "persistence.coordinated_deletion requires an attached SQL store".into(),
            ));
        }
        let manifest_signing_key = load_signing_key(
            config.audit.manifest_signing_key_path.as_deref(),
            "manifest signing",
        )?;
        let manifest_verifying_key = parse_verifying_key(
            config.audit.manifest_verifying_key.as_deref(),
            "manifest verifying",
        )?;
        if manifest_signing_key
            .as_ref()
            .zip(manifest_verifying_key.as_ref())
            .is_some_and(|(signing, verifying)| {
                SigningKey::from_bytes(signing).verifying_key() != *verifying
            })
        {
            return Err(TempestError::Config(
                "Manifest signing and verifying keys do not match".into(),
            ));
        }
        if config.audit.require_signed_manifests
            && manifest_signing_key.is_none()
            && manifest_verifying_key.is_none()
        {
            return Err(TempestError::Config(
                "Signed manifests require a signing or verifying key".into(),
            ));
        }
        let require_signed_manifests = config.audit.require_signed_manifests
            || manifest_signing_key.is_some()
            || manifest_verifying_key.is_some();
        let effective_listener_shards = config.server.effective_listener_shards();
        let mut config = config;
        config.server.listener_shards = effective_listener_shards;
        let config = Arc::new(config);
        let active_transfers = Arc::new(AtomicUsize::new(0));
        let queued_transfers = Arc::new(AtomicUsize::new(0));
        let metrics = Arc::new(ServerMetrics::new(active_transfers.clone()));
        let critical_services_healthy = Arc::new(AtomicBool::new(true));
        let phase_classifier = PhaseClassifier::new(&config.boot_phases);
        // DSCP manager from config
        let dscp_manager = Arc::new(DscpManager::new(
            &config.dscp.phase_dscp,
            config.dscp.ecn_enabled,
        ));

        // Audit log — only if enabled and log_path is configured.
        let audit_log = if config.audit.enabled {
            Some(Arc::new(AuditLog::new_with_rotation(
                config.audit.log_path.clone().ok_or_else(|| {
                    TempestError::Config("audit.enabled requires audit.log_path".to_string())
                })?,
                config.audit.rotate_max_bytes,
                config.audit.rotate_keep_segments,
            )?))
        } else {
            None
        };
        let audit_writer = audit_log
            .as_ref()
            .map(|log| {
                AuditWriter::start(
                    log.clone(),
                    config.audit.queue_max_bytes,
                    critical_services_healthy.clone(),
                )
            })
            .transpose()?;

        // Bandwidth governor — global NIC rate cap shared by TFTP and HTTP artifact streams
        let bandwidth_governor = if config.server.bandwidth_governor_enabled {
            let rate = config
                .server
                .total_bandwidth_bytes_per_second()
                .unwrap_or(125_000_000);
            Some(Arc::new(BandwidthGovernor::new(rate, true)))
        } else {
            None
        };

        let version_store = VersionStore::new_with_manifest_keys(
            manifest_signing_key.as_ref(),
            manifest_verifying_key,
            require_signed_manifests,
        );
        let artifact_hash_budget = version_store.artifact_hash_budget.clone();
        let state = Arc::new(ServerState {
            config: config.clone(),
            version_store,
            phase_classifier,
            shared_blocks,
            transfer_pacing,
            read_protocol,
            read_request_router,
            admission_policy,
            metrics,
            active_transfers,
            queued_transfers,
            inflight_tftp_tids: Arc::new(DashMap::new()),
            tftp_client_limits: Arc::new(TftpClientLimits::new(
                config.server.max_tftp_transfers_per_ip,
            )),
            transfer_ids: TransferIdGenerator::new(),
            drain_mode: AtomicBool::new(false),
            tftp_ready: AtomicBool::new(false),
            tftp_bound_port: AtomicU16::new(0),
            critical_services_healthy,
            start_time: Instant::now(),
            tftp_rate_limiter: Arc::new(PerIpRateLimiter::new(
                config.server.tftp_requests_per_ip_per_second,
                "TFTP",
            )),
            malformed_log_limiter: Arc::new(PerIpRateLimiter::new(2, "TFTP malformed packet")),
            unexpected_log_limiter: Arc::new(PerIpRateLimiter::new(2, "TFTP unexpected opcode")),
            http_rate_limiter: Arc::new(PerIpRateLimiter::new(
                config.server.http_requests_per_ip_per_second,
                "API",
            )),
            http_observer,
            dscp_manager,
            audit_log,
            audit_writer,
            audit_read_budget: Arc::new(Semaphore::new(MAX_CONCURRENT_AUDIT_READS)),
            quarantined_files,
            quarantine_admission: parking_lot::Mutex::new(()),
            scheduler,
            provisioning_priority,
            boot_sessions: Arc::new(DashMap::new()),
            http_session_tokens: Arc::new(DashMap::new()),
            persistence,
            persistence_revision: AtomicI64::new(-1),
            persistence_snapshot_validated_at: parking_lot::Mutex::new(None),
            control_plane_lock: Arc::new(tokio::sync::Mutex::new(())),
            session_registration_queue: std::sync::OnceLock::new(),
            bandwidth_governor,
            artifact_hash_budget,
            artifact_root: std::sync::OnceLock::new(),
            artifact_io_budget: Arc::new(Semaphore::new(32)),
            hot_artifact_cache: Arc::new(HotArtifactCache::with_limits(
                hot_artifact_cache_max_bytes,
                hot_artifact_cache_max_file_bytes,
            )),
            http_artifact_cache: Arc::new(HotArtifactCache::with_limits(
                http_artifact_cache_max_bytes,
                http_artifact_cache_max_file_bytes,
            )),
        });

        crate::api::metrics::initialize(&state, meter);
        Ok(Self { state })
    }

    /// Returns shared ownership of the runtime state for HTTP and background tasks.
    pub fn state(&self) -> Arc<ServerState> {
        self.state.clone()
    }

    /// Re-enable admission and publish the state change to listener tasks.
    pub fn undrain(&self) {
        self.state.drain_mode.store(false, Ordering::Release);
        info!("Drain mode disabled — server accepting new transfers");
    }

    /// Run the TFTP server — listens for incoming requests and spawns transfer tasks
    pub async fn run(&self) -> Result<(), TempestError> {
        self.state.ensure_persistence_admission().await?;
        let bind_addr =
            SocketAddr::new(self.state.config.server.bind, self.state.config.server.port);
        let shard_count = self.state.config.server.listener_shards;
        let mut sockets = Vec::with_capacity(shard_count);
        let mut effective_bind_addr = bind_addr;
        let mut listener_receive_buffer_bytes = 0;
        for shard in 0..shard_count {
            let shard_addr = if shard == 0 {
                bind_addr
            } else {
                effective_bind_addr
            };
            let socket = bind_tftp_listener(shard_addr, shard_count > 1)?;
            configure_udp_socket_buffers(
                &socket,
                self.state.config.server.listener_receive_buffer_bytes,
                None,
            )?;
            if shard == 0 {
                effective_bind_addr = socket.local_addr()?;
                listener_receive_buffer_bytes =
                    socket2::SockRef::from(&socket).recv_buffer_size()?;
            }
            sockets.push(socket);
        }
        self.state
            .tftp_bound_port
            .store(effective_bind_addr.port(), Ordering::Release);
        self.state.tftp_ready.store(true, Ordering::Release);
        let _readiness = TftpReadinessGuard(self.state.clone());
        info!(
            addr = %effective_bind_addr,
            listener_shards = shard_count,
            listener_receive_buffer_bytes,
            "TFTP server listening"
        );

        // Spawn bandwidth governor refill task if enabled
        let _gov_handle = self
            .state
            .bandwidth_governor
            .as_ref()
            .map(|gov| bandwidth_governor::spawn_refill_task(gov.clone()));

        let _maintenance_task =
            BackgroundTaskGuard(tokio::spawn(run_maintenance_task(self.state.clone())));

        // The channel is only a handoff. Permits remain owned by each request
        // while it is in either the channel or the priority heap.
        let admission_queue: Option<AdmissionQueue> =
            if let Some(policy) = self.state.admission_policy.as_ref() {
                const MAX_ADMISSION_QUEUE: usize = 100_000;
                const MAX_ADMISSION_BYTES: usize = 64 * 1024 * 1024;
                let depth = policy.queue_capacity().clamp(1, MAX_ADMISSION_QUEUE);
                let (tx, rx) = mpsc::channel::<PendingTransfer>(depth);
                let state_for_drain = self.state.clone();
                tokio::spawn(run_admission_drain_task(state_for_drain, rx));
                let byte_capacity = depth.saturating_mul(4096).min(MAX_ADMISSION_BYTES);
                info!(depth, byte_capacity, "Admission queue enabled");
                Some(AdmissionQueue {
                    sender: tx,
                    entry_budget: Arc::new(Semaphore::new(depth)),
                    byte_budget: Arc::new(Semaphore::new(byte_capacity)),
                })
            } else {
                None
            };

        let mut listeners = tokio::task::JoinSet::new();
        for (shard, socket) in sockets.into_iter().enumerate() {
            let server = self.clone();
            let queue = admission_queue.clone();
            listeners.spawn(async move { server.run_listener(shard, socket, queue).await });
        }

        let result = match listeners.join_next().await {
            Some(Ok(result)) => result,
            Some(Err(error)) => Err(TempestError::Io(std::io::Error::other(format!(
                "TFTP listener task failed: {error}"
            )))),
            None => Err(TempestError::Io(std::io::Error::other(
                "TFTP listener set exited unexpectedly",
            ))),
        };
        listeners.abort_all();
        while listeners.join_next().await.is_some() {}
        result
    }

    async fn run_listener(
        &self,
        shard: usize,
        socket: UdpSocket,
        admission_queue: Option<AdmissionQueue>,
    ) -> Result<(), TempestError> {
        // Initial RRQ/WRQ packets are small (<600 bytes typically),
        // use a reasonably sized buffer instead of 64KB
        let mut buf = vec![0u8; 4096];

        loop {
            let (len, client_addr) = match socket.recv_from(&mut buf).await {
                Ok(result) => result,
                Err(error) => {
                    error!(%error, "Failed to receive packet");
                    continue;
                }
            };

            if !self.state.critical_services_healthy.load(Ordering::Acquire) {
                let packet = TftpPacket::error(
                    TftpErrorCode::NotDefined,
                    "Server audit service is unavailable",
                );
                let _ = socket.send_to(&packet, client_addr).await;
                continue;
            }

            if !self.state.tftp_rate_limiter.check(client_addr.ip()) {
                debug!(client = %client_addr, "TFTP rate limit exceeded");
                continue;
            }

            // Pair with drain's Release store before admitting more work.
            if self.state.drain_mode.load(Ordering::Acquire) {
                let err_pkt = TftpPacket::error(
                    TftpErrorCode::NotDefined,
                    "Server is draining — no new transfers accepted",
                );
                let _ = socket.send_to(&err_pkt, client_addr).await;
                continue;
            }

            let request_tid_guard = match buf[..len].get(..2) {
                Some(opcode) if matches!(u16::from_be_bytes([opcode[0], opcode[1]]), 1 | 2) => {
                    match InflightTftpTidGuard::claim(
                        self.state.inflight_tftp_tids.clone(),
                        client_addr,
                    ) {
                        Some(mut guard) => {
                            // Claim the TID first: duplicates notify its owner
                            // without reserving another source permit. This
                            // permit follows the TID through queue and transport.
                            let Some(permit) =
                                self.state.tftp_client_limits.try_acquire(client_addr.ip())
                            else {
                                self.state
                                    .metrics
                                    .capacity_rejected_total
                                    .fetch_add(1, Ordering::Relaxed);
                                let packet = TftpPacket::error(
                                    TftpErrorCode::NotDefined,
                                    "Client transfer limit reached",
                                );
                                let _ = socket.send_to(&packet, client_addr).await;
                                continue;
                            };
                            guard.client_limit = Some(permit);
                            Some(guard)
                        }
                        None => {
                            self.state
                                .metrics
                                .duplicate_requests_total
                                .fetch_add(1, Ordering::Relaxed);
                            debug!(
                                client = %client_addr,
                                "Ignoring duplicate request from active client TID"
                            );
                            continue;
                        }
                    }
                }
                _ => None,
            };

            let audit_reservation = match self.state.audit_writer.as_ref() {
                Some(writer) => match writer.try_reserve() {
                    Ok(reservation) => Some(reservation),
                    Err(_) => {
                        let packet = TftpPacket::error(
                            TftpErrorCode::NotDefined,
                            "Audit service is at capacity",
                        );
                        let _ = socket.send_to(&packet, client_addr).await;
                        continue;
                    }
                },
                None => None,
            };

            // Atomically increment transfer count (avoid TOCTOU race)
            let prev = self.state.active_transfers.fetch_add(1, Ordering::AcqRel);
            if prev >= self.state.config.server.max_concurrent_transfers {
                // Over capacity — decrement the optimistic increment
                release_active_transfer_counter(&self.state.active_transfers);

                let Some(queue) = admission_queue.as_ref() else {
                    self.state
                        .metrics
                        .capacity_rejected_total
                        .fetch_add(1, Ordering::Relaxed);
                    let packet = TftpPacket::error(TftpErrorCode::NotDefined, "Server at capacity");
                    let _ = socket.send_to(&packet, client_addr).await;
                    continue;
                };
                let Ok(queue_entry_permit) = queue.entry_budget.clone().try_acquire_owned() else {
                    reject_queued_request(&self.state, &socket, client_addr).await;
                    continue;
                };
                let Ok(queue_byte_permit) =
                    queue.byte_budget.clone().try_acquire_many_owned(len as u32)
                else {
                    reject_queued_request(&self.state, &socket, client_addr).await;
                    continue;
                };

                let packet = match TftpPacket::parse(&buf[..len], client_addr) {
                    Ok(p) => p,
                    Err(e) => {
                        record_malformed_packet(&self.state, client_addr, &e, true);
                        continue;
                    }
                };

                let (req, is_write) = match packet {
                    TftpPacket::Rrq(r) => (r, false),
                    TftpPacket::Wrq(r) => (r, true),
                    _ => {
                        record_unexpected_opcode(&self.state, client_addr, true);
                        continue;
                    }
                };
                self.state.metrics.listener_shard_requests[shard].fetch_add(1, Ordering::Relaxed);

                let phase = self.state.phase_classifier.classify(&req.filename);
                let policy = self
                    .state
                    .admission_policy
                    .as_ref()
                    .expect("admission channel requires policy");
                let priority = policy.priority(&AdmissionContext {
                    client_addr,
                    filename: req.filename.clone(),
                    phase,
                    is_write,
                });
                let phase_weight = if priority.is_finite() { priority } else { 0.0 };
                let pending = PendingTransfer {
                    client_addr,
                    request: req,
                    is_write,
                    arrived_at: Instant::now(),
                    phase_weight,
                    queue_entry_permit,
                    queue_byte_permit,
                    audit_reservation,
                    client_tid_guard: request_tid_guard
                        .expect("parsed TFTP request must own its client TID"),
                    queue_count_guard: QueuedTransferGuard::new(
                        self.state.queued_transfers.clone(),
                        self.state.metrics.clone(),
                    ),
                };
                match queue.sender.try_send(pending) {
                    Ok(()) => {
                        self.state
                            .metrics
                            .admission_queued_total
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => reject_queued_request(&self.state, &socket, client_addr).await,
                }
                continue;
            }
            // We've reserved a slot; the transfer task is responsible for
            // releasing it via metrics.transfer_completed/failed.

            let packet = match TftpPacket::parse(&buf[..len], client_addr) {
                Ok(p) => p,
                Err(e) => {
                    // Decrement the active_transfers slot we reserved above
                    release_active_transfer_counter(&self.state.active_transfers);
                    record_malformed_packet(&self.state, client_addr, &e, false);
                    continue;
                }
            };

            if !matches!(&packet, TftpPacket::Rrq(_) | TftpPacket::Wrq(_)) {
                release_active_transfer_counter(&self.state.active_transfers);
                record_unexpected_opcode(&self.state, client_addr, false);
                continue;
            }
            self.state.metrics.listener_shard_requests[shard].fetch_add(1, Ordering::Relaxed);
            let client_tid_guard =
                request_tid_guard.expect("parsed TFTP request must own its client TID");

            // Clone Arc<ServerState> only for the spawned task (after parse succeeds).
            match packet {
                TftpPacket::Rrq(req) => {
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_rrq(state, client_addr, req, audit_reservation, client_tid_guard)
                                .await
                        {
                            log_rrq_handler_error(client_addr, &e, false);
                        }
                    });
                }
                TftpPacket::Wrq(req) => {
                    let state = self.state.clone();
                    tokio::spawn(async move {
                        if let Err(e) =
                            handle_wrq(state, client_addr, req, audit_reservation, client_tid_guard)
                                .await
                        {
                            warn!(
                                client = %client_addr,
                                error = %e,
                                "WRQ handler failed"
                            );
                        }
                    });
                }
                _ => unreachable!("non-request packet returned before task dispatch"),
            }
        }
    }

    /// Stop admission after publishing all state that preceded the drain.
    pub fn drain(&self) {
        self.state.drain_mode.store(true, Ordering::Release);
        info!("Drain mode enabled — no new transfers will be accepted");
    }

    /// Wait for all transfers and reserved audit records to finish.
    pub async fn wait_for_drain(&self) {
        loop {
            // Queue-to-active handoff increments active before decrementing
            // queued, so read in the opposite order to observe at least one.
            let queued = self.state.queued_transfers.load(Ordering::Acquire);
            let active = self.state.active_transfers.load(Ordering::Acquire);
            if active == 0 && queued == 0 {
                if let Some(writer) = self.state.audit_writer.as_ref() {
                    if let Err(error) = writer.wait_idle().await {
                        self.state
                            .critical_services_healthy
                            .store(false, Ordering::Release);
                        error!(%error, "audit writer failed while draining");
                    }
                }
                info!("All transfers completed — safe to shut down");
                return;
            }
            info!(active, queued, "Waiting for accepted transfers to complete");
            // Terminal metrics wake this promptly; the timeout also covers a
            // notification racing the counter check above.
            tokio::time::timeout(
                Duration::from_secs(1),
                self.state.metrics.drain_notify.notified(),
            )
            .await
            .ok();
        }
    }
}

async fn reject_queued_request(state: &ServerState, socket: &UdpSocket, client_addr: SocketAddr) {
    state
        .metrics
        .capacity_rejected_total
        .fetch_add(1, Ordering::Relaxed);
    state
        .metrics
        .admission_dropped_total
        .fetch_add(1, Ordering::Relaxed);
    let packet = TftpPacket::error(TftpErrorCode::NotDefined, "Server at capacity");
    let _ = socket.send_to(&packet, client_addr).await;
}

fn record_malformed_packet(
    state: &ServerState,
    client_addr: SocketAddr,
    error: &impl std::fmt::Display,
    at_capacity: bool,
) {
    state
        .metrics
        .malformed_packets_total
        .fetch_add(1, Ordering::Relaxed);
    if state.malformed_log_limiter.check(client_addr.ip()) {
        warn!(client = %client_addr, %error, at_capacity, "Malformed TFTP packet");
    }
}

fn record_unexpected_opcode(state: &ServerState, client_addr: SocketAddr, at_capacity: bool) {
    state
        .metrics
        .unexpected_opcodes_total
        .fetch_add(1, Ordering::Relaxed);
    if state.unexpected_log_limiter.check(client_addr.ip()) {
        warn!(client = %client_addr, at_capacity, "Unexpected opcode on TFTP listener");
    }
}

fn log_rrq_handler_error(client_addr: SocketAddr, error: &TempestError, queued: bool) {
    if matches!(
        error,
        TempestError::Protocol(ProtocolError::Timeout { block: 0, .. })
    ) {
        debug!(
            client = %client_addr,
            queued,
            error = %error,
            "RRQ option handshake abandoned"
        );
    } else {
        warn!(
            client = %client_addr,
            queued,
            error = %error,
            "RRQ handler failed"
        );
    }
}

async fn run_maintenance_task(state: Arc<ServerState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut maintenance_tick = 0u8;
    loop {
        interval.tick().await;
        maintenance_tick = maintenance_tick.wrapping_add(1);
        if maintenance_tick % 6 == 0 {
            state.metrics.evict_inactive_profiles();
        }
        refresh_maintenance_metrics(&state).await;
        if maintenance_tick % 6 != 0 {
            continue;
        }
        state.tftp_rate_limiter.cleanup_stale(100);
        state.malformed_log_limiter.cleanup_stale(100);
        state.unexpected_log_limiter.cleanup_stale(100);
        state.http_rate_limiter.cleanup_stale(100);
        state.prune_expired_boot_sessions(Instant::now());
        state.version_store.prune_group_history();
        if let Some(persistence) = &state.persistence {
            if let Err(error) = persistence.prune_expired_boot_sessions().await {
                warn!(%error, "failed to prune persisted boot sessions");
            }
        }
    }
}

async fn refresh_maintenance_metrics(state: &Arc<ServerState>) {
    if state.config.api.enable_metrics {
        crate::api::metrics::refresh_metrics_snapshot_async(state).await;
    }
}

/// Returns a live client session, removing it and its pin when expired.
pub(crate) fn active_boot_session(
    state: &ServerState,
    client_ip: IpAddr,
) -> Option<BootSessionEntry> {
    loop {
        let session = state
            .boot_sessions
            .get(&client_ip)
            .map(|entry| entry.clone())?;
        let now = Instant::now();
        if session.expires_at > now {
            return Some(session);
        }
        if state
            .remove_boot_session_if(client_ip, |_, current| current.expires_at <= now)
            .is_some()
        {
            state.version_store.prune_group_history();
            return None;
        }
    }
}

fn routed_boot_profile(options: &[(String, String)]) -> Result<Option<&str>, TempestError> {
    let option = |name: &str| {
        options
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };
    let Some(profile) = option(ROUTE_BOOT_PROFILE_OPTION) else {
        return Ok(None);
    };
    let complete_identity = option(EXTENSION_PROTOCOL_VERSION_OPTION)
        == Some(EXTENSION_PROTOCOL_VERSION)
        && option(ROUTE_GROUP_OPTION).is_some()
        && option(ROUTE_ARTIFACT_VERSION_OPTION).is_some()
        && option(ROUTE_MANIFEST_DIGEST_OPTION).is_some()
        && option(ROUTE_CONTENT_HASH_OPTION).is_some();
    if !complete_identity || !is_valid_boot_profile(profile) {
        return Err(TempestError::Protocol(ProtocolError::OptionNegotiation(
            "routed boot profile requires a complete, versioned release identity".into(),
        )));
    }
    Ok(Some(profile))
}

/// Removes queued requests older than `cutoff` and returns the number dropped.
fn prune_expired_pending_transfers(
    heap: &mut BinaryHeap<PendingTransfer>,
    cutoff: Instant,
) -> usize {
    let before_len = heap.len();
    heap.retain(|entry| entry.arrived_at >= cutoff);
    before_len.saturating_sub(heap.len())
}

/// Starts queued requests by priority as transfer slots become available.
async fn run_admission_drain_task(
    state: Arc<ServerState>,
    mut rx: mpsc::Receiver<PendingTransfer>,
) {
    let policy = state
        .admission_policy
        .as_ref()
        .expect("admission drain requires policy")
        .clone();
    let max_age = policy
        .max_queue_age()
        .clamp(Duration::from_secs(1), Duration::from_secs(300));
    let mut launch_sequence = 0u64;
    // Local priority queue — drains mpsc into BinaryHeap for priority ordering
    let mut heap: BinaryHeap<PendingTransfer> = BinaryHeap::new();
    let mut expiry = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(1),
        Duration::from_secs(1),
    );
    expiry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        // Drain any newly queued items from the channel into the local heap
        while let Ok(pending) = rx.try_recv() {
            heap.push(pending);
        }

        // Try to start the highest-priority pending transfer if a slot is available
        while heap.peek().is_some() {
            let current = state.active_transfers.load(Ordering::Acquire);
            if current >= state.config.server.max_concurrent_transfers {
                break; // No slots available
            }

            // Try to claim a slot
            let prev = state.active_transfers.fetch_add(1, Ordering::AcqRel);
            if prev >= state.config.server.max_concurrent_transfers {
                // Race: another task grabbed the slot first — undo
                release_active_transfer_counter(&state.active_transfers);
                break;
            }

            let pending = heap.pop().unwrap();
            let launch_delay = policy
                .launch_delay(launch_sequence)
                .min(Duration::from_secs(30));
            launch_sequence = launch_sequence.wrapping_add(1);
            state
                .metrics
                .admission_started_total
                .fetch_add(1, Ordering::Relaxed);

            let PendingTransfer {
                client_addr,
                request,
                is_write,
                queue_entry_permit,
                queue_byte_permit,
                audit_reservation,
                client_tid_guard,
                queue_count_guard,
                ..
            } = pending;
            drop(queue_entry_permit);
            drop(queue_byte_permit);
            drop(queue_count_guard);
            let state_clone = state.clone();
            if is_write {
                tokio::spawn(async move {
                    if !launch_delay.is_zero() {
                        tokio::time::sleep(launch_delay).await;
                    }
                    if let Err(e) = handle_wrq(
                        state_clone,
                        client_addr,
                        request,
                        audit_reservation,
                        client_tid_guard,
                    )
                    .await
                    {
                        warn!(
                            client = %client_addr,
                            error = %e,
                            "WRQ handler failed (from admission queue)"
                        );
                    }
                });
            } else {
                tokio::spawn(async move {
                    if !launch_delay.is_zero() {
                        tokio::time::sleep(launch_delay).await;
                    }
                    if let Err(e) = handle_rrq(
                        state_clone,
                        client_addr,
                        request,
                        audit_reservation,
                        client_tid_guard,
                    )
                    .await
                    {
                        log_rrq_handler_error(client_addr, &e, true);
                    }
                });
            }
        }

        // If heap is empty and channel is closed, exit the drain task
        if heap.is_empty() && rx.is_closed() {
            info!("Admission queue drain task exiting — channel closed");
            return;
        }

        // Capacity and queue changes are the only reasons to reconsider the heap.
        tokio::select! {
            biased;
            _ = state.metrics.admission_notify.notified() => {},
            _ = expiry.tick() => {
                let cutoff = Instant::now() - max_age;
                let dropped = prune_expired_pending_transfers(&mut heap, cutoff);
                if dropped > 0 {
                    state
                        .metrics
                        .admission_dropped_total
                        .fetch_add(dropped as u64, Ordering::Relaxed);
                    info!(dropped, "admission queue expired stale entries");
                }
            },
            item = rx.recv() => {
                match item {
                    Some(pending) => heap.push(pending),
                    None => {
                        // Channel closed — drain remaining heap then exit
                        if heap.is_empty() {
                            return;
                        }
                    }
                }
            }
        }
    }
}

/// Validates an RRQ, resolves its release, and runs the read-transfer lifecycle.
async fn handle_rrq(
    state: Arc<ServerState>,
    client_addr: SocketAddr,
    req: crate::protocol::packet::RequestPacket,
    audit_reservation: Option<AuditReservation>,
    client_tid_guard: InflightTftpTidGuard,
) -> Result<(), TempestError> {
    let transfer_id = state.transfer_ids.next()?;
    let mut slot_guard = ReservedTransferSlotGuard::new(&state);
    let duplicate_request = client_tid_guard.duplicate_request();

    // Log only option count, not option values (user-controlled data).
    debug!(
        transfer_id = %transfer_id,
        client = %client_addr,
        filename = %req.filename,
        mode = %req.mode.as_str(),
        option_count = req.options.len(),
        "Received RRQ"
    );

    if !supported_transfer_mode(req.mode) {
        let err_pkt =
            TftpPacket::error(TftpErrorCode::IllegalOperation, "Unsupported transfer mode");
        let ephemeral = SocketAddr::new(state.config.server.bind, 0);
        if let Ok(sock) = UdpSocket::bind(ephemeral).await {
            let _ = sock.send_to(&err_pkt, client_addr).await;
        }
        return Err(TempestError::Protocol(
            crate::error::ProtocolError::UnsupportedMode(req.mode.as_str().to_string()),
        ));
    }

    if state.quarantined_files.contains(req.filename.as_str()) {
        let err_pkt = TftpPacket::error(
            TftpErrorCode::AccessViolation,
            "File is quarantined due to integrity violation",
        );
        let ephemeral = SocketAddr::new(state.config.server.bind, 0);
        if let Ok(sock) = UdpSocket::bind(ephemeral).await {
            let _ = sock.send_to(&err_pkt, client_addr).await;
        }
        return Err(TempestError::Protocol(
            crate::error::ProtocolError::AccessViolation(format!("quarantined: {}", req.filename)),
        ));
    }

    // Combined classify_and_profile to avoid double regex_set.matches() call.
    // Boot phase classification  — determine option defaults
    let (phase_for_logging, profile) = state.phase_classifier.classify_and_profile(&req.filename);

    let option_defaults = option_defaults_for_profile(&state, profile);

    // Negotiate options
    let negotiated = negotiate_options_only_for_request(
        &req.options,
        &option_defaults,
        OptionRequestKind::Read,
        state.config.server.accept_client_timeout,
        state.config.server.max_client_timeout_secs,
    );

    let boot_session = active_boot_session(&state, client_addr.ip());
    let boot_profile = routed_boot_profile(&req.options)?
        .or_else(|| {
            boot_session
                .as_ref()
                .map(|session| session.boot_profile.as_str())
        })
        .unwrap_or(DEFAULT_BOOT_PROFILE);

    let trace_id = boot_session
        .as_ref()
        .and_then(|session| session.trace_id.clone());
    if let Some(ref tid) = trace_id {
        debug!(transfer_id = %transfer_id, trace_id = %tid, boot_profile, "RRQ linked to provisioning session");
    }

    // Bind ephemeral socket for this transfer. Keep it unconnected so wrong-TID
    // packets can receive RFC 1350 ERROR 5 instead of being dropped by the kernel.
    let ephemeral_bind = SocketAddr::new(state.config.server.bind, 0);
    let socket = Arc::new(UdpSocket::bind(ephemeral_bind).await?);
    configure_transfer_socket_buffers(
        socket.as_ref(),
        state.config.server.transfer_socket_buffer_bytes,
    )?;

    if let Err(e) = state.dscp_manager.apply_to_sock_ref_for(
        socket2::SockRef::from(socket.as_ref()),
        ephemeral_bind.ip(),
        &phase_for_logging,
    ) {
        warn!(transfer_id = %transfer_id, error = %e, "Failed to apply DSCP marking");
    }

    // Run the transfer
    slot_guard.hand_off();
    let mut metrics = TransferMetrics::default();
    let result = run_read_transfer_for_phase(
        socket,
        client_addr,
        &req.filename,
        boot_profile,
        boot_session
            .as_ref()
            .and_then(|session| session.serial.as_deref()),
        negotiated,
        &req.options,
        state.as_ref(),
        transfer_id,
        phase_for_logging,
        Some(duplicate_request.as_ref()),
        &mut metrics,
    )
    .await;
    metrics.end_time = Some(Instant::now());
    if matches!(
        &result,
        Err(TempestError::Protocol(ProtocolError::Timeout {
            block: 0,
            ..
        }))
    ) {
        state
            .metrics
            .oack_timeouts_total
            .fetch_add(1, Ordering::Relaxed);
    }
    // Transport has ended: permit the next boot-file request on this endpoint
    // before audit work. Audit retains its own separately bounded reservation.
    drop(client_tid_guard);

    if state.audit_log.is_some() {
        let outcome = match &result {
            Ok(()) if metrics.redirected => TransferOutcome::Redirected,
            Ok(()) => TransferOutcome::Completed,
            Err(error) => TransferOutcome::from_error(error),
        };
        let boot_chain = metrics.boot_chain.as_ref();
        let content_hash = metrics.content_hash.take().unwrap_or_default();
        // Keep the terminal identity coherent with the session used to resolve
        // this transfer. A replacement session for the same IP must not rewrite
        // the audit identity after delivery has already started.
        let client_mac = boot_session
            .as_ref()
            .and_then(|session| session.client_mac.clone());
        let client_serial = boot_session
            .as_ref()
            .and_then(|session| session.serial.clone());
        let blocks_sent = metrics.blocks_sent;
        let retransmissions = metrics.retransmissions;
        let delivery = crate::features::audit::DeliveryIdentity {
            transfer_id: transfer_id.to_string(),
            group_id: boot_chain.map(|pin| pin.group_id.clone()),
            artifact_version_id: metrics
                .artifact_version_id
                .or_else(|| boot_chain.map(|pin| pin.version_id)),
            manifest_digest: boot_chain.map(|pin| pin.manifest_digest.clone()),
            phase: phase_for_logging.as_str().to_string(),
            transport: TRANSPORT_TFTP.to_string(),
        };
        let record = AuditRecord {
            client_ip: client_addr.ip().to_string(),
            client_mac,
            client_serial,
            boot_profile: Some(boot_profile.to_owned()),
            file_path: req.filename,
            file_sha256: content_hash,
            blocks_sent,
            retransmissions,
            outcome,
            timestamp: jiff::Timestamp::now(),
            trace_id,
            delivery: Some(delivery),
        };
        if let Err(e) = record_terminal_audit(&state, audit_reservation, record).await {
            state
                .critical_services_healthy
                .store(false, Ordering::Release);
            error!(transfer_id = %transfer_id, error = %e, "audit write failed; rejecting new transfers");
            return Err(e);
        }
    }

    result
}

/// Validates a WRQ and runs the write-transfer lifecycle with audit reporting.
async fn handle_wrq(
    state: Arc<ServerState>,
    client_addr: SocketAddr,
    req: crate::protocol::packet::RequestPacket,
    audit_reservation: Option<AuditReservation>,
    client_tid_guard: InflightTftpTidGuard,
) -> Result<(), TempestError> {
    let transfer_id = state.transfer_ids.next()?;
    let mut slot_guard = ReservedTransferSlotGuard::new(&state);

    if !supported_transfer_mode(req.mode) {
        let err_pkt =
            TftpPacket::error(TftpErrorCode::IllegalOperation, "Unsupported transfer mode");
        let ephemeral = SocketAddr::new(state.config.server.bind, 0);
        if let Ok(sock) = UdpSocket::bind(ephemeral).await {
            let _ = sock.send_to(&err_pkt, client_addr).await;
        }
        return Err(TempestError::Protocol(
            crate::error::ProtocolError::UnsupportedMode(req.mode.as_str().to_string()),
        ));
    }

    // Quarantine blocks reads and writes through the same logical-name key.
    if state.quarantined_files.contains(req.filename.as_str()) {
        let ephemeral = SocketAddr::new(state.config.server.bind, 0);
        if let Ok(sock) = UdpSocket::bind(ephemeral).await {
            let err_pkt = TftpPacket::error(
                TftpErrorCode::AccessViolation,
                "File is quarantined due to integrity violation",
            );
            let _ = sock.send_to(&err_pkt, client_addr).await;
        }
        return Err(TempestError::Protocol(
            crate::error::ProtocolError::AccessViolation(format!("quarantined: {}", req.filename)),
        ));
    }

    let wrq_profile = state.phase_classifier.profile(&req.filename);
    let option_defaults = option_defaults_for_profile(&state, wrq_profile);

    debug!(
        transfer_id = %transfer_id,
        client = %client_addr,
        filename = %req.filename,
        option_count = req.options.len(),
        "Received WRQ"
    );

    let negotiated = negotiate_options_only_for_request(
        &req.options,
        &option_defaults,
        OptionRequestKind::Write,
        state.config.server.accept_client_timeout,
        state.config.server.max_client_timeout_secs,
    );

    let boot_session = active_boot_session(&state, client_addr.ip());
    let boot_profile = boot_session
        .as_ref()
        .map(|session| session.boot_profile.clone())
        .unwrap_or_else(|| DEFAULT_BOOT_PROFILE.to_string());

    let trace_id = boot_session
        .as_ref()
        .and_then(|session| session.trace_id.clone());
    if let Some(ref tid) = trace_id {
        debug!(transfer_id = %transfer_id, trace_id = %tid, boot_profile = %boot_profile, "WRQ linked to provisioning session");
    }

    let ephemeral_bind = SocketAddr::new(state.config.server.bind, 0);
    let socket = Arc::new(UdpSocket::bind(ephemeral_bind).await?);
    configure_transfer_socket_buffers(
        socket.as_ref(),
        state.config.server.transfer_socket_buffer_bytes,
    )?;

    let duplicate_request = client_tid_guard.duplicate_request();
    slot_guard.hand_off();
    let result = run_write_transfer_with_duplicate_request(
        socket,
        client_addr,
        req.filename.clone(),
        boot_profile.clone(),
        negotiated,
        state.clone(),
        transfer_id,
        Some(duplicate_request.as_ref()),
    )
    .await;
    // As with RRQ, audit must not retain the completed transport's TID/quota.
    drop(client_tid_guard);

    if state.audit_log.is_some() {
        let outcome = match &result {
            Ok(_) => TransferOutcome::Completed,
            Err(error) => TransferOutcome::from_error(error),
        };
        let metrics = result.as_ref().ok();
        let client_mac = boot_session
            .as_ref()
            .and_then(|session| session.client_mac.clone());
        let client_serial = boot_session
            .as_ref()
            .and_then(|session| session.serial.clone());
        let blocks_sent = metrics.map_or(0, |metrics| metrics.blocks_sent);
        let retransmissions = metrics.map_or(0, |metrics| metrics.retransmissions);
        let record = AuditRecord {
            client_ip: client_addr.ip().to_string(),
            client_mac,
            client_serial,
            boot_profile: Some(boot_profile),
            file_path: req.filename,
            file_sha256: String::new(),
            blocks_sent,
            retransmissions,
            outcome,
            timestamp: jiff::Timestamp::now(),
            trace_id,
            delivery: None,
        };
        if let Err(error) = record_terminal_audit(&state, audit_reservation, record).await {
            state
                .critical_services_healthy
                .store(false, Ordering::Release);
            tracing::error!(transfer_id = %transfer_id, %error, "audit write failed; rejecting new transfers");
            return Err(error);
        }
    }

    result.map(|_| ())
}

async fn record_terminal_audit(
    state: &ServerState,
    reservation: Option<AuditReservation>,
    record: AuditRecord,
) -> Result<(), TempestError> {
    if let Some(reservation) = reservation {
        reservation.record(record)?;
        return Ok(());
    }
    let Some(audit) = state.audit_log.clone() else {
        return Ok(());
    };
    tokio::task::spawn_blocking(move || {
        if let Some(delivery) = record.delivery {
            audit.append_delivery(
                record.client_ip,
                record.client_mac,
                record.client_serial,
                record.boot_profile,
                record.file_path,
                record.file_sha256,
                record.blocks_sent,
                record.retransmissions,
                record.outcome,
                record.trace_id,
                delivery,
            )
        } else {
            audit.append_with_identity(
                record.client_ip,
                record.client_mac,
                record.client_serial,
                record.boot_profile,
                record.file_path,
                record.file_sha256,
                record.blocks_sent,
                record.retransmissions,
                record.outcome,
                record.trace_id,
            )
        }
    })
    .await
    .map_err(|error| TempestError::Audit(format!("audit writer task failed: {error}")))??;
    Ok(())
}

#[cfg(test)]
mod tests;
