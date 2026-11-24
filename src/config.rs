// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

/// Hard bound shared by file loading and programmatic server construction.
pub(crate) const MAX_ALLOWED_BOOT_SESSIONS: usize = 1_000_000;

pub(crate) fn validate_boot_session_capacity(capacity: usize) -> crate::error::Result<()> {
    if !(1..=MAX_ALLOWED_BOOT_SESSIONS).contains(&capacity) {
        return Err(crate::error::TempestError::Config(format!(
            "server.max_boot_sessions must be in 1..={MAX_ALLOWED_BOOT_SESSIONS}"
        )));
    }
    Ok(())
}

/// Open and read one security-sensitive regular file without trusting a second
/// pathname lookup. Pre/post identity checks detect replacement during open.
pub(crate) fn read_secure_file(
    path: &Path,
    role: &str,
    max_bytes: u64,
    private: bool,
) -> crate::error::Result<Vec<u8>> {
    let before = std::fs::symlink_metadata(path).map_err(|error| {
        crate::error::TempestError::Config(format!("Failed to inspect {role}: {error}"))
    })?;
    if before.file_type().is_symlink() || !before.is_file() {
        return Err(crate::error::TempestError::Config(format!(
            "{role} must be a regular non-symlink file"
        )));
    }
    if before.len() > max_bytes {
        return Err(crate::error::TempestError::Config(format!(
            "{role} exceeds the {max_bytes}-byte limit"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = before.permissions().mode();
        if mode & 0o022 != 0 || (private && (mode & 0o077 != 0 || mode & 0o400 == 0)) {
            return Err(crate::error::TempestError::Config(format!(
                "{role} has unsafe Unix permissions"
            )));
        }
    }

    let file = std::fs::File::open(path).map_err(|error| {
        crate::error::TempestError::Config(format!("Failed to open {role}: {error}"))
    })?;
    let after = file.metadata().map_err(|error| {
        crate::error::TempestError::Config(format!("Failed to inspect opened {role}: {error}"))
    })?;
    if !after.is_file() || after.len() != before.len() || !same_file_identity(&before, &after) {
        return Err(crate::error::TempestError::Config(format!(
            "{role} changed while it was being opened"
        )));
    }
    let mut contents = Vec::with_capacity(after.len() as usize);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut contents)
        .map_err(|error| {
            crate::error::TempestError::Config(format!("Failed to read {role}: {error}"))
        })?;
    if contents.len() as u64 > max_bytes {
        return Err(crate::error::TempestError::Config(format!(
            "{role} exceeds the {max_bytes}-byte limit"
        )));
    }
    Ok(contents)
}

#[cfg(unix)]
fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file_identity(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
        && left.created().ok() == right.created().ok()
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Complete core configuration loaded from one strict TOML document.
pub struct TempestConfig {
    /// TFTP listener, artifact root, transfer limits, and logging settings.
    #[serde(default = "default_server")]
    pub server: ServerConfig,

    /// HTTP listener, endpoint enablement, authentication, and body limits.
    #[serde(default)]
    pub api: ApiConfig,

    /// Ordered regex rules used to classify artifacts and tune transfers.
    #[serde(default)]
    pub boot_phases: Vec<BootPhaseConfig>,

    /// Per-phase differentiated-services and ECN settings.
    #[serde(default)]
    pub dscp: DscpConfig,

    /// Tamper-evident transfer logging, rotation, and signing settings.
    #[serde(default)]
    pub audit: AuditConfig,

    /// Optional durable control-plane storage and reconciliation settings.
    #[serde(default)]
    pub persistence: PersistenceConfig,

    /// Namespaced configuration owned by an embedding extension composition.
    /// The core binary rejects a non-empty table; first-party compositions parse
    /// and validate their own entries instead of weakening the core schema.
    #[serde(default)]
    pub extensions: toml::Table,
}

impl std::fmt::Debug for TempestConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TempestConfig")
            .field("server", &self.server)
            .field("api", &self.api)
            .field("boot_phases", &self.boot_phases)
            .field("dscp", &self.dscp)
            .field("audit", &self.audit)
            .field("persistence", &self.persistence)
            .field("extensions", &self.extensions.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// Supplies the default server section when it is omitted from TOML.
fn default_server() -> ServerConfig {
    ServerConfig::default()
}

/// TFTP data-plane listener, filesystem, capacity, and transfer defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// IP address on which the UDP TFTP listener binds.
    #[serde(default = "default_bind")]
    pub bind: IpAddr,

    /// UDP TFTP port; port `0` requests an ephemeral port.
    #[serde(default = "default_port")]
    pub port: u16,

    /// Number of Linux `SO_REUSEPORT` listener shards.
    ///
    /// Zero selects one shard per available CPU on Linux, bounded to 64, and
    /// one shard on other platforms. One forces the portable single-listener
    /// path. Larger values spread initial request parsing across runtime
    /// workers while all security and capacity state remains shared.
    #[serde(default = "default_listener_shards")]
    pub listener_shards: usize,

    /// Filesystem root containing all readable and writable artifacts.
    #[serde(default = "default_root")]
    pub root: PathBuf,

    /// Maximum age of capability validation reused by the unmanaged hot cache.
    ///
    /// Zero validates every request. A nonzero value trades bounded visibility
    /// delay for fewer filesystem syscalls; managed artifacts use digest-verified
    /// immutable snapshots instead.
    #[serde(default)]
    pub unmanaged_cache_validation_interval_ms: u64,

    /// Maximum total bytes retained by the shared immutable artifact cache.
    #[serde(default = "default_hot_artifact_cache_max_bytes")]
    pub hot_artifact_cache_max_bytes: u64,

    /// Maximum size of one artifact admitted to the shared immutable cache.
    ///
    /// This must not exceed `hot_artifact_cache_max_bytes`. Managed entries are
    /// reusable without a path reopen only after their size and SHA-256 match
    /// the pinned release metadata.
    #[serde(default = "default_hot_artifact_cache_max_file_bytes")]
    pub hot_artifact_cache_max_file_bytes: u64,

    /// Maximum active read and write transfers before admission is rejected.
    #[serde(default = "default_max_transfers")]
    pub max_concurrent_transfers: usize,

    /// Maximum queued, reserved, and running TFTP requests per source IP.
    ///
    /// Default 16; valid range `1..=10000`. Queued requests retain their
    /// reservation through transport cleanup, then release it before terminal
    /// audit work (separately bounded). HTTP is not counted. Raise this
    /// explicitly for shared NAT or trusted single-source load generators.
    #[serde(default = "default_max_tftp_transfers_per_ip")]
    pub max_tftp_transfers_per_ip: usize,

    /// Maximum TFTP request datagrams accepted from one source IP per second.
    ///
    /// Zero disables this protection for isolated benchmark environments.
    #[serde(default = "default_tftp_requests_per_ip_per_second")]
    pub tftp_requests_per_ip_per_second: u32,

    /// Maximum HTTP requests accepted from one source IP per second.
    ///
    /// This shared budget covers control, metrics, and artifact routes. Zero
    /// disables this protection for isolated benchmark environments.
    #[serde(default = "default_http_requests_per_ip_per_second")]
    pub http_requests_per_ip_per_second: u32,

    /// Maximum unexpired source-IP boot sessions retained by one server node.
    #[serde(default = "default_max_boot_sessions")]
    pub max_boot_sessions: usize,

    /// Default RFC 2348 DATA payload size in bytes.
    #[serde(default = "default_block_size")]
    pub default_block_size: u16,

    /// Maximum RFC 7440 window accepted when no boot-phase rule matches.
    ///
    /// A client that does not request `windowsize` retains RFC lockstep
    /// behavior with a one-block window.
    #[serde(default = "default_max_window_size")]
    pub max_window_size: u16,

    /// Opt in to Linux UDP segmentation for eligible standard DATA windows.
    ///
    /// Disabled by default. Capability rejection falls back per transfer to
    /// ordinary datagram batching. Ignored on other platforms; negotiation,
    /// provider exclusions, pacing and bandwidth budgets remain unchanged.
    #[serde(default)]
    pub udp_segmentation_offload: bool,

    /// Accept and echo the client's RFC 2349 retransmission interval.
    ///
    /// When disabled, Tempest omits only `timeout` from OACK and uses its
    /// bounded adaptive RTO. RFC 2347 requires clients to ignore omitted
    /// options, so this remains standards-compliant without acknowledging a
    /// value the server will not honor.
    #[serde(default = "default_true")]
    pub accept_client_timeout: bool,

    /// Largest client RFC 2349 timeout accepted, in seconds (default 255).
    ///
    /// Values above this ceiling are omitted, never counteroffered. Other
    /// requested options are unaffected. Valid range `1..=255`; ignored when
    /// `accept_client_timeout` is false. Accepted intervals remain exact.
    #[serde(default = "default_max_client_timeout_secs")]
    pub max_client_timeout_secs: u8,

    /// Absolute TFTP network-exchange deadline in seconds (default 300).
    ///
    /// Must be in `1..=86400`; zero cannot disable it. Starts on entry to each
    /// RRQ/WRQ transfer and is never refreshed by progress, duplicates, or retries.
    /// Covers read OACK/DATA (including scheduling and pacing), write DATA
    /// reception, and final ACK dally. Preparation consumes elapsed time but
    /// unabortable setup is not interrupted. Once the entire write is received
    /// before the deadline, final durable flush/publication may finish without
    /// timed cancellation. This does not shorten an accepted RFC 2349 interval:
    /// the server may terminate at the deadline, but does not retransmit early.
    /// Expiry before completion attempts one nonblocking TFTP ERROR. This is
    /// server resource policy, not an RFC-mandated lifetime or retry count.
    #[serde(default = "default_max_transfer_duration_secs")]
    pub max_transfer_duration_secs: u64,

    /// Initial internal retransmission interval when RFC 2349 is not negotiated.
    #[serde(default = "default_retransmit_ms")]
    pub retransmit_interval_ms: u64,

    /// Adaptive retransmission floor when RFC 2349 is not negotiated.
    #[serde(default = "default_min_retransmit_ms")]
    pub min_retransmit_interval_ms: u64,

    /// Adaptive retransmission ceiling when RFC 2349 is not negotiated.
    #[serde(default = "default_max_retransmit_ms")]
    pub max_retransmit_interval_ms: u64,

    /// Maximum retransmissions before a transfer is failed.
    #[serde(default = "default_max_retries")]
    pub max_retries: u8,

    /// Requested receive-buffer size for the well-known TFTP listener.
    #[serde(default = "default_listener_receive_buffer_bytes")]
    pub listener_receive_buffer_bytes: usize,

    /// Requested send and receive buffer size for each transfer socket.
    ///
    /// Zero keeps the operating-system defaults and avoids per-transfer
    /// `setsockopt` calls.
    #[serde(default = "default_transfer_socket_buffer_bytes")]
    pub transfer_socket_buffer_bytes: usize,

    /// `tracing` filter level used when initializing logging.
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Emit structured JSON logs instead of human-readable text.
    #[serde(default)]
    pub json_logging: bool,

    /// Whether WRQ (write) operations are permitted
    #[serde(default)]
    pub write_enabled: bool,

    /// Maximum file size allowed for WRQ writes (bytes)
    #[serde(default = "default_max_write_file_size")]
    pub max_write_file_size: u64,

    /// Require a live provisioning session before accepting a WRQ.
    #[serde(default = "default_true")]
    pub write_require_session: bool,

    /// Permit an authenticated WRQ to replace an existing artifact.
    #[serde(default)]
    pub write_allow_overwrite: bool,

    /// Whether the global bandwidth governor is enabled.
    /// When enabled, aggregate TFTP output is capped at the configured byte rate.
    #[serde(default)]
    pub bandwidth_governor_enabled: bool,

    /// Total server NIC bandwidth in bytes per second (default: 125_000_000 = 1 Gbps).
    /// Used by both the bandwidth governor and the per-transfer ceiling calculation.
    /// `None` uses the default of 125 MB/s.
    #[serde(
        default,
        rename = "total_bandwidth_bytes_per_second",
        alias = "total_bandwidth_bps"
    )]
    pub total_bandwidth_bps: Option<u64>,
}

impl ServerConfig {
    /// Returns the aggregate TFTP and HTTP artifact budget in bytes per second.
    ///
    /// The Rust field retains its legacy name for source compatibility. New
    /// serialized configuration uses `total_bandwidth_bytes_per_second`.
    pub fn total_bandwidth_bytes_per_second(&self) -> Option<u64> {
        self.total_bandwidth_bps
    }

    /// Resolves automatic listener fan-out once for the current host.
    pub fn effective_listener_shards(&self) -> usize {
        if self.listener_shards != 0 {
            return self.listener_shards;
        }

        #[cfg(target_os = "linux")]
        {
            std::thread::available_parallelism()
                .map(std::num::NonZeroUsize::get)
                .unwrap_or(1)
                .clamp(1, 64)
        }

        #[cfg(not(target_os = "linux"))]
        {
            1
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            port: default_port(),
            listener_shards: default_listener_shards(),
            root: default_root(),
            unmanaged_cache_validation_interval_ms: 0,
            hot_artifact_cache_max_bytes: default_hot_artifact_cache_max_bytes(),
            hot_artifact_cache_max_file_bytes: default_hot_artifact_cache_max_file_bytes(),
            max_concurrent_transfers: default_max_transfers(),
            max_tftp_transfers_per_ip: default_max_tftp_transfers_per_ip(),
            tftp_requests_per_ip_per_second: default_tftp_requests_per_ip_per_second(),
            http_requests_per_ip_per_second: default_http_requests_per_ip_per_second(),
            max_boot_sessions: default_max_boot_sessions(),
            default_block_size: default_block_size(),
            max_window_size: default_max_window_size(),
            udp_segmentation_offload: false,
            accept_client_timeout: true,
            max_client_timeout_secs: default_max_client_timeout_secs(),
            max_transfer_duration_secs: default_max_transfer_duration_secs(),
            retransmit_interval_ms: default_retransmit_ms(),
            min_retransmit_interval_ms: default_min_retransmit_ms(),
            max_retransmit_interval_ms: default_max_retransmit_ms(),
            max_retries: default_max_retries(),
            listener_receive_buffer_bytes: default_listener_receive_buffer_bytes(),
            transfer_socket_buffer_bytes: default_transfer_socket_buffer_bytes(),
            log_level: default_log_level(),
            json_logging: false,
            write_enabled: false,
            max_write_file_size: default_max_write_file_size(),
            write_require_session: true,
            write_allow_overwrite: false,
            bandwidth_governor_enabled: false,
            total_bandwidth_bps: None,
        }
    }
}

/// Returns the default all-interface TFTP bind address.
fn default_bind() -> IpAddr {
    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
}

/// Returns the standard TFTP port.
fn default_port() -> u16 {
    69
}

/// Returns the automatic host-scaled listener default.
fn default_listener_shards() -> usize {
    0
}

/// Returns the default artifact root.
fn default_root() -> PathBuf {
    PathBuf::from("/tftpboot")
}

/// Returns the conservative shared immutable-artifact cache budget.
fn default_hot_artifact_cache_max_bytes() -> u64 {
    crate::artifact_cache::HOT_ARTIFACT_CACHE_MAX_BYTES as u64
}

/// Returns the conservative maximum size of one cached artifact.
fn default_hot_artifact_cache_max_file_bytes() -> u64 {
    crate::artifact_cache::HOT_ARTIFACT_CACHE_MAX_FILE_BYTES as u64
}

/// Returns the default active-transfer limit.
fn default_max_transfers() -> usize {
    500
}

fn default_max_tftp_transfers_per_ip() -> usize {
    16
}

fn default_max_client_timeout_secs() -> u8 {
    255
}

/// Returns the default one-second per-source TFTP request budget.
fn default_tftp_requests_per_ip_per_second() -> u32 {
    50
}

/// Returns the default one-second per-source HTTP request budget.
fn default_http_requests_per_ip_per_second() -> u32 {
    100
}

/// Returns the default live boot-session limit.
fn default_max_boot_sessions() -> usize {
    100_000
}

/// Returns the RFC default DATA payload size.
fn default_block_size() -> u16 {
    512
}

/// Returns the largest window accepted without a phase-specific ceiling.
fn default_max_window_size() -> u16 {
    64
}

/// Returns the absolute TFTP network-exchange budget in seconds.
fn default_max_transfer_duration_secs() -> u64 {
    300
}

/// Returns the conservative initial internal retransmission interval.
fn default_retransmit_ms() -> u64 {
    1_000
}

/// Returns the adaptive retransmission floor for a provisioned LAN.
fn default_min_retransmit_ms() -> u64 {
    250
}

/// Returns the adaptive retransmission ceiling.
fn default_max_retransmit_ms() -> u64 {
    4_000
}

/// Returns the listener receive-buffer request.
fn default_listener_receive_buffer_bytes() -> usize {
    4 * 1024 * 1024
}

/// Returns the per-transfer socket-buffer request.
fn default_transfer_socket_buffer_bytes() -> usize {
    0
}

fn validate_retransmission_policy(
    scope: &str,
    initial_ms: u64,
    min_ms: u64,
    max_ms: u64,
) -> Result<(), crate::error::TempestError> {
    const MIN_INTERNAL_RTO_MS: u64 = 50;
    const MAX_INTERNAL_RTO_MS: u64 = 60_000;
    if min_ms < MIN_INTERNAL_RTO_MS
        || min_ms > initial_ms
        || initial_ms > max_ms
        || max_ms > MAX_INTERNAL_RTO_MS
    {
        return Err(crate::error::TempestError::Config(format!(
            "{scope} retransmission policy must satisfy {MIN_INTERNAL_RTO_MS} <= \
             min_retransmit_interval_ms <= retransmit_interval_ms <= \
             max_retransmit_interval_ms <= {MAX_INTERNAL_RTO_MS}"
        )));
    }
    Ok(())
}

pub(crate) fn validate_tftp_performance_config(
    config: &TempestConfig,
) -> Result<(), crate::error::TempestError> {
    if !(1..=10_000).contains(&config.server.max_tftp_transfers_per_ip) {
        return Err(crate::error::TempestError::Config(
            "server.max_tftp_transfers_per_ip must be in 1..=10000".into(),
        ));
    }
    if config.server.max_client_timeout_secs == 0 {
        return Err(crate::error::TempestError::Config(
            "server.max_client_timeout_secs must be in 1..=255".into(),
        ));
    }
    if !(1..=86_400).contains(&config.server.max_transfer_duration_secs) {
        return Err(crate::error::TempestError::Config(
            "server.max_transfer_duration_secs must be in 1..=86400 (zero cannot disable it)"
                .into(),
        ));
    }
    if config.server.listener_shards > 64 {
        return Err(crate::error::TempestError::Config(
            "server.listener_shards must be in 0..=64 (0 selects automatic fan-out)".into(),
        ));
    }
    #[cfg(not(target_os = "linux"))]
    if config.server.listener_shards > 1 {
        return Err(crate::error::TempestError::Config(
            "server.listener_shards above 1 requires Linux SO_REUSEPORT".into(),
        ));
    }

    if !(1..=64).contains(&config.server.max_window_size) {
        return Err(crate::error::TempestError::Config(
            "server.max_window_size must be in 1..=64".into(),
        ));
    }
    if config.server.unmanaged_cache_validation_interval_ms > 1_000 {
        return Err(crate::error::TempestError::Config(
            "server.unmanaged_cache_validation_interval_ms must be in 0..=1000".into(),
        ));
    }
    const MAX_HOT_ARTIFACT_CACHE_BYTES: u64 = 16 * 1024 * 1024 * 1024;
    let cache_bytes = config.server.hot_artifact_cache_max_bytes;
    let max_file_bytes = config.server.hot_artifact_cache_max_file_bytes;
    if cache_bytes == 0
        || cache_bytes > MAX_HOT_ARTIFACT_CACHE_BYTES
        || usize::try_from(cache_bytes).is_err()
    {
        return Err(crate::error::TempestError::Config(format!(
            "server.hot_artifact_cache_max_bytes must be in 1..={MAX_HOT_ARTIFACT_CACHE_BYTES} and fit this platform"
        )));
    }
    if max_file_bytes == 0 || max_file_bytes > cache_bytes {
        return Err(crate::error::TempestError::Config(
            "server.hot_artifact_cache_max_file_bytes must be in 1..=hot_artifact_cache_max_bytes"
                .into(),
        ));
    }
    let http_cache_bytes = config.api.artifact_cache_max_bytes;
    let http_max_file_bytes = config.api.artifact_cache_max_file_bytes;
    if http_cache_bytes > MAX_HOT_ARTIFACT_CACHE_BYTES
        || usize::try_from(http_cache_bytes).is_err()
        || (http_cache_bytes == 0) != (http_max_file_bytes == 0)
        || http_max_file_bytes > http_cache_bytes
    {
        return Err(crate::error::TempestError::Config(format!(
            "api artifact cache limits must both be zero or satisfy artifact_cache_max_file_bytes <= artifact_cache_max_bytes <= {MAX_HOT_ARTIFACT_CACHE_BYTES} and fit this platform"
        )));
    }
    validate_retransmission_policy(
        "server",
        config.server.retransmit_interval_ms,
        config.server.min_retransmit_interval_ms,
        config.server.max_retransmit_interval_ms,
    )?;

    const MIN_LISTENER_BUFFER_BYTES: usize = 64 * 1024;
    const MAX_LISTENER_BUFFER_BYTES: usize = 16 * 1024 * 1024;
    if !(MIN_LISTENER_BUFFER_BYTES..=MAX_LISTENER_BUFFER_BYTES)
        .contains(&config.server.listener_receive_buffer_bytes)
    {
        return Err(crate::error::TempestError::Config(format!(
            "server.listener_receive_buffer_bytes must be in \
             {MIN_LISTENER_BUFFER_BYTES}..={MAX_LISTENER_BUFFER_BYTES}"
        )));
    }
    const MIN_TRANSFER_BUFFER_BYTES: usize = 16 * 1024;
    const MAX_TRANSFER_BUFFER_BYTES: usize = 4 * 1024 * 1024;
    if config.server.transfer_socket_buffer_bytes != 0
        && !(MIN_TRANSFER_BUFFER_BYTES..=MAX_TRANSFER_BUFFER_BYTES)
            .contains(&config.server.transfer_socket_buffer_bytes)
    {
        return Err(crate::error::TempestError::Config(format!(
            "server.transfer_socket_buffer_bytes must be in \
             {MIN_TRANSFER_BUFFER_BYTES}..={MAX_TRANSFER_BUFFER_BYTES}"
        )));
    }
    const MAX_TRANSFER_SOCKET_BUFFER_BUDGET: usize = 1024 * 1024 * 1024;
    let requested_transfer_socket_budget = config
        .server
        .transfer_socket_buffer_bytes
        .checked_mul(2)
        .and_then(|per_transfer| per_transfer.checked_mul(config.server.max_concurrent_transfers))
        .ok_or_else(|| {
            crate::error::TempestError::Config(
                "server transfer socket buffer budget overflows usize".into(),
            )
        })?;
    if requested_transfer_socket_budget > MAX_TRANSFER_SOCKET_BUFFER_BUDGET {
        return Err(crate::error::TempestError::Config(format!(
            "server.transfer_socket_buffer_bytes for send and receive, multiplied \
             by max_concurrent_transfers, must not exceed \
             {MAX_TRANSFER_SOCKET_BUFFER_BUDGET}"
        )));
    }

    for phase in &config.boot_phases {
        if !(1..=64).contains(&phase.max_window_size) {
            return Err(crate::error::TempestError::Config(format!(
                "boot phase {} max_window_size must be in 1..=64",
                phase.name
            )));
        }
        validate_retransmission_policy(
            &format!("boot phase {}", phase.name),
            phase.retransmit_interval_ms,
            phase.min_retransmit_interval_ms,
            phase.max_retransmit_interval_ms,
        )?;
    }
    Ok(())
}

/// Returns the default retransmission limit.
fn default_max_retries() -> u8 {
    5
}

/// Returns the default tracing filter level.
fn default_log_level() -> String {
    "info".into()
}

/// Returns the default 512 MiB write limit.
fn default_max_write_file_size() -> u64 {
    512 * 1024 * 1024 // 512 MB default limit
}

const fn default_true() -> bool {
    true
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// HTTP control-plane, artifact, metrics, and authentication settings.
pub struct ApiConfig {
    /// Maximum accepted HTTP connections, including idle keep-alive sockets.
    #[serde(default = "default_http_max_connections")]
    pub max_connections: usize,

    /// Maximum time to receive headers (including idle keep-alive) or a request body.
    /// Application processing and response streaming do not consume this budget.
    #[serde(default = "default_http_read_timeout_secs")]
    pub read_timeout_secs: u64,

    /// Maximum continuous socket-write stall; zero disables the deadline.
    #[serde(default = "default_http_write_timeout_secs")]
    pub write_timeout_secs: u64,
    /// TCP port for HTTP health, control, artifact, and metrics routes.
    #[serde(default = "default_api_port")]
    pub port: u16,

    /// IP address on which the HTTP listener binds.
    #[serde(default = "default_api_bind")]
    pub bind: IpAddr,

    /// Expose the Prometheus metrics route.
    #[serde(default)]
    pub enable_metrics: bool,

    /// Require `x-api-key` authentication for the Prometheus metrics route.
    ///
    /// Disable only when network policy restricts the listener to trusted
    /// Prometheus scrapers. Other API routes remain authenticated.
    #[serde(default = "default_true")]
    pub metrics_require_api_key: bool,

    /// Expose release listing and mutation routes.
    #[serde(default)]
    pub enable_versions_api: bool,

    /// Expose audit-query routes.
    #[serde(default)]
    pub enable_audit_api: bool,

    /// Expose the source-IP-authorized native UEFI HTTP Boot route.
    #[serde(default)]
    pub enable_native_http_boot: bool,

    /// Release-managed logical artifact served by the native HTTP Boot route.
    #[serde(default = "default_native_http_boot_filename")]
    pub native_http_boot_filename: String,

    /// API key for authentication (if set, all mutation endpoints require it)
    /// Supports environment variable via "env:VARNAME" syntax
    #[serde(default)]
    pub api_key: Option<String>,

    /// Development-only escape hatch for an unauthenticated loopback API.
    #[serde(default)]
    pub allow_insecure_loopback: bool,

    /// Socket peers allowed to supply one `X-Forwarded-For` client address.
    #[serde(default)]
    pub trusted_proxy_ips: Vec<IpAddr>,

    /// Maximum request body size in bytes
    #[serde(default = "default_max_request_body")]
    pub max_request_body_bytes: usize,

    /// Maximum bytes retained by the HTTP-only managed-artifact cache.
    #[serde(default = "default_http_artifact_cache_max_bytes")]
    pub artifact_cache_max_bytes: u64,

    /// Maximum size of one HTTP artifact admitted to that cache.
    #[serde(default = "default_http_artifact_cache_max_file_bytes")]
    pub artifact_cache_max_file_bytes: u64,
}

impl std::fmt::Debug for ApiConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiConfig")
            .field("port", &self.port)
            .field("max_connections", &self.max_connections)
            .field("write_timeout_secs", &self.write_timeout_secs)
            .field("read_timeout_secs", &self.read_timeout_secs)
            .field("bind", &self.bind)
            .field("enable_metrics", &self.enable_metrics)
            .field("metrics_require_api_key", &self.metrics_require_api_key)
            .field("enable_versions_api", &self.enable_versions_api)
            .field("enable_audit_api", &self.enable_audit_api)
            .field("enable_native_http_boot", &self.enable_native_http_boot)
            .field("native_http_boot_filename", &self.native_http_boot_filename)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("allow_insecure_loopback", &self.allow_insecure_loopback)
            .field("trusted_proxy_ips", &self.trusted_proxy_ips)
            .field("max_request_body_bytes", &self.max_request_body_bytes)
            .field("artifact_cache_max_bytes", &self.artifact_cache_max_bytes)
            .field(
                "artifact_cache_max_file_bytes",
                &self.artifact_cache_max_file_bytes,
            )
            .finish()
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            max_connections: default_http_max_connections(),
            write_timeout_secs: default_http_write_timeout_secs(),
            read_timeout_secs: default_http_read_timeout_secs(),
            port: default_api_port(),
            bind: default_api_bind(),
            enable_metrics: true,
            metrics_require_api_key: true,
            enable_versions_api: true,
            enable_audit_api: true,
            enable_native_http_boot: false,
            native_http_boot_filename: default_native_http_boot_filename(),
            api_key: None,
            allow_insecure_loopback: false,
            trusted_proxy_ips: Vec::new(),
            max_request_body_bytes: default_max_request_body(),
            artifact_cache_max_bytes: default_http_artifact_cache_max_bytes(),
            artifact_cache_max_file_bytes: default_http_artifact_cache_max_file_bytes(),
        }
    }
}

/// Leaves space for boot traffic and control connections without unbounded accepts.
fn default_http_max_connections() -> usize {
    1024
}

fn default_http_read_timeout_secs() -> u64 {
    30
}

fn default_http_write_timeout_secs() -> u64 {
    120
}

/// Returns the default HTTP control-plane port.
fn default_api_port() -> u16 {
    8080
}

/// Returns the default loopback HTTP bind address.
fn default_api_bind() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

/// Returns the conventional profile-relative UEFI network boot program name.
fn default_native_http_boot_filename() -> String {
    "boot.efi".to_string()
}

/// Returns the default one-megabyte request-body limit.
fn default_max_request_body() -> usize {
    1024 * 1024 // 1 MB
}

fn default_http_artifact_cache_max_bytes() -> u64 {
    64 * 1024 * 1024
}

fn default_http_artifact_cache_max_file_bytes() -> u64 {
    16 * 1024 * 1024
}

/// One regex-based boot-phase classification rule and transfer profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootPhaseConfig {
    /// Case-insensitive phase name such as `KERNEL` or `INITRD`.
    pub name: String,
    /// Rust regular expression matched against the requested artifact path.
    pub pattern: String,
    /// Preferred RFC 2348 payload size in bytes.
    #[serde(default = "default_block_size")]
    pub block_size: u16,
    /// Maximum RFC 7440 window accepted for this phase.
    #[serde(default = "default_max_window_size")]
    pub max_window_size: u16,
    /// Initial internal retransmission interval in milliseconds.
    #[serde(default = "default_retransmit_ms")]
    pub retransmit_interval_ms: u64,
    /// Adaptive retransmission floor in milliseconds.
    #[serde(default = "default_min_retransmit_ms")]
    pub min_retransmit_interval_ms: u64,
    /// Adaptive retransmission ceiling in milliseconds.
    #[serde(default = "default_max_retransmit_ms")]
    pub max_retransmit_interval_ms: u64,
    /// Maximum retransmissions before aborting the transfer.
    #[serde(default = "default_max_retries")]
    pub max_retries: u8,
}

/// Per-boot-phase DSCP mapping and ECN enablement.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DscpConfig {
    /// Phase-name to six-bit DSCP value mapping; values must not exceed 63.
    #[serde(default)]
    pub phase_dscp: HashMap<String, u8>,

    /// Set ECT(0) on outgoing packets and recognize CE on incoming traffic.
    #[serde(default)]
    pub ecn_enabled: bool,
}

/// Durable transfer-delivery logging and independent release-manifest verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Record completed and failed transfer events when true.
    #[serde(default)]
    pub enabled: bool,

    /// Maximum bytes reserved by terminal records awaiting a durable JSONL
    /// group commit. Admission fails closed when this budget is exhausted.
    #[serde(default = "default_audit_queue_max_bytes")]
    pub queue_max_bytes: u64,

    /// Optional approximate log-segment rotation threshold in bytes.
    #[serde(default)]
    pub rotate_max_bytes: Option<u64>,

    /// Number of rotated segments retained; zero keeps every segment.
    #[serde(default)]
    pub rotate_keep_segments: usize,

    /// JSON-lines audit log path; absence selects runtime defaults.
    #[serde(default)]
    pub log_path: Option<PathBuf>,

    /// Path to a raw 32-byte Ed25519 private key used for release manifests.
    #[serde(default)]
    pub manifest_signing_key_path: Option<PathBuf>,

    /// Hex-encoded Ed25519 public key used to verify release manifests.
    #[serde(default)]
    pub manifest_verifying_key: Option<String>,

    /// Reject unsigned managed manifests when true.
    #[serde(default)]
    pub require_signed_manifests: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            queue_max_bytes: default_audit_queue_max_bytes(),
            rotate_max_bytes: None,
            rotate_keep_segments: 0,
            log_path: None,
            manifest_signing_key_path: None,
            manifest_verifying_key: None,
            require_signed_manifests: false,
        }
    }
}

/// Two large JSONL batches of worst-case validated records without unbounded memory.
fn default_audit_queue_max_bytes() -> u64 {
    256 * 1024 * 1024
}

/// Optional SQL-backed control-plane persistence settings.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistenceConfig {
    /// Enable metadata deletion with a database-enforced single serving node.
    /// Requires a stopped upgrade of every pre-coordination server.
    #[serde(default)]
    pub coordinated_deletion: bool,

    /// Enable durable control-plane state storage.
    /// Supports postgres:// and mysql:// URLs; mysql:// covers MariaDB/Percona.
    #[serde(default)]
    pub enabled: bool,

    /// Database URL, or env:VARNAME to read it from the environment.
    #[serde(default)]
    pub database_url: Option<String>,

    /// How often this node rehydrates DB-backed state from the shared store.
    #[serde(default = "default_persistence_sync_interval_secs")]
    pub sync_interval_secs: u64,

    /// Maximum age of ordinary SQL serving state; zero cannot disable the bound.
    #[serde(default = "default_persistence_max_snapshot_age_secs")]
    pub max_snapshot_age_secs: u64,
}

impl std::fmt::Debug for PersistenceConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PersistenceConfig")
            .field("coordinated_deletion", &self.coordinated_deletion)
            .field("enabled", &self.enabled)
            .field(
                "database_url",
                &self.database_url.as_ref().map(|_| "[REDACTED]"),
            )
            .field("sync_interval_secs", &self.sync_interval_secs)
            .field("max_snapshot_age_secs", &self.max_snapshot_age_secs)
            .finish()
    }
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            coordinated_deletion: false,
            database_url: None,
            sync_interval_secs: default_persistence_sync_interval_secs(),
            max_snapshot_age_secs: default_persistence_max_snapshot_age_secs(),
        }
    }
}

/// Returns the default durable-state synchronization interval in seconds.
fn default_persistence_sync_interval_secs() -> u64 {
    5
}

fn default_persistence_max_snapshot_age_secs() -> u64 {
    300
}

/// Concurrent durable reader registrations, including pending cleanups, that
/// one coordinated-deletion store admits.
pub(crate) const COORDINATED_DELETION_READER_LIMIT: usize = 4096;

impl TempestConfig {
    /// Coordinated deletion registers one durable reader per in-flight managed
    /// TFTP transfer or HTTP body; configured concurrency must fit that budget.
    pub(crate) fn validate_coordinated_reader_capacity(&self) -> crate::error::Result<()> {
        if !self.persistence.coordinated_deletion {
            return Ok(());
        }
        let demand = self
            .server
            .max_concurrent_transfers
            .saturating_add(self.api.max_connections);
        if demand > COORDINATED_DELETION_READER_LIMIT {
            return Err(crate::error::TempestError::Config(format!(
                "persistence.coordinated_deletion supports at most \
                 {COORDINATED_DELETION_READER_LIMIT} concurrent readers; \
                 server.max_concurrent_transfers + api.max_connections is {demand}"
            )));
        }
        Ok(())
    }
}

impl PersistenceConfig {
    pub(crate) fn validate_snapshot_age(&self) -> crate::error::Result<()> {
        if !(1..=86_400).contains(&self.max_snapshot_age_secs)
            || (!self.coordinated_deletion && self.sync_interval_secs >= self.max_snapshot_age_secs)
        {
            return Err(crate::error::TempestError::Config(
                "persistence.max_snapshot_age_secs must be 1-86400 and greater than persistence.sync_interval_secs".into(),
            ));
        }
        Ok(())
    }
}

impl TempestConfig {
    /// Rejects an unauthenticated control API unless the explicit loopback-only
    /// development escape hatch is enabled.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::TempestError::Config`] when external exposure is
    /// unauthenticated or uses a key shorter than the required minimum.
    pub fn validate_api_exposure(&self) -> crate::error::Result<()> {
        const MIN_API_KEY_LEN: usize = 16;
        if !(1..=100_000).contains(&self.api.max_connections)
            || self.api.write_timeout_secs > 3600
            || !(1..=3600).contains(&self.api.read_timeout_secs)
        {
            return Err(crate::error::TempestError::Config(
                "api.max_connections must be 1-100000, api.write_timeout_secs must be 0-3600, and api.read_timeout_secs must be 1-3600"
                    .into(),
            ));
        }

        if !crate::features::versioning::is_valid_logical_name(&self.api.native_http_boot_filename)
        {
            return Err(crate::error::TempestError::Config(
                "api.native_http_boot_filename must be a safe relative logical artifact name of at most 255 bytes"
                    .to_string(),
            ));
        }

        if self.api.bind.is_loopback() && self.api.allow_insecure_loopback {
            return Ok(());
        }

        match self.api.api_key.as_deref() {
            Some(key) if key.len() >= MIN_API_KEY_LEN => Ok(()),
            Some(_) => Err(crate::error::TempestError::Config(format!(
                "api.api_key must be at least {MIN_API_KEY_LEN} characters"
            ))),
            None => Err(crate::error::TempestError::Config(
                "api.api_key is required; set api.allow_insecure_loopback=true only for local development"
                    .to_string(),
            )),
        }
    }

    /// Loads, resolves environment-backed secrets, and validates a TOML file.
    ///
    /// Files larger than 1 MiB are rejected before allocation. Values prefixed
    /// with `env:` read the named environment variable. Missing or empty secret
    /// values fail configuration loading.
    ///
    /// # Errors
    ///
    /// Returns a configuration error for metadata/read/TOML failures, unsafe API
    /// exposure, missing persistence URLs, or invalid security key material.
    pub fn load(path: &std::path::Path) -> crate::error::Result<Self> {
        const MAX_CONFIG_SIZE: u64 = 1024 * 1024; // 1 MB
        let content = String::from_utf8(read_secure_file(
            path,
            "configuration file",
            MAX_CONFIG_SIZE,
            false,
        )?)
        .map_err(|error| {
            crate::error::TempestError::Config(format!("Configuration is not UTF-8: {error}"))
        })?;
        let mut config: Self = toml::from_str(&content).map_err(|e| {
            crate::error::TempestError::Config(format!("Failed to parse config: {e}"))
        })?;

        config.api.api_key = resolve_secret("api.api_key", config.api.api_key.take())?;
        config.validate_api_exposure()?;

        config.persistence.database_url = resolve_secret(
            "persistence.database_url",
            config.persistence.database_url.take(),
        )?;
        if config.persistence.enabled && config.persistence.database_url.is_none() {
            return Err(crate::error::TempestError::Config(
                "persistence.enabled requires persistence.database_url".to_string(),
            ));
        }
        if config.persistence.coordinated_deletion && !config.persistence.enabled {
            return Err(crate::error::TempestError::Config(
                "persistence.coordinated_deletion requires persistence.enabled".into(),
            ));
        }
        if config.audit.enabled && config.audit.log_path.is_none() {
            return Err(crate::error::TempestError::Config(
                "audit.enabled requires audit.log_path".to_string(),
            ));
        }
        #[cfg(not(feature = "sql-persistence"))]
        if config.persistence.enabled {
            return Err(crate::error::TempestError::Config(
                "persistence is not available in this build; rebuild with --features sql-persistence"
                    .into(),
            ));
        }
        if config.persistence.sync_interval_secs == 0 {
            config.persistence.sync_interval_secs = 1;
        }
        config.persistence.validate_snapshot_age()?;
        const MIN_AUDIT_QUEUE_BYTES: u64 = 1024 * 1024;
        const MAX_AUDIT_QUEUE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
        config.audit.queue_max_bytes = config
            .audit
            .queue_max_bytes
            .clamp(MIN_AUDIT_QUEUE_BYTES, MAX_AUDIT_QUEUE_BYTES);
        if config.audit.rotate_max_bytes == Some(0) {
            config.audit.rotate_max_bytes = None;
        }
        if let Some(max_bytes) = config.audit.rotate_max_bytes.as_mut() {
            const MIN_AUDIT_ROTATE_BYTES: u64 = 1024;
            const MAX_AUDIT_ROTATE_BYTES: u64 = 1024 * 1024 * 1024 * 1024;
            *max_bytes = (*max_bytes).clamp(MIN_AUDIT_ROTATE_BYTES, MAX_AUDIT_ROTATE_BYTES);
        }
        const MAX_AUDIT_ROTATE_SEGMENTS: usize = 10_000;
        if config.audit.rotate_keep_segments > MAX_AUDIT_ROTATE_SEGMENTS {
            config.audit.rotate_keep_segments = MAX_AUDIT_ROTATE_SEGMENTS;
        }
        if let Some((phase, value)) = config
            .dscp
            .phase_dscp
            .iter()
            .find(|(_, value)| **value > 63)
        {
            return Err(crate::error::TempestError::Config(format!(
                "dscp.phase_dscp.{phase} must be in 0..=63, got {value}"
            )));
        }

        // Ensure at least one concurrent transfer is allowed.
        if config.server.max_concurrent_transfers == 0 {
            config.server.max_concurrent_transfers = 1;
        }
        // Keep one configuration from reserving an impractical task population.
        const MAX_ALLOWED_TRANSFERS: usize = 10_000;
        if config.server.max_concurrent_transfers > MAX_ALLOWED_TRANSFERS {
            config.server.max_concurrent_transfers = MAX_ALLOWED_TRANSFERS;
        }
        config.validate_coordinated_reader_capacity()?;

        const MAX_TFTP_REQUESTS_PER_IP_PER_SECOND: u32 = 1_000_000;
        if config.server.tftp_requests_per_ip_per_second > MAX_TFTP_REQUESTS_PER_IP_PER_SECOND {
            return Err(crate::error::TempestError::Config(format!(
                "server.tftp_requests_per_ip_per_second must be in 0..={MAX_TFTP_REQUESTS_PER_IP_PER_SECOND}"
            )));
        }
        const MAX_HTTP_REQUESTS_PER_IP_PER_SECOND: u32 = 1_000_000;
        if config.server.http_requests_per_ip_per_second > MAX_HTTP_REQUESTS_PER_IP_PER_SECOND {
            return Err(crate::error::TempestError::Config(format!(
                "server.http_requests_per_ip_per_second must be in 0..={MAX_HTTP_REQUESTS_PER_IP_PER_SECOND}"
            )));
        }

        config.server.max_boot_sessions = config
            .server
            .max_boot_sessions
            .clamp(1, MAX_ALLOWED_BOOT_SESSIONS);

        // Cap the number of boot phases to prevent memory exhaustion.
        const MAX_BOOT_PHASES: usize = 50;
        if config.boot_phases.len() > MAX_BOOT_PHASES {
            config.boot_phases.truncate(MAX_BOOT_PHASES);
        }
        if let Some(phase) = config
            .boot_phases
            .iter()
            .find(|phase| Regex::new(&phase.pattern).is_err())
        {
            return Err(crate::error::TempestError::Config(format!(
                "Invalid boot phase regex for {}: {}",
                phase.name, phase.pattern
            )));
        }

        // Ensure every negotiated DATA payload can hold RFC framing.
        for phase in &mut config.boot_phases {
            if phase.block_size < 8 {
                phase.block_size = 512; // Reset to safe default
            }
        }
        validate_tftp_performance_config(&config)?;

        // WRQ is externally driven, so its configured ceiling also has a hard cap.
        const MAX_WRITE_LIMIT: u64 = 4 * 1024 * 1024 * 1024; // 4GB
        if config.server.max_write_file_size > MAX_WRITE_LIMIT {
            config.server.max_write_file_size = MAX_WRITE_LIMIT;
        }

        if config.server.bandwidth_governor_enabled
            && config.server.total_bandwidth_bytes_per_second() == Some(0)
        {
            return Err(crate::error::TempestError::Config(
                "total_bandwidth_bytes_per_second must be > 0 when bandwidth governor is enabled"
                    .into(),
            ));
        }

        // Request bodies are buffered only inside this absolute ceiling.
        const MAX_REQUEST_BODY_LIMIT: usize = 10 * 1024 * 1024; // 10MB
        if config.api.max_request_body_bytes > MAX_REQUEST_BODY_LIMIT {
            config.api.max_request_body_bytes = MAX_REQUEST_BODY_LIMIT;
        }

        Ok(config)
    }
}

impl Default for TempestConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            api: ApiConfig::default(),
            boot_phases: default_boot_phases(),
            dscp: DscpConfig::default(),
            audit: AuditConfig::default(),
            persistence: PersistenceConfig::default(),
            extensions: toml::Table::new(),
        }
    }
}

fn resolve_secret(field: &str, value: Option<String>) -> crate::error::Result<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if let Some(variable) = value.strip_prefix("env:") {
        if variable.is_empty() {
            return Err(crate::error::TempestError::Config(format!(
                "{field} contains an empty environment variable name"
            )));
        }
        let resolved = std::env::var(variable).map_err(|_| {
            crate::error::TempestError::Config(format!(
                "{field} requires missing environment variable {variable}"
            ))
        })?;
        if resolved.is_empty() {
            return Err(crate::error::TempestError::Config(format!(
                "{field} resolved environment variable {variable} to an empty value"
            )));
        }
        return Ok(Some(resolved));
    }
    if value.is_empty() {
        return Err(crate::error::TempestError::Config(format!(
            "{field} must not be empty"
        )));
    }
    Ok(Some(value))
}

/// Returns the built-in artifact classification and transfer profiles.
fn default_boot_phases() -> Vec<BootPhaseConfig> {
    vec![
        BootPhaseConfig {
            name: "PXE_ROM".into(),
            pattern: r"(?i)(pxelinux\.0|undionly\.kpxe|ipxe\.\w+)$".into(),
            block_size: 512,
            max_window_size: 1,
            retransmit_interval_ms: 200,
            min_retransmit_interval_ms: 100,
            max_retransmit_interval_ms: 1_000,
            max_retries: 10,
        },
        BootPhaseConfig {
            name: "IPXE".into(),
            pattern: r"(?i)\.ipxe$".into(),
            block_size: 1468,
            max_window_size: 4,
            retransmit_interval_ms: 300,
            min_retransmit_interval_ms: 100,
            max_retransmit_interval_ms: 1_500,
            max_retries: 5,
        },
        BootPhaseConfig {
            name: "KERNEL".into(),
            pattern: r"(?i)(vmlinuz|bzImage|kernel)".into(),
            block_size: 8192,
            max_window_size: 32,
            retransmit_interval_ms: 1000,
            min_retransmit_interval_ms: 250,
            max_retransmit_interval_ms: 4_000,
            max_retries: 5,
        },
        BootPhaseConfig {
            name: "INITRD".into(),
            pattern: r"(?i)(initrd|initramfs)".into(),
            block_size: 8192,
            max_window_size: 32,
            retransmit_interval_ms: 1000,
            min_retransmit_interval_ms: 250,
            max_retransmit_interval_ms: 4_000,
            max_retries: 5,
        },
        BootPhaseConfig {
            name: "OS_IMAGE".into(),
            pattern: r"(?i)\.(img|iso|squashfs)$".into(),
            block_size: 65464,
            max_window_size: 64,
            retransmit_interval_ms: 1_000,
            min_retransmit_interval_ms: 250,
            max_retransmit_interval_ms: 4_000,
            max_retries: 3,
        },
        BootPhaseConfig {
            name: "CONFIG".into(),
            pattern: r"(?i)(pxelinux\.cfg/|grub\.cfg|boot\.conf)".into(),
            block_size: 512,
            max_window_size: 1,
            retransmit_interval_ms: 200,
            min_retransmit_interval_ms: 100,
            max_retransmit_interval_ms: 1_000,
            max_retries: 10,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn coordinated_deletion_requires_concurrency_within_reader_budget() {
        let mut config = TempestConfig::default();
        config.server.max_concurrent_transfers = 10_000;
        assert!(config.validate_coordinated_reader_capacity().is_ok());
        config.persistence.coordinated_deletion = true;
        let error = config
            .validate_coordinated_reader_capacity()
            .unwrap_err()
            .to_string();
        assert!(error.contains("11024"), "{error}");
        config.server.max_concurrent_transfers =
            COORDINATED_DELETION_READER_LIMIT - config.api.max_connections;
        assert!(config.validate_coordinated_reader_capacity().is_ok());
        config.server.max_concurrent_transfers += 1;
        assert!(config.validate_coordinated_reader_capacity().is_err());
        let Err(error) = crate::server::TftpServer::builder(config).build() else {
            panic!("the builder must enforce the deletion reader budget");
        };
        assert!(error.to_string().contains("concurrent readers"), "{error}");
    }

    #[test]
    fn persistence_snapshot_age_has_a_finite_validated_default() {
        let mut config = PersistenceConfig::default();
        assert_eq!(config.max_snapshot_age_secs, 300);
        assert!(config.validate_snapshot_age().is_ok());
        for age in [0, 5, 86_401, u64::MAX] {
            config.max_snapshot_age_secs = age;
            assert!(config.validate_snapshot_age().is_err());
        }
        for age in [6, 300, 86_400] {
            config.max_snapshot_age_secs = age;
            assert!(config.validate_snapshot_age().is_ok());
        }
        let parsed: TempestConfig = toml::from_str("").unwrap();
        assert_eq!(parsed.persistence.max_snapshot_age_secs, 300);
        config.max_snapshot_age_secs = 0;
        let server_config = TempestConfig {
            persistence: config,
            ..Default::default()
        };
        assert!(
            crate::server::TftpServer::builder(server_config)
                .build()
                .is_err()
        );
    }

    #[test]
    fn udp_segmentation_offload_defaults_to_disabled() {
        assert!(!ServerConfig::default().udp_segmentation_offload);
        assert!(!TempestConfig::default().server.udp_segmentation_offload);
        for source in ["", "[server]\n", "[server]\nmax_window_size = 8\n"] {
            let config: TempestConfig = toml::from_str(source).unwrap();
            assert!(!config.server.udp_segmentation_offload);
            assert!(validate_tftp_performance_config(&config).is_ok());
        }
    }

    #[test]
    fn udp_segmentation_offload_round_trip_load_and_validate() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("tempest.toml");
        for enabled in [false, true] {
            let source = format!(
                "[server]\nudp_segmentation_offload = {enabled}\n\
                 [api]\nallow_insecure_loopback = true\n"
            );
            let config: TempestConfig = toml::from_str(&source).unwrap();
            assert!(validate_tftp_performance_config(&config).is_ok());
            let serialized = toml::to_string(&config).unwrap();
            assert!(serialized.contains(&format!("udp_segmentation_offload = {enabled}")));
            std::fs::write(&config_path, &serialized).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
            let restored: TempestConfig = toml::from_str(&serialized).unwrap();
            let loaded = TempestConfig::load(&config_path).unwrap();
            for config in [restored, loaded] {
                assert_eq!(config.server.udp_segmentation_offload, enabled);
                assert!(crate::server::TftpServer::builder(config).build().is_ok());
            }
        }
        for value in ["0", "1", "\"true\"", "\"false\""] {
            let source = format!("[server]\nudp_segmentation_offload = {value}\n");
            assert!(toml::from_str::<TempestConfig>(&source).is_err());
        }
    }

    #[test]
    fn tftp_client_policy_omitted_fields_retain_defaults() {
        let defaults = ServerConfig::default();
        assert_eq!(defaults.max_tftp_transfers_per_ip, 16);
        assert_eq!(defaults.max_client_timeout_secs, 255);
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("tempest.toml");
        for source in [
            "",
            "[server]\n",
            "[server]\naccept_client_timeout = false\n",
        ] {
            let config: TempestConfig = toml::from_str(source).unwrap();
            assert_eq!(config.server.max_tftp_transfers_per_ip, 16);
            assert_eq!(config.server.max_client_timeout_secs, 255);
            std::fs::write(
                &config_path,
                format!("{source}\n[api]\nallow_insecure_loopback = true\n"),
            )
            .unwrap();
            let loaded = TempestConfig::load(&config_path).unwrap();
            assert_eq!(loaded.server.max_tftp_transfers_per_ip, 16);
            assert_eq!(loaded.server.max_client_timeout_secs, 255);
            assert!(crate::server::TftpServer::builder(loaded).build().is_ok());
        }
    }

    #[test]
    fn tftp_client_policy_boundaries_round_trip_load_and_build() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("tempest.toml");
        for per_ip in [1, 16, 10_000] {
            for ceiling in [1, 5, 255] {
                for accept in [false, true] {
                    let source = format!(
                        "[server]\nmax_tftp_transfers_per_ip = {per_ip}\n\
                         max_client_timeout_secs = {ceiling}\naccept_client_timeout = {accept}\n\
                         [api]\nallow_insecure_loopback = true\n"
                    );
                    let config: TempestConfig = toml::from_str(&source).unwrap();
                    let serialized = toml::to_string(&config).unwrap();
                    assert!(serialized.contains(&format!("max_tftp_transfers_per_ip = {per_ip}")));
                    assert!(serialized.contains(&format!("max_client_timeout_secs = {ceiling}")));
                    std::fs::write(&config_path, &serialized).unwrap();
                    let restored: TempestConfig = toml::from_str(&serialized).unwrap();
                    let loaded = TempestConfig::load(&config_path).unwrap();
                    for config in [restored, loaded] {
                        assert_eq!(config.server.max_tftp_transfers_per_ip, per_ip);
                        assert_eq!(config.server.max_client_timeout_secs, ceiling);
                        assert_eq!(config.server.accept_client_timeout, accept);
                        assert!(crate::server::TftpServer::builder(config).build().is_ok());
                    }
                }
            }
        }
    }

    #[test]
    fn tftp_client_policy_invalid_values_rejected_by_load() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("tempest.toml");
        for (field, invalid) in [
            ("max_tftp_transfers_per_ip", "10001"),
            ("max_client_timeout_secs", "256"),
        ] {
            for value in [
                "0",
                invalid,
                "-1",
                "18446744073709551616",
                "1.5",
                "\"1\"",
                "true",
                "[]",
                "{}",
            ] {
                // Disabling negotiation must not bypass validation of its ceiling.
                for accept in [false, true] {
                    std::fs::write(
                        &config_path,
                        format!(
                            "[server]\n{field} = {value}\naccept_client_timeout = {accept}\n\
                             [api]\nallow_insecure_loopback = true\n"
                        ),
                    )
                    .unwrap();
                    let error = TempestConfig::load(&config_path).unwrap_err().to_string();
                    assert!(error.contains(field), "{field}={value}: {error}");
                }
            }
        }
    }

    #[test]
    fn tftp_client_policy_invalid_programmatic_values_rejected_by_builder() {
        for per_ip in [0, 10_001, usize::MAX] {
            let mut config = TempestConfig::default();
            config.server.max_tftp_transfers_per_ip = per_ip;
            let error = crate::server::TftpServer::builder(config)
                .build()
                .err()
                .expect("invalid per-IP transfer limit must fail");
            assert!(
                error
                    .to_string()
                    .contains("server.max_tftp_transfers_per_ip")
            );
        }
        // Values above 255 and negative values cannot be represented by u8.
        for accept in [false, true] {
            let mut config = TempestConfig::default();
            config.server.max_client_timeout_secs = 0;
            config.server.accept_client_timeout = accept;
            let error = crate::server::TftpServer::builder(config)
                .build()
                .err()
                .expect("invalid timeout ceiling must fail even when disabled");
            assert!(error.to_string().contains("server.max_client_timeout_secs"));
        }
    }

    #[test]
    fn tftp_client_policy_limits_are_independent_and_extended_lifetime_supported() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("tempest.toml");
        for (global, per_ip) in [(1, 16), (1, 10_000), (500, 16), (16, 16)] {
            std::fs::write(
                &config_path,
                format!(
                    "[server]\nmax_concurrent_transfers = {global}\n\
                     max_tftp_transfers_per_ip = {per_ip}\nmax_client_timeout_secs = 255\n\
                     max_transfer_duration_secs = 1800\n\
                     [api]\nallow_insecure_loopback = true\n"
                ),
            )
            .unwrap();
            let config = TempestConfig::load(&config_path).unwrap();
            assert_eq!(config.server.max_concurrent_transfers, global);
            assert_eq!(config.server.max_tftp_transfers_per_ip, per_ip);
            assert_eq!(config.server.max_client_timeout_secs, 255);
            assert_eq!(config.server.max_transfer_duration_secs, 1_800);
            assert!(crate::server::TftpServer::builder(config).build().is_ok());
        }
    }

    #[test]
    fn shipped_core_configs_match_the_public_schema() {
        let core = include_str!("../config/tempest.toml");
        let demo = include_str!("../demo/l2-flat/tempest-demo.toml");
        let ipv6_demo = include_str!("../demo/l2-flat/tempest-demo-ipv6.toml");

        toml::from_str::<TempestConfig>(core).expect("core example config must parse");
        toml::from_str::<TempestConfig>(demo).expect("demo config must parse");
        let ipv6 = toml::from_str::<TempestConfig>(ipv6_demo).expect("IPv6 demo config must parse");
        assert!(ipv6.server.bind.is_ipv6());
        assert!(ipv6.api.bind.is_ipv6());
    }

    #[test]
    fn shipped_salt_formula_renders_explicit_cache_and_timeout_policy() {
        let sources = [
            include_str!("../salt/tempest/map.jinja"),
            include_str!("../salt/tempest/files/tempest.toml.jinja"),
            include_str!("../salt/pillar/tempest.sls"),
        ];

        for source in sources {
            assert!(source.contains("unmanaged_cache_validation_interval_ms"));
            assert!(source.contains("hot_artifact_cache_max_bytes"));
            assert!(source.contains("hot_artifact_cache_max_file_bytes"));
            assert!(source.contains("http_requests_per_ip_per_second"));
            assert!(source.contains("artifact_cache_max_bytes"));
            assert!(source.contains("artifact_cache_max_file_bytes"));
            assert!(source.contains("accept_client_timeout"));
        }
    }

    #[test]
    fn test_default_config() {
        let config = TempestConfig::default();
        assert_eq!(config.server.port, 69);
        assert_eq!(config.server.listener_shards, 0);
        assert!((1..=64).contains(&config.server.effective_listener_shards()));
        assert_eq!(config.server.max_concurrent_transfers, 500);
        assert_eq!(config.server.tftp_requests_per_ip_per_second, 50);
        assert_eq!(config.server.http_requests_per_ip_per_second, 100);
        assert_eq!(config.server.max_boot_sessions, 100_000);
        assert!(!config.server.write_enabled); // writes disabled by default
        assert_eq!(config.server.max_write_file_size, 512 * 1024 * 1024); // 512MB
        assert!(config.api.api_key.is_none());
        assert_eq!(config.api.max_request_body_bytes, 1024 * 1024); // 1MB
        assert_eq!(config.audit.rotate_max_bytes, None);
        assert_eq!(config.audit.rotate_keep_segments, 0);
    }

    #[test]
    fn test_default_boot_phases() {
        let config = TempestConfig::default();
        assert!(!config.boot_phases.is_empty());
        let names: Vec<&str> = config.boot_phases.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"PXE_ROM"));
        assert!(names.contains(&"KERNEL"));
        assert!(names.contains(&"OS_IMAGE"));
    }

    #[test]
    fn test_server_config_defaults() {
        let server = ServerConfig::default();
        assert_eq!(server.default_block_size, 512);
        assert_eq!(server.max_window_size, 64);
        assert!(server.accept_client_timeout);
        assert_eq!(server.retransmit_interval_ms, 1_000);
        assert_eq!(server.min_retransmit_interval_ms, 250);
        assert_eq!(server.max_retransmit_interval_ms, 4_000);
        assert_eq!(server.listener_receive_buffer_bytes, 4 * 1024 * 1024);
        assert_eq!(server.transfer_socket_buffer_bytes, 0);
        assert_eq!(server.unmanaged_cache_validation_interval_ms, 0);
        assert_eq!(
            server.hot_artifact_cache_max_bytes,
            crate::artifact_cache::HOT_ARTIFACT_CACHE_MAX_BYTES as u64
        );
        assert_eq!(
            server.hot_artifact_cache_max_file_bytes,
            crate::artifact_cache::HOT_ARTIFACT_CACHE_MAX_FILE_BYTES as u64
        );
        assert_eq!(server.max_retries, 5);
        assert!(!server.json_logging);
    }

    #[test]
    fn bandwidth_byte_rate_accepts_legacy_key_and_serializes_canonical_key() {
        let legacy: TempestConfig =
            toml::from_str("[server]\ntotal_bandwidth_bps = 125000000\n").unwrap();
        assert_eq!(
            legacy.server.total_bandwidth_bytes_per_second(),
            Some(125_000_000)
        );

        let canonical: TempestConfig =
            toml::from_str("[server]\ntotal_bandwidth_bytes_per_second = 250000000\n").unwrap();
        assert_eq!(
            canonical.server.total_bandwidth_bytes_per_second(),
            Some(250_000_000)
        );
        let serialized = toml::to_string(&canonical).unwrap();
        assert!(serialized.contains("total_bandwidth_bytes_per_second = 250000000"));
        assert!(!serialized.contains("total_bandwidth_bps"));
    }

    #[test]
    fn client_timeout_acceptance_is_explicitly_configurable() {
        let config: TempestConfig =
            toml::from_str("[server]\naccept_client_timeout = false\n").unwrap();
        assert!(!config.server.accept_client_timeout);
    }

    #[test]
    fn max_transfer_duration_defaults_and_serde_round_trip() {
        assert_eq!(ServerConfig::default().max_transfer_duration_secs, 300);
        assert_eq!(
            TempestConfig::default().server.max_transfer_duration_secs,
            300
        );
        for source in [
            "",
            "[server]\n",
            "[server]\naccept_client_timeout = false\n",
        ] {
            let config: TempestConfig = toml::from_str(source).unwrap();
            assert_eq!(config.server.max_transfer_duration_secs, 300);
            assert!(validate_tftp_performance_config(&config).is_ok());
        }
        for seconds in [1, 300, 86_400] {
            let source = format!("[server]\nmax_transfer_duration_secs = {seconds}\n");
            let config: TempestConfig = toml::from_str(&source).unwrap();
            assert_eq!(config.server.max_transfer_duration_secs, seconds);
            assert!(validate_tftp_performance_config(&config).is_ok());
            let serialized = toml::to_string(&config).unwrap();
            let restored: TempestConfig = toml::from_str(&serialized).unwrap();
            assert_eq!(restored.server.max_transfer_duration_secs, seconds);
        }
    }

    #[test]
    fn max_transfer_duration_validation_rejects_zero_and_overflow() {
        let mut config = TempestConfig::default();
        for seconds in [0, 86_401, u64::MAX] {
            config.server.max_transfer_duration_secs = seconds;
            let error = validate_tftp_performance_config(&config).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("server.max_transfer_duration_secs")
            );
        }
        for value in ["-1", "18446744073709551616", "1.5", "\"300\""] {
            let source = format!("[server]\nmax_transfer_duration_secs = {value}\n");
            assert!(toml::from_str::<TempestConfig>(&source).is_err());
        }
    }

    #[test]
    fn max_transfer_duration_file_loading_validates_boundaries() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("tempest.toml");
        for seconds in [0, 1, 300, 86_400, 86_401, i64::MAX as u64] {
            std::fs::write(
                &config_path,
                format!(
                    "[server]\nmax_transfer_duration_secs = {seconds}\n\
                     [api]\nallow_insecure_loopback = true\n"
                ),
            )
            .unwrap();
            let result = TempestConfig::load(&config_path);
            if (1..=86_400).contains(&seconds) {
                assert_eq!(result.unwrap().server.max_transfer_duration_secs, seconds);
            } else {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("server.max_transfer_duration_secs")
                );
            }
        }
    }

    #[test]
    fn max_transfer_duration_builder_rejects_invalid_programmatic_values() {
        for seconds in [0, 86_401, u64::MAX] {
            let mut config = TempestConfig::default();
            config.server.max_transfer_duration_secs = seconds;
            let error = crate::server::TftpServer::builder(config)
                .build()
                .err()
                .expect("builder must reject an invalid transfer deadline");
            assert!(
                error
                    .to_string()
                    .contains("server.max_transfer_duration_secs")
            );
        }
    }

    #[test]
    fn test_core_server_rejects_extracted_admission_settings() {
        let result = toml::from_str::<TempestConfig>(
            "[server]\nadmission_queue_enabled = true\nmax_pending_queue_depth = 4000\n",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_dscp_defaults() {
        let dscp = DscpConfig::default();
        assert!(dscp.phase_dscp.is_empty());
        assert!(!dscp.ecn_enabled);
    }

    #[test]
    fn test_api_config_defaults() {
        let api = ApiConfig::default();
        assert_eq!(api.port, 8080);
        assert!(api.bind.is_loopback());
        assert!(api.enable_metrics);
        assert!(api.metrics_require_api_key);
        assert!(!api.enable_native_http_boot);
        assert_eq!(api.native_http_boot_filename, "boot.efi");
        assert!(api.api_key.is_none());
        assert_eq!(api.max_request_body_bytes, 1024 * 1024);
        assert_eq!(api.max_connections, 1024);
        assert_eq!(api.write_timeout_secs, 120);
        assert_eq!(api.read_timeout_secs, 30);
        assert_eq!(api.artifact_cache_max_bytes, 64 * 1024 * 1024);
        assert_eq!(api.artifact_cache_max_file_bytes, 16 * 1024 * 1024);
    }

    #[test]
    fn http_connection_limits_apply_even_on_insecure_loopback() {
        let mut config = TempestConfig::default();
        config.api.allow_insecure_loopback = true;
        for limit in [0, 100_001, usize::MAX] {
            config.api.max_connections = limit;
            assert!(config.validate_api_exposure().is_err());
        }
        config.api.max_connections = 1;
        for timeout in [0, 120, 3600] {
            config.api.write_timeout_secs = timeout;
            assert!(config.validate_api_exposure().is_ok());
        }
        config.api.write_timeout_secs = 3601;
        assert!(config.validate_api_exposure().is_err());
        config.api.write_timeout_secs = 120;
        for timeout in [0, 3601, u64::MAX] {
            config.api.read_timeout_secs = timeout;
            assert!(config.validate_api_exposure().is_err());
        }
        for timeout in [1, 30, 3600] {
            config.api.read_timeout_secs = timeout;
            assert!(config.validate_api_exposure().is_ok());
        }
    }

    #[test]
    fn test_dscp_config_all_values_valid() {
        let dscp = DscpConfig::default();
        for &v in dscp.phase_dscp.values() {
            assert!(v <= 63, "Default DSCP value {v} exceeds valid range 0-63");
        }
    }

    #[test]
    fn test_config_rejects_invalid_phase_regex() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid.toml");
        std::fs::write(&path, "[[boot_phases]]\nname='bad'\npattern='['\n").unwrap();
        assert!(TempestConfig::load(&path).is_err());
    }

    #[test]
    fn test_api_config_debug_redacts_key() {
        let api = ApiConfig {
            api_key: Some("super-secret-key-12345".into()),
            ..Default::default()
        };
        let debug_str = format!("{api:?}");
        assert!(!debug_str.contains("super-secret-key-12345"));
        assert!(debug_str.contains("REDACTED"));
    }

    #[test]
    fn native_http_boot_config_accepts_only_safe_logical_names() {
        let dir = tempfile::tempdir().unwrap();
        let valid = dir.path().join("valid-native-http.toml");
        std::fs::write(
            &valid,
            "[api]\nallow_insecure_loopback = true\nenable_native_http_boot = true\nnative_http_boot_filename = 'efi/boot.efi'\n",
        )
        .unwrap();
        let loaded = TempestConfig::load(&valid).unwrap();
        assert!(loaded.api.enable_native_http_boot);
        assert_eq!(loaded.api.native_http_boot_filename, "efi/boot.efi");

        let invalid = dir.path().join("invalid-native-http.toml");
        std::fs::write(
            &invalid,
            "[api]\nallow_insecure_loopback = true\nnative_http_boot_filename = '../boot.efi'\n",
        )
        .unwrap();
        let error = TempestConfig::load(&invalid).unwrap_err().to_string();
        assert!(error.contains("native_http_boot_filename"));
    }

    #[test]
    fn test_tempest_config_debug_redacts_key() {
        let mut config = TempestConfig::default();
        config.api.api_key = Some("my-api-key".into());
        let debug_str = format!("{config:?}");
        assert!(!debug_str.contains("my-api-key"));
    }

    #[test]
    fn test_empty_api_key_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("empty-api-key.toml");
        std::fs::write(&path, "[api]\napi_key = \"\"\n").unwrap();
        let error = TempestConfig::load(&path).unwrap_err().to_string();
        assert!(error.contains("api.api_key must not be empty"));
    }

    #[test]
    fn test_config_load_rejects_oversized_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("oversized.toml");
        std::fs::write(&path, vec![b'x'; 1024 * 1024 + 1]).unwrap();
        assert!(TempestConfig::load(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn config_load_rejects_symlinks_and_writable_modes() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("tempest.toml");
        std::fs::write(&config_path, "[api]\nallow_insecure_loopback = true\n").unwrap();

        let symlink_path = directory.path().join("linked.toml");
        symlink(&config_path, &symlink_path).unwrap();
        assert!(TempestConfig::load(&symlink_path).is_err());

        std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(TempestConfig::load(&config_path).is_err());
    }

    #[test]
    fn test_config_max_transfers_zero_clamped() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("zero-transfers.toml");
        std::fs::write(
            &path,
            "[server]\nmax_concurrent_transfers = 0\n[api]\nallow_insecure_loopback = true\n",
        )
        .unwrap();
        let config = TempestConfig::load(&path).unwrap();
        assert_eq!(config.server.max_concurrent_transfers, 1);
    }

    #[test]
    fn test_config_boot_phase_block_size_validated() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("small-block.toml");
        std::fs::write(
            &path,
            "[api]\nallow_insecure_loopback = true\n\
             [[boot_phases]]\nname = \"test\"\npattern = \"test.*\"\nblock_size = 4\n",
        )
        .unwrap();
        let config = TempestConfig::load(&path).unwrap();
        assert_eq!(config.boot_phases[0].block_size, 512);
    }

    #[test]
    fn test_config_boot_phases_capped() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("many-phases.toml");
        let mut contents = "[api]\nallow_insecure_loopback = true\n".to_string();
        for index in 0..60 {
            contents.push_str(&format!(
                "[[boot_phases]]\nname = \"phase-{index}\"\npattern = \"phase-{index}\"\n"
            ));
        }
        std::fs::write(&path, contents).unwrap();
        let config = TempestConfig::load(&path).unwrap();
        assert_eq!(config.boot_phases.len(), 50);
    }

    #[test]
    fn test_config_rejects_exposed_api_without_key() {
        let temp_root = tempfile::tempdir().unwrap();
        let dir = temp_root.path().to_path_buf();
        let config_path = dir.join("test.toml");
        std::fs::write(
            &config_path,
            r#"
            [api]
            bind = "0.0.0.0"
        "#,
        )
        .unwrap();

        let error = TempestConfig::load(&config_path).unwrap_err().to_string();
        assert!(error.contains("api.api_key is required"));
    }

    #[test]
    fn test_audit_rotation_config_sanitized() {
        let temp_root = tempfile::tempdir().unwrap();
        let dir = temp_root.path().to_path_buf();
        let config_path = dir.join("test.toml");
        std::fs::write(
            &config_path,
            r#"
            [audit]
            queue_max_bytes = 1024
            rotate_max_bytes = 10
            rotate_keep_segments = 20000

            [api]
            allow_insecure_loopback = true
        "#,
        )
        .unwrap();

        let config = TempestConfig::load(&config_path).unwrap();
        assert_eq!(config.audit.queue_max_bytes, 1024 * 1024);
        assert_eq!(config.audit.rotate_max_bytes, Some(1024));
        assert_eq!(config.audit.rotate_keep_segments, 10000);
    }

    #[test]
    fn test_audit_config_rejects_obsolete_spool_capacity() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("obsolete-audit-spool.toml");
        std::fs::write(
            &config_path,
            r#"
            [audit]
            spool_max_bytes = 268435456

            [api]
            allow_insecure_loopback = true
        "#,
        )
        .unwrap();

        let error = TempestConfig::load(&config_path).unwrap_err().to_string();
        assert!(error.contains("spool_max_bytes"));
    }

    #[test]
    fn test_config_rejects_exposed_api_with_weak_key() {
        let temp_root = tempfile::tempdir().unwrap();
        let dir = temp_root.path().to_path_buf();
        let config_path = dir.join("test.toml");
        std::fs::write(
            &config_path,
            r#"
            [api]
            bind = "0.0.0.0"
            api_key = "short"
        "#,
        )
        .unwrap();

        let error = TempestConfig::load(&config_path).unwrap_err().to_string();
        assert!(error.contains("at least 16 characters"));
    }

    #[test]
    fn test_config_allows_exposed_api_with_strong_key() {
        let temp_root = tempfile::tempdir().unwrap();
        let dir = temp_root.path().to_path_buf();
        let config_path = dir.join("test.toml");
        std::fs::write(
            &config_path,
            r#"
            [api]
            bind = "0.0.0.0"
            api_key = "strong-api-key-123456"
        "#,
        )
        .unwrap();

        let config = TempestConfig::load(&config_path).unwrap();
        assert_eq!(config.api.api_key.as_deref(), Some("strong-api-key-123456"));
    }

    #[test]
    fn test_config_phase_window_size_validated() {
        let temp_root = tempfile::tempdir().unwrap();
        let dir = temp_root.path().to_path_buf();
        let config_path = dir.join("test.toml");
        std::fs::write(
            &config_path,
            r#"
            [[boot_phases]]
            name = "TEST"
            pattern = "test"
            block_size = 512
            max_window_size = 0
            retransmit_interval_ms = 100
            min_retransmit_interval_ms = 50
            max_retransmit_interval_ms = 1000
            max_retries = 3

            [api]
            allow_insecure_loopback = true
        "#,
        )
        .unwrap();
        let error = TempestConfig::load(&config_path).unwrap_err();
        assert!(error.to_string().contains("max_window_size"));
    }

    #[test]
    fn legacy_window_ceiling_names_are_rejected() {
        assert!(toml::from_str::<TempestConfig>("[server]\ndefault_window_size = 8\n").is_err());
        assert!(
            toml::from_str::<TempestConfig>(
                "[[boot_phases]]\nname = \"TEST\"\npattern = \"test\"\nwindow_size = 8\n"
            )
            .is_err()
        );
        assert!(toml::from_str::<TempestConfig>("[server]\ndefault_timeout_secs = 5\n").is_err());
        assert!(
            toml::from_str::<TempestConfig>(
                "[[boot_phases]]\nname = \"TEST\"\npattern = \"test\"\ntimeout_secs = 5\n"
            )
            .is_err()
        );
    }

    #[test]
    fn retransmission_policy_order_is_validated() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("test.toml");
        std::fs::write(
            &config_path,
            r#"
            [server]
            retransmit_interval_ms = 250
            min_retransmit_interval_ms = 500
            max_retransmit_interval_ms = 4000

            [api]
            allow_insecure_loopback = true
            "#,
        )
        .unwrap();

        let error = match TempestConfig::load(&config_path) {
            Ok(_) => panic!("reversed retransmission bounds must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("retransmission policy"));
    }

    #[test]
    fn socket_buffer_limits_are_validated() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("test.toml");
        std::fs::write(
            &config_path,
            r#"
            [server]
            transfer_socket_buffer_bytes = 1

            [api]
            allow_insecure_loopback = true
            "#,
        )
        .unwrap();

        let error = match TempestConfig::load(&config_path) {
            Ok(_) => panic!("unboundedly small socket buffer must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("transfer_socket_buffer_bytes"));
    }

    #[test]
    fn test_config_max_concurrent_transfers_capped() {
        let temp_root = tempfile::tempdir().unwrap();
        let dir = temp_root.path().to_path_buf();
        let config_path = dir.join("test.toml");
        std::fs::write(
            &config_path,
            r#"
            [server]
            max_concurrent_transfers = 999999

            [api]
            allow_insecure_loopback = true
        "#,
        )
        .unwrap();
        let config = TempestConfig::load(&config_path).unwrap();
        assert!(config.server.max_concurrent_transfers <= 10_000);
    }

    #[test]
    fn tftp_per_ip_request_limit_is_configurable_and_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("tempest.toml");

        std::fs::write(
            &config_path,
            "[server]\ntftp_requests_per_ip_per_second = 5000\n\
             [api]\nallow_insecure_loopback = true\n",
        )
        .unwrap();
        let config = TempestConfig::load(&config_path).unwrap();
        assert_eq!(config.server.tftp_requests_per_ip_per_second, 5_000);

        std::fs::write(
            &config_path,
            "[server]\ntftp_requests_per_ip_per_second = 0\n\
             [api]\nallow_insecure_loopback = true\n",
        )
        .unwrap();
        let config = TempestConfig::load(&config_path).unwrap();
        assert_eq!(config.server.tftp_requests_per_ip_per_second, 0);

        std::fs::write(
            &config_path,
            "[server]\ntftp_requests_per_ip_per_second = 1000001\n\
             [api]\nallow_insecure_loopback = true\n",
        )
        .unwrap();
        let error = TempestConfig::load(&config_path).unwrap_err().to_string();
        assert!(error.contains("tftp_requests_per_ip_per_second"));
    }

    #[test]
    fn http_per_ip_request_limit_is_configurable_and_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let config_path = directory.path().join("tempest.toml");

        std::fs::write(
            &config_path,
            "[server]\nhttp_requests_per_ip_per_second = 5000\n\
             [api]\nallow_insecure_loopback = true\n",
        )
        .unwrap();
        let config = TempestConfig::load(&config_path).unwrap();
        assert_eq!(config.server.http_requests_per_ip_per_second, 5_000);

        std::fs::write(
            &config_path,
            "[server]\nhttp_requests_per_ip_per_second = 0\n\
             [api]\nallow_insecure_loopback = true\n",
        )
        .unwrap();
        let config = TempestConfig::load(&config_path).unwrap();
        assert_eq!(config.server.http_requests_per_ip_per_second, 0);

        std::fs::write(
            &config_path,
            "[server]\nhttp_requests_per_ip_per_second = 1000001\n\
             [api]\nallow_insecure_loopback = true\n",
        )
        .unwrap();
        let error = TempestConfig::load(&config_path).unwrap_err().to_string();
        assert!(error.contains("http_requests_per_ip_per_second"));
    }

    #[test]
    fn listener_shards_are_bounded_and_platform_safe() {
        let mut config = TempestConfig::default();
        config.server.listener_shards = 0;
        assert!(validate_tftp_performance_config(&config).is_ok());
        assert!((1..=64).contains(&config.server.effective_listener_shards()));
        config.server.listener_shards = 65;
        assert!(validate_tftp_performance_config(&config).is_err());

        config.server.listener_shards = 2;
        #[cfg(target_os = "linux")]
        assert!(validate_tftp_performance_config(&config).is_ok());
        #[cfg(not(target_os = "linux"))]
        assert!(validate_tftp_performance_config(&config).is_err());
    }

    #[test]
    fn unmanaged_cache_validation_interval_is_bounded() {
        let mut config = TempestConfig::default();
        config.server.unmanaged_cache_validation_interval_ms = 1_000;
        assert!(validate_tftp_performance_config(&config).is_ok());
        config.server.unmanaged_cache_validation_interval_ms = 1_001;
        assert!(validate_tftp_performance_config(&config).is_err());
    }

    #[test]
    fn hot_artifact_cache_limits_are_bounded_and_ordered() {
        let mut config = TempestConfig::default();
        config.server.hot_artifact_cache_max_bytes = 512 * 1024 * 1024;
        config.server.hot_artifact_cache_max_file_bytes = 128 * 1024 * 1024;
        assert!(validate_tftp_performance_config(&config).is_ok());

        config.server.hot_artifact_cache_max_file_bytes =
            config.server.hot_artifact_cache_max_bytes + 1;
        assert!(validate_tftp_performance_config(&config).is_err());

        config.server.hot_artifact_cache_max_file_bytes = 1;
        config.server.hot_artifact_cache_max_bytes = 0;
        assert!(validate_tftp_performance_config(&config).is_err());

        config.server.hot_artifact_cache_max_bytes = u64::MAX;
        assert!(validate_tftp_performance_config(&config).is_err());
    }

    #[test]
    fn http_artifact_cache_limits_are_bounded_ordered_and_disable_together() {
        let mut config = TempestConfig::default();
        config.api.artifact_cache_max_bytes = 512 * 1024 * 1024;
        config.api.artifact_cache_max_file_bytes = 128 * 1024 * 1024;
        assert!(validate_tftp_performance_config(&config).is_ok());

        config.api.artifact_cache_max_file_bytes = config.api.artifact_cache_max_bytes + 1;
        assert!(validate_tftp_performance_config(&config).is_err());

        config.api.artifact_cache_max_bytes = 0;
        config.api.artifact_cache_max_file_bytes = 0;
        assert!(validate_tftp_performance_config(&config).is_ok());

        config.api.artifact_cache_max_file_bytes = 1;
        assert!(validate_tftp_performance_config(&config).is_err());
    }

    #[test]
    fn session_capacity_validation_covers_both_boundaries() {
        for capacity in [1, 100_000, MAX_ALLOWED_BOOT_SESSIONS] {
            assert!(validate_boot_session_capacity(capacity).is_ok());
        }
        for capacity in [0, MAX_ALLOWED_BOOT_SESSIONS + 1, usize::MAX / 2, usize::MAX] {
            assert!(validate_boot_session_capacity(capacity).is_err());
        }
    }

    #[test]
    fn test_config_max_boot_sessions_is_bounded() {
        let temp_root = tempfile::tempdir().unwrap();
        let dir = temp_root.path().to_path_buf();
        let config_path = dir.join("test.toml");
        std::fs::write(
            &config_path,
            "[server]\nmax_boot_sessions = 999999999\n[api]\nallow_insecure_loopback = true\n",
        )
        .unwrap();
        let config = TempestConfig::load(&config_path).unwrap();
        assert_eq!(config.server.max_boot_sessions, 1_000_000);

        std::fs::write(
            &config_path,
            "[server]\nmax_boot_sessions = 0\n[api]\nallow_insecure_loopback = true\n",
        )
        .unwrap();
        let config = TempestConfig::load(&config_path).unwrap();
        assert_eq!(config.server.max_boot_sessions, 1);
    }

    #[test]
    fn test_config_max_write_size_capped() {
        let temp_root = tempfile::tempdir().unwrap();
        let dir = temp_root.path().to_path_buf();
        let config_path = dir.join("test.toml");
        std::fs::write(
            &config_path,
            r#"
            [server]
            max_write_file_size = 999999999999

            [api]
            allow_insecure_loopback = true
        "#,
        )
        .unwrap();
        let config = TempestConfig::load(&config_path).unwrap();
        assert!(config.server.max_write_file_size <= 4 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_config_max_request_body_capped() {
        let temp_root = tempfile::tempdir().unwrap();
        let dir = temp_root.path().to_path_buf();
        let config_path = dir.join("test.toml");
        std::fs::write(
            &config_path,
            r#"
            [api]
            max_request_body_bytes = 999999999
            allow_insecure_loopback = true
        "#,
        )
        .unwrap();
        let config = TempestConfig::load(&config_path).unwrap();
        assert!(config.api.max_request_body_bytes <= 10 * 1024 * 1024);
    }

    #[test]
    fn test_config_env_api_key_resolution() {
        let temp_root = tempfile::tempdir().unwrap();
        let dir = temp_root.path().to_path_buf();
        let config_path = dir.join("test.toml");
        std::fs::write(
            &config_path,
            r#"
            [api]
            api_key = "env:TEMPEST_NONEXISTENT_TEST_KEY"
        "#,
        )
        .unwrap();
        let error = TempestConfig::load(&config_path).unwrap_err().to_string();
        assert!(error.contains("TEMPEST_NONEXISTENT_TEST_KEY"));
    }
    #[test]
    fn removed_public_http_boot_settings_are_rejected() {
        for setting in [
            "public_http_boot_files = []",
            "public_http_boot_files = [\"kernel\"]",
            "public_http_boot_profile = \"default\"",
        ] {
            let error = toml::from_str::<TempestConfig>(&format!("[api]\n{setting}\n"))
                .unwrap_err()
                .to_string();
            assert!(error.contains("unknown field"), "{error}");
            assert!(error.contains("public_http_boot_"), "{error}");
        }
    }
}
