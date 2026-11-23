// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::borrow::Cow;
use std::io::SeekFrom;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use std::{future::Future, io};

use axum::Router;
use axum::body::{Body, HttpBody};
use axum::extract::{ConnectInfo, Json, Path as AxumPath, Query, State};
use axum::http::{HeaderMap, HeaderValue, Request, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use bytes::Bytes;
use futures_core::Stream;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;
use tracing::{error, info, warn};

use crate::artifact_cache::{ArtifactContent, PreparedArtifact};
use crate::error::{ProtocolError, TempestError};
use crate::features::audit::{AuditRecord, AuditReservation, DeliveryIdentity, TransferOutcome};
use crate::features::bandwidth_governor::BandwidthGovernor;
use crate::features::boot_phase::{BootPhase, boot_phase_weight};
use crate::features::versioning::{DEFAULT_BOOT_PROFILE, PinnedVersion, is_valid_boot_profile};
use crate::protocol::transfer::{
    TransferMetrics, verify_cached_artifact, verify_opened_artifact_with_metadata,
};
use crate::server::{
    BootSessionEntry, ReservedTransferSlotGuard, ServerState, TRANSPORT_HTTP,
    TRANSPORT_HTTP_NATIVE, active_boot_session,
};

mod connection;
/// Prometheus metrics response generation.
pub mod metrics;
pub(crate) mod sessions;
/// Release deployment, withdrawal, listing, and rollback endpoints.
pub mod versions;

mod deletion;

#[cfg(test)]
mod additional_hotpath_tests;

#[cfg(test)]
mod deletion_route_tests;

#[cfg(test)]
mod numeric_header_tests;

#[cfg(test)]
mod quarantine_key_tests;

use metrics::metrics_handler;
use versions::{
    deploy_version, list_groups, list_versions, release_snapshot, rollback_version,
    rollback_version_exact, verify_group, withdraw_version, withdraw_version_exact,
};

async fn require_api_key(
    State(state): State<Arc<ServerState>>,
    request: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    if let Some(ref expected_key) = state.config.api.api_key {
        if expected_key.is_empty() {
            return (StatusCode::INTERNAL_SERVER_ERROR, "Server misconfiguration").into_response();
        }
        let provided = request
            .headers()
            .get("x-api-key")
            .and_then(|v| v.to_str().ok());
        match provided {
            Some(key)
                if !key.is_empty() && bool::from(key.as_bytes().ct_eq(expected_key.as_bytes())) => {
            }
            _ => {
                return (StatusCode::UNAUTHORIZED, "Missing or invalid API key").into_response();
            }
        }
    } else if !(state.config.api.bind.is_loopback() && state.config.api.allow_insecure_loopback) {
        return (StatusCode::UNAUTHORIZED, "API key required").into_response();
    }
    next.run(request).await.into_response()
}

/// Buffer only request bodies, under the existing byte cap and an absolute deadline.
/// This runs after admission/authentication on protected routes, before JSON parsing.
async fn read_request_body(
    State(state): State<Arc<ServerState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if request.body().is_end_stream() {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let result = tokio::time::timeout(
        Duration::from_secs(state.config.api.read_timeout_secs),
        axum::body::to_bytes(body, state.config.api.max_request_body_bytes),
    )
    .await;
    let (status, message) = match result {
        Ok(Ok(bytes)) => {
            return next
                .run(Request::from_parts(parts, Body::from(bytes)))
                .await;
        }
        Ok(Err(error)) => {
            use std::error::Error;
            if error
                .source()
                .is_some_and(|source| source.is::<http_body_util::LengthLimitError>())
            {
                (
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "Request body exceeds configured limit",
                )
            } else {
                (StatusCode::BAD_REQUEST, "Invalid request body")
            }
        }
        Err(_) => (StatusCode::REQUEST_TIMEOUT, "Request body timed out"),
    };
    // Do not drain an unfinished or oversized body to reuse this connection.
    (status, [(header::CONNECTION, "close")], message).into_response()
}

async fn rate_limit(
    State(state): State<Arc<ServerState>>,
    request: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let socket_ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    let Some(socket_ip) = socket_ip else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Peer identity unavailable").into_response();
    };
    let ip = match resolved_client_ip(
        socket_ip,
        request.headers(),
        &state.config.api.trusted_proxy_ips,
    ) {
        Ok(ip) => ip,
        Err(()) => {
            return (StatusCode::BAD_REQUEST, "Invalid forwarded client address").into_response();
        }
    };
    if !state.http_rate_limiter.check(ip) {
        return (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded").into_response();
    }

    next.run(request).await.into_response()
}

/// Resolve one rate-limit identity without trusting attacker-supplied proxy
/// chains. Only an exact configured socket peer may supply one numeric address.
fn resolved_client_ip(
    socket_ip: IpAddr,
    headers: &HeaderMap,
    trusted_proxy_ips: &[IpAddr],
) -> Result<IpAddr, ()> {
    if !trusted_proxy_ips.contains(&socket_ip) {
        return Ok(socket_ip);
    }
    if headers.get_all("x-forwarded-for").iter().count() > 1 {
        return Err(());
    }
    let Some(value) = headers.get("x-forwarded-for") else {
        return Ok(socket_ip);
    };
    let value = value.to_str().map_err(|_| ())?;
    if value.contains(',') {
        return Err(());
    }
    value.trim().parse().map_err(|_| ())
}

/// Apply non-cacheable browser hardening headers to every HTTP response.
async fn security_headers(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

/// Atomically reserves an HTTP transfer slot when capacity is available.
fn try_acquire_http_transfer_slot(state: &ServerState) -> bool {
    let max = state.config.server.max_concurrent_transfers;
    let mut current = state.active_transfers.load(Ordering::Acquire);
    loop {
        if current >= max {
            return false;
        }
        match state.active_transfers.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return true,
            Err(actual) => current = actual,
        }
    }
}

/// Returns the root-relative quarantine key for an HTTP artifact path.
fn quarantine_key_for_http_path<'a>(path: &'a Path, root: &Path) -> Option<Cow<'a, str>> {
    if let Ok(relative) = path.strip_prefix(root) {
        let key = relative.to_string_lossy();
        return Some(if key.contains('\\') {
            Cow::Owned(key.replace('\\', "/"))
        } else {
            key
        });
    }
    // Canonical fallback owns its temporary path; never borrow from it.
    let canonical_root = root.canonicalize().ok()?;
    let canonical_path = path.canonicalize().ok()?;
    let relative = canonical_path.strip_prefix(canonical_root).ok()?;
    Some(Cow::Owned(relative.to_string_lossy().replace('\\', "/")))
}

/// Accepts only bounded, component-safe relative artifact names.
fn is_safe_http_artifact_name(filename: &str) -> bool {
    filename.len() <= 1024 && crate::features::versioning::is_canonical_artifact_name(filename)
}

/// Returns a non-disclosing response for malformed or unsafe artifact names.
fn validate_http_artifact_name(filename: &str) -> Result<(), (StatusCode, &'static str)> {
    if filename.is_empty() || filename.len() > 1024 || filename.chars().any(char::is_control) {
        return Err((StatusCode::BAD_REQUEST, "Invalid artifact name"));
    }
    if !is_safe_http_artifact_name(filename) {
        return Err((StatusCode::FORBIDDEN, "Artifact access denied"));
    }
    Ok(())
}

/// Maps internal artifact failures to non-disclosing HTTP responses.
fn artifact_error_response(error: TempestError) -> Response {
    let (status, message) = match &error {
        TempestError::Protocol(ProtocolError::FileNotFound(_)) => {
            (StatusCode::NOT_FOUND, "Artifact not found")
        }
        TempestError::Protocol(ProtocolError::AccessViolation(_)) => {
            (StatusCode::FORBIDDEN, "Artifact access denied")
        }
        TempestError::Version(_) => (StatusCode::CONFLICT, "Pinned boot chain unavailable"),
        TempestError::PersistenceSnapshotStale => {
            (StatusCode::SERVICE_UNAVAILABLE, "Persistent state is stale")
        }
        TempestError::PersistenceBusy(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Artifact temporarily unavailable",
        ),
        TempestError::Io(err) if err.kind() == std::io::ErrorKind::NotFound => {
            (StatusCode::NOT_FOUND, "Artifact not found")
        }
        TempestError::Io(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            (StatusCode::FORBIDDEN, "Artifact access denied")
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "Artifact unavailable"),
    };
    (status, message).into_response()
}

/// Converts boot-phase weight into HTTP governor cost.
fn http_governor_cost_multiplier(phase: BootPhase) -> f64 {
    const MAX_HTTP_PHASE_WEIGHT: f64 = 10.0;
    let weight = boot_phase_weight(phase);
    if weight.is_finite() && weight > 0.0 {
        (MAX_HTTP_PHASE_WEIGHT / weight).max(1.0)
    } else {
        MAX_HTTP_PHASE_WEIGHT
    }
}

/// Scales a chunk length by its validated governor cost multiplier.
fn governed_http_charge_len(len: usize, multiplier: f64) -> usize {
    if len == 0 {
        return 0;
    }
    let multiplier = if multiplier.is_finite() && multiplier >= 1.0 {
        multiplier
    } else {
        1.0
    };
    ((len as f64) * multiplier).ceil().min(usize::MAX as f64) as usize
}

/// Owns HTTP transfer metrics, audit emission, and version-pin cleanup.
struct HttpArtifactTransferGuard {
    durable_reader: Option<Arc<crate::persistence::ReaderRegistration>>,
    state: Arc<ServerState>,
    pinned: Option<PinnedVersion>,
    phase: BootPhase,
    boot_profile: String,
    client_ip: IpAddr,
    filename: String,
    expected_bytes: u64,
    metrics: TransferMetrics,
    session: Option<BootSessionEntry>,
    delivery: DeliveryIdentity,
    audit_reservation: Option<AuditReservation>,
    transport: &'static str,
    started: bool,
    finished: bool,
}

impl HttpArtifactTransferGuard {
    /// Creates an unstarted guard for one resolved HTTP artifact.
    #[allow(clippy::too_many_arguments)]
    fn new(
        state: Arc<ServerState>,
        pinned: Option<PinnedVersion>,
        phase: BootPhase,
        boot_profile: String,
        client_ip: IpAddr,
        filename: String,
        expected_bytes: u64,
        content_hash: Option<String>,
        boot_chain: Option<&crate::features::versioning::BootChainPin>,
        session: Option<BootSessionEntry>,
        audit_reservation: Option<AuditReservation>,
        transport: &'static str,
    ) -> Self {
        let delivery = DeliveryIdentity {
            transfer_id: uuid::Uuid::new_v4().to_string(),
            group_id: boot_chain.map(|pin| pin.group_id.clone()),
            artifact_version_id: pinned.as_ref().map(|version| version.version_id),
            manifest_digest: boot_chain.map(|pin| pin.manifest_digest.clone()),
            phase: phase.as_str().to_string(),
            transport: transport.to_string(),
        };
        Self {
            state,
            pinned,
            durable_reader: None,
            phase,
            boot_profile,
            client_ip,
            filename,
            expected_bytes,
            metrics: TransferMetrics {
                start_time: Some(Instant::now()),
                content_hash,
                ..Default::default()
            },
            session,
            delivery,
            audit_reservation,
            transport,
            started: false,
            finished: false,
        }
    }

    /// Starts transport metrics after the artifact is ready to stream.
    fn start(&mut self) {
        self.started = true;
        self.metrics.start_time = Some(Instant::now());
        self.state.metrics.transfer_started_for_transport(
            &self.phase,
            &self.boot_profile,
            self.transport,
        );
    }

    /// Accounts for one emitted HTTP body chunk.
    fn record_chunk(&mut self, len: usize) {
        self.metrics.bytes_sent = self.metrics.bytes_sent.saturating_add(len as u64);
        self.metrics.blocks_sent = self.metrics.blocks_sent.saturating_add(1);
    }

    /// Releases the transfer-owned artifact version pin once.
    fn release_pin(&mut self) {
        if let Some(pinned) = self.pinned.take() {
            self.state.version_store.unpin_version_for_profile(
                &pinned.boot_profile,
                &pinned.logical_name,
                pinned.version_id,
            );
        }
    }

    /// Appends the terminal delivery outcome when auditing is enabled.
    fn audit(&mut self, outcome: TransferOutcome) {
        let Some(audit) = self.state.audit_log.as_ref() else {
            return;
        };
        let record = AuditRecord {
            client_ip: self.client_ip.to_string(),
            client_mac: self
                .session
                .as_ref()
                .and_then(|session| session.client_mac.clone()),
            client_serial: self
                .session
                .as_ref()
                .and_then(|session| session.serial.clone()),
            boot_profile: Some(self.boot_profile.clone()),
            file_path: self.filename.clone(),
            file_sha256: self.metrics.content_hash.clone().unwrap_or_default(),
            blocks_sent: self.metrics.blocks_sent,
            retransmissions: self.metrics.retransmissions,
            outcome,
            timestamp: jiff::Timestamp::now(),
            trace_id: self
                .session
                .as_ref()
                .and_then(|session| session.trace_id.clone()),
            delivery: Some(self.delivery.clone()),
        };
        let result = if let Some(reservation) = self.audit_reservation.take() {
            // A response body is finalized from Drop, where waiting is impossible. The
            // admission-owned permit keeps this terminal record bounded until synced.
            reservation.record(record)
        } else {
            audit
                .append_delivery(
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
                    record
                        .delivery
                        .expect("HTTP records always carry delivery identity"),
                )
                .map(|_| ())
        };
        if let Err(error) = result {
            self.state
                .critical_services_healthy
                .store(false, Ordering::Release);
            tracing::error!(error = %error, transfer_id = %self.delivery.transfer_id, "audit write failed; rejecting new transfers");
        }
    }

    /// Records successful completion and releases all transfer-owned state.
    fn complete(&mut self) {
        if self.finished {
            return;
        }
        self.metrics.end_time = Some(Instant::now());
        self.release_pin();
        self.state.metrics.transfer_completed_for_transport(
            &self.phase,
            &self.boot_profile,
            &self.metrics,
            self.transport,
        );
        self.audit(TransferOutcome::Completed);
        tracing::debug!(
            transport = self.transport,
            client = %self.client_ip,
            filename = %self.filename,
            boot_profile = %self.boot_profile,
            phase = self.phase.as_str(),
            content_hash = ?self.metrics.content_hash.as_deref(),
            bytes = self.metrics.bytes_sent,
            chunks = self.metrics.blocks_sent,
            duration_ms = ?self.metrics.duration().map(|d| d.as_millis()),
            "HTTP artifact transfer completed"
        );
        self.finished = true;
    }

    /// Records an incomplete transfer and releases all transfer-owned state.
    fn fail(&mut self) {
        if self.finished {
            return;
        }
        self.release_pin();
        self.audit(TransferOutcome::Failed("transfer incomplete".to_string()));
        if self.started {
            self.state.metrics.transfer_failed_for_transport(
                &self.phase,
                &self.boot_profile,
                self.transport,
            );
            warn!(
                transport = self.transport,
                client = %self.client_ip,
                filename = %self.filename,
                boot_profile = %self.boot_profile,
                phase = self.phase.as_str(),
                content_hash = ?self.metrics.content_hash.as_deref(),
                bytes = self.metrics.bytes_sent,
                "HTTP artifact transfer failed or disconnected"
            );
        } else {
            self.state.release_reserved_transfer_slot();
        }
        self.finished = true;
    }
}

impl Drop for HttpArtifactTransferGuard {
    fn drop(&mut self) {
        if !self.finished {
            if self.started && self.metrics.bytes_sent >= self.expected_bytes {
                self.complete();
            } else {
                self.fail();
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HttpByteRange {
    start: u64,
    len: u64,
}

impl HttpByteRange {
    fn end(self) -> u64 {
        self.start + self.len - 1
    }
}

#[derive(Debug, PartialEq, Eq)]
enum HttpRangeSelection {
    Full,
    Partial(HttpByteRange),
    Unsatisfiable,
}

/// Selects one bounded byte range for a managed representation. Unsupported
/// units, malformed syntax, duplicate headers, and multipart ranges are ignored.
fn select_http_range(headers: &HeaderMap, size: u64, etag: Option<&str>) -> HttpRangeSelection {
    let Some(etag) = etag else {
        return HttpRangeSelection::Full;
    };
    let mut values = headers.get_all(header::RANGE).iter();
    let Some(value) = values.next() else {
        return HttpRangeSelection::Full;
    };
    if values.next().is_some() {
        return HttpRangeSelection::Full;
    }
    let mut if_ranges = headers.get_all(header::IF_RANGE).iter();
    if let Some(if_range) = if_ranges.next() {
        if if_ranges.next().is_some() || if_range.as_bytes() != etag.as_bytes() {
            return HttpRangeSelection::Full;
        }
    }
    let Ok(value) = value.to_str() else {
        return HttpRangeSelection::Full;
    };
    let Some((unit, value)) = value.trim().split_once('=') else {
        return HttpRangeSelection::Full;
    };
    if !unit.eq_ignore_ascii_case("bytes") || value.contains(',') {
        return HttpRangeSelection::Full;
    }
    let Some((start, end)) = value.split_once('-') else {
        return HttpRangeSelection::Full;
    };
    if start.is_empty() {
        if end.is_empty() || !end.bytes().all(|byte| byte.is_ascii_digit()) {
            return HttpRangeSelection::Full;
        }
        let Ok(suffix) = end.parse::<u64>() else {
            return HttpRangeSelection::Full;
        };
        if suffix == 0 || size == 0 {
            return HttpRangeSelection::Unsatisfiable;
        }
        let len = suffix.min(size);
        return HttpRangeSelection::Partial(HttpByteRange {
            start: size - len,
            len,
        });
    }
    if !start.bytes().all(|byte| byte.is_ascii_digit()) {
        return HttpRangeSelection::Full;
    }
    let Ok(start) = start.parse::<u64>() else {
        return HttpRangeSelection::Full;
    };
    if start >= size {
        return HttpRangeSelection::Unsatisfiable;
    }
    let end = if end.is_empty() {
        size - 1
    } else {
        if !end.bytes().all(|byte| byte.is_ascii_digit()) {
            return HttpRangeSelection::Full;
        }
        let Ok(end) = end.parse::<u64>() else {
            return HttpRangeSelection::Full;
        };
        if end < start {
            return HttpRangeSelection::Unsatisfiable;
        }
        end.min(size - 1)
    };
    HttpRangeSelection::Partial(HttpByteRange {
        start,
        len: end - start + 1,
    })
}

/// Streams an artifact while applying bandwidth governance and lifecycle accounting.
enum HttpArtifactSource {
    File(ReaderStream<tokio::io::Take<File>>),
    Memory {
        bytes: Arc<Bytes>,
        offset: usize,
        end: usize,
        chunk_bytes: usize,
    },
}

impl HttpArtifactSource {
    fn file(file: tokio::io::Take<File>, chunk_bytes: usize) -> Self {
        Self::File(ReaderStream::with_capacity(file, chunk_bytes))
    }

    fn memory(
        bytes: Arc<Bytes>,
        chunk_bytes: usize,
        range: Option<HttpByteRange>,
    ) -> Result<Self, TempestError> {
        let (offset, end) = match range {
            Some(range) => {
                let offset = usize::try_from(range.start).map_err(|_| {
                    TempestError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HTTP range offset does not fit this platform",
                    ))
                })?;
                let len = usize::try_from(range.len).map_err(|_| {
                    TempestError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HTTP range length does not fit this platform",
                    ))
                })?;
                let Some(end) = offset.checked_add(len).filter(|end| *end <= bytes.len()) else {
                    return Err(TempestError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "HTTP range exceeds verified artifact",
                    )));
                };
                (offset, end)
            }
            None => (0, bytes.len()),
        };
        Ok(Self::Memory {
            bytes,
            offset,
            end,
            chunk_bytes,
        })
    }

    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Bytes, io::Error>>> {
        match self {
            Self::File(reader) => Pin::new(reader).poll_next(cx),
            Self::Memory {
                bytes,
                offset,
                end,
                chunk_bytes,
            } => {
                if *offset == *end {
                    return Poll::Ready(None);
                }
                let chunk_end = offset.saturating_add(*chunk_bytes).min(*end);
                let chunk = bytes.as_ref().slice(*offset..chunk_end);
                *offset = chunk_end;
                Poll::Ready(Some(Ok(chunk)))
            }
        }
    }
}

#[derive(Clone, Copy)]
struct HttpSourceOptions {
    already_verified: bool,
    chunk_bytes: usize,
    range: Option<HttpByteRange>,
}

async fn verified_http_source(
    content: ArtifactContent,
    path: &Path,
    metadata: &std::fs::Metadata,
    pinned: Option<&PinnedVersion>,
    store: &crate::features::versioning::VersionStore,
    options: HttpSourceOptions,
) -> Result<HttpArtifactSource, TempestError> {
    match content {
        ArtifactContent::File(file) => {
            let mut file = File::from_std(file);
            if !options.already_verified {
                verify_opened_artifact_with_metadata(&mut file, path, metadata, pinned, store)
                    .await?;
            }
            let range = options.range.unwrap_or(HttpByteRange {
                start: 0,
                len: metadata.len(),
            });
            if range.start != 0 {
                file.seek(SeekFrom::Start(range.start)).await?;
            }
            Ok(HttpArtifactSource::file(
                file.take(range.len),
                options.chunk_bytes,
            ))
        }
        ArtifactContent::Memory(bytes) => {
            if !options.already_verified {
                verify_cached_artifact(&bytes, path, metadata, pinned, store).await?;
            }
            HttpArtifactSource::memory(bytes, options.chunk_bytes, options.range)
        }
    }
}

struct HttpArtifactStream {
    source: HttpArtifactSource,
    guard: Option<HttpArtifactTransferGuard>,
    governor: Option<Arc<BandwidthGovernor>>,
    governor_cost_multiplier: f64,
    pending_chunk: Option<Bytes>,
    pending_governor: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

const HTTP_STREAM_CHUNK_BYTES: usize = 4 * 1024 * 1024;
const HTTP_STREAM_BUSY_CHUNK_BYTES: usize = 256 * 1024;
const HTTP_STREAM_SATURATED_CHUNK_BYTES: usize = 64 * 1024;
const HTTP_STREAM_BUSY_TRANSFERS: usize = 32;
const HTTP_STREAM_SATURATED_TRANSFERS: usize = 128;

/// Emits a retained snapshot in one zero-copy frame unless governance requires
/// progressive charging; file and governed sources retain adaptive chunking.
fn http_source_chunk_bytes(
    active_transfers: usize,
    memory_cache_hit: bool,
    bandwidth_governed: bool,
) -> usize {
    if memory_cache_hit && !bandwidth_governed {
        return usize::MAX;
    }
    http_stream_chunk_bytes(active_transfers)
}

/// Chooses fewer blocking-pool reads at ordinary concurrency without allowing
/// maximum transfer admission to imply four MiB of buffering per response.
fn http_stream_chunk_bytes(active_transfers: usize) -> usize {
    if active_transfers < HTTP_STREAM_BUSY_TRANSFERS {
        HTTP_STREAM_CHUNK_BYTES
    } else if active_transfers < HTTP_STREAM_SATURATED_TRANSFERS {
        HTTP_STREAM_BUSY_CHUNK_BYTES
    } else {
        HTTP_STREAM_SATURATED_CHUNK_BYTES
    }
}

impl HttpArtifactStream {
    /// Wraps a file stream with its transfer guard and optional governor.
    fn new(
        source: HttpArtifactSource,
        guard: HttpArtifactTransferGuard,
        governor: Option<Arc<BandwidthGovernor>>,
        governor_cost_multiplier: f64,
    ) -> Self {
        Self {
            source,
            guard: Some(guard),
            governor,
            governor_cost_multiplier,
            pending_chunk: None,
            pending_governor: None,
        }
    }
}

impl Stream for HttpArtifactStream {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if self.pending_chunk.is_some() {
                if self.pending_governor.is_none() {
                    if let Some(governor) = self.governor.clone() {
                        let len = self.pending_chunk.as_ref().map_or(0, Bytes::len);
                        let charge_len =
                            governed_http_charge_len(len, self.governor_cost_multiplier);
                        if !governor.try_acquire(charge_len) {
                            self.pending_governor = Some(Box::pin(async move {
                                governor.acquire(charge_len).await;
                            }));
                        }
                    }
                }

                if let Some(wait) = self.pending_governor.as_mut() {
                    match wait.as_mut().poll(cx) {
                        Poll::Ready(()) => self.pending_governor = None,
                        Poll::Pending => return Poll::Pending,
                    }
                }

                let Some(bytes) = self.pending_chunk.take() else {
                    continue;
                };
                if let Some(guard) = self.guard.as_mut() {
                    guard.record_chunk(bytes.len());
                }
                return Poll::Ready(Some(Ok(bytes)));
            }

            match self.source.poll_next(cx) {
                Poll::Ready(Some(Ok(bytes))) => {
                    if self.governor.is_some() {
                        self.pending_chunk = Some(bytes);
                        continue;
                    }
                    if let Some(guard) = self.guard.as_mut() {
                        guard.record_chunk(bytes.len());
                    }
                    return Poll::Ready(Some(Ok(bytes)));
                }
                Poll::Ready(Some(Err(error))) => {
                    if let Some(mut guard) = self.guard.take() {
                        guard.fail();
                    }
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(None) => {
                    if let Some(mut guard) = self.guard.take() {
                        guard.complete();
                    }
                    return Poll::Ready(None);
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Inserts a response header only when its value is valid.
fn insert_header(headers: &mut axum::http::HeaderMap, name: &'static str, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

/// Formats an unsigned response field directly into its owned header storage.
fn numeric_header_value(value: u64) -> HeaderValue {
    use std::io::Write;

    // Every u64 decimal representation fits in 20 ASCII bytes. Cursor keeps
    // formatting bounded on the stack; only the final HeaderValue owns bytes.
    let mut buffer = io::Cursor::new([0_u8; 20]);
    write!(&mut buffer, "{value}").expect("u64 decimal fits in 20 bytes");
    let len = buffer.position() as usize;
    HeaderValue::from_bytes(&buffer.get_ref()[..len]).expect("decimal ASCII is a valid header")
}

/// Returns the UEFI media type associated with the configured native boot name.
fn native_boot_content_type(filename: &str) -> &'static str {
    let extension = Path::new(filename)
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    if extension.eq_ignore_ascii_case("efi") {
        "application/efi"
    } else if extension.eq_ignore_ascii_case("iso") {
        "application/vnd.efi.iso"
    } else if extension.eq_ignore_ascii_case("img") {
        "application/vnd.efi.img"
    } else {
        "application/octet-stream"
    }
}

/// Resolves, verifies, and streams one already-authorized HTTP artifact.
#[allow(clippy::too_many_arguments)]
async fn serve_session_artifact(
    state: Arc<ServerState>,
    request_ip: IpAddr,
    session_ip: IpAddr,
    session: BootSessionEntry,
    headers: &HeaderMap,
    filename: String,
    transport: &'static str,
    content_type: &'static str,
    head_only: bool,
    require_managed: bool,
) -> Response {
    if let Err(error) = validate_http_artifact_name(&filename) {
        return error.into_response();
    }

    if state.drain_mode.load(Ordering::Acquire) {
        return (StatusCode::SERVICE_UNAVAILABLE, "Server draining").into_response();
    }

    let audit_reservation = match state.audit_writer.as_ref() {
        Some(writer) => match writer.try_reserve() {
            Ok(reservation) => Some(reservation),
            Err(_) => {
                return (StatusCode::SERVICE_UNAVAILABLE, "Audit service at capacity")
                    .into_response();
            }
        },
        None => None,
    };

    if !try_acquire_http_transfer_slot(&state) {
        state
            .metrics
            .capacity_rejected_total
            .fetch_add(1, Ordering::Relaxed);
        return (StatusCode::SERVICE_UNAVAILABLE, "Server at capacity").into_response();
    }

    // Reserve cleanup before session resolution can suspend or be cancelled.
    let mut slot_guard = ReservedTransferSlotGuard::new(&state);
    let resolved = match (transport, session.artifact_token_hash.as_ref()) {
        (TRANSPORT_HTTP, Some(token_hash)) => {
            state
                .resolve_file_for_authorized_boot_session(session_ip, token_hash, &filename)
                .await
        }
        (TRANSPORT_HTTP, None) => Err(TempestError::Protocol(
            crate::error::ProtocolError::AccessViolation("active boot session required".into()),
        )),
        _ => {
            state
                .resolve_file_for_required_boot_session(session_ip, &filename)
                .await
        }
    };
    let resolved_file = match resolved {
        Ok(resolved) => resolved,
        Err(error) => {
            return artifact_error_response(error);
        }
    };

    if require_managed
        && (resolved_file.pinned_version.is_none() || resolved_file.boot_chain.is_none())
    {
        if let Some(pinned) = resolved_file.pinned_version.as_ref() {
            state.version_store.unpin_version_for_profile(
                &pinned.boot_profile,
                &pinned.logical_name,
                pinned.version_id,
            );
        }
        return (StatusCode::NOT_FOUND, "Managed boot artifact not found").into_response();
    }

    let boot_chain = resolved_file.boot_chain;
    let boot_profile = resolved_file
        .pinned_version
        .as_ref()
        .map(|pinned| pinned.boot_profile.clone())
        .unwrap_or_else(|| session.boot_profile.clone());
    let phase = state.phase_classifier.classify(&filename);
    let content_hash = resolved_file.content_hash;
    let pinned_version = resolved_file.pinned_version;
    let etag = pinned_version
        .as_ref()
        .map(|pinned| format!("\"sha256-{}\"", pinned.content_hash));
    let range = if head_only {
        HttpRangeSelection::Full
    } else {
        select_http_range(
            headers,
            pinned_version.as_ref().map_or(0, |pinned| pinned.size),
            etag.as_deref(),
        )
    };
    let range = match range {
        HttpRangeSelection::Partial(range) => Some(range),
        HttpRangeSelection::Full => None,
        HttpRangeSelection::Unsatisfiable => {
            let Some(pinned) = pinned_version.as_ref() else {
                return (StatusCode::INTERNAL_SERVER_ERROR, "Invalid range state").into_response();
            };
            state.version_store.unpin_version_for_profile(
                &pinned.boot_profile,
                &pinned.logical_name,
                pinned.version_id,
            );
            let mut response = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
            let response_headers = response.headers_mut();
            response_headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            insert_header(
                response_headers,
                header::CONTENT_RANGE.as_str(),
                &format!("bytes */{}", pinned.size),
            );
            insert_header(
                response_headers,
                header::ETAG.as_str(),
                &format!("\"sha256-{}\"", pinned.content_hash),
            );
            return response;
        }
    };
    let mut guard = HttpArtifactTransferGuard::new(
        state.clone(),
        pinned_version.clone(),
        phase,
        boot_profile.clone(),
        request_ip,
        filename.clone(),
        0,
        content_hash.clone(),
        boot_chain.as_ref(),
        Some(session),
        audit_reservation,
        transport,
    );
    guard.durable_reader = resolved_file.durable_reader;

    slot_guard.hand_off();

    let cache_path = resolved_file.path;
    if quarantine_key_for_http_path(&cache_path, &state.config.server.root)
        .is_some_and(|key| state.quarantined_files.contains(key.as_ref()))
    {
        return artifact_error_response(TempestError::Protocol(ProtocolError::AccessViolation(
            "quarantined artifact".to_string(),
        )));
    }
    let verified = pinned_version.as_ref().and_then(|pinned| {
        state
            .http_artifact_cache
            .verified_path(&cache_path, &pinned.content_hash, pinned.size)
    });
    let verified_cache_hit = verified.is_some();
    let cached = verified.or_else(|| {
        pinned_version.is_none().then(|| {
            state.http_artifact_cache.recent_unmanaged_path(
                &cache_path,
                state.config.server.unmanaged_cache_validation_interval_ms,
            )
        })?
    });
    let memory_cache_hit = cached.is_some();
    let (content, file_path, metadata) = if let Some((bytes, metadata)) = cached {
        (
            ArtifactContent::Memory(bytes),
            Cow::Borrowed(cache_path.as_path()),
            metadata,
        )
    } else {
        let artifact_root = match state.artifact_root() {
            Ok(root) => root,
            Err(error) => return artifact_error_response(error),
        };
        let cache = state.http_artifact_cache.clone();
        let fill_path = cache_path.clone();
        let cache_artifact = !head_only && range.is_none();
        let opened = match state
            .artifact_io(move || {
                let opened = artifact_root.open_read_with_metadata(&fill_path)?;
                let prepared = if cache_artifact {
                    cache.prepare(opened.file, &fill_path, &opened.metadata)?
                } else {
                    PreparedArtifact::File(opened.file)
                };
                Ok::<_, TempestError>((prepared, opened.path, opened.metadata))
            })
            .await
        {
            Ok(opened) => opened,
            Err(error) => return artifact_error_response(error),
        };
        let content = match opened.0.resolve().await {
            Ok(content) => content,
            Err(error) => return artifact_error_response(error),
        };
        (content, Cow::Owned(opened.1), opened.2)
    };

    if quarantine_key_for_http_path(&file_path, &state.config.server.root)
        .is_some_and(|key| state.quarantined_files.contains(key.as_ref()))
    {
        return artifact_error_response(TempestError::Protocol(ProtocolError::AccessViolation(
            "quarantined artifact".to_string(),
        )));
    }

    let chunk_bytes = http_source_chunk_bytes(
        state.active_transfers.load(Ordering::Relaxed),
        memory_cache_hit,
        state.bandwidth_governor.is_some(),
    );
    let source = match verified_http_source(
        content,
        &file_path,
        &metadata,
        pinned_version.as_ref(),
        &state.version_store,
        HttpSourceOptions {
            already_verified: verified_cache_hit,
            chunk_bytes,
            range,
        },
    )
    .await
    {
        Ok(source) => source,
        Err(error) => {
            if let Some(key) = quarantine_key_for_http_path(&file_path, &state.config.server.root) {
                state.quarantine_artifact(key.into_owned());
            }
            return artifact_error_response(error);
        }
    };
    if !verified_cache_hit {
        if let Some(pinned) = pinned_version.as_ref() {
            state
                .http_artifact_cache
                .mark_verified(&cache_path, &metadata, &pinned.content_hash);
        }
    }
    let response_bytes = range.map_or(metadata.len(), |range| range.len);
    guard.expected_bytes = if head_only { 0 } else { response_bytes };

    guard.start();
    let phase_weight = boot_phase_weight(phase);
    let governor_cost_multiplier = http_governor_cost_multiplier(phase);
    tracing::debug!(
        transport,
        client = %request_ip,
        method = if head_only { "HEAD" } else { "GET" },
        filename = %filename,
        boot_profile = %boot_profile,
        phase = phase.as_str(),
        phase_weight,
        governor_cost_multiplier,
        content_hash = ?content_hash.as_deref(),
        artifact_version_id = ?pinned_version.as_ref().map(|p| p.version_id),
        group_id = ?boot_chain.as_ref().map(|p| p.group_id.as_str()),
        boot_chain_version_id = ?boot_chain.as_ref().map(|p| p.version_id),
        manifest_digest = ?boot_chain.as_ref().map(|p| p.manifest_digest.as_str()),
        range_start = ?range.map(|range| range.start),
        bytes = response_bytes,
        "HTTP artifact transfer started"
    );

    let body = if head_only {
        guard.complete();
        Body::empty()
    } else {
        Body::from_stream(HttpArtifactStream::new(
            source,
            guard,
            state.bandwidth_governor.clone(),
            governor_cost_multiplier,
        ))
    };
    let mut response = Response::new(body);
    if range.is_some() {
        *response.status_mut() = StatusCode::PARTIAL_CONTENT;
    }
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(header::CONTENT_LENGTH, numeric_header_value(response_bytes));
    headers.insert(
        header::ACCEPT_RANGES,
        HeaderValue::from_static(if etag.is_some() { "bytes" } else { "none" }),
    );
    if let Some(etag) = etag.as_deref() {
        insert_header(headers, header::ETAG.as_str(), etag);
    }
    if let Some(range) = range {
        insert_header(
            headers,
            header::CONTENT_RANGE.as_str(),
            &format!("bytes {}-{}/{}", range.start, range.end(), metadata.len()),
        );
    }
    if transport == TRANSPORT_HTTP_NATIVE {
        // Source-IP-selected routes may return different releases for the same URI.
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    insert_header(headers, "x-tempest-boot-profile", &boot_profile);
    headers.insert("x-tempest-transport", HeaderValue::from_static(transport));
    headers.insert(
        "x-tempest-http-mode",
        HeaderValue::from_static(if transport == TRANSPORT_HTTP_NATIVE {
            "native"
        } else {
            "bearer"
        }),
    );
    headers.insert(
        "x-tempest-boot-phase",
        HeaderValue::from_static(phase.as_str()),
    );
    insert_header(headers, "x-tempest-phase-weight", &phase_weight.to_string());
    insert_header(
        headers,
        "x-tempest-http-governor-cost-multiplier",
        &format!("{governor_cost_multiplier:.3}"),
    );
    if let Some(hash) = content_hash.as_deref() {
        insert_header(headers, "x-tempest-content-sha256", hash);
    }
    if let Some(pinned) = pinned_version.as_ref() {
        headers.insert(
            "x-tempest-artifact-version-id",
            numeric_header_value(pinned.version_id),
        );
    }
    if let Some(pin) = boot_chain.as_ref() {
        insert_header(headers, "x-tempest-group-id", &pin.group_id);
        headers.insert("x-tempest-version-id", numeric_header_value(pin.version_id));
        insert_header(headers, "x-tempest-manifest-digest", &pin.manifest_digest);
    }
    response
}

/// Resolves a bearer token and streams its session-authorized HTTP artifact.
async fn serve_artifact(
    State(state): State<Arc<ServerState>>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AxumPath(filename): AxumPath<String>,
) -> Response {
    if let Err(error) = validate_http_artifact_name(&filename) {
        return error.into_response();
    }
    let request_ip = match resolved_client_ip(
        client_addr.ip(),
        &headers,
        &state.config.api.trusted_proxy_ips,
    ) {
        Ok(ip) => ip,
        Err(()) => {
            return (StatusCode::BAD_REQUEST, "Invalid forwarded client address").into_response();
        }
    };
    let Some(token_hash) = artifact_bearer_hash(&headers) else {
        return (StatusCode::UNAUTHORIZED, "Artifact bearer token required").into_response();
    };
    let Some((session_ip, session)) = state.boot_session_for_artifact_token(&token_hash) else {
        return (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired artifact token",
        )
            .into_response();
    };

    // Possession of a token alone must not authorize a different machine.
    if request_ip.to_canonical() != session_ip.to_canonical() {
        return (
            StatusCode::FORBIDDEN,
            "Artifact token source address mismatch",
        )
            .into_response();
    }

    serve_session_artifact(
        state,
        request_ip,
        session_ip,
        session,
        &headers,
        filename,
        TRANSPORT_HTTP,
        "application/octet-stream",
        false,
        false,
    )
    .await
}

/// Serves the configured release-managed NBP to a registered source-IP session.
async fn serve_native_boot_artifact(
    state: Arc<ServerState>,
    client_addr: SocketAddr,
    headers: HeaderMap,
    filename: String,
    head_only: bool,
) -> Response {
    if let Err(error) = validate_http_artifact_name(&filename) {
        return error.into_response();
    }
    if filename != state.config.api.native_http_boot_filename {
        return (StatusCode::NOT_FOUND, "Native boot artifact not found").into_response();
    }
    let client_ip = match resolved_client_ip(
        client_addr.ip(),
        &headers,
        &state.config.api.trusted_proxy_ips,
    ) {
        Ok(ip) => ip,
        Err(()) => {
            return (StatusCode::BAD_REQUEST, "Invalid forwarded client address").into_response();
        }
    };
    let Some(session) = active_boot_session(&state, client_ip) else {
        return (StatusCode::FORBIDDEN, "Active boot session required").into_response();
    };
    let content_type = native_boot_content_type(&filename);

    serve_session_artifact(
        state,
        client_ip,
        client_ip,
        session,
        &headers,
        filename,
        TRANSPORT_HTTP_NATIVE,
        content_type,
        head_only,
        true,
    )
    .await
}

async fn get_native_boot_artifact(
    State(state): State<Arc<ServerState>>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AxumPath(filename): AxumPath<String>,
) -> Response {
    serve_native_boot_artifact(state, client_addr, headers, filename, false).await
}

async fn head_native_boot_artifact(
    State(state): State<Arc<ServerState>>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    AxumPath(filename): AxumPath<String>,
) -> Response {
    serve_native_boot_artifact(state, client_addr, headers, filename, true).await
}

fn artifact_bearer_hash(headers: &HeaderMap) -> Option<[u8; 32]> {
    let token = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")?;
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(Sha256::digest(token.as_bytes()).into())
}

/// Filters and bounds audit-log queries.
#[derive(Deserialize)]
struct AuditQuery {
    client_mac: Option<String>,
    limit: Option<usize>,
}

fn audit_query_join_error_response(error: tokio::task::JoinError) -> Response {
    error!(error = %error, "Audit query task failed");
    (StatusCode::INTERNAL_SERVER_ERROR, "Audit query failed").into_response()
}

/// Returns recent audit entries after validating optional filters.
async fn list_audit(
    State(state): State<Arc<ServerState>>,
    Query(query): Query<AuditQuery>,
) -> Response {
    let client_mac = match query.client_mac.as_deref().map(normalize_mac_address) {
        Some(Some(mac)) => Some(mac),
        Some(None) => return (StatusCode::BAD_REQUEST, "Invalid client MAC").into_response(),
        None => None,
    };
    let Some(audit) = state.audit_log.clone() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Audit log unavailable").into_response();
    };
    let Ok(audit_read_permit) = state.audit_read_budget.clone().try_acquire_owned() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "Audit query capacity reached",
        )
            .into_response();
    };
    match tokio::task::spawn_blocking(move || {
        let _audit_read_permit = audit_read_permit;
        audit.recent_entries(
            client_mac.as_deref(),
            query.limit.unwrap_or(100).clamp(1, 1000),
        )
    })
    .await
    {
        Ok(Ok(entries)) => Json(entries).into_response(),
        Ok(Err(error)) => artifact_error_response(error),
        Err(error) => audit_query_join_error_response(error),
    }
}

/// Build the control, artifact, metrics, and health router.
pub fn api_router(state: Arc<ServerState>) -> Router {
    let body_limit = state.config.api.max_request_body_bytes;

    let mut protected_routes = Router::new()
        .route("/api/v1/drain", post(enable_drain))
        .route("/api/v1/undrain", post(disable_drain))
        .route("/api/v1/sessions", post(register_session))
        .route("/api/v1/sessions/{client_ip}", delete(revoke_session))
        .route("/api/v1/transfers/active", get(active_transfers))
        .route("/api/v1/drain/status", get(drain_status))
        .route("/api/v1/info", get(server_info));
    if state.config.api.enable_metrics && state.config.api.metrics_require_api_key {
        protected_routes = protected_routes.route("/metrics", get(metrics_handler));
    }
    if state.config.api.enable_versions_api {
        protected_routes = protected_routes
            .route("/api/v2/delete/preview", post(deletion::preview_delete))
            .route("/api/v2/delete/confirm", post(deletion::confirm_delete))
            .route("/api/v1/versions/switch", post(deploy_version))
            .route("/api/v1/versions/rollback", post(rollback_version))
            .route("/api/v1/versions/withdraw", post(withdraw_version))
            .route("/api/v2/versions/rollback", post(rollback_version_exact))
            .route("/api/v2/versions/withdraw", post(withdraw_version_exact))
            .route("/api/v1/versions/snapshot", get(release_snapshot))
            .route("/api/v1/versions/verify", post(verify_group))
            .route("/api/v1/versions", get(list_versions))
            .route("/api/v1/versions/groups", get(list_groups));
    }
    if state.config.api.enable_audit_api {
        protected_routes = protected_routes.route("/api/v1/audit", get(list_audit));
    }
    let protected_routes = protected_routes
        .layer(middleware::from_fn_with_state(
            state.clone(),
            read_request_body,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ))
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
        .layer(axum::extract::DefaultBodyLimit::max(body_limit));

    let mut unauthenticated_metrics_route = Router::new();
    if state.config.api.enable_metrics && !state.config.api.metrics_require_api_key {
        unauthenticated_metrics_route = unauthenticated_metrics_route
            .route("/metrics", get(metrics_handler))
            .layer(middleware::from_fn_with_state(
                state.clone(),
                read_request_body,
            ))
            .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
            .layer(axum::extract::DefaultBodyLimit::max(body_limit));
    }

    let mut boot_artifact_routes =
        Router::new().route("/api/v1/artifacts/{*filename}", get(serve_artifact));
    if state.config.api.enable_native_http_boot {
        boot_artifact_routes = boot_artifact_routes.route(
            "/boot/v1/{*filename}",
            get(get_native_boot_artifact).head(head_native_boot_artifact),
        );
    }
    let boot_artifact_routes = boot_artifact_routes
        .layer(middleware::from_fn_with_state(
            state.clone(),
            read_request_body,
        ))
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit))
        .layer(axum::extract::DefaultBodyLimit::max(body_limit));

    let health_routes = Router::new()
        .route("/health", get(health_check))
        .route("/ready", get(readiness_check))
        .fallback(|| async { StatusCode::NOT_FOUND })
        .method_not_allowed_fallback(|| async { StatusCode::METHOD_NOT_ALLOWED })
        .layer(middleware::from_fn_with_state(
            state.clone(),
            read_request_body,
        ));

    Router::new()
        .merge(protected_routes)
        .merge(unauthenticated_metrics_route)
        .merge(boot_artifact_routes)
        .merge(health_routes)
        .layer(middleware::from_fn(security_headers))
        .layer(middleware::from_fn_with_state(state.clone(), observe_http))
        .with_state(state)
}

struct HttpObservationGuard {
    state: Arc<ServerState>,
    started: Instant,
    observation: crate::extension::HttpObservation,
}

impl Drop for HttpObservationGuard {
    fn drop(&mut self) {
        self.observation.elapsed = self.started.elapsed();
        if let Some(observer) = &self.state.http_observer {
            observer(self.observation.clone());
        }
    }
}

async fn observe_http(
    State(state): State<Arc<ServerState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if state.http_observer.is_none() {
        return next.run(request).await;
    }
    let method = match request.method().as_str() {
        "GET" => "GET",
        "HEAD" => "HEAD",
        "POST" => "POST",
        "PUT" => "PUT",
        "DELETE" => "DELETE",
        "PATCH" => "PATCH",
        "OPTIONS" => "OPTIONS",
        "CONNECT" => "CONNECT",
        "TRACE" => "TRACE",
        _ => "OTHER",
    };
    let mut guard = HttpObservationGuard {
        started: Instant::now(),
        observation: crate::extension::HttpObservation {
            method,
            route: request
                .extensions()
                .get::<axum::extract::MatchedPath>()
                .map(|path| path.as_str().to_owned()),
            status: None,
            elapsed: Duration::ZERO,
        },
        state,
    };
    let response = next.run(request).await;
    guard.observation.status = Some(response.status().as_u16());
    response
}

/// Serve HTTP routes until the listener fails or is cancelled.
pub async fn run_http_server(
    state: Arc<ServerState>,
    bind: SocketAddr,
) -> Result<(), crate::error::TempestError> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    run_http_server_on(state, listener).await
}

/// Serve HTTP routes on an already-bound listener.
pub(crate) async fn run_http_server_on(
    state: Arc<ServerState>,
    listener: tokio::net::TcpListener,
) -> Result<(), crate::error::TempestError> {
    state.config.validate_api_exposure()?;
    state.ensure_persistence_admission().await?;
    use axum::serve::Listener;
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
    use hyper_util::server::conn::auto::Builder;
    use hyper_util::service::TowerToHyperService;

    let mut listener = connection::HttpListener::new(
        listener,
        state.config.api.max_connections,
        Duration::from_secs(state.config.api.write_timeout_secs),
    );
    let read_timeout = Duration::from_secs(state.config.api.read_timeout_secs);
    let app = api_router(state.clone());
    let address = listener.local_addr()?;
    info!(addr = %address, "HTTP server listening (API + health)");
    let mut connections = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            (connection, peer) = listener.accept() => {
                let service = TowerToHyperService::new(app.clone().layer(axum::Extension(ConnectInfo(peer))));
                connections.spawn(async move {
                    // Serve the supported HTTP/1 protocol directly: automatic
                    // version/upgrade sniffing waits outside the header timer.
                    let mut builder = Builder::new(TokioExecutor::new()).http1_only();
                    // Hyper starts this timer only while awaiting the next request
                    // head, never while producing or writing a response.
                    builder.http1().timer(TokioTimer::new()).header_read_timeout(read_timeout);
                    if let Err(error) = builder.serve_connection(TokioIo::new(connection), service).await {
                        tracing::debug!(%error, "HTTP connection closed");
                    }
                });
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    tracing::warn!(%error, "HTTP connection task failed");
                }
            }
        }
    }
}

/// Active transfer count and drain state returned by the control API.
#[derive(Serialize)]
struct ActiveTransfersResponse {
    count: usize,
    drain_mode: bool,
}

/// Returns active transfer and drain counters.
async fn active_transfers(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    let response = ActiveTransfersResponse {
        count: state.active_transfers.load(Ordering::Relaxed),
        drain_mode: state.drain_mode.load(Ordering::Relaxed),
    };
    Json(response)
}

/// Enables drain mode through the control API.
async fn enable_drain(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    state.drain_mode.store(true, Ordering::Release);
    info!("Drain mode enabled via API");
    (StatusCode::OK, "Drain mode enabled")
}

/// Register a client IP boot session ahead of a TFTP boot.
/// The provisioning layer calls this before triggering PXE so subsequent TFTP
/// reads resolve through the requested boot profile for the session TTL.
///
/// `ttl_seconds` defaults to 600 (10 min) and is capped at 3600 (1 hour).
#[derive(Deserialize)]
struct RegisterSessionRequest {
    client_ip: IpAddr,
    #[serde(default)]
    trace_id: Option<String>,
    #[serde(default)]
    boot_profile: Option<String>,
    #[serde(default)]
    client_mac: Option<String>,
    #[serde(default)]
    serial: Option<String>,
    ttl_seconds: Option<u64>,
    #[serde(default)]
    new_epoch: bool,
    /// Refuse unmanaged sessions when provisioning requires release coherence.
    #[serde(default)]
    require_managed: bool,
}

#[derive(Serialize)]
struct RegisterSessionResponse {
    artifact_token: String,
    boot_profile: String,
    manifest_digest: Option<String>,
    #[serde(with = "crate::timestamp")]
    expires_at: jiff::Timestamp,
    boot_epoch: u64,
}

#[derive(Deserialize)]
struct RevokeSessionRequest {
    artifact_token: String,
}

/// Validates the bounded trace identifier accepted by session registration.
fn is_valid_trace_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Normalizes supported MAC address forms to lowercase colon notation.
fn normalize_mac_address(value: &str) -> Option<String> {
    if value.is_empty() || value.len() > 32 {
        return None;
    }
    let compact: String = value
        .bytes()
        .filter(|b| *b != b':' && *b != b'-')
        .map(char::from)
        .collect();
    if compact.len() != 12 || !compact.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }

    let lower = compact.to_ascii_lowercase();
    let mut canonical = String::with_capacity(17);
    for idx in 0..6 {
        if idx > 0 {
            canonical.push(':');
        }
        canonical.push_str(&lower[idx * 2..idx * 2 + 2]);
    }
    Some(canonical)
}

/// Validates the bounded inventory serial accepted by session registration.
fn is_valid_serial(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

/// Validates and registers a boot session, persisting it when configured.
async fn register_session(
    State(state): State<Arc<ServerState>>,
    Json(req): Json<RegisterSessionRequest>,
) -> impl IntoResponse {
    let boot_profile = req
        .boot_profile
        .unwrap_or_else(|| DEFAULT_BOOT_PROFILE.to_string());
    if !is_valid_boot_profile(&boot_profile) {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid boot_profile: must be 1-64 alphanumeric/dash/underscore/dot characters",
        )
            .into_response();
    }

    if req
        .trace_id
        .as_deref()
        .is_some_and(|id| !is_valid_trace_id(id))
    {
        return (
            StatusCode::BAD_REQUEST,
            "Invalid trace_id: must be 1-128 alphanumeric/hyphen characters",
        )
            .into_response();
    }

    let client_mac = match req.client_mac.as_deref() {
        Some(value) => match normalize_mac_address(value) {
            Some(mac) => Some(mac),
            None => {
                return (StatusCode::BAD_REQUEST, "Invalid client_mac format").into_response();
            }
        },
        None => None,
    };

    if req
        .serial
        .as_deref()
        .is_some_and(|serial| !is_valid_serial(serial))
    {
        return (StatusCode::BAD_REQUEST, "Invalid serial format").into_response();
    }

    if req.trace_id.is_none()
        && client_mac.is_none()
        && req.serial.is_none()
        && boot_profile == DEFAULT_BOOT_PROFILE
    {
        return (
            StatusCode::BAD_REQUEST,
            "Session must include trace_id, boot_profile, client_mac, or serial",
        )
            .into_response();
    }

    sessions::register(
        state,
        sessions::Registration {
            client_ip: req.client_ip,
            boot_profile,
            trace_id: req.trace_id,
            client_mac,
            serial: req.serial,
            ttl_seconds: req.ttl_seconds,
            new_epoch: req.new_epoch,
            require_managed: req.require_managed,
        },
    )
    .await
}

/// Revokes only the current session authorized by its one-time artifact token.
/// Durable state is removed before the in-memory session and release pin.
async fn revoke_session(
    State(state): State<Arc<ServerState>>,
    AxumPath(client_ip): AxumPath<IpAddr>,
    Json(req): Json<RevokeSessionRequest>,
) -> Response {
    if req.artifact_token.len() != 64
        || !req
            .artifact_token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return (StatusCode::BAD_REQUEST, "Invalid artifact token").into_response();
    }
    let token_hash: [u8; 32] = Sha256::digest(req.artifact_token.as_bytes()).into();
    let control_guard = state.control_plane_lock.clone().lock_owned().await;
    match tokio::spawn(revoke_session_mutation(
        state,
        client_ip,
        token_hash,
        control_guard,
    ))
    .await
    {
        Ok(response) => response,
        Err(error) => {
            let correlation_id = uuid::Uuid::new_v4();
            tracing::error!(%correlation_id, %error, "boot session revocation task failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Session revocation failed; reference {correlation_id}"),
            )
                .into_response()
        }
    }
}

async fn revoke_session_mutation(
    state: Arc<ServerState>,
    client_ip: IpAddr,
    token_hash: [u8; 32],
    _control_guard: tokio::sync::OwnedMutexGuard<()>,
) -> Response {
    if state.ensure_persistence_admission().await.is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Session persistence unavailable",
        )
            .into_response();
    }
    if let Some(persistence) = &state.persistence {
        let deletion = persistence
            .delete_boot_session_with_token(client_ip, &token_hash)
            .await;
        if matches!(deletion, Ok(false)) {
            return (StatusCode::CONFLICT, "Boot session was replaced").into_response();
        }
        if let Err(error) = deletion {
            let correlation_id = uuid::Uuid::new_v4();
            tracing::error!(%correlation_id, %error, "boot session revocation persistence failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Session revocation failed; reference {correlation_id}"),
            )
                .into_response();
        }
    } else if let Some(session) = active_boot_session(&state, client_ip) {
        if session.artifact_token_hash.as_ref() != Some(&token_hash) {
            return (StatusCode::CONFLICT, "Boot session was replaced").into_response();
        }
    }
    state.remove_boot_session(client_ip);
    StatusCode::NO_CONTENT.into_response()
}

/// Re-enable transfer admission without restarting the server.
async fn disable_drain(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    state.drain_mode.store(false, Ordering::Release);
    info!("Drain mode disabled via API");
    (StatusCode::OK, "Drain mode disabled")
}

/// Drain state and completion counters returned by the control API.
#[derive(Serialize)]
struct DrainStatusResponse {
    drain_mode: bool,
    active_transfers: usize,
    queued_transfers: usize,
    drain_complete: bool,
}

/// Returns current drain state and whether all transfers have finished.
async fn drain_status(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    let drain_mode = state.drain_mode.load(Ordering::Relaxed);
    let queued_transfers = state.queued_transfers.load(Ordering::Acquire);
    let active_transfers = state.active_transfers.load(Ordering::Acquire);
    Json(DrainStatusResponse {
        drain_mode,
        active_transfers,
        queued_transfers,
        drain_complete: drain_mode && active_transfers == 0 && queued_transfers == 0,
    })
}

/// Public process metadata; deliberately excludes filesystem and write policy.
#[derive(Serialize)]
struct ServerInfo {
    name: &'static str,
    version: &'static str,
    tftp_port: u16,
    active_transfers: usize,
    drain_mode: bool,
    uptime_secs: u64,
}

/// Returns non-sensitive process and transfer metadata.
async fn server_info(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    let info = ServerInfo {
        name: "Tempest",
        version: env!("CARGO_PKG_VERSION"),
        tftp_port: state.config.server.port,
        active_transfers: state.active_transfers.load(Ordering::Relaxed),
        drain_mode: state.drain_mode.load(Ordering::Relaxed),
        uptime_secs: state.start_time.elapsed().as_secs(),
    };
    Json(info)
}

/// Report process liveness without consulting protected control state.
async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// Report whether critical services are healthy and TFTP is accepting work.
async fn readiness_check(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    if !state.critical_services_healthy.load(Ordering::Acquire) {
        (StatusCode::SERVICE_UNAVAILABLE, "DEGRADED")
    } else if state.drain_mode.load(Ordering::Acquire) {
        (StatusCode::SERVICE_UNAVAILABLE, "DRAINING")
    } else if !state.tftp_ready.load(Ordering::Acquire) {
        (StatusCode::SERVICE_UNAVAILABLE, "STARTING")
    } else if state
        .persistence
        .as_ref()
        .is_some_and(|store| store.serving_lease_lost())
    {
        (StatusCode::SERVICE_UNAVAILABLE, "DEGRADED")
    } else if state.ensure_persistence_snapshot_fresh().is_err() {
        (StatusCode::SERVICE_UNAVAILABLE, "STALE")
    } else {
        (StatusCode::OK, "READY")
    }
}

#[cfg(test)]
mod tests;
