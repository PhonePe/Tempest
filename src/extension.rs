// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Public, versioned extension contracts for Tempest data-plane integrations.
//!
//! The default server does not require an extension. Downstream composition
//! binaries can provide implementations without exposing their
//! concrete types through [`crate::server::ServerState`]. Contracts in this
//! module preserve Tempest's transfer socket, release pin, and lifecycle
//! ownership; extensions may influence scheduling, but do not own resolution or
//! protocol correctness.
//!
//! # Composition model
//!
//! Tempest uses statically linked, typed capability injection rather than a
//! runtime plugin ABI or an order-dependent middleware chain. A
//! [`crate::server::TftpServerBuilder`] accepts one implementation of each
//! contract in this module. Implementations of different contracts can be
//! installed together, and one integration crate may implement several
//! contracts. When multiple implementations of the same contract must be
//! chained, a downstream crate can expose one composite implementation with
//! explicit ordering and failure semantics.
//!
//! The default `tempest` binary does not discover extension crates or their
//! configuration. A composition binary links the desired crates and installs
//! their implementations before starting the server:
//!
//! ```no_run
//! use std::sync::Arc;
//! use std::time::Duration;
//!
//! use tempest::config::TempestConfig;
//! use tempest::error::TempestError;
//! use tempest::extension::{AdmissionContext, AdmissionPolicy};
//! use tempest::server::TftpServer;
//!
//! struct FifoAdmission;
//!
//! impl AdmissionPolicy for FifoAdmission {
//!     fn queue_capacity(&self) -> usize {
//!         256
//!     }
//!
//!     fn max_queue_age(&self) -> Duration {
//!         Duration::from_secs(5)
//!     }
//!
//!     fn priority(&self, _context: &AdmissionContext) -> f64 {
//!         0.0
//!     }
//! }
//!
//! fn compose(config: TempestConfig) -> Result<TftpServer, TempestError> {
//!     TftpServer::builder(config)
//!         .with_admission_policy(Arc::new(FifoAdmission))
//!         .build()
//! }
//! ```

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;

use crate::error::TempestError;
use crate::features::boot_phase::BootPhase;

/// Stable identifier assigned to one TFTP transfer.
pub type TransferId = uuid::Uuid;

/// Future returned when an extension accepts a packet for transmission.
pub type PacketSendFuture<'a> = Pin<Box<dyn Future<Output = Result<(), TempestError>> + Send + 'a>>;

/// Future returned after a scheduler grants one negotiated transfer window.
pub type WindowScheduleFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), TempestError>> + Send + 'a>>;

/// Future returned by a provisioning-priority provider.
pub type ProvisioningPriorityFuture<'a> = Pin<Box<dyn Future<Output = Option<f64>> + Send + 'a>>;

/// Future returned when shared block storage checks its retention window.
pub type SharedBlockFuture<'a> = Pin<Box<dyn Future<Output = Option<Bytes>> + Send + 'a>>;

/// Future returned by an optional RRQ routing handler.
pub type ReadRequestRoutingFuture<'a> =
    Pin<Box<dyn Future<Output = Result<RouteDecision, TempestError>> + Send + 'a>>;

/// RRQ option that selects the version of Tempest-specific extension semantics.
pub const EXTENSION_PROTOCOL_VERSION_OPTION: &str = "x-tempest-protocol-version";
/// Current version of the Tempest-specific RRQ extension contract.
pub const EXTENSION_PROTOCOL_VERSION: &str = "2";
/// RRQ option by which a capable client explicitly requests redirect handling.
pub const REDIRECT_REQUEST_OPTION: &str = "x-tempest-redirect";
/// RRQ option binding a routed request to one release group.
pub const ROUTE_GROUP_OPTION: &str = "x-tempest-group-id";
/// RRQ option binding a routed request to one boot-profile namespace.
pub const ROUTE_BOOT_PROFILE_OPTION: &str = "x-tempest-boot-profile";
/// RRQ option binding a routed request to one artifact version.
pub const ROUTE_ARTIFACT_VERSION_OPTION: &str = "x-tempest-artifact-version";
/// RRQ option binding a routed request to one release manifest.
pub const ROUTE_MANIFEST_DIGEST_OPTION: &str = "x-tempest-manifest-digest";
/// RRQ option binding a routed request to the verified artifact bytes.
pub const ROUTE_CONTENT_HASH_OPTION: &str = "x-tempest-content-hash";
/// OACK option containing the redirect authorization expiry as Unix seconds.
pub const ROUTE_EXPIRY_OPTION: &str = "x-tempest-redirect-expiry";
/// OACK option containing the Ed25519 redirect authorization signature.
pub const ROUTE_SIGNATURE_OPTION: &str = "x-tempest-redirect-signature";

/// Future returned while an optional protocol pack prepares transfer state.
pub type ReadProtocolFuture<'a> = Pin<
    Box<
        dyn Future<Output = Result<Option<Box<dyn ReadProtocolSession>>, TempestError>> + Send + 'a,
    >,
>;

/// Future returned while an extension encodes one DATA packet.
pub type ReadProtocolEncodeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<EncodedDataPacket, TempestError>> + Send + 'a>>;

/// Future returned while an extension encodes a bounded batch of DATA packets.
pub type ReadProtocolBatchEncodeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<EncodedDataPacket>, TempestError>> + Send + 'a>>;

/// Payload supplied to a read-protocol encoder.
///
/// Core preserves already-owned shared blocks and avoids copying ordinary file
/// reads. An encoder that moves work to a blocking worker can call
/// [`Self::into_bytes`] to obtain owned storage only when it needs it.
pub enum ReadProtocolPayload<'a> {
    /// Bytes borrowed from core's reusable read buffer.
    Borrowed(&'a [u8]),
    /// Immutable bytes already owned by a cache or extension.
    Owned(Bytes),
}

impl ReadProtocolPayload<'_> {
    /// Return the payload as a byte slice without allocating.
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(payload) => payload,
            Self::Owned(payload) => payload,
        }
    }

    /// Return owned immutable storage, copying only a borrowed payload.
    pub fn into_bytes(self) -> Bytes {
        match self {
            Self::Borrowed(payload) => Bytes::copy_from_slice(payload),
            Self::Owned(payload) => payload,
        }
    }
}

/// Core-owned handle to the exact artifact opened and verified for a transfer.
///
/// Extensions can perform positioned reads without reopening a pathname. When
/// a managed hash is present, [`Self::read_all_verified`] rehashes the exact
/// bytes returned to the extension and rejects a mismatch.
#[derive(Clone)]
pub struct VerifiedArtifactSource {
    file: Arc<std::fs::File>,
    size: u64,
    expected_sha256: Option<String>,
}

impl std::fmt::Debug for VerifiedArtifactSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedArtifactSource")
            .field("size", &self.size)
            .field("managed", &self.expected_sha256.is_some())
            .finish_non_exhaustive()
    }
}

impl VerifiedArtifactSource {
    /// Construct a source from a handle whose identity and digest were verified.
    ///
    /// Tempest core is the normal caller. Alternate transfer engines must verify
    /// the supplied handle before constructing this capability.
    pub fn from_verified_file(
        file: std::fs::File,
        size: u64,
        expected_sha256: Option<String>,
    ) -> Self {
        Self {
            file: Arc::new(file),
            size,
            expected_sha256,
        }
    }

    /// Return the size observed on the verified handle.
    pub fn len(&self) -> u64 {
        self.size
    }

    /// Return whether this source contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Return the release-manifest digest expected for these bytes, if managed.
    pub fn expected_sha256(&self) -> Option<&str> {
        self.expected_sha256.as_deref()
    }

    /// Read and hash the complete verified handle without changing its cursor.
    ///
    /// The caller supplies its own byte ceiling so extension-specific memory
    /// budgets remain explicit. Managed sources fail if the returned byte stream
    /// no longer matches the release manifest.
    pub fn read_all_verified(&self, max_bytes: u64) -> Result<Bytes, TempestError> {
        if self.size > max_bytes {
            return Err(TempestError::Protocol(
                crate::error::ProtocolError::OptionNegotiation(
                    "verified artifact exceeds extension byte limit".into(),
                ),
            ));
        }
        let capacity = usize::try_from(self.size).map_err(|_| {
            TempestError::Protocol(crate::error::ProtocolError::OptionNegotiation(
                "verified artifact is too large for this platform".into(),
            ))
        })?;
        let mut contents = vec![0u8; capacity];
        let mut offset = 0usize;
        while offset < contents.len() {
            let read = positioned_read(&self.file, &mut contents[offset..], offset as u64)?;
            if read == 0 {
                return Err(TempestError::Protocol(
                    crate::error::ProtocolError::OptionNegotiation(
                        "verified artifact changed while being read".into(),
                    ),
                ));
            }
            offset += read;
        }

        if let Some(expected) = self.expected_sha256.as_deref() {
            let actual = hex::encode(Sha256::digest(&contents));
            if actual != expected {
                return Err(TempestError::Protocol(
                    crate::error::ProtocolError::VersionMismatch {
                        expected: expected.to_string(),
                        actual,
                    },
                ));
            }
        }
        Ok(Bytes::from(contents))
    }
}

#[cfg(unix)]
fn positioned_read(file: &std::fs::File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buffer, offset)
}

#[cfg(windows)]
fn positioned_read(file: &std::fs::File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buffer, offset)
}

#[cfg(not(any(unix, windows)))]
fn positioned_read(file: &std::fs::File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    use std::io::{Read, Seek};
    let mut file = file.try_clone()?;
    file.seek(std::io::SeekFrom::Start(offset))?;
    file.read(buffer)
}

/// Bounded transfer context supplied to an optional custom protocol pack.
#[derive(Debug, Clone)]
pub struct ReadProtocolContext {
    /// Raw RRQ options after packet parser size/count validation.
    pub requested_options: Vec<(String, String)>,
    /// Core-owned handle for the exact bytes verified for this transfer.
    pub source: VerifiedArtifactSource,
    /// File size observed after opening and verifying the artifact.
    pub file_size: u64,
    /// Negotiated RFC 2348 block size.
    pub block_size: u16,
    /// Negotiated RFC 7440 window size.
    pub window_size: u16,
    /// Managed artifact hash when the release resolver supplies one.
    pub content_hash: Option<String>,
    /// Source address used for bounded per-client extension state.
    pub client_ip: IpAddr,
}

/// Source decision for one absolute TFTP block index.
#[derive(Debug)]
pub enum ExtensionPayload {
    /// Read the ordinary file block in the OSS transfer engine.
    Core,
    /// Use extension-provided bytes instead of reading the ordinary file block.
    Data(Bytes),
    /// End the transfer without producing another packet.
    End,
}

/// Encoded TFTP DATA packet returned by a custom protocol session.
#[derive(Debug)]
pub struct EncodedDataPacket {
    /// Complete UDP payload, including TFTP opcode and block number.
    pub packet: BytesMut,
    /// Logical payload bytes attributed to transfer metrics.
    pub accounted_bytes: u64,
}

/// Immutable identity supplied after signed active-manifest resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRequestIdentity {
    /// Profile namespace selected by the boot session or fallback policy.
    pub boot_profile: String,
    /// Release group containing the requested artifact.
    pub group_id: String,
    /// Monotonic version shared by the release artifacts.
    pub artifact_version_id: u64,
    /// Digest binding the release manifest.
    pub manifest_digest: String,
    /// Verified SHA-256 digest of the requested artifact.
    pub content_hash: String,
}

/// Bounded context for routing a verified, release-managed RRQ.
#[derive(Debug, Clone)]
pub struct ReadRequestContext {
    /// Original client endpoint, including its UDP transfer identifier.
    pub client_addr: SocketAddr,
    /// Local address on which a routing extension may bind an ephemeral socket.
    pub server_bind: IpAddr,
    /// Requested logical filename after packet parser validation.
    pub filename: String,
    /// Raw RRQ options after packet parser size/count validation.
    pub requested_options: Vec<(String, String)>,
    /// Signed release identity. Unmanaged files have no routeable identity.
    pub identity: Option<ReadRequestIdentity>,
    /// Artifact size declared by the signed managed release.
    pub file_size: u64,
    /// Number of transfer slots currently reserved on this process.
    pub active_transfers: usize,
}

/// Core-owned routing decision for a release-managed RRQ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteDecision {
    /// Continue through the capability-confined local transfer path.
    Local,
    /// Emit a core-signed redirect to this numeric TFTP endpoint.
    Redirect(SocketAddr),
}

/// Canonically encode the fields authorized by a redirect signature.
///
/// Each variable-length field is prefixed with a big-endian `u32` length; the
/// expiry is a big-endian `u64`. This encoding is part of protocol v2.
pub fn redirect_signature_message(
    peer: SocketAddr,
    filename: &str,
    identity: &ReadRequestIdentity,
    expires_at: u64,
) -> Vec<u8> {
    let mut message = b"tempest-redirect-v2\0".to_vec();
    let peer = peer.to_string();
    for value in [
        peer.as_str(),
        filename,
        identity.boot_profile.as_str(),
        identity.group_id.as_str(),
        identity.manifest_digest.as_str(),
        identity.content_hash.as_str(),
    ] {
        let bytes = value.as_bytes();
        message.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        message.extend_from_slice(bytes);
    }
    message.extend_from_slice(&identity.artifact_version_id.to_be_bytes());
    message.extend_from_slice(&expires_at.to_be_bytes());
    message
}

/// Context used to rank an over-capacity request in an optional admission queue.
#[derive(Debug, Clone)]
pub struct AdmissionContext {
    /// Original client endpoint.
    pub client_addr: SocketAddr,
    /// Requested logical filename after packet parser validation.
    pub filename: String,
    /// Boot phase assigned by the public classifier.
    pub phase: BootPhase,
    /// Whether the request is a WRQ rather than an RRQ.
    pub is_write: bool,
}

/// Optional selector for a core-owned local or signed-redirect route.
pub trait ReadRequestRouter: Send + Sync {
    /// Select a route after active-manifest resolution and before local file I/O.
    fn handle(&self, context: ReadRequestContext) -> ReadRequestRoutingFuture<'_>;

    /// Record a release-managed artifact after core-owned local verification.
    /// Implementations must keep this synchronous callback bounded and non-blocking.
    fn local_artifact_verified(&self, _identity: &ReadRequestIdentity, _filename: &str) {}
}

/// Policy for the core's bounded over-capacity request queue.
///
/// Tempest retains ownership of request packets and transfer-slot accounting;
/// the extension supplies only bounded queue policy and launch timing.
pub trait AdmissionPolicy: Send + Sync {
    /// Maximum number of requests retained while all transfer slots are busy.
    fn queue_capacity(&self) -> usize;

    /// Maximum time a queued request remains eligible for launch.
    fn max_queue_age(&self) -> Duration;

    /// Return dequeue priority; larger finite values launch first.
    fn priority(&self, context: &AdmissionContext) -> f64;

    /// Return a bounded delay before starting the selected request.
    fn launch_delay(&self, _launch_sequence: u64) -> Duration {
        Duration::ZERO
    }
}

/// Factory for optional, versioned custom TFTP behavior.
pub trait ReadProtocolExtension: Send + Sync {
    /// Whether these bounded RRQ options require provider preparation.
    ///
    /// Returning false promises that `prepare` would return `None` without any
    /// required checks or side effects, allowing core's verified cache path.
    /// The conservative default preserves existing provider behavior.
    fn requires_preparation(&self, _requested_options: &[(String, String)]) -> bool {
        true
    }

    /// Prepare a transfer session, or return `None` when no supported custom
    /// option was requested.
    fn prepare(&self, context: ReadProtocolContext) -> ReadProtocolFuture<'_>;
}

/// Per-transfer state for a custom protocol pack.
pub trait ReadProtocolSession: Send {
    /// Additional options to append to the final OACK.
    fn oack_options(&self) -> Vec<(String, String)>;

    /// Decide whether an absolute block should be skipped.
    fn skip_block(&self, _absolute_block: u64, _wire_block: u16) -> bool {
        false
    }

    /// Select the source for an absolute block.
    fn payload(&self, _absolute_block: u64) -> ExtensionPayload {
        ExtensionPayload::Core
    }

    /// Whether the session consumes ordinary file blocks.
    fn uses_core_file(&self) -> bool {
        true
    }

    /// Return the number of ordinary file bytes represented by one DATA block.
    ///
    /// Framed protocols may reserve bytes from the negotiated RFC 2348 payload
    /// for their own header. The transfer engine clamps the result to
    /// `1..=negotiated_block_size` and still enforces the negotiated wire limit.
    fn core_payload_size(&self, negotiated_block_size: usize) -> usize {
        negotiated_block_size
    }

    /// Encode one DATA packet from the selected payload.
    ///
    /// # Errors
    ///
    /// Returns an error when extension encoding cannot safely represent the
    /// payload within the negotiated contract.
    fn encode_packet(
        &mut self,
        wire_block: u16,
        payload: &[u8],
    ) -> Result<EncodedDataPacket, TempestError>;

    /// Whether packet encoding needs the asynchronous worker path.
    fn uses_async_encoding(&self) -> bool {
        false
    }

    /// Opt into ordered encoding ahead of transmission for ordinary file data.
    ///
    /// Values above one promise that encoding is independent of send/ACK
    /// feedback. Core caps lookahead at 32 packets and 64 KiB of input, retains
    /// negotiated send windows, and discards lookahead on retransmission.
    /// Sparse or alternate-payload protocols should keep the default.
    fn encoding_batch_size(&self) -> usize {
        1
    }

    /// Encode an ordered batch, returning exactly one packet per input.
    /// CPU-heavy providers can amortize bounded worker dispatch here.
    fn encode_packets_async(
        &mut self,
        packets: Vec<(u16, Bytes)>,
    ) -> ReadProtocolBatchEncodeFuture<'_> {
        Box::pin(async move {
            let mut encoded = Vec::with_capacity(packets.len());
            for (block, payload) in packets {
                encoded.push(
                    self.encode_packet_async(block, ReadProtocolPayload::Owned(payload))
                        .await?,
                );
            }
            Ok(encoded)
        })
    }

    /// Encode one DATA packet without requiring CPU-heavy transforms to run on
    /// the Tokio worker driving the transfer.
    ///
    /// Lightweight implementations can use this default. Implementations that
    /// compress or otherwise transform payloads should override it with bounded
    /// worker execution.
    fn encode_packet_async<'a>(
        &'a mut self,
        wire_block: u16,
        payload: ReadProtocolPayload<'a>,
    ) -> ReadProtocolEncodeFuture<'a> {
        Box::pin(async move { self.encode_packet(wire_block, payload.as_slice()) })
    }

    /// Determine completion after a packet is accepted for transmission.
    fn transfer_complete(
        &self,
        _absolute_block: u64,
        payload_len: usize,
        block_size: usize,
    ) -> bool {
        payload_len < block_size
    }

    /// Whether timeout recovery should seek the ordinary file source.
    fn seek_file_on_retransmit(&self) -> bool {
        true
    }

    /// Record one sent block for bounded extension feedback.
    fn record_block_sent(&mut self) {}

    /// Record one retransmission signal for bounded extension feedback.
    fn record_retransmission(&mut self) {}
}

/// Factory for ACK-driven, per-transfer pacing state.
pub trait TransferPacing: Send + Sync {
    /// Start observing one transfer.
    fn start(
        &self,
        client_ip: IpAddr,
        block_size: usize,
        ceiling_bps: Option<f64>,
    ) -> Box<dyn TransferPacingSession>;
}

/// Pacing state owned for the lifetime of one read transfer.
pub trait TransferPacingSession: Send {
    /// Return the delay to apply after the next encoded DATA packet.
    fn current_delay(&self) -> Option<Duration>;

    /// Opt into rate pacing with at most this many packets of burst credit.
    /// Values above one interpret `current_delay` as a packet interval, credit
    /// elapsed processing/ACK time, and pace before sending. Core caps the burst
    /// at 32 packets and the negotiated window. One preserves post-send delays.
    fn max_burst_packets(&self) -> usize {
        1
    }

    /// Record an accepted ACK and the total DATA blocks sent so far.
    fn record_ack(&mut self, block: u16, blocks_sent: u64);
}

/// Factory for shared block storage used by concurrent readers.
pub trait SharedBlockCache: Send + Sync {
    /// Open a transfer-local view of one content and block-size identity.
    fn open(&self, key: &str, block_size: usize) -> Box<dyn SharedBlockSession>;
}

/// Transfer-local view of shared block storage.
///
/// Dropping a session must release reader registration held by the
/// implementation.
pub trait SharedBlockSession: Send {
    /// Return a retained block or `None` when the caller should read from disk.
    fn read(&self, absolute_block: usize) -> SharedBlockFuture<'_>;

    /// Publish a disk-read block when this session owns the shared writer role.
    fn publish(&self, absolute_block: usize, block: Bytes);
}

/// Optional source of scheduling priority for a provisioned machine.
///
/// Release selection and artifact staging use Tempest's HTTP control API. This
/// contract is intentionally narrower: it only supplies an optional scheduling
/// weight to a registered transfer scheduler.
pub trait ProvisioningPriorityProvider: Send + Sync {
    /// Look up a scheduling weight for one inventory serial number.
    ///
    /// Implementations return `None` when the serial is unknown or the backing
    /// service is unavailable. Schedulers remain responsible for validating and
    /// clamping any returned value.
    fn priority_for_serial<'a>(&'a self, serial: &'a str) -> ProvisioningPriorityFuture<'a>;
}

/// Optional packet scheduler used by the TFTP transfer path.
///
/// Implementations must transmit each packet through the supplied transfer
/// socket. Sending through a shared replacement socket would violate the TFTP
/// transfer-ID requirements in RFC 1350.
pub trait TransferScheduler: Send + Sync {
    /// Register scheduling metadata before the first DATA packet is submitted.
    fn register_transfer(
        &self,
        transfer_id: TransferId,
        phase: BootPhase,
        total_bytes: u64,
        provisioning_priority: Option<f64>,
    );

    /// Remove all scheduling state associated with a completed transfer.
    fn unregister_transfer(&self, transfer_id: &TransferId);

    /// Return an optional pacing ceiling for the registered transfer.
    fn phase_adjusted_ceiling(&self, transfer_id: &TransferId) -> Option<f64>;

    /// Wait until one negotiated transfer window may be transmitted.
    ///
    /// `packet_count` and `encoded_bytes` are bounded estimates for the next
    /// window. The default adapter grants immediately, preserving schedulers
    /// that only customize packet transmission. Cross-transfer schedulers can
    /// override this method to perform one queue operation per window.
    fn schedule_window(
        &self,
        _transfer_id: TransferId,
        _packet_count: usize,
        _encoded_bytes: usize,
    ) -> WindowScheduleFuture<'_> {
        Box::pin(async { Ok(()) })
    }

    /// Accept one encoded TFTP DATA packet for transmission.
    ///
    /// # Errors
    ///
    /// Returns an error when the scheduler cannot accept or transmit the
    /// packet. The transfer is then failed by the caller rather than silently
    /// bypassing the configured scheduler.
    fn send_packet(
        &self,
        transfer_id: TransferId,
        socket: Arc<UdpSocket>,
        data: BytesMut,
        destination: SocketAddr,
    ) -> PacketSendFuture<'_>;
}

/// Read-only HTTP response-production observation supplied by core.
///
/// Installed with [`crate::server::TftpServerBuilder::with_http_observer`].
/// Called once when response headers are ready, or when request processing is
/// cancelled (no status). Elapsed time excludes streaming the response body.
/// No headers, tokens, client addresses, raw paths, or bodies are exposed.
/// Callbacks must not panic or block and must bound any retained state or export
/// queue; telemetry overload must drop observations rather than block requests.
/// Core retains routing, authentication, rate limits, and response ownership.
#[derive(Clone, Debug)]
pub struct HttpObservation {
    /// Standard HTTP method, or `OTHER` for extension methods.
    pub method: &'static str,
    /// Core route template, or `None` when no route matched.
    pub route: Option<String>,
    /// HTTP status, or `None` if processing was cancelled before a response.
    pub status: Option<u16>,
    /// Time spent producing response headers, including core middleware.
    pub elapsed: Duration,
}
