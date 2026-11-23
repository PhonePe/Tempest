// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::collections::VecDeque;
use std::io::IoSlice;
use std::net::SocketAddr;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::{BufMut, Bytes, BytesMut};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::fs::File;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, BufReader, Interest, SeekFrom};
use tokio::net::UdpSocket;
use tracing::{debug, warn};

use crate::artifact_cache::{ArtifactContent, ArtifactIdentity, HotPathTicket, PreparedArtifact};
use crate::artifact_root::ArtifactRoot;
#[cfg(test)]
use crate::artifact_root::lexical_artifact_path;
use crate::error::{ProtocolError, TempestError, TftpErrorCode};
use crate::extension::{
    EXTENSION_PROTOCOL_VERSION, EXTENSION_PROTOCOL_VERSION_OPTION, EncodedDataPacket,
    ExtensionPayload, ROUTE_ARTIFACT_VERSION_OPTION, ROUTE_BOOT_PROFILE_OPTION,
    ROUTE_CONTENT_HASH_OPTION, ROUTE_EXPIRY_OPTION, ROUTE_GROUP_OPTION,
    ROUTE_MANIFEST_DIGEST_OPTION, ROUTE_SIGNATURE_OPTION, ReadProtocolContext, ReadProtocolPayload,
    ReadProtocolSession, ReadRequestContext, ReadRequestIdentity, RouteDecision,
    SharedBlockSession, TransferPacingSession, TransferScheduler, VerifiedArtifactSource,
    redirect_signature_message,
};
use crate::features::versioning::{BootChainPin, PinnedVersion, ResolvedFile};
use crate::protocol::options::NegotiatedOptions;
use crate::protocol::packet::{TftpPacket, TransferMode};
#[cfg(test)]
use crate::protocol::window::RetransmissionPolicy;
use crate::protocol::window::{TimeoutAction, WindowAdvance, WindowState};
use crate::server::{
    ExtensionFailure, ServerMetrics, ServerState, TRANSPORT_TFTP, active_boot_session,
    release_active_transfer_counter,
};

#[cfg(target_os = "linux")]
mod udp_gso;

#[cfg(target_os = "linux")]
pub(crate) fn initialize_udp_segmentation(bind: std::net::IpAddr) -> std::io::Result<()> {
    udp_gso::initialize(bind)
}

pub(crate) fn udp_segmentation_counters() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        udp_gso::counters()
    }
    #[cfg(not(target_os = "linux"))]
    {
        (0, 0)
    }
}

#[cfg(test)]
fn normalize_path_secure(root: &Path, filename: &str) -> Result<PathBuf, TempestError> {
    lexical_artifact_path(root, Path::new(filename))
}

/// RAII guard that decrements active_transfers when dropped,
/// unless `hand_off()` is called (transferring responsibility to metrics).
struct TransferSlotGuard {
    active_transfers: Arc<std::sync::atomic::AtomicUsize>,
    released: bool,
}

impl TransferSlotGuard {
    /// Arms a guard for a slot already counted as active.
    fn new(active_transfers: Arc<std::sync::atomic::AtomicUsize>) -> Self {
        Self {
            active_transfers,
            released: false,
        }
    }
    /// Call when entering the main transfer loop (metrics will handle cleanup).
    fn hand_off(&mut self) {
        self.released = true;
    }
}

impl Drop for TransferSlotGuard {
    fn drop(&mut self) {
        if !self.released {
            release_active_transfer_counter(&self.active_transfers);
        }
    }
}

/// Sends a DATA datagram through the scheduler or directly through its transfer socket.
///
/// Direct sends return their storage so the standard transfer path can reuse it.
async fn send_data_packet(
    socket: &Arc<UdpSocket>,
    scheduler: Option<&dyn TransferScheduler>,
    metrics: &ServerMetrics,
    transfer_id: TransferId,
    client_addr: SocketAddr,
    data_pkt: BytesMut,
) -> Result<BytesMut, TempestError> {
    if let Some(scheduler) = scheduler {
        if let Err(error) = scheduler
            .send_packet(transfer_id, socket.clone(), data_pkt, client_addr)
            .await
        {
            metrics.extension_failed(ExtensionFailure::SchedulerSendPacket);
            return Err(error);
        }
        Ok(BytesMut::new())
    } else {
        socket.send_to(&data_pkt, client_addr).await?;
        Ok(data_pkt)
    }
}

/// Sends a standard DATA packet from retained immutable bytes without building
/// a second contiguous payload buffer.
async fn send_cached_data_packet(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    block_number: u16,
    payload: &[u8],
) -> Result<(), TempestError> {
    let mut header = [0u8; 4];
    header[..2].copy_from_slice(&3u16.to_be_bytes());
    header[2..].copy_from_slice(&block_number.to_be_bytes());
    let slices = [IoSlice::new(&header), IoSlice::new(payload)];
    let destination = socket2::SockAddr::from(client_addr);
    let expected = header.len().saturating_add(payload.len());
    socket
        .async_io(Interest::WRITABLE, || {
            let sent = socket2::SockRef::from(socket).send_to_vectored(&slices, &destination)?;
            if sent == expected {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "partial UDP datagram send",
                ))
            }
        })
        .await?;
    Ok(())
}

/// One DATA datagram whose payload is borrowed from a stable window buffer.
struct WindowDataPacket {
    header: [u8; 4],
    payload: Range<usize>,
}

impl WindowDataPacket {
    fn new(block_number: u16, payload: Range<usize>) -> Self {
        let mut header = [0u8; 4];
        header[..2].copy_from_slice(&3u16.to_be_bytes());
        header[2..].copy_from_slice(&block_number.to_be_bytes());
        Self { header, payload }
    }

    fn wire_len(&self) -> usize {
        self.header.len().saturating_add(self.payload.len())
    }
}

fn governed_batch_len(packets: &[WindowDataPacket], burst_cap: u64) -> usize {
    let maximum_bytes = usize::try_from(burst_cap).unwrap_or(usize::MAX).max(1);
    let mut batch_bytes = 0usize;
    let mut batch_len = 0usize;
    for packet in packets {
        let next_bytes = batch_bytes.saturating_add(packet.wire_len());
        if batch_len > 0 && next_bytes > maximum_bytes {
            break;
        }
        batch_bytes = next_bytes;
        batch_len += 1;
    }
    batch_len
}

#[cfg(target_os = "linux")]
fn try_send_data_batch<const N: usize>(
    socket: &UdpSocket,
    destination: &rustix::net::SocketAddrAny,
    artifact: &[u8],
    packets: &[WindowDataPacket],
) -> std::io::Result<usize> {
    debug_assert!(packets.len() <= N);
    let slices: [[IoSlice<'_>; 2]; N] = std::array::from_fn(|index| {
        packets.get(index).map_or_else(
            || [IoSlice::new(&[]), IoSlice::new(&[])],
            |packet| {
                [
                    IoSlice::new(&packet.header),
                    IoSlice::new(&artifact[packet.payload.clone()]),
                ]
            },
        )
    });
    let mut controls: [rustix::net::SendAncillaryBuffer<'_, '_, '_>; N] =
        std::array::from_fn(|_| Default::default());
    let mut message_inputs = slices.iter().zip(controls.iter_mut());
    let mut messages: [rustix::net::MMsgHdr<'_>; N] = std::array::from_fn(|_| {
        let (iov, control) = message_inputs
            .next()
            .expect("message input arrays have identical lengths");
        rustix::net::MMsgHdr::new_with_addr(destination, iov, control)
    });
    let messages = &mut messages[..packets.len()];
    let count = rustix::net::sendmmsg(socket, messages, rustix::net::SendFlags::DONTWAIT)
        .map_err(|error| std::io::Error::from_raw_os_error(error.raw_os_error()))?;
    if count == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "sendmmsg sent no UDP datagrams",
        ));
    }
    if messages[..count]
        .iter()
        .zip(packets)
        .any(|(message, packet)| message.bytes_sent() != packet.wire_len())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "partial UDP datagram in sendmmsg batch",
        ));
    }
    Ok(count)
}

#[derive(Default)]
struct DataWindowSendState {
    #[cfg(target_os = "linux")]
    gso: udp_gso::GsoState,
}

impl DataWindowSendState {
    fn new(udp_segmentation_offload: bool) -> Self {
        #[cfg(not(target_os = "linux"))]
        let _ = udp_segmentation_offload;
        Self {
            #[cfg(target_os = "linux")]
            gso: udp_gso::GsoState::new(udp_segmentation_offload),
        }
    }
}

/// Sends one negotiated window while retaining each UDP datagram boundary.
///
/// Linux uses `sendmmsg` by default. Opt-in bounded UDP segmentation falls back
/// per transfer when rejected. Other platforms retain vectored sends.
async fn send_data_window_batch(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    artifact: &[u8],
    packets: &[WindowDataPacket],
    send_state: &mut DataWindowSendState,
) -> Result<(), TempestError> {
    if packets.len() <= 1 {
        if let Some(packet) = packets.first() {
            send_cached_data_packet(
                socket,
                client_addr,
                u16::from_be_bytes([packet.header[2], packet.header[3]]),
                &artifact[packet.payload.clone()],
            )
            .await?;
        }
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let destination = rustix::net::SocketAddrAny::from(client_addr);
        let mut sent_packets = 0;
        while sent_packets < packets.len() {
            let remaining = &packets[sent_packets..];
            let sent = socket
                .async_io(Interest::WRITABLE, || {
                    if let Some(sent) =
                        send_state
                            .gso
                            .try_send(socket, client_addr, artifact, remaining)?
                    {
                        return Ok(sent);
                    }
                    match remaining.len() {
                        0 => Ok(0),
                        1..=8 => {
                            try_send_data_batch::<8>(socket, &destination, artifact, remaining)
                        }
                        9..=16 => {
                            try_send_data_batch::<16>(socket, &destination, artifact, remaining)
                        }
                        17..=32 => {
                            try_send_data_batch::<32>(socket, &destination, artifact, remaining)
                        }
                        _ => try_send_data_batch::<64>(socket, &destination, artifact, remaining),
                    }
                })
                .await;
            let sent = match sent {
                Ok(sent) => sent,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            sent_packets = sent_packets.saturating_add(sent);
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = send_state;
        for packet in packets {
            send_cached_data_packet(
                socket,
                client_addr,
                u16::from_be_bytes([packet.header[2], packet.header[3]]),
                &artifact[packet.payload.clone()],
            )
            .await?;
        }
        Ok(())
    }
}

/// Shapes and sends one DATA window in the largest burst-bounded groups.
///
/// A fast link normally admits the full negotiated window in one group. At a
/// low configured rate, smaller groups prevent waiting for and releasing a
/// burst larger than the governor's explicit cap.
async fn send_data_window(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    artifact: &[u8],
    packets: &[WindowDataPacket],
    governor: Option<&crate::features::bandwidth_governor::BandwidthGovernor>,
    send_state: &mut DataWindowSendState,
) -> Result<(), TempestError> {
    let mut sent_packets = 0usize;
    while sent_packets < packets.len() {
        let remaining = &packets[sent_packets..];
        let batch_len = governor.map_or(remaining.len(), |governor| {
            governed_batch_len(remaining, governor.burst_cap())
        });
        debug_assert!(batch_len > 0);
        let batch = &remaining[..batch_len];
        if let Some(governor) = governor {
            let wire_bytes = batch
                .iter()
                .map(WindowDataPacket::wire_len)
                .fold(0usize, usize::saturating_add);
            governor.acquire(wire_bytes).await;
        }
        send_data_window_batch(socket, client_addr, artifact, batch, send_state).await?;
        sent_packets = sent_packets.saturating_add(batch_len);
    }
    Ok(())
}

/// Describes one bounded standard DATA window without copying its payload.
///
/// `end_of_source` is true only when the supplied bytes reach EOF. An empty
/// final DATA packet is retained when the artifact length is an exact multiple
/// of the negotiated block size, as required by TFTP.
fn describe_data_window(
    packets: &mut Vec<WindowDataPacket>,
    first_block: u16,
    available_bytes: usize,
    block_size: usize,
    packet_capacity: usize,
    end_of_source: bool,
) -> bool {
    debug_assert!(block_size > 0);
    debug_assert!(packet_capacity > 0);
    packets.clear();

    let data_packets = available_bytes.div_ceil(block_size);
    let needs_empty_final = end_of_source && available_bytes % block_size == 0;
    let packet_count = data_packets.saturating_add(usize::from(needs_empty_final));
    debug_assert!(packet_count <= packet_capacity);

    for ordinal in 0..packet_count {
        let start = ordinal.saturating_mul(block_size).min(available_bytes);
        let end = start.saturating_add(block_size).min(available_bytes);
        packets.push(WindowDataPacket::new(
            first_block.wrapping_add(ordinal as u16),
            start..end,
        ));
    }
    end_of_source
}

struct StandardWindowExchange<'a> {
    socket: &'a UdpSocket,
    client_addr: SocketAddr,
    payload_size: usize,
    file: &'a mut ArtifactReader,
    retained_artifact: Option<&'a Bytes>,
    file_buffer: &'a mut Vec<u8>,
    packets: &'a mut Vec<WindowDataPacket>,
    governor: Option<&'a crate::features::bandwidth_governor::BandwidthGovernor>,
    send_state: &'a mut DataWindowSendState,
}

struct SentDataWindow {
    transfer_complete: bool,
    payload_bytes: u64,
    blocks: usize,
}

async fn send_standard_data_window(
    exchange: StandardWindowExchange<'_>,
    first_block_index: u64,
    first_block_number: u16,
    packet_capacity: usize,
) -> Result<SentDataWindow, TempestError> {
    let maximum_bytes = packet_capacity.saturating_mul(exchange.payload_size);
    let offset = first_block_index
        .saturating_sub(1)
        .saturating_mul(exchange.payload_size as u64);

    let transfer_complete = if let Some(artifact) = exchange.retained_artifact {
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(artifact.len());
        let end = start.saturating_add(maximum_bytes).min(artifact.len());
        let window_bytes = &artifact[start..end];
        let end_of_source = window_bytes.len() < maximum_bytes;
        let complete = describe_data_window(
            exchange.packets,
            first_block_number,
            window_bytes.len(),
            exchange.payload_size,
            packet_capacity,
            end_of_source,
        );
        send_data_window(
            exchange.socket,
            exchange.client_addr,
            window_bytes,
            exchange.packets,
            exchange.governor,
            exchange.send_state,
        )
        .await?;
        complete
    } else {
        exchange.file_buffer.resize(maximum_bytes, 0);
        let bytes_read = exchange
            .file
            .read_block(offset, exchange.file_buffer)
            .await?;
        exchange.file_buffer.truncate(bytes_read);
        let end_of_source = bytes_read < maximum_bytes;
        let complete = describe_data_window(
            exchange.packets,
            first_block_number,
            bytes_read,
            exchange.payload_size,
            packet_capacity,
            end_of_source,
        );
        send_data_window(
            exchange.socket,
            exchange.client_addr,
            exchange.file_buffer,
            exchange.packets,
            exchange.governor,
            exchange.send_state,
        )
        .await?;
        complete
    };

    debug_assert!(!exchange.packets.is_empty());
    Ok(SentDataWindow {
        transfer_complete,
        payload_bytes: exchange
            .packets
            .iter()
            .map(|packet| packet.payload.len() as u64)
            .sum(),
        blocks: exchange.packets.len(),
    })
}

/// Returns whether the core transfer engine can serve `mode` without conversion.
pub fn supported_transfer_mode(mode: TransferMode) -> bool {
    matches!(mode, TransferMode::Octet)
}

const MAX_UNKNOWN_TID_RESPONSES_PER_EXCHANGE: u8 = 4;

#[derive(Debug)]
struct UnknownTidResponder {
    responses_remaining: u8,
}

impl Default for UnknownTidResponder {
    fn default() -> Self {
        Self {
            responses_remaining: MAX_UNKNOWN_TID_RESPONSES_PER_EXCHANGE,
        }
    }
}

/// Receives from the expected peer and rejects a bounded number of other TIDs.
async fn recv_from_transfer_peer(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    buf: &mut [u8],
    unknown_tid_responder: &mut UnknownTidResponder,
) -> Result<usize, std::io::Error> {
    loop {
        let (len, peer) = socket.recv_from(buf).await?;
        if peer == client_addr {
            return Ok(len);
        }

        if unknown_tid_responder.responses_remaining > 0 {
            unknown_tid_responder.responses_remaining -= 1;
            let err_pkt =
                TftpPacket::error(TftpErrorCode::UnknownTransferId, "Unknown transfer ID");
            let _ = socket.send_to(&err_pkt, peer).await;
        }
    }
}

/// Releases an in-flight artifact version pin when the transfer scope ends.
pub(crate) struct PinnedVersionGuard<'a> {
    version_store: &'a crate::features::versioning::VersionStore,
    pinned: Option<PinnedVersion>,
}

impl<'a> PinnedVersionGuard<'a> {
    /// Wraps an existing version pin without incrementing its count.
    pub(crate) fn new(
        version_store: &'a crate::features::versioning::VersionStore,
        pinned: Option<PinnedVersion>,
    ) -> Self {
        Self {
            version_store,
            pinned,
        }
    }

    /// Transfers the existing pin to the caller of session resolution.
    pub(crate) fn hand_off(mut self) -> Option<PinnedVersion> {
        self.pinned.take()
    }
}

impl Drop for PinnedVersionGuard<'_> {
    fn drop(&mut self) {
        if let Some(pinned) = self.pinned.take() {
            self.version_store.unpin_version_for_profile(
                &pinned.boot_profile,
                &pinned.logical_name,
                pinned.version_id,
            );
        }
    }
}

/// Registers scheduler state for a transfer and removes it on drop.
struct SchedulerTransferGuard {
    scheduler: Option<Arc<dyn TransferScheduler>>,
    transfer_id: TransferId,
}

impl SchedulerTransferGuard {
    /// Registers transfer metadata when a scheduler is installed.
    fn register(
        scheduler: Option<Arc<dyn TransferScheduler>>,
        transfer_id: TransferId,
        phase: crate::features::boot_phase::BootPhase,
        total_bytes: u64,
        provisioning_priority: Option<f64>,
    ) -> Self {
        if let Some(ref scheduler) = scheduler {
            scheduler.register_transfer(transfer_id, phase, total_bytes, provisioning_priority);
        }

        Self {
            scheduler,
            transfer_id,
        }
    }

    /// Returns the installed scheduler used for packet dispatch.
    fn scheduler(&self) -> Option<&dyn TransferScheduler> {
        self.scheduler.as_deref()
    }
}

impl Drop for SchedulerTransferGuard {
    fn drop(&mut self) {
        if let Some(ref scheduler) = self.scheduler {
            scheduler.unregister_transfer(&self.transfer_id);
        }
    }
}

/// Records transfer failure on drop unless terminal success was reported.
struct TransferLifecycleGuard<'a> {
    metrics: Arc<ServerMetrics>,
    phase: crate::features::boot_phase::BootPhase,
    boot_profile: &'a str,
    completed: bool,
}

impl<'a> TransferLifecycleGuard<'a> {
    /// Arms failure reporting for a started transfer.
    fn new(
        metrics: Arc<ServerMetrics>,
        phase: crate::features::boot_phase::BootPhase,
        boot_profile: &'a str,
    ) -> Self {
        Self {
            metrics,
            phase,
            boot_profile,
            completed: false,
        }
    }

    /// Suppresses drop-time failure reporting after successful completion.
    fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for TransferLifecycleGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.metrics.transfer_failed(&self.phase, self.boot_profile);
        }
    }
}

/// Returns the root-relative quarantine key for a resolved artifact path.
fn quarantine_key_for_resolved_path(path: &Path, root: &Path) -> Option<String> {
    let relative = path
        .strip_prefix(root)
        .ok()
        .map(Path::to_path_buf)
        .or_else(|| {
            let canonical_root = root.canonicalize().ok()?;
            let canonical_path = path.canonicalize().ok()?;
            canonical_path
                .strip_prefix(canonical_root)
                .ok()
                .map(Path::to_path_buf)
        })?;

    Some(relative.to_string_lossy().replace('\\', "/"))
}

/// RAII guard that removes a temp file if not committed.
struct TempFileGuard {
    root: Arc<ArtifactRoot>,
    relative_path: PathBuf,
    committed: bool,
}

impl TempFileGuard {
    /// Arms cleanup for a temporary file path.
    fn new(root: Arc<ArtifactRoot>, relative_path: PathBuf) -> Self {
        Self {
            root,
            relative_path,
            committed: false,
        }
    }

    /// Preserves the file after its atomic commit succeeds.
    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if !self.committed {
            self.root.remove_file(&self.relative_path);
        }
    }
}

/// Unique transfer identifier.
pub use crate::extension::TransferId;

/// Transfer direction
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    /// Server-to-client RRQ transfer.
    Read,
    /// Client-to-server WRQ transfer.
    Write,
}

/// Per-transfer metrics
#[derive(Debug, Default)]
pub struct TransferMetrics {
    /// Payload bytes successfully accounted for, excluding TFTP headers.
    pub bytes_sent: u64,
    /// DATA blocks sent, including retransmitted blocks where recorded.
    pub blocks_sent: u64,
    /// Number of retransmission events.
    pub retransmissions: u64,
    /// Monotonic transfer start timestamp.
    pub start_time: Option<Instant>,
    /// Monotonic completion or failure timestamp.
    pub end_time: Option<Instant>,
    /// Expected managed content hash; failure does not imply verified delivery.
    pub content_hash: Option<String>,
    /// Release-local version identifier when the artifact was managed.
    pub artifact_version_id: Option<u64>,
    /// Profile release identity pinned for this transfer.
    pub boot_chain: Option<BootChainPin>,
    /// Whether core emitted a signed redirect instead of delivering bytes.
    pub redirected: bool,
}

impl TransferMetrics {
    /// Returns elapsed wall-clock duration, using the current instant if active.
    pub fn duration(&self) -> Option<Duration> {
        match (self.start_time, self.end_time) {
            (Some(s), Some(e)) => Some(e.duration_since(s)),
            (Some(s), None) => Some(s.elapsed()),
            _ => None,
        }
    }

    /// Returns average payload throughput in bits per second.
    pub fn throughput_bps(&self) -> Option<f64> {
        self.duration().map(|d| {
            let secs = d.as_secs_f64();
            if secs > 0.0 {
                (self.bytes_sent as f64 * 8.0) / secs
            } else {
                0.0
            }
        })
    }
}

/// Verifies an opened managed artifact against its pinned size and content hash.
pub(crate) async fn verify_opened_artifact(
    file: &mut File,
    path: &Path,
    pinned: Option<&PinnedVersion>,
    store: &crate::features::versioning::VersionStore,
) -> Result<(), TempestError> {
    let Some(pinned) = pinned else { return Ok(()) };
    let metadata = file.metadata().await?;
    verify_opened_artifact_with_metadata(file, path, &metadata, Some(pinned), store).await
}

/// Verifies an opened artifact using metadata obtained from that same handle.
///
/// Callers that capability-opened and described the file together can avoid an
/// additional blocking-pool metadata operation on the request path.
pub(crate) async fn verify_opened_artifact_with_metadata(
    file: &mut File,
    path: &Path,
    metadata: &std::fs::Metadata,
    pinned: Option<&PinnedVersion>,
    store: &crate::features::versioning::VersionStore,
) -> Result<(), TempestError> {
    let Some(pinned) = pinned else { return Ok(()) };
    if metadata.len() != pinned.size {
        return Err(TempestError::Protocol(ProtocolError::VersionMismatch {
            expected: pinned.content_hash.clone(),
            actual: "size mismatch".into(),
        }));
    }
    let verification = store.artifact_verification(path, metadata, &pinned.content_hash);
    let actual = verification
        .get_or_try_init(|| async {
            // Only the single-flight owner consumes a worker. The blocking task
            // retains its permit and opened handle even if this request is cancelled.
            let permit = store
                .artifact_hash_budget
                .clone()
                .acquire_owned()
                .await
                .map_err(|error| TempestError::Io(std::io::Error::other(error)))?;
            let opened = file.try_clone().await?.into_std().await;
            let path = path.to_path_buf();
            let before = metadata.clone();
            let (hash, _) = tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let size = before.len();
                crate::features::versioning::hash_stable_open_file(
                    opened,
                    &path,
                    before,
                    Some(size),
                )
            })
            .await
            .map_err(|error| TempestError::Io(std::io::Error::other(error)))?
            .map_err(|error| match error {
                TempestError::Version(_) => {
                    TempestError::Protocol(ProtocolError::VersionMismatch {
                        expected: pinned.content_hash.clone(),
                        actual: "file changed during verification".into(),
                    })
                }
                other => other,
            })?;
            file.seek(SeekFrom::Start(0)).await?;
            Ok::<_, TempestError>(hash)
        })
        .await?;
    if bool::from(actual.as_bytes().ct_eq(pinned.content_hash.as_bytes())) {
        Ok(())
    } else {
        Err(TempestError::Protocol(ProtocolError::VersionMismatch {
            expected: pinned.content_hash.clone(),
            actual: actual.clone(),
        }))
    }
}

pub(crate) async fn verify_cached_artifact(
    bytes: &Arc<Bytes>,
    path: &Path,
    metadata: &std::fs::Metadata,
    pinned: Option<&PinnedVersion>,
    store: &crate::features::versioning::VersionStore,
) -> Result<(), TempestError> {
    let Some(pinned) = pinned else { return Ok(()) };
    if metadata.len() != pinned.size {
        return Err(TempestError::Protocol(ProtocolError::VersionMismatch {
            expected: pinned.content_hash.clone(),
            actual: "size mismatch".into(),
        }));
    }
    let verification = store.artifact_verification(path, metadata, &pinned.content_hash);
    let source = bytes.clone();
    let actual = verification
        .get_or_try_init(|| async move {
            let permit = store
                .artifact_hash_budget
                .clone()
                .acquire_owned()
                .await
                .map_err(|error| TempestError::Io(std::io::Error::other(error)))?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                hex::encode(Sha256::digest(source.as_ref()))
            })
            .await
            .map_err(|error| TempestError::Io(std::io::Error::other(error)))
        })
        .await?;
    if bool::from(actual.as_bytes().ct_eq(pinned.content_hash.as_bytes())) {
        Ok(())
    } else {
        Err(TempestError::Protocol(ProtocolError::VersionMismatch {
            expected: pinned.content_hash.clone(),
            actual: actual.clone(),
        }))
    }
}

/// Builds the standard OACK values that differ from RFC defaults.
#[cfg(test)]
fn base_oack_options(options: &NegotiatedOptions) -> Vec<(String, String)> {
    let mut result = Vec::with_capacity(8);
    if options.block_size != 512 {
        result.push(("blksize".into(), options.block_size.to_string()));
    }
    if options.window_size != 1 {
        result.push(("windowsize".into(), options.window_size.to_string()));
    }
    if options.timeout_requested {
        result.push(("timeout".into(), options.timeout.to_string()));
    }
    result
}

fn put_oack_option(packet: &mut BytesMut, name: &[u8], value: &[u8]) {
    packet.put_slice(name);
    packet.put_u8(0);
    packet.put_slice(value);
    packet.put_u8(0);
}

fn decimal_bytes(value: u64, storage: &mut [u8; 20]) -> &[u8] {
    let mut cursor = storage.len();
    let mut remaining = value;
    loop {
        cursor -= 1;
        storage[cursor] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
        if remaining == 0 {
            return &storage[cursor..];
        }
    }
}

/// Serializes the final OACK once, after authoritative size and extension
/// values are known, without allocating temporary decimal strings.
fn build_oack_packet(
    options: &NegotiatedOptions,
    transfer_size: Option<u64>,
    extension_options: &[(String, String)],
) -> Option<BytesMut> {
    let has_standard_options = options.block_size != 512
        || options.window_size != 1
        || options.timeout_requested
        || transfer_size.is_some();
    if !has_standard_options && extension_options.is_empty() {
        return None;
    }

    let mut packet = BytesMut::with_capacity(128);
    packet.put_u16(6);
    let mut digits = [0u8; 20];
    if options.block_size != 512 {
        put_oack_option(
            &mut packet,
            b"blksize",
            decimal_bytes(u64::from(options.block_size), &mut digits),
        );
    }
    if options.window_size != 1 {
        put_oack_option(
            &mut packet,
            b"windowsize",
            decimal_bytes(u64::from(options.window_size), &mut digits),
        );
    }
    if options.timeout_requested {
        put_oack_option(
            &mut packet,
            b"timeout",
            decimal_bytes(u64::from(options.timeout), &mut digits),
        );
    }
    if let Some(size) = transfer_size {
        put_oack_option(&mut packet, b"tsize", decimal_bytes(size, &mut digits));
    }
    for (name, value) in extension_options {
        put_oack_option(&mut packet, name.as_bytes(), value.as_bytes());
    }
    Some(packet)
}

async fn exchange_oack(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    options: &NegotiatedOptions,
    packet: Option<&[u8]>,
    transfer_id: TransferId,
    duplicate_request: Option<&tokio::sync::Notify>,
) -> Result<(), TempestError> {
    let Some(packet) = packet else {
        return Ok(());
    };
    let mut buffer = [0u8; 512];
    let mut unknown_tid_responder = UnknownTidResponder::default();
    // The option handshake has not begun moving artifact bytes and must not
    // retain a socket and capacity slot for the full data retry budget.
    const MAX_OACK_RETRIES: u8 = 3;
    let max_retries = options.max_retries.min(MAX_OACK_RETRIES);
    // RFC 2347 starts DATA only after ACK(0). Keep the transfer TID alive and
    // resend the same OACK when either it or the ACK is lost.
    let mut retry = 0;
    loop {
        // Register before sending so an RRQ retransmission racing this OACK
        // cannot be lost between the listener lookup and this wait.
        let duplicate = async {
            match duplicate_request {
                Some(signal) => signal.notified().await,
                None => std::future::pending().await,
            }
        };
        tokio::pin!(duplicate);
        socket.send_to(packet, client_addr).await?;

        let response = tokio::select! {
            biased;
            response = tokio::time::timeout(options.retransmission_policy.retry_rto(retry), async {
                loop {
                    let length = recv_from_transfer_peer(
                        socket,
                        client_addr,
                        &mut buffer,
                        &mut unknown_tid_responder,
                    )
                    .await?;
                    match TftpPacket::parse(&buffer[..length], client_addr) {
                        Ok(TftpPacket::Ack(ack)) if ack.block == 0 => return Ok(()),
                        Ok(TftpPacket::Error(error)) => {
                            let safe_message: String = error
                                .message
                                .chars()
                                .map(|character| {
                                    if character.is_control() {
                                        '_'
                                    } else {
                                        character
                                    }
                                })
                                .take(200)
                                .collect();
                            warn!(
                                transfer_id = %transfer_id,
                                "Client rejected options: {} (code {})",
                                safe_message,
                                error.code
                            );
                            return Err(TempestError::Protocol(ProtocolError::OptionNegotiation(
                                error.message,
                            )));
                        }
                        Ok(_) => {
                            debug!(
                                transfer_id = %transfer_id,
                                "Ignoring unexpected response while awaiting ACK(0)"
                            );
                        }
                        Err(error) => {
                            debug!(
                                transfer_id = %transfer_id,
                                error = %error,
                                "Ignoring malformed response while awaiting ACK(0)"
                            );
                        }
                    }
                }
            }) => response,
            () = &mut duplicate => {
                if retry >= max_retries {
                    return Err(TempestError::Protocol(ProtocolError::Timeout {
                        addr: client_addr,
                        block: 0,
                    }));
                }
                retry += 1;
                debug!(
                    transfer_id = %transfer_id,
                    retry,
                    "Duplicate request received; resending OACK from existing transfer TID"
                );
                continue;
            }
        };

        match response {
            Ok(result) => return result,
            Err(_) if retry < max_retries => {
                retry += 1;
                debug!(
                    transfer_id = %transfer_id,
                    retry,
                    "OACK acknowledgement timed out; retrying"
                );
            }
            Err(_) => {
                return Err(TempestError::Protocol(ProtocolError::Timeout {
                    addr: client_addr,
                    block: 0,
                }));
            }
        }
    }
}

fn pacing_delay(
    block_size: usize,
    rate_bytes_per_second: f64,
    ceiling_bytes_per_second: Option<f64>,
) -> Option<Duration> {
    let effective_rate = match ceiling_bytes_per_second {
        Some(ceiling) if ceiling.is_finite() && ceiling > 0.0 => rate_bytes_per_second.min(ceiling),
        _ => rate_bytes_per_second,
    };
    if !effective_rate.is_finite() || effective_rate <= 0.0 {
        return None;
    }

    let seconds = block_size as f64 / effective_rate;
    Some(Duration::from_secs_f64(seconds.clamp(10e-6, 10.0)))
}

/// Absolute rate clock with bounded burst credit, not one timer per DATA packet.
struct PacketPacer {
    next_send: tokio::time::Instant,
    interval: Option<Duration>,
}

impl PacketPacer {
    fn new() -> Self {
        Self {
            next_send: tokio::time::Instant::now(),
            interval: None,
        }
    }

    async fn before_send(&mut self, interval: Option<Duration>, burst: usize) {
        let Some(interval) = interval.filter(|delay| !delay.is_zero()) else {
            self.interval = None;
            return;
        };
        let interval = interval.min(Duration::from_secs(10));
        if self.interval != Some(interval) {
            self.next_send = tokio::time::Instant::now();
            self.interval = Some(interval);
        }
        let credit = interval.saturating_mul(burst.clamp(1, 32) as u32 - 1);
        if let Some(deadline) = self.next_send.checked_sub(credit) {
            if deadline > tokio::time::Instant::now() {
                tokio::time::sleep_until(deadline).await;
            }
        }
        // Discard idle credit beyond the bounded burst; processing and ACK time
        // already elapsed must not incur an additional relative sleep.
        self.next_send = self.next_send.max(tokio::time::Instant::now()) + interval;
    }
}

fn requested_option<'a>(options: &'a [(String, String)], name: &str) -> Option<&'a str> {
    options
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn verified_read_identity(
    boot_profile: &str,
    pinned: Option<&PinnedVersion>,
    boot_chain: Option<&BootChainPin>,
    content_hash: Option<&str>,
) -> Option<ReadRequestIdentity> {
    let pinned = pinned?;
    let boot_chain = boot_chain?;
    let content_hash = content_hash?;
    (pinned.boot_profile == boot_profile
        && boot_chain.boot_profile == boot_profile
        && pinned.version_id == boot_chain.version_id
        && pinned.content_hash == content_hash)
        .then(|| ReadRequestIdentity {
            boot_profile: boot_profile.to_owned(),
            group_id: boot_chain.group_id.clone(),
            artifact_version_id: pinned.version_id,
            manifest_digest: boot_chain.manifest_digest.clone(),
            content_hash: content_hash.to_owned(),
        })
}

fn validate_requested_read_identity(
    requested_options: &[(String, String)],
    identity: Option<&ReadRequestIdentity>,
) -> Result<(), TempestError> {
    let identity_options = [
        ROUTE_BOOT_PROFILE_OPTION,
        ROUTE_GROUP_OPTION,
        ROUTE_ARTIFACT_VERSION_OPTION,
        ROUTE_MANIFEST_DIGEST_OPTION,
        ROUTE_CONTENT_HASH_OPTION,
    ];
    if !identity_options
        .iter()
        .any(|name| requested_option(requested_options, name).is_some())
    {
        return Ok(());
    }

    if requested_option(requested_options, EXTENSION_PROTOCOL_VERSION_OPTION)
        != Some(EXTENSION_PROTOCOL_VERSION)
    {
        return Err(TempestError::Protocol(ProtocolError::OptionNegotiation(
            "routed release identity requires a supported Tempest protocol version".into(),
        )));
    }
    let Some(identity) = identity else {
        return Err(TempestError::Protocol(ProtocolError::VersionMismatch {
            expected: "managed release identity".into(),
            actual: "unmanaged artifact".into(),
        }));
    };
    let expected_version = identity.artifact_version_id.to_string();
    let matches = requested_option(requested_options, ROUTE_GROUP_OPTION)
        == Some(identity.group_id.as_str())
        && requested_option(requested_options, ROUTE_BOOT_PROFILE_OPTION)
            == Some(identity.boot_profile.as_str())
        && requested_option(requested_options, ROUTE_ARTIFACT_VERSION_OPTION)
            == Some(expected_version.as_str())
        && requested_option(requested_options, ROUTE_MANIFEST_DIGEST_OPTION)
            == Some(identity.manifest_digest.as_str())
        && requested_option(requested_options, ROUTE_CONTENT_HASH_OPTION)
            == Some(identity.content_hash.as_str());
    if !matches {
        return Err(TempestError::Protocol(ProtocolError::VersionMismatch {
            expected: format!(
                "{}/{}/{}",
                identity.boot_profile, identity.group_id, identity.artifact_version_id
            ),
            actual: "routed request identity mismatch".into(),
        }));
    }
    Ok(())
}

/// Test helper for rejecting a final symlink outside the configured root.
#[cfg(test)]
fn check_symlink_escape(path: &Path, root: &Path) -> Result<(), TempestError> {
    if path.is_symlink() {
        if let Ok(real_path) = path.canonicalize() {
            let root_canonical = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());
            if !real_path.starts_with(&root_canonical) {
                return Err(TempestError::Protocol(ProtocolError::AccessViolation(
                    "symlink escapes root directory".to_string(),
                )));
            }
        }
    }
    Ok(())
}

/// Emit one short-lived redirect authorization signed by the manifest key.
async fn send_signed_redirect(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    peer: SocketAddr,
    filename: &str,
    identity: &ReadRequestIdentity,
    state: &ServerState,
) -> Result<(), TempestError> {
    const REDIRECT_TTL_SECS: u64 = 30;
    let expires_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TempestError::Config("system clock precedes Unix epoch".into()))?
        .as_secs()
        .saturating_add(REDIRECT_TTL_SECS);
    let message = redirect_signature_message(peer, filename, identity, expires_at);
    let signature = state.version_store.sign_manifest_message(&message)?;
    let packet = TftpPacket::oack(&[
        ("x-redirect-server".into(), peer.to_string()),
        (
            EXTENSION_PROTOCOL_VERSION_OPTION.into(),
            EXTENSION_PROTOCOL_VERSION.into(),
        ),
        (
            ROUTE_BOOT_PROFILE_OPTION.into(),
            identity.boot_profile.clone(),
        ),
        (ROUTE_GROUP_OPTION.into(), identity.group_id.clone()),
        (
            ROUTE_ARTIFACT_VERSION_OPTION.into(),
            identity.artifact_version_id.to_string(),
        ),
        (
            ROUTE_MANIFEST_DIGEST_OPTION.into(),
            identity.manifest_digest.clone(),
        ),
        (
            ROUTE_CONTENT_HASH_OPTION.into(),
            identity.content_hash.clone(),
        ),
        (ROUTE_EXPIRY_OPTION.into(), expires_at.to_string()),
        (ROUTE_SIGNATURE_OPTION.into(), signature),
    ]);
    socket.send_to(&packet, client_addr).await?;
    Ok(())
}

async fn resolve_read_file(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    boot_profile: &str,
    filename: &str,
    state: &ServerState,
) -> Result<ResolvedFile, TempestError> {
    match state
        .resolve_file_for_boot_session(client_addr.ip(), boot_profile, filename)
        .await
    {
        Ok(resolved) => Ok(resolved),
        Err(error) => {
            send_read_error(socket, client_addr, &error).await;
            Err(error)
        }
    }
}

async fn send_read_error(socket: &UdpSocket, client_addr: SocketAddr, error: &TempestError) {
    let (code, message) = match error {
        TempestError::Protocol(ProtocolError::FileNotFound(_)) => {
            (TftpErrorCode::FileNotFound, "File not found")
        }
        TempestError::Protocol(
            ProtocolError::AccessViolation(_) | ProtocolError::VersionMismatch { .. },
        ) => (TftpErrorCode::AccessViolation, "Artifact access denied"),
        TempestError::Conflict(_) => (
            TftpErrorCode::NotDefined,
            "Release state changed; retry request",
        ),
        TempestError::PersistenceBusy(_) | TempestError::PersistenceSnapshotStale => {
            (TftpErrorCode::NotDefined, "Server busy; retry request")
        }
        _ => (TftpErrorCode::NotDefined, "Artifact resolution failed"),
    };
    let _ = socket
        .send_to(&TftpPacket::error(code, message), client_addr)
        .await;
}

async fn route_read_request(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    filename: &str,
    requested_options: &[(String, String)],
    identity: Option<&ReadRequestIdentity>,
    file_size: u64,
    state: &ServerState,
) -> Result<RouteDecision, TempestError> {
    if let Err(error) = validate_requested_read_identity(requested_options, identity) {
        let packet = TftpPacket::error(
            TftpErrorCode::AccessViolation,
            "Routed release identity does not match",
        );
        let _ = socket.send_to(&packet, client_addr).await;
        return Err(error);
    }

    let Some(router) = state.read_request_router.as_ref() else {
        return Ok(RouteDecision::Local);
    };
    let decision = router
        .handle(ReadRequestContext {
            client_addr,
            server_bind: state.config.server.bind,
            filename: filename.to_owned(),
            requested_options: requested_options.to_vec(),
            identity: identity.cloned(),
            file_size,
            active_transfers: state
                .active_transfers
                .load(std::sync::atomic::Ordering::Acquire),
        })
        .await;
    match decision {
        Ok(RouteDecision::Local) => Ok(RouteDecision::Local),
        Ok(RouteDecision::Redirect(peer)) => {
            let identity = identity.ok_or_else(|| {
                TempestError::Protocol(ProtocolError::OptionNegotiation(
                    "redirect requires a managed release identity".into(),
                ))
            })?;
            send_signed_redirect(socket, client_addr, peer, filename, identity, state).await?;
            Ok(RouteDecision::Redirect(peer))
        }
        Err(error) => {
            state
                .metrics
                .extension_failed(ExtensionFailure::RouterHandle);
            let packet = TftpPacket::error(
                TftpErrorCode::IllegalOperation,
                "RRQ extension negotiation failed",
            );
            let _ = socket.send_to(&packet, client_addr).await;
            Err(error)
        }
    }
}

enum CoreReadSource {
    File(File),
    Memory(Arc<Bytes>),
}

struct PreparedReadSource {
    source: CoreReadSource,
    path: PathBuf,
    metadata: std::fs::Metadata,
    size: u64,
    protocol_session: Option<Box<dyn ReadProtocolSession>>,
}

fn open_core_read_source(
    artifact_root: &crate::artifact_root::ArtifactRoot,
    hot_artifact_cache: &crate::artifact_cache::HotArtifactCache,
    candidate: &Path,
    use_hot_cache: bool,
    hot_path_ticket: Option<HotPathTicket>,
) -> Result<(PreparedArtifact, PathBuf, std::fs::Metadata), TempestError> {
    let opened = artifact_root.open_read_with_metadata(candidate)?;
    let prepared = if let Some(ticket) = hot_path_ticket {
        hot_artifact_cache.prepare_ticket(ticket, opened.file, &opened.path, &opened.metadata)
    } else if use_hot_cache {
        hot_artifact_cache.prepare(opened.file, &opened.path, &opened.metadata)?
    } else {
        PreparedArtifact::File(opened.file)
    };
    Ok((prepared, opened.path, opened.metadata))
}

#[allow(clippy::too_many_arguments)]
async fn prepare_read_source(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    path: PathBuf,
    pinned_version: Option<&PinnedVersion>,
    content_hash: Option<&str>,
    requested_options: &[(String, String)],
    options: &NegotiatedOptions,
    state: &ServerState,
) -> Result<PreparedReadSource, TempestError> {
    if quarantine_key_for_resolved_path(&path, &state.config.server.root)
        .is_some_and(|key| state.quarantined_files.contains(key.as_str()))
    {
        let packet = TftpPacket::error(
            TftpErrorCode::AccessViolation,
            "File is quarantined due to integrity violation",
        );
        let _ = socket.send_to(&packet, client_addr).await;
        return Err(TempestError::Protocol(ProtocolError::AccessViolation(
            format!("quarantined: {}", path.display()),
        )));
    }

    let hot_artifact_cache = state.hot_artifact_cache.clone();
    let read_protocol = state
        .read_protocol
        .as_ref()
        .filter(|protocol| protocol.requires_preparation(requested_options));
    let use_hot_cache = read_protocol.is_none();
    let candidate = path;
    let verified_snapshot = pinned_version.and_then(|pinned| {
        use_hot_cache
            .then(|| {
                hot_artifact_cache.verified_path(&candidate, &pinned.content_hash, pinned.size)
            })
            .flatten()
    });
    let verified_cache_hit = verified_snapshot.is_some();
    let cached_snapshot = verified_snapshot.or_else(|| {
        (use_hot_cache && pinned_version.is_none())
            .then(|| {
                hot_artifact_cache.recent_unmanaged_path(
                    &candidate,
                    state.config.server.unmanaged_cache_validation_interval_ms,
                )
            })
            .flatten()
    });
    let opened = if let Some((bytes, metadata)) = cached_snapshot {
        Ok((PreparedArtifact::Memory(bytes), candidate, metadata))
    } else {
        let artifact_root = state.artifact_root()?;
        let hot_path_ticket = use_hot_cache
            .then(|| hot_artifact_cache.hot_path_ticket(&candidate))
            .flatten();
        // Capability traversal and same-handle metadata validation are
        // filesystem operations even when a cache ticket is expected to hit.
        // Keep both the hot and cold paths off Tokio runtime workers.
        state
            .artifact_io(move || {
                open_core_read_source(
                    artifact_root.as_ref(),
                    hot_artifact_cache.as_ref(),
                    &candidate,
                    use_hot_cache,
                    hot_path_ticket,
                )
            })
            .await
    };
    let (prepared, path, metadata) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            send_read_error(socket, client_addr, &error).await;
            return Err(error);
        }
    };
    let mut source = match prepared.resolve().await? {
        ArtifactContent::File(file) => CoreReadSource::File(File::from_std(file)),
        ArtifactContent::Memory(bytes) => CoreReadSource::Memory(bytes),
    };

    let verification = if verified_cache_hit {
        Ok(())
    } else {
        match &mut source {
            CoreReadSource::File(file) => {
                verify_opened_artifact(file, &path, pinned_version, &state.version_store).await
            }
            CoreReadSource::Memory(bytes) => {
                verify_cached_artifact(
                    bytes,
                    &path,
                    &metadata,
                    pinned_version,
                    &state.version_store,
                )
                .await
            }
        }
    };
    if let Err(error) = verification {
        if let Some(key) = quarantine_key_for_resolved_path(&path, &state.config.server.root) {
            state.quarantine_artifact(key);
        }
        let packet = TftpPacket::error(
            TftpErrorCode::AccessViolation,
            "Artifact integrity check failed",
        );
        let _ = socket.send_to(&packet, client_addr).await;
        return Err(error);
    }
    if !verified_cache_hit {
        if let Some(pinned) = pinned_version {
            state
                .hot_artifact_cache
                .mark_verified(&path, &metadata, &pinned.content_hash);
        }
    }

    let size = metadata.len();
    let protocol_session = if let Some(protocol) = read_protocol {
        let CoreReadSource::File(file) = &mut source else {
            return Err(TempestError::Protocol(ProtocolError::OptionNegotiation(
                "protocol extension requires an opened artifact handle".into(),
            )));
        };
        let extension_file = file.try_clone().await?.into_std().await;
        let source = VerifiedArtifactSource::from_verified_file(
            extension_file,
            size,
            content_hash.map(str::to_owned),
        );
        match protocol
            .prepare(ReadProtocolContext {
                requested_options: requested_options.to_vec(),
                source,
                file_size: size,
                block_size: options.block_size,
                window_size: options.window_size,
                content_hash: content_hash.map(str::to_owned),
                client_ip: client_addr.ip(),
            })
            .await
        {
            Ok(session) => session,
            Err(error) => {
                state
                    .metrics
                    .extension_failed(ExtensionFailure::ReadProtocolPrepare);
                return Err(error);
            }
        }
    } else {
        None
    };

    Ok(PreparedReadSource {
        source,
        path,
        metadata,
        size,
        protocol_session,
    })
}

struct ReadRuntime {
    scheduler: SchedulerTransferGuard,
    shared_blocks: Option<Box<dyn SharedBlockSession>>,
    pacing_session: Option<Box<dyn TransferPacingSession>>,
    core_payload_size: usize,
    fallback_pacing_delay: Option<Duration>,
}

const TFTP_READ_AHEAD_BYTES: usize = 64 * 1024;
const TFTP_LOW_PRESSURE_READ_AHEAD_BYTES: usize = 128 * 1024;
// Keep file-backed batching bounded per transfer. Retained immutable artifacts
// borrow their existing allocation and therefore do not consume this budget.
const TFTP_FILE_WINDOW_BATCH_MAX_BYTES: usize = 256 * 1024;
// Preserve the portable batching threshold and the single-transfer path.
// Linux can reduce kernel crossings earlier with its sendmmsg implementation.
const TFTP_BATCHED_WINDOW_MIN_ACTIVE_TRANSFERS: usize = 8;

fn use_standard_window_batching(active_transfers: usize, window_size: u16) -> bool {
    let minimum_active = if cfg!(target_os = "linux") {
        2
    } else {
        TFTP_BATCHED_WINDOW_MIN_ACTIVE_TRANSFERS
    };
    window_size > 1 && active_transfers >= minimum_active
}

fn artifact_read_buffer_capacity(
    file_size: u64,
    core_payload_size: usize,
    uses_core_file: bool,
    active_transfers: usize,
) -> usize {
    if !uses_core_file {
        return core_payload_size;
    }
    let read_ahead = if active_transfers < TFTP_BATCHED_WINDOW_MIN_ACTIVE_TRANSFERS {
        TFTP_LOW_PRESSURE_READ_AHEAD_BYTES
    } else {
        TFTP_READ_AHEAD_BYTES
    };
    usize::try_from(file_size)
        .unwrap_or(usize::MAX)
        .min(read_ahead)
        .max(core_payload_size)
}

/// Keeps sequential TFTP reads ahead without reopening the verified artifact.
struct BufferedArtifactReader<R> {
    inner: BufReader<R>,
    position: u64,
}

impl<R: AsyncRead> BufferedArtifactReader<R> {
    fn new(
        inner: R,
        file_size: u64,
        core_payload_size: usize,
        uses_core_file: bool,
        active_transfers: usize,
    ) -> Self {
        let capacity = artifact_read_buffer_capacity(
            file_size,
            core_payload_size,
            uses_core_file,
            active_transfers,
        );
        Self {
            inner: BufReader::with_capacity(capacity, inner),
            position: 0,
        }
    }
}

impl<R> BufferedArtifactReader<R>
where
    R: AsyncRead + AsyncSeek + Unpin,
{
    async fn read_block(&mut self, offset: u64, target: &mut [u8]) -> std::io::Result<usize> {
        if offset != self.position {
            self.position = self.inner.seek(SeekFrom::Start(offset)).await?;
        }
        let mut filled = 0;
        while filled < target.len() {
            let bytes_read = self.inner.read(&mut target[filled..]).await?;
            if bytes_read == 0 {
                break;
            }
            filled += bytes_read;
        }
        self.position = self.position.saturating_add(filled as u64);
        Ok(filled)
    }

    async fn seek_to(&mut self, offset: u64) -> std::io::Result<()> {
        self.position = self.inner.seek(SeekFrom::Start(offset)).await?;
        Ok(())
    }
}

struct MemoryArtifactReader {
    bytes: Arc<Bytes>,
    position: u64,
}

impl MemoryArtifactReader {
    fn block_slice(&mut self, offset: u64, maximum_bytes: usize) -> &[u8] {
        let start = usize::try_from(offset)
            .unwrap_or(usize::MAX)
            .min(self.bytes.len());
        let end = start.saturating_add(maximum_bytes).min(self.bytes.len());
        self.position = end as u64;
        &self.bytes[start..end]
    }

    fn read_block(&mut self, offset: u64, target: &mut [u8]) -> usize {
        let block = self.block_slice(offset, target.len());
        target[..block.len()].copy_from_slice(block);
        block.len()
    }

    fn seek_to(&mut self, offset: u64) {
        self.position = offset;
    }
}

enum ArtifactReader {
    File(BufferedArtifactReader<File>),
    Memory(MemoryArtifactReader),
}

impl ArtifactReader {
    fn new(
        source: CoreReadSource,
        file_size: u64,
        core_payload_size: usize,
        uses_core_file: bool,
        active_transfers: usize,
    ) -> Self {
        match source {
            CoreReadSource::File(file) => Self::File(BufferedArtifactReader::new(
                file,
                file_size,
                core_payload_size,
                uses_core_file,
                active_transfers,
            )),
            CoreReadSource::Memory(bytes) => {
                Self::Memory(MemoryArtifactReader { bytes, position: 0 })
            }
        }
    }

    async fn read_block(&mut self, offset: u64, target: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::File(file) => file.read_block(offset, target).await,
            Self::Memory(memory) => Ok(memory.read_block(offset, target)),
        }
    }

    fn memory_block(&mut self, offset: u64, maximum_bytes: usize) -> Option<&[u8]> {
        match self {
            Self::Memory(memory) => Some(memory.block_slice(offset, maximum_bytes)),
            Self::File(_) => None,
        }
    }

    fn retained_memory(&self) -> Option<Arc<Bytes>> {
        match self {
            Self::Memory(memory) => Some(memory.bytes.clone()),
            Self::File(_) => None,
        }
    }

    async fn seek_to(&mut self, offset: u64) -> std::io::Result<()> {
        match self {
            Self::File(file) => file.seek_to(offset).await,
            Self::Memory(memory) => {
                memory.seek_to(offset);
                Ok(())
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn prepare_read_runtime(
    state: &ServerState,
    client_addr: SocketAddr,
    transfer_id: TransferId,
    phase: crate::features::boot_phase::BootPhase,
    file_size: u64,
    file_path: &Path,
    file_metadata: &std::fs::Metadata,
    content_hash: Option<&str>,
    provisioning_serial: Option<&str>,
    block_size: usize,
    core_payload_size: usize,
    uses_core_file: bool,
) -> ReadRuntime {
    let provisioning_priority = if let (Some(client), Some(serial)) =
        (state.provisioning_priority.as_ref(), provisioning_serial)
    {
        client.priority_for_serial(serial).await
    } else {
        None
    };
    let scheduler = SchedulerTransferGuard::register(
        state.scheduler.clone(),
        transfer_id,
        phase,
        file_size,
        provisioning_priority,
    );
    let ceiling = scheduler
        .scheduler()
        .and_then(|scheduler| scheduler.phase_adjusted_ceiling(&transfer_id));
    let fallback_pacing_delay = ceiling.and_then(|limit| pacing_delay(block_size, limit, None));
    let pacing_session = state
        .transfer_pacing
        .as_ref()
        .map(|provider| provider.start(client_addr.ip(), block_size, ceiling));

    let shared_blocks = uses_core_file
        .then(|| {
            state.shared_blocks.as_ref().map(|provider| {
                let shared_identity = content_hash.map(str::to_owned).unwrap_or_else(|| {
                    ArtifactIdentity::new(file_path, file_metadata).shared_cache_key()
                });
                let shared_block_key = format!("{shared_identity}:bs:{core_payload_size}");
                provider.open(&shared_block_key, core_payload_size)
            })
        })
        .flatten();

    ReadRuntime {
        scheduler,
        shared_blocks,
        pacing_session,
        core_payload_size,
        fallback_pacing_delay,
    }
}

struct ReadDataLoop<'a> {
    socket: &'a Arc<UdpSocket>,
    client_addr: SocketAddr,
    transfer_id: TransferId,
    state: &'a ServerState,
    scheduler: &'a SchedulerTransferGuard,
    shared_blocks: Option<Box<dyn SharedBlockSession>>,
    options: &'a NegotiatedOptions,
    core_payload_size: usize,
    fallback_pacing_delay: Option<Duration>,
}

struct ReadAcknowledgment<'a> {
    socket: &'a UdpSocket,
    client_addr: SocketAddr,
    transfer_id: TransferId,
    ack_spin: Option<&'a mut AckSpin>,
    core_payload_size: usize,
    file: &'a mut ArtifactReader,
    protocol_session: &'a mut Option<Box<dyn ReadProtocolSession>>,
    pacing_session: &'a mut Option<Box<dyn TransferPacingSession>>,
    metrics: &'a mut TransferMetrics,
    unknown_tid_responder: &'a mut UnknownTidResponder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadAckAction {
    Complete,
    Continue,
    Retransmit,
}

/// Busy-poll state for one transfer's ACK waits. The poll occupies a Tokio
/// worker, so it is limited to an otherwise idle server and ends for the rest
/// of the transfer once ACKs stop arriving within the budget.
#[derive(Debug, Default)]
struct AckSpin {
    consecutive_misses: u8,
}

impl AckSpin {
    const BUDGET: Duration = Duration::from_micros(40);
    const MAX_ACTIVE_TRANSFERS: usize = 1;
    const MAX_CONSECUTIVE_MISSES: u8 = 8;

    fn when_idle(&mut self, active_transfers: usize) -> Option<&mut Self> {
        (cfg!(target_os = "linux")
            && active_transfers <= Self::MAX_ACTIVE_TRANSFERS
            && self.consecutive_misses < Self::MAX_CONSECUTIVE_MISSES)
            .then_some(self)
    }

    fn poll(
        &mut self,
        socket: &UdpSocket,
        client_addr: SocketAddr,
        buffer: &mut [u8],
    ) -> Option<usize> {
        let received = spin_for_peer_datagram(socket, client_addr, buffer, Self::BUDGET);
        self.consecutive_misses = if received.is_some() {
            0
        } else {
            self.consecutive_misses.saturating_add(1)
        };
        received
    }
}

/// Takes a pending datagram from `client_addr` without waiting for Tokio's
/// readiness notification. A datagram from any other source is left queued
/// for the unknown-TID handling in `recv_from_transfer_peer`.
#[cfg(target_os = "linux")]
fn spin_for_peer_datagram(
    socket: &UdpSocket,
    client_addr: SocketAddr,
    buffer: &mut [u8],
    budget: Duration,
) -> Option<usize> {
    use rustix::io::Errno;
    use rustix::net::{RecvFlags, recvfrom};

    let started = Instant::now();
    let expected = rustix::net::SocketAddrAny::from(client_addr);
    loop {
        match recvfrom(socket, &mut *buffer, RecvFlags::PEEK | RecvFlags::DONTWAIT) {
            Ok((_, _, Some(peer))) if peer == expected => {
                return recvfrom(socket, buffer, RecvFlags::DONTWAIT)
                    .ok()
                    .map(|(length, _, _)| length);
            }
            Err(Errno::AGAIN) => {}
            _ => return None,
        }
        if started.elapsed() >= budget {
            return None;
        }
        std::hint::spin_loop();
    }
}

#[cfg(not(target_os = "linux"))]
fn spin_for_peer_datagram(
    _socket: &UdpSocket,
    _client_addr: SocketAddr,
    _buffer: &mut [u8],
    _budget: Duration,
) -> Option<usize> {
    None
}

async fn await_read_ack(
    exchange: ReadAcknowledgment<'_>,
    window: &mut WindowState,
    transfer_complete: bool,
    mut deadline: Pin<&mut tokio::time::Sleep>,
) -> Result<ReadAckAction, TempestError> {
    let mut buffer = [0u8; 64];
    deadline
        .as_mut()
        .reset(tokio::time::Instant::now() + window.rto());
    let mut spun = exchange
        .ack_spin
        .and_then(|spin| spin.poll(exchange.socket, exchange.client_addr, &mut buffer));
    loop {
        let received = if let Some(length) = spun.take() {
            Some(Ok(length))
        } else {
            tokio::select! {
                biased;
                _ = deadline.as_mut() => None,
                result = recv_from_transfer_peer(
                    exchange.socket,
                    exchange.client_addr,
                    &mut buffer,
                    exchange.unknown_tid_responder,
                ) => {
                    Some(result)
                }
            }
        };

        match received {
            Some(Ok(length)) => match TftpPacket::parse(&buffer[..length], exchange.client_addr) {
                Ok(TftpPacket::Ack(ack)) => {
                    let advance = window.process_ack(ack.block);
                    if !matches!(advance, WindowAdvance::Duplicate) {
                        if let Some(pacing) = exchange.pacing_session.as_mut() {
                            pacing.record_ack(ack.block, exchange.metrics.blocks_sent);
                        }
                    }

                    match advance {
                        WindowAdvance::FullWindow { acked: _ } if transfer_complete => {
                            return Ok(ReadAckAction::Complete);
                        }
                        WindowAdvance::FullWindow { acked: _ }
                        | WindowAdvance::Partial { acked: _ } => {
                            return Ok(ReadAckAction::Continue);
                        }
                        // Repeated and stale ACKs do not reset the deadline or
                        // influence pacing extensions.
                        WindowAdvance::Duplicate => continue,
                    }
                }
                Ok(TftpPacket::Error(error)) => {
                    let safe_message: String = error
                        .message
                        .chars()
                        .map(|character| {
                            if character.is_control() {
                                '_'
                            } else {
                                character
                            }
                        })
                        .take(200)
                        .collect();
                    warn!(
                        transfer_id = %exchange.transfer_id,
                        "Client error during transfer: {} (code {})",
                        safe_message,
                        error.code
                    );
                    return Err(TempestError::Protocol(ProtocolError::ClientAbort {
                        addr: exchange.client_addr,
                    }));
                }
                _ => continue,
            },
            Some(Err(error)) => return Err(error.into()),
            None => match window.handle_timeout() {
                TimeoutAction::Retransmit {
                    from_block,
                    from_block_index,
                } => {
                    exchange.metrics.retransmissions += 1;
                    if let Some(session) = exchange.protocol_session.as_mut() {
                        session.record_retransmission();
                    }
                    debug!(
                        transfer_id = %exchange.transfer_id,
                        from_block,
                        "Retransmitting from block"
                    );
                    let seek_core_file = exchange
                        .protocol_session
                        .as_ref()
                        .is_none_or(|session| session.seek_file_on_retransmit());
                    if seek_core_file {
                        let offset = from_block_index
                            .saturating_sub(1)
                            .saturating_mul(exchange.core_payload_size as u64);
                        exchange.file.seek_to(offset).await?;
                    }
                    return Ok(ReadAckAction::Retransmit);
                }
                TimeoutAction::Abort => {
                    debug!(
                        transfer_id = %exchange.transfer_id,
                        client = %exchange.client_addr,
                        "Transfer retry budget exhausted"
                    );
                    return Err(TempestError::Protocol(ProtocolError::Timeout {
                        addr: exchange.client_addr,
                        block: window.window_start(),
                    }));
                }
            },
        }
    }
}

/// Bound transform lookahead independently of the negotiated transmission window.
async fn encode_file_batch(
    file: &mut ArtifactReader,
    session: &mut dyn ReadProtocolSession,
    shared_blocks: &mut Option<Box<dyn SharedBlockSession>>,
    first_block: u64,
    payload_size: usize,
    block_size: usize,
) -> Result<VecDeque<(usize, EncodedDataPacket)>, TempestError> {
    let capacity = session
        .encoding_batch_size()
        .min(32)
        .min(64 * 1024 / payload_size.max(1));
    if capacity < 2 {
        return Ok(VecDeque::new());
    }
    let mut inputs = Vec::with_capacity(capacity);
    let mut lengths = Vec::with_capacity(capacity);
    for index in 0..capacity {
        let absolute = first_block.saturating_add(index as u64);
        let wire = absolute as u16;
        if session.skip_block(absolute, wire)
            || !matches!(session.payload(absolute), ExtensionPayload::Core)
        {
            break;
        }
        let ring_block = usize::try_from(absolute).ok();
        let cached = if let (Some(shared), Some(block)) = (shared_blocks.as_ref(), ring_block) {
            shared.read(block).await
        } else {
            None
        };
        let payload = if let Some(bytes) = cached {
            bytes
        } else {
            let mut buffer = vec![0; payload_size];
            let offset = absolute
                .saturating_sub(1)
                .saturating_mul(payload_size as u64);
            let len = file.read_block(offset, &mut buffer).await?;
            buffer.truncate(len);
            let bytes = Bytes::from(buffer);
            if let (Some(shared), Some(block)) = (shared_blocks.as_ref(), ring_block) {
                shared.publish(block, bytes.clone());
            }
            bytes
        };
        let len = payload.len();
        inputs.push((wire, payload));
        lengths.push(len);
        if len < payload_size {
            break;
        }
    }
    if inputs.is_empty() {
        return Ok(VecDeque::new());
    }
    let encoded = session.encode_packets_async(inputs).await?;
    if encoded.len() != lengths.len()
        || encoded
            .iter()
            .any(|packet| packet.packet.len() > block_size.saturating_add(4))
    {
        return Err(TempestError::Protocol(ProtocolError::OptionNegotiation(
            "protocol extension returned an invalid DATA batch".into(),
        )));
    }
    Ok(lengths.into_iter().zip(encoded).collect())
}

async fn run_read_data_loop(
    mut context: ReadDataLoop<'_>,
    file: &mut ArtifactReader,
    protocol_session: &mut Option<Box<dyn ReadProtocolSession>>,
    pacing_session: &mut Option<Box<dyn TransferPacingSession>>,
    metrics: &mut TransferMetrics,
) -> Result<(), TempestError> {
    let block_size = context.options.block_size as usize;
    let mut window = WindowState::with_policy(
        context.options.window_size,
        context.options.retransmission_policy,
        context.options.max_retries,
    );
    let can_send_cached_bytes = matches!(file, ArtifactReader::Memory(_))
        && protocol_session.is_none()
        && context.shared_blocks.is_none()
        && context.scheduler.scheduler().is_none();
    let active_transfers = context
        .state
        .active_transfers
        .load(std::sync::atomic::Ordering::Relaxed);
    let standard_window_batching = protocol_session.is_none()
        && context.shared_blocks.is_none()
        && context.scheduler.scheduler().is_none()
        && pacing_session.is_none()
        && context.fallback_pacing_delay.is_none()
        && use_standard_window_batching(active_transfers, context.options.window_size);
    let retained_artifact = standard_window_batching
        .then(|| file.retained_memory())
        .flatten();
    let can_batch_retained = retained_artifact
        .as_ref()
        .is_some_and(|artifact| artifact.len() >= context.core_payload_size);
    let configured_window_bytes =
        usize::from(context.options.window_size).saturating_mul(context.core_payload_size);
    let can_batch_file = standard_window_batching
        && matches!(file, ArtifactReader::File(_))
        && configured_window_bytes <= TFTP_FILE_WINDOW_BATCH_MAX_BYTES;
    let can_batch_windows = can_batch_retained || can_batch_file;
    let mut data_window = if can_batch_windows {
        Vec::with_capacity(usize::from(context.options.window_size))
    } else {
        Vec::new()
    };
    let mut file_window_buffer = Vec::new();
    let mut read_buffer = if can_send_cached_bytes || can_batch_windows {
        Vec::new()
    } else {
        vec![0u8; context.core_payload_size]
    };
    let mut data_packet_buffer = BytesMut::new();
    let mut encoded_lookahead = VecDeque::new();
    let mut transfer_complete = false;
    let mut window_send_state =
        DataWindowSendState::new(context.state.config.server.udp_segmentation_offload);
    let mut ack_spin = AckSpin::default();
    let acknowledgment_deadline = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(acknowledgment_deadline);
    let mut unknown_tid_responder = UnknownTidResponder::default();

    let requested_burst = pacing_session
        .as_ref()
        .map_or(32, |session| session.max_burst_packets())
        .clamp(1, 32);
    let rate_pacing = requested_burst > 1;
    let pacing_burst = requested_burst.min(usize::from(context.options.window_size));
    let mut pacer = PacketPacer::new();

    'transfer: loop {
        if let Some(scheduler) = context.scheduler.scheduler() {
            let packet_count = window.remaining_capacity();
            let encoded_bytes = packet_count.saturating_mul(block_size.saturating_add(4));
            if let Err(error) = scheduler
                .schedule_window(context.transfer_id, packet_count, encoded_bytes)
                .await
            {
                context
                    .state
                    .metrics
                    .extension_failed(ExtensionFailure::SchedulerScheduleWindow);
                return Err(error);
            }
        }

        if can_batch_windows {
            let packet_capacity = window.remaining_capacity();
            let sent = send_standard_data_window(
                StandardWindowExchange {
                    socket: context.socket.as_ref(),
                    client_addr: context.client_addr,
                    payload_size: context.core_payload_size,
                    file,
                    retained_artifact: retained_artifact.as_deref(),
                    file_buffer: &mut file_window_buffer,
                    packets: &mut data_window,
                    governor: context.state.bandwidth_governor.as_deref(),
                    send_state: &mut window_send_state,
                },
                window.next_block_index(),
                window.next_block(),
                packet_capacity,
            )
            .await?;
            transfer_complete = sent.transfer_complete;
            metrics.bytes_sent = metrics.bytes_sent.saturating_add(sent.payload_bytes);
            metrics.blocks_sent = metrics.blocks_sent.saturating_add(sent.blocks as u64);
            for _ in 0..sent.blocks {
                window.block_sent();
            }
            // Socket readiness and ACK receives usually consume cooperative
            // budget themselves. This only yields when a run of immediately
            // ready windows has exhausted the task's budget.
            tokio::task::coop::consume_budget().await;
        }

        while !can_batch_windows && window.can_send() {
            let block_index = window.next_block_index();
            let block_number = window.next_block();

            if protocol_session
                .as_ref()
                .is_some_and(|session| session.skip_block(block_index, block_number))
            {
                if !window.block_skipped() {
                    return Err(TempestError::Protocol(ProtocolError::OptionNegotiation(
                        "protocol extension cannot skip a block while DATA is in flight".into(),
                    )));
                }
                continue;
            }

            if rate_pacing {
                let delay = pacing_session
                    .as_ref()
                    .and_then(|session| session.current_delay())
                    .or(context.fallback_pacing_delay);
                pacer.before_send(delay, pacing_burst).await;
            }

            let offset = block_index
                .saturating_sub(1)
                .saturating_mul(context.core_payload_size as u64);
            let direct_bytes_read = if can_send_cached_bytes {
                if let Some(payload) = file.memory_block(offset, context.core_payload_size) {
                    let packet_bytes = payload.len().saturating_add(4);
                    if let Some(ref governor) = context.state.bandwidth_governor {
                        governor.acquire(packet_bytes).await;
                    }
                    send_cached_data_packet(
                        context.socket.as_ref(),
                        context.client_addr,
                        block_number,
                        payload,
                    )
                    .await?;
                    Some(payload.len())
                } else {
                    None
                }
            } else {
                None
            };

            if encoded_lookahead.is_empty() {
                if let Some(session) = protocol_session
                    .as_mut()
                    .filter(|session| session.encoding_batch_size() > 1 && session.uses_core_file())
                {
                    encoded_lookahead = encode_file_batch(
                        file,
                        session.as_mut(),
                        &mut context.shared_blocks,
                        block_index,
                        context.core_payload_size,
                        block_size,
                    )
                    .await
                    .inspect_err(|_| {
                        context
                            .state
                            .metrics
                            .extension_failed(ExtensionFailure::ReadProtocolEncodePacket)
                    })?;
                }
            }

            let (bytes_read, accounted_bytes) = if let Some(bytes_read) = direct_bytes_read {
                (bytes_read, bytes_read as u64)
            } else if let Some((bytes_read, encoded)) = encoded_lookahead.pop_front() {
                if let Some(ref governor) = context.state.bandwidth_governor {
                    governor.acquire(encoded.packet.len()).await;
                }
                send_data_packet(
                    context.socket,
                    context.scheduler.scheduler(),
                    context.state.metrics.as_ref(),
                    context.transfer_id,
                    context.client_addr,
                    encoded.packet,
                )
                .await?;
                (bytes_read, encoded.accounted_bytes)
            } else {
                let mut owned_payload: Option<Bytes> = None;
                let bytes_read;
                let payload;
                let extension_payload = protocol_session
                    .as_ref()
                    .map_or(ExtensionPayload::Core, |session| {
                        session.payload(block_index)
                    });
                match extension_payload {
                    ExtensionPayload::End => {
                        transfer_complete = true;
                        break;
                    }
                    ExtensionPayload::Data(data) => {
                        owned_payload = Some(data);
                        bytes_read = owned_payload.as_ref().map_or(0, Bytes::len);
                        payload = owned_payload.as_deref().unwrap_or_default();
                    }
                    ExtensionPayload::Core => {
                        if let (Some(shared_blocks), Ok(ring_block)) = (
                            context.shared_blocks.as_deref(),
                            usize::try_from(block_index),
                        ) {
                            owned_payload = shared_blocks.read(ring_block).await;
                        }

                        if let Some(ref block) = owned_payload {
                            bytes_read = block.len();
                            payload = block;
                        } else {
                            bytes_read = file.read_block(offset, &mut read_buffer).await?;
                            payload = &read_buffer[..bytes_read];
                            if let (Some(shared_blocks), Ok(ring_block)) = (
                                context.shared_blocks.as_deref(),
                                usize::try_from(block_index),
                            ) {
                                shared_blocks.publish(ring_block, Bytes::copy_from_slice(payload));
                            }
                        }
                    }
                }

                let EncodedDataPacket {
                    packet: data_packet,
                    accounted_bytes,
                } = if let Some(session) = protocol_session.as_mut() {
                    let encoded = if session.uses_async_encoding() {
                        let extension_input = owned_payload.clone().map_or(
                            ReadProtocolPayload::Borrowed(payload),
                            ReadProtocolPayload::Owned,
                        );
                        session
                            .encode_packet_async(block_number, extension_input)
                            .await
                    } else {
                        session.encode_packet(block_number, payload)
                    };
                    match encoded {
                        Ok(packet) => packet,
                        Err(error) => {
                            context
                                .state
                                .metrics
                                .extension_failed(ExtensionFailure::ReadProtocolEncodePacket);
                            return Err(error);
                        }
                    }
                } else {
                    TftpPacket::data_into(&mut data_packet_buffer, block_number, payload);
                    EncodedDataPacket {
                        packet: std::mem::take(&mut data_packet_buffer),
                        accounted_bytes: bytes_read as u64,
                    }
                };
                if data_packet.len() > block_size.saturating_add(4) {
                    context
                        .state
                        .metrics
                        .extension_failed(ExtensionFailure::ReadProtocolEncodePacket);
                    return Err(TempestError::Protocol(ProtocolError::OptionNegotiation(
                        "protocol extension DATA payload exceeds negotiated blksize".into(),
                    )));
                }
                if let Some(ref governor) = context.state.bandwidth_governor {
                    governor.acquire(data_packet.len()).await;
                }
                let returned_packet = send_data_packet(
                    context.socket,
                    context.scheduler.scheduler(),
                    context.state.metrics.as_ref(),
                    context.transfer_id,
                    context.client_addr,
                    data_packet,
                )
                .await?;
                if protocol_session.is_none() && context.scheduler.scheduler().is_none() {
                    data_packet_buffer = returned_packet;
                }
                (bytes_read, accounted_bytes)
            };
            metrics.bytes_sent += accounted_bytes;
            metrics.blocks_sent += 1;
            if let Some(session) = protocol_session.as_mut() {
                session.record_block_sent();
            }
            window.block_sent();

            let pacing_delay = pacing_session
                .as_ref()
                .and_then(|session| session.current_delay())
                .or(context.fallback_pacing_delay);
            if let Some(delay) = pacing_delay.filter(|_| !rate_pacing) {
                tokio::time::sleep(delay).await;
            }

            let block_complete = protocol_session.as_ref().map_or_else(
                || bytes_read < block_size,
                |session| {
                    session.transfer_complete(block_index, bytes_read, context.core_payload_size)
                },
            );
            if block_complete {
                transfer_complete = true;
                break;
            }
        }

        loop {
            let action = await_read_ack(
                ReadAcknowledgment {
                    socket: context.socket.as_ref(),
                    client_addr: context.client_addr,
                    transfer_id: context.transfer_id,
                    ack_spin: ack_spin.when_idle(
                        context
                            .state
                            .active_transfers
                            .load(std::sync::atomic::Ordering::Relaxed),
                    ),
                    core_payload_size: context.core_payload_size,
                    file,
                    protocol_session,
                    pacing_session,
                    metrics,
                    unknown_tid_responder: &mut unknown_tid_responder,
                },
                &mut window,
                transfer_complete,
                acknowledgment_deadline.as_mut(),
            )
            .await?;
            match action {
                ReadAckAction::Complete => break 'transfer,
                ReadAckAction::Retransmit => {
                    encoded_lookahead.clear();
                    // A timeout after the final DATA packet must re-enter the
                    // send path for the first still-unacknowledged block.
                    transfer_complete = false;
                    break;
                }
                ReadAckAction::Continue if transfer_complete => {
                    // A partial or repeated ACK cannot complete the transfer.
                    // Keep the final window in flight and wait for progress.
                }
                ReadAckAction::Continue => break,
            }
        }
    }

    Ok(())
}

/// One server-controlled deadline shared by every network phase. Unlike the
/// RFC retransmission timer, neither progress nor duplicate traffic renews it.
struct TransferDeadline(tokio::time::Instant);

impl TransferDeadline {
    fn new(state: &ServerState) -> Self {
        Self(
            tokio::time::Instant::now()
                + Duration::from_secs(state.config.server.max_transfer_duration_secs),
        )
    }

    async fn run_network<T>(
        &self,
        socket: &UdpSocket,
        addr: SocketAddr,
        work: impl std::future::Future<Output = Result<T, TempestError>>,
    ) -> Result<T, TempestError> {
        let result = self.run(addr, work).await;
        if matches!(
            result,
            Err(TempestError::Protocol(
                ProtocolError::TransferDeadline { .. }
            ))
        ) {
            // RFC 1350 ERROR is a one-shot courtesy, not a retransmission.
            // Never await writable capacity after the budget has expired, and
            // never let a notification failure mask the terminal outcome.
            let packet =
                TftpPacket::error(TftpErrorCode::NotDefined, "Transfer time limit exceeded");
            let _ = socket.try_send_to(&packet, addr);
        }
        result
    }

    async fn acknowledge_committed_write(
        &self,
        socket: &UdpSocket,
        addr: SocketAddr,
        final_ack: &[u8],
    ) -> Result<(), TempestError> {
        // Durable publication may have crossed the deadline. Still attempt
        // the final ACK, but never report a committed upload as deadline-failed
        // or give it a new network budget. Dally remains bounded separately.
        match socket.try_send_to(final_ack, addr) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                match tokio::time::timeout_at(self.0, socket.send_to(final_ack, addr)).await {
                    Ok(result) => {
                        result?;
                    }
                    Err(_) => {
                        debug!(client = %addr, "Committed WRQ final ACK could not be sent before deadline")
                    }
                }
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    async fn run<T>(
        &self,
        addr: SocketAddr,
        work: impl std::future::Future<Output = Result<T, TempestError>>,
    ) -> Result<T, TempestError> {
        // Timer priority also terminates continuously ready packet streams.
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(self.0) => {
                Err(ProtocolError::TransferDeadline { addr }.into())
            }
            result = work => result,
        }
    }
}

/// Run one RRQ on its transfer-owned ephemeral socket.
/// Network exchange is bounded by `ServerConfig::max_transfer_duration_secs`.
#[allow(clippy::too_many_arguments)]
pub async fn run_read_transfer(
    socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    filename: String,
    boot_profile: String,
    provisioning_serial: Option<String>,
    options: NegotiatedOptions,
    requested_options: Vec<(String, String)>,
    state: Arc<ServerState>,
    transfer_id: TransferId,
) -> Result<TransferMetrics, TempestError> {
    let phase = state.phase_classifier.classify(&filename);
    let mut metrics = TransferMetrics::default();
    run_read_transfer_for_phase(
        socket,
        client_addr,
        &filename,
        &boot_profile,
        provisioning_serial.as_deref(),
        options,
        &requested_options,
        state.as_ref(),
        transfer_id,
        phase,
        None,
        &mut metrics,
    )
    .await?;
    Ok(metrics)
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_read_transfer_for_phase(
    socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    filename: &str,
    boot_profile: &str,
    provisioning_serial: Option<&str>,
    options: NegotiatedOptions,
    requested_options: &[(String, String)],
    state: &ServerState,
    transfer_id: TransferId,
    phase: crate::features::boot_phase::BootPhase,
    duplicate_request: Option<&tokio::sync::Notify>,
    metrics: &mut TransferMetrics,
) -> Result<(), TempestError> {
    // RAII guard — decrements active_transfers if we return early
    // (before hand_off() transfers responsibility to metrics).
    let mut slot_guard = TransferSlotGuard::new(state.active_transfers.clone());
    let transfer_deadline = TransferDeadline::new(state);

    // Caller-owned metrics retain identity and progress on every error path.
    metrics.start_time = Some(Instant::now());
    // The returned managed pin is held until this function exits.
    let resolved_file =
        resolve_read_file(socket.as_ref(), client_addr, boot_profile, filename, state).await?;
    let _durable_reader = resolved_file.durable_reader;
    let pinned_version = resolved_file.pinned_version.clone();
    metrics.artifact_version_id = pinned_version.as_ref().map(|pinned| pinned.version_id);
    metrics.boot_chain = resolved_file.boot_chain.clone();
    let _pinned_version_guard =
        PinnedVersionGuard::new(&state.version_store, pinned_version.clone());
    let file_path = resolved_file.path;
    let content_hash = resolved_file.content_hash;
    metrics.content_hash = content_hash.clone();
    // The caller's profile hint is not authority. Use the resolved identity,
    // including when a session expired or changed after listener dispatch.
    let boot_profile = pinned_version
        .as_ref()
        .map_or(boot_profile, |pinned| pinned.boot_profile.as_str());
    let read_identity = verified_read_identity(
        boot_profile,
        pinned_version.as_ref(),
        metrics.boot_chain.as_ref(),
        content_hash.as_deref(),
    );
    if matches!(
        route_read_request(
            socket.as_ref(),
            client_addr,
            filename,
            requested_options,
            read_identity.as_ref(),
            pinned_version.as_ref().map_or(0, |version| version.size),
            state,
        )
        .await?,
        RouteDecision::Redirect(_)
    ) {
        metrics.redirected = true;
        metrics.end_time = Some(Instant::now());
        return Ok(());
    }

    let PreparedReadSource {
        source,
        path: file_path,
        metadata: file_metadata,
        size: file_size,
        mut protocol_session,
    } = prepare_read_source(
        socket.as_ref(),
        client_addr,
        file_path,
        pinned_version.as_ref(),
        content_hash.as_deref(),
        requested_options,
        &options,
        state,
    )
    .await?;
    if let (Some(router), Some(identity)) = (state.read_request_router.as_ref(), &read_identity) {
        router.local_artifact_verified(identity, filename);
    }

    debug!(
        transport = TRANSPORT_TFTP,
        client = %client_addr,
        filename = %filename,
        boot_profile = %boot_profile,
        phase = phase.as_str(),
        content_hash = ?metrics.content_hash.as_deref(),
        artifact_version_id = ?pinned_version.as_ref().map(|p| p.version_id),
        "TFTP artifact transfer started"
    );
    debug!(
        transfer_id = %transfer_id,
        filename = %filename,
        phase = ?phase,
        block_size = options.block_size,
        window_size = options.window_size,
        timeout_requested = options.timeout_requested,
        rto_initial_ms = options.retransmission_policy.initial_rto().as_millis(),
        rto_min_ms = options.retransmission_policy.min_rto().as_millis(),
        rto_max_ms = options.retransmission_policy.max_rto().as_millis(),
        rto_adaptive = options.retransmission_policy.is_adaptive(),
        "Starting read transfer"
    );

    let extension_oack = protocol_session
        .as_ref()
        .map(|session| session.oack_options())
        .unwrap_or_default();
    let oack_packet = build_oack_packet(
        &options,
        options.transfer_size.map(|_| file_size),
        &extension_oack,
    );

    transfer_deadline
        .run_network(
            socket.as_ref(),
            client_addr,
            exchange_oack(
                socket.as_ref(),
                client_addr,
                &options,
                oack_packet.as_deref(),
                transfer_id,
                duplicate_request,
            ),
        )
        .await?;

    if oack_packet.is_some() {
        if let Some(duplicate_request) = duplicate_request {
            state
                .inflight_tftp_tids
                .remove_if(&client_addr, |_, owner| {
                    std::ptr::eq(owner.as_ref(), duplicate_request)
                });
        }
    }

    let block_size = options.block_size as usize;
    let core_payload_size = protocol_session
        .as_ref()
        .map_or(block_size, |session| session.core_payload_size(block_size))
        .clamp(1, block_size);
    let uses_core_file = protocol_session
        .as_ref()
        .is_none_or(|session| session.uses_core_file());
    let ReadRuntime {
        scheduler,
        shared_blocks,
        mut pacing_session,
        core_payload_size,
        fallback_pacing_delay,
    } = transfer_deadline
        .run_network(socket.as_ref(), client_addr, async {
            Ok(prepare_read_runtime(
                state,
                client_addr,
                transfer_id,
                phase,
                file_size,
                &file_path,
                &file_metadata,
                content_hash.as_deref(),
                provisioning_serial,
                block_size,
                core_payload_size,
                uses_core_file,
            )
            .await)
        })
        .await?;
    let mut file = ArtifactReader::new(
        source,
        file_size,
        core_payload_size,
        uses_core_file,
        state
            .active_transfers
            .load(std::sync::atomic::Ordering::Relaxed),
    );

    // Record transfer in metrics — hand off active_transfers responsibility.
    state.metrics.transfer_started(&phase, boot_profile);
    slot_guard.hand_off();
    let mut lifecycle_guard =
        TransferLifecycleGuard::new(state.metrics.clone(), phase, boot_profile);

    transfer_deadline
        .run_network(
            socket.as_ref(),
            client_addr,
            run_read_data_loop(
                ReadDataLoop {
                    socket: &socket,
                    client_addr,
                    transfer_id,
                    state,
                    scheduler: &scheduler,
                    shared_blocks,
                    options: &options,
                    core_payload_size,
                    fallback_pacing_delay,
                },
                &mut file,
                &mut protocol_session,
                &mut pacing_session,
                metrics,
            ),
        )
        .await?;

    metrics.end_time = Some(Instant::now());

    // Record completion metrics
    state
        .metrics
        .transfer_completed(&phase, boot_profile, metrics);
    lifecycle_guard.complete();

    debug!(
        transport = TRANSPORT_TFTP,
        transfer_id = %transfer_id,
        filename = %filename,
        boot_profile = %boot_profile,
        content_hash = ?metrics.content_hash.as_deref(),
        bytes = metrics.bytes_sent,
        blocks = metrics.blocks_sent,
        retransmissions = metrics.retransmissions,
        duration_ms = ?metrics.duration().map(|d| d.as_millis()),
        phase = ?phase,
        "Transfer completed"
    );

    Ok(())
}

/// Run one WRQ on its transfer-owned ephemeral socket.
/// Receive and final-ACK dally use an absolute server-controlled deadline;
/// publication of a fully received artifact is not cancelled by that deadline.
pub async fn run_write_transfer(
    socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    filename: String,
    boot_profile: String,
    options: NegotiatedOptions,
    state: Arc<ServerState>,
    transfer_id: TransferId,
) -> Result<TransferMetrics, TempestError> {
    run_write_transfer_with_duplicate_request(
        socket,
        client_addr,
        filename,
        boot_profile,
        options,
        state,
        transfer_id,
        None,
    )
    .await
}

/// Runs one WRQ while allowing the listener to signal retransmitted requests.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_write_transfer_with_duplicate_request(
    socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    filename: String,
    boot_profile: String,
    options: NegotiatedOptions,
    state: Arc<ServerState>,
    transfer_id: TransferId,
    duplicate_request: Option<&tokio::sync::Notify>,
) -> Result<TransferMetrics, TempestError> {
    // Own the slot until metrics takes over, including every early return.
    let mut slot_guard = TransferSlotGuard::new(state.active_transfers.clone());
    let transfer_deadline = TransferDeadline::new(&state);

    let mut metrics = TransferMetrics {
        start_time: Some(Instant::now()),
        ..Default::default()
    };

    if !state.config.server.write_enabled {
        // Keep the wire error generic while retaining the local reason.
        let err_pkt = TftpPacket::error(TftpErrorCode::AccessViolation, "Operation not permitted");
        socket.send_to(&err_pkt, client_addr).await?;
        return Err(TempestError::Protocol(ProtocolError::AccessViolation(
            "writes disabled".to_string(),
        )));
    }

    if state.config.server.write_require_session
        && active_boot_session(&state, client_addr.ip()).is_none()
    {
        let packet = TftpPacket::error(TftpErrorCode::AccessViolation, "Operation not permitted");
        socket.send_to(&packet, client_addr).await?;
        return Err(TempestError::Protocol(ProtocolError::AccessViolation(
            "active boot session required for write".to_string(),
        )));
    }

    if let Some(declared_size) = options.transfer_size {
        if declared_size > state.config.server.max_write_file_size {
            let err_pkt = TftpPacket::error(
                TftpErrorCode::OptionNegotiation,
                "Transfer size limit exceeded",
            );
            socket.send_to(&err_pkt, client_addr).await?;
            return Err(TempestError::Protocol(ProtocolError::OptionNegotiation(
                "declared write size exceeds configured limit".into(),
            )));
        }
    }

    let artifact_root = state.artifact_root()?;
    let write_root = artifact_root.clone();
    let logical_name = filename.clone();
    let suffix = transfer_id.as_simple().to_string();
    let (file, temp_relative, final_relative) =
        tokio::task::spawn_blocking(move || write_root.create_write_temp(&logical_name, &suffix))
            .await
            .map_err(|error| TempestError::Io(std::io::Error::other(error)))??;
    let file = tokio::fs::File::from_std(file);

    // The capability-relative path, not an ambient pathname, owns cleanup.
    let mut temp_guard = TempFileGuard::new(artifact_root.clone(), temp_relative.clone());

    // Wrap in BufWriter to reduce syscall frequency for WRQ writes
    let mut file = tokio::io::BufWriter::with_capacity(64 * 1024, file);

    // Retain the exact response representing the current receive state. Before
    // DATA(1), retransmitting ACK(0) in place of a negotiated OACK would make a
    // client fall back to 512-byte blocks while this transfer still expects the
    // negotiated size.
    let mut last_response = build_oack_packet(&options, options.transfer_size, &[])
        .unwrap_or_else(|| TftpPacket::ack(0));

    let block_size = options.block_size as usize;
    let mut expected_block: u16 = 1;
    let mut retries = 0u8;
    let max_retries = options.max_retries;
    // Track total bytes written to enforce file size limit
    let max_write_size: u64 = state.config.server.max_write_file_size;
    let mut total_bytes_written: u64 = 0;
    // Pre-allocate recv buffer outside loop
    let mut buf = vec![0u8; 4 + block_size + 1];
    let mut unknown_tid_responder = UnknownTidResponder::default();

    // Metrics owns the active-transfer count after this handoff.
    let phase = state.phase_classifier.classify(&filename);
    state.metrics.transfer_started(&phase, &boot_profile);
    slot_guard.hand_off();
    let mut lifecycle_guard =
        TransferLifecycleGuard::new(state.metrics.clone(), phase, &boot_profile);

    let final_block = transfer_deadline
        .run_network(socket.as_ref(), client_addr, async {
            socket.send_to(&last_response, client_addr).await?;
            loop {
                let duplicate = async {
                    match duplicate_request {
                        Some(signal) => signal.notified().await,
                        None => std::future::pending().await,
                    }
                };
                tokio::pin!(duplicate);
                let received = tokio::select! {
                    biased;
                    _ = &mut duplicate => {
                        socket.send_to(&last_response, client_addr).await?;
                        metrics.retransmissions = metrics.retransmissions.saturating_add(1);
                        continue;
                    }
                    received = tokio::time::timeout(
                        options.retransmission_policy.retry_rto(retries),
                        recv_from_transfer_peer(
                            socket.as_ref(),
                            client_addr,
                            &mut buf,
                            &mut unknown_tid_responder,
                        ),
                    ) => received,
                };
                match received {
                    Ok(Ok(len)) => {
                        match TftpPacket::parse(&buf[..len], client_addr) {
                            Ok(TftpPacket::Data(data)) => {
                                if data.data.len() > block_size {
                                    let packet = TftpPacket::error(
                                        TftpErrorCode::IllegalOperation,
                                        "Invalid DATA block size",
                                    );
                                    socket.send_to(&packet, client_addr).await?;
                                    return Err(TempestError::Protocol(
                                        ProtocolError::MalformedPacket {
                                            addr: client_addr,
                                            reason: "DATA block exceeds negotiated size".into(),
                                        },
                                    ));
                                }
                                if data.block == expected_block {
                                    // Enforce file size limit
                                    total_bytes_written = total_bytes_written
                                        .checked_add(data.data.len() as u64)
                                        .ok_or_else(|| {
                                            TempestError::Protocol(ProtocolError::AccessViolation(
                                                "file size counter overflow".into(),
                                            ))
                                        })?;
                                    if total_bytes_written > max_write_size {
                                        // Generic error message, don't reveal exact limit
                                        let err_pkt = TftpPacket::error(
                                            TftpErrorCode::DiskFull,
                                            "Transfer size limit exceeded",
                                        );
                                        socket.send_to(&err_pkt, client_addr).await?;
                                        return Err(TempestError::Protocol(
                                            ProtocolError::AccessViolation(
                                                "file size limit exceeded".into(),
                                            ),
                                        ));
                                    }
                                    use tokio::io::AsyncWriteExt;
                                    file.write_all(&data.data).await?;
                                    // Flush BufWriter to ensure data hits disk
                                    metrics.bytes_sent =
                                        metrics.bytes_sent.saturating_add(data.data.len() as u64);
                                    metrics.blocks_sent = metrics.blocks_sent.saturating_add(1);

                                    retries = 0;

                                    // Last block if data < block_size
                                    if data.data.len() < block_size {
                                        return Ok(data.block);
                                    }
                                    last_response = TftpPacket::ack(data.block);
                                    socket.send_to(&last_response, client_addr).await?;
                                    expected_block = expected_block.wrapping_add(1);
                                } else {
                                    // Duplicate or out of order — repeat the response
                                    // representing the last accepted receive state.
                                    socket.send_to(&last_response, client_addr).await?;
                                    metrics.retransmissions =
                                        metrics.retransmissions.saturating_add(1);
                                }
                            }
                            Ok(TftpPacket::Error(e)) => {
                                // Sanitize error message before logging.
                                let safe_msg: String = e
                                    .message
                                    .chars()
                                    .map(|c| if c.is_control() { '_' } else { c })
                                    .take(200)
                                    .collect();
                                warn!(
                                    transfer_id = %transfer_id,
                                    "Client error during write: {} (code {})",
                                    safe_msg, e.code
                                );
                                return Err(TempestError::Protocol(ProtocolError::ClientAbort {
                                    addr: client_addr,
                                }));
                            }
                            _ => {}
                        }
                    }
                    Ok(Err(e)) => return Err(e.into()),
                    Err(_) => {
                        if retries >= max_retries {
                            return Err(TempestError::Protocol(ProtocolError::Timeout {
                                addr: client_addr,
                                block: expected_block,
                            }));
                        }
                        retries = retries.saturating_add(1);
                        socket.send_to(&last_response, client_addr).await?;
                        metrics.retransmissions = metrics.retransmissions.saturating_add(1);
                    }
                }
            }
        })
        .await?;

    // Only a fully received upload reaches publication. Do not cancel a
    // blocking durable publish: it could otherwise rename after cancellation.
    // Flush and sync to ensure data is persisted before acknowledging
    {
        use tokio::io::AsyncWriteExt;
        file.flush().await?;
        file.get_ref().sync_all().await?;
    }

    drop(file);
    let publish_root = artifact_root;
    let allow_overwrite = state.config.server.write_allow_overwrite;
    tokio::task::spawn_blocking(move || {
        publish_root.publish_write(&temp_relative, &final_relative, allow_overwrite)
    })
    .await
    .map_err(|error| TempestError::Io(std::io::Error::other(error)))??;
    temp_guard.commit();
    let final_ack = TftpPacket::ack(final_block);
    transfer_deadline
        .acknowledge_committed_write(socket.as_ref(), client_addr, &final_ack)
        .await?;

    // RFC 1350 receivers briefly retain their transfer TID after committing the
    // final block. Otherwise a lost final ACK leaves the writer retrying a DATA
    // packet to a closed socket even though the artifact was already published.
    // The fixed deadline prevents duplicate traffic from extending transfer
    // ownership indefinitely.
    let dally_period = options.retransmission_policy.retry_rto(0).saturating_mul(2);
    let dally_deadline = (tokio::time::Instant::now() + dally_period).min(transfer_deadline.0);
    loop {
        // Ready duplicates must not win over an already expired deadline.
        if tokio::time::Instant::now() >= dally_deadline {
            break;
        }
        match tokio::time::timeout_at(
            dally_deadline,
            recv_from_transfer_peer(
                socket.as_ref(),
                client_addr,
                &mut buf,
                &mut unknown_tid_responder,
            ),
        )
        .await
        {
            Ok(Ok(len)) => match TftpPacket::parse(&buf[..len], client_addr) {
                Ok(TftpPacket::Data(data)) if data.block == final_block => {
                    let Ok(sent) = tokio::time::timeout_at(
                        dally_deadline,
                        socket.send_to(&final_ack, client_addr),
                    )
                    .await
                    else {
                        break;
                    };
                    if let Err(error) = sent {
                        debug!(
                            transfer_id = %transfer_id,
                            %error,
                            "WRQ final-ACK dally ended after send failure"
                        );
                        break;
                    }
                    metrics.retransmissions = metrics.retransmissions.saturating_add(1);
                }
                Ok(TftpPacket::Error(_)) => break,
                _ => {}
            },
            Ok(Err(error)) => {
                debug!(
                    transfer_id = %transfer_id,
                    %error,
                    "WRQ final-ACK dally ended after receive failure"
                );
                break;
            }
            Err(_) => break,
        }
    }

    metrics.end_time = Some(Instant::now());

    state
        .metrics
        .transfer_completed(&phase, &boot_profile, &metrics);
    lifecycle_guard.complete();

    debug!(
        transfer_id = %transfer_id,
        filename = %filename,
        bytes = metrics.bytes_sent,
        blocks = metrics.blocks_sent,
        "Write transfer completed"
    );

    Ok(metrics)
}

#[cfg(test)]
mod tests;
