// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Optional Linux segmentation for already bounded standard DATA windows.
//! Every segment is an ordinary TFTP datagram, including its own header.

use std::io::{self, IoSlice};
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use nix::errno::Errno;
use nix::sys::socket::{ControlMessage, MsgFlags, SockaddrStorage, sendmsg};
use tokio::net::UdpSocket;

use super::WindowDataPacket;

const MAX_SEGMENTS: usize = 64;
const MAX_BATCH_BYTES: usize = 65_507;

static IPV4_CAPABILITY: AtomicBool = AtomicBool::new(true);
static IPV6_CAPABILITY: AtomicBool = AtomicBool::new(true);
static IPV4_PROBE: OnceLock<io::Result<()>> = OnceLock::new();
static IPV6_PROBE: OnceLock<io::Result<()>> = OnceLock::new();
static BATCHES_SENT: AtomicU64 = AtomicU64::new(0);
static FALLBACKS: AtomicU64 = AtomicU64::new(0);

fn probe_kernel(bind: IpAddr) -> io::Result<()> {
    let domain = if bind.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    nix::sys::socket::setsockopt(&socket, nix::sys::socket::sockopt::UdpGsoSegment, &0)
        .map_err(|error| io::Error::from_raw_os_error(error as i32))
}

fn capability_with(
    cache: &OnceLock<io::Result<()>>,
    probe: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    cache.get_or_init(probe).as_ref().copied().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("UDP_SEGMENT socket-option probe failed: {error}"),
        )
    })
}

/// Kernel support is tracked per address family, matching the startup probe:
/// an unsupported IPv6 path must not disable segmentation for IPv4 transfers.
fn capability(ipv4: bool) -> &'static AtomicBool {
    select_capability(&IPV4_CAPABILITY, &IPV6_CAPABILITY, ipv4)
}

fn select_capability<'a>(
    ipv4_capability: &'a AtomicBool,
    ipv6_capability: &'a AtomicBool,
    ipv4: bool,
) -> &'a AtomicBool {
    if ipv4 {
        ipv4_capability
    } else {
        ipv6_capability
    }
}

pub(super) fn initialize(bind: IpAddr) -> io::Result<()> {
    if !capability(bind.is_ipv4()).load(Ordering::Acquire) {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "UDP segmentation was disabled for this address family by a capability failure; restart required",
        ));
    }
    let cache = if bind.is_ipv4() {
        &IPV4_PROBE
    } else {
        &IPV6_PROBE
    };
    capability_with(cache, || probe_kernel(bind))
}

fn reject_capability(capability: &AtomicBool, error: Errno) {
    if matches!(error, Errno::ENOPROTOOPT | Errno::EOPNOTSUPP) {
        capability.store(false, Ordering::Release);
    }
}

pub(super) fn counters() -> (u64, u64) {
    (
        BATCHES_SENT.load(Ordering::Relaxed),
        FALLBACKS.load(Ordering::Relaxed),
    )
}

#[derive(Debug, PartialEq, Eq)]
struct GsoBatch {
    segments: usize,
    segment_size: u16,
    wire_bytes: usize,
}

impl GsoBatch {
    fn new(packets: &[WindowDataPacket]) -> Option<Self> {
        let segment_size = packets.first()?.wire_len();
        if segment_size > MAX_BATCH_BYTES {
            return None;
        }
        let mut segments = 0;
        let mut wire_bytes = 0;
        for packet in packets.iter().take(MAX_SEGMENTS) {
            let length = packet.wire_len();
            if length > segment_size || length > MAX_BATCH_BYTES - wire_bytes {
                break;
            }
            segments += 1;
            wire_bytes += length;
            if length < segment_size {
                break;
            }
        }
        (segments > 1).then_some(Self {
            segments,
            segment_size: segment_size as u16,
            wire_bytes,
        })
    }
}

pub(super) struct GsoState {
    disabled: bool,
}

impl Default for GsoState {
    fn default() -> Self {
        Self::new(false)
    }
}

impl GsoState {
    pub(super) fn new(enabled: bool) -> Self {
        Self { disabled: !enabled }
    }

    pub(super) fn try_send(
        &mut self,
        socket: &UdpSocket,
        destination: SocketAddr,
        artifact: &[u8],
        packets: &[WindowDataPacket],
    ) -> io::Result<Option<usize>> {
        if self.disabled {
            return Ok(None);
        }
        let capability = capability(destination.is_ipv4());
        if !capability.load(Ordering::Acquire) {
            self.disabled = true;
            return Ok(None);
        }
        let Some(batch) = GsoBatch::new(packets) else {
            return Ok(None);
        };
        let mut slices = [IoSlice::new(&[]); MAX_SEGMENTS * 2];
        for (index, packet) in packets[..batch.segments].iter().enumerate() {
            slices[2 * index] = IoSlice::new(&packet.header);
            slices[2 * index + 1] = IoSlice::new(&artifact[packet.payload.clone()]);
        }
        let destination = SockaddrStorage::from(destination);
        let result = sendmsg(
            socket.as_raw_fd(),
            &slices[..batch.segments * 2],
            &[ControlMessage::UdpGsoSegments(&batch.segment_size)],
            MsgFlags::MSG_DONTWAIT,
            Some(&destination),
        );
        if let Err(error) = result {
            reject_capability(capability, error);
        }
        self.complete(&batch, result)
    }

    fn complete(
        &mut self,
        batch: &GsoBatch,
        result: Result<usize, Errno>,
    ) -> io::Result<Option<usize>> {
        match result {
            Ok(sent) if sent == batch.wire_bytes => {
                BATCHES_SENT.fetch_add(1, Ordering::Relaxed);
                Ok(Some(batch.segments))
            }
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial UDP segmentation batch",
            )),
            Err(
                Errno::ENOPROTOOPT
                | Errno::EOPNOTSUPP
                | Errno::EINVAL
                | Errno::EMSGSIZE
                | Errno::EIO,
            ) => {
                self.disabled = true;
                FALLBACKS.fetch_add(1, Ordering::Relaxed);
                Ok(None)
            }
            Err(error) => Err(io::Error::from_raw_os_error(error as i32)),
        }
    }
}

#[cfg(test)]
mod tests;
