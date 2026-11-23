// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use super::super::{DataWindowSendState, send_data_window, send_data_window_batch};
use super::*;

#[test]
fn unsupported_kernel_is_probed_once_without_sending_a_batch() {
    let cache = OnceLock::new();
    let error = capability_with(&cache, || {
        Err(io::Error::from_raw_os_error(Errno::ENOPROTOOPT as i32))
    })
    .unwrap_err();
    assert!(error.to_string().contains("UDP_SEGMENT"));
    assert!(
        error
            .to_string()
            .contains(&io::Error::from_raw_os_error(Errno::ENOPROTOOPT as i32).to_string())
    );
    assert_eq!(
        capability_with(&cache, || panic!("unsupported capability was reprobed"))
            .unwrap_err()
            .to_string(),
        error.to_string()
    );
}

#[test]
fn address_family_probe_failures_are_independent_and_preserve_the_cause() {
    let ipv4 = OnceLock::new();
    let ipv6 = OnceLock::new();
    let error = capability_with(&ipv4, || {
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "IPv4 disabled",
        ))
    })
    .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::AddrNotAvailable);
    assert!(error.to_string().contains("IPv4 disabled"));
    capability_with(&ipv6, || Ok(())).unwrap();
    capability_with(&ipv6, || panic!("successful capability was reprobed")).unwrap();
}

#[test]
#[ignore = "requires Linux UDP_SEGMENT; also run with AF_INET denied for IPv6-only qualification"]
fn gso_kernel_ipv6_probe_does_not_bind_or_require_ipv4() {
    let bind = "2001:db8::1".parse().unwrap();
    probe_kernel(bind).unwrap();
    initialize(bind).unwrap();
}

#[test]
fn capability_failures_are_family_wide_but_io_and_mtu_rejections_are_local() {
    for error in [
        Errno::ENOPROTOOPT,
        Errno::EOPNOTSUPP,
        Errno::EIO,
        Errno::EINVAL,
        Errno::EMSGSIZE,
        Errno::EINTR,
    ] {
        let available = AtomicBool::new(true);
        reject_capability(&available, error);
        assert_eq!(
            available.load(Ordering::Acquire),
            matches!(
                error,
                Errno::EIO | Errno::EINVAL | Errno::EMSGSIZE | Errno::EINTR
            )
        );
    }
}

#[test]
fn capability_is_tracked_independently_per_address_family() {
    assert!(std::ptr::eq(capability(true), &IPV4_CAPABILITY));
    assert!(std::ptr::eq(capability(false), &IPV6_CAPABILITY));
    let ipv4 = AtomicBool::new(true);
    let ipv6 = AtomicBool::new(true);
    let ipv4_peer: SocketAddr = "192.0.2.1:69".parse().unwrap();
    let ipv6_peer: SocketAddr = "[2001:db8::1]:69".parse().unwrap();
    // IPv6 sockets report IPv4-mapped peers as IPv6, matching the socket family.
    let mapped_peer: SocketAddr = "[::ffff:192.0.2.1]:69".parse().unwrap();
    reject_capability(
        select_capability(&ipv4, &ipv6, ipv6_peer.is_ipv4()),
        Errno::EOPNOTSUPP,
    );
    assert!(!ipv6.load(Ordering::Acquire));
    assert!(select_capability(&ipv4, &ipv6, ipv4_peer.is_ipv4()).load(Ordering::Acquire));
    assert!(!select_capability(&ipv4, &ipv6, mapped_peer.is_ipv4()).load(Ordering::Acquire));
    reject_capability(
        select_capability(&ipv4, &ipv6, ipv4_peer.is_ipv4()),
        Errno::ENOPROTOOPT,
    );
    assert!(!ipv4.load(Ordering::Acquire));
}

fn packets(lengths: &[usize]) -> Vec<WindowDataPacket> {
    lengths
        .iter()
        .enumerate()
        .map(|(index, length)| WindowDataPacket::new(index as u16, 0..length - 4))
        .collect()
}

#[test]
fn gso_sender_captures_config_opt_in_and_keeps_rejection_local() {
    assert!(DataWindowSendState::default().gso.disabled);
    for source in ["", "[server]\nudp_segmentation_offload = false\n"] {
        let config: crate::config::TempestConfig = toml::from_str(source).unwrap();
        assert!(
            DataWindowSendState::new(config.server.udp_segmentation_offload)
                .gso
                .disabled
        );
    }
    let mut config: crate::config::TempestConfig =
        toml::from_str("[server]\nudp_segmentation_offload = true\n").unwrap();
    let mut state = DataWindowSendState::new(config.server.udp_segmentation_offload);
    config.server.udp_segmentation_offload = false;
    assert!(!state.gso.disabled);
    let batch = GsoBatch::new(&packets(&[8, 8])).unwrap();
    assert_eq!(state.gso.complete(&batch, Ok(16)).unwrap(), Some(2));
    assert_eq!(
        state.gso.complete(&batch, Err(Errno::EMSGSIZE)).unwrap(),
        None
    );
    assert!(state.gso.disabled);
    assert!(!DataWindowSendState::new(true).gso.disabled);
    assert!(
        DataWindowSendState::new(config.server.udp_segmentation_offload)
            .gso
            .disabled
    );
}

#[tokio::test]
async fn gso_disabled_skips_syscall_and_never_advances_prefix() {
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packets = packets(&[8, 8]);
    assert!(GsoBatch::new(&packets).is_some());
    for mut state in [GsoState::default(), GsoState::new(false)] {
        for artifact in [&[][..], &b"abcd"[..]] {
            assert_eq!(
                state
                    .try_send(&sender, receiver.local_addr().unwrap(), artifact, &packets)
                    .unwrap(),
                None
            );
        }
        assert!(state.disabled);
        assert_eq!(
            receiver.try_recv_from(&mut [0; 64]).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn gso_plan_bounds_segments_bytes_and_short_final() {
    assert_eq!(GsoBatch::new(&[]), None);
    assert_eq!(GsoBatch::new(&packets(&[1472])), None);
    assert_eq!(GsoBatch::new(&packets(&[65_508, 4])), None);
    let batch = GsoBatch::new(&packets(&[1472; 64])).unwrap();
    assert_eq!(
        (batch.segments, batch.wire_bytes, batch.segment_size),
        (44, 64_768, 1472)
    );
    let batch = GsoBatch::new(&packets(&[100; 65])).unwrap();
    assert_eq!((batch.segments, batch.wire_bytes), (64, 6400));
    assert_eq!(
        GsoBatch::new(&packets(&[32_754, 32_753]))
            .unwrap()
            .wire_bytes,
        65_507
    );
    assert_eq!(GsoBatch::new(&packets(&[32_754, 32_754])), None);
    let batch = GsoBatch::new(&packets(&[1472, 4, 1472])).unwrap();
    assert_eq!((batch.segments, batch.wire_bytes), (2, 1476));
    assert_eq!(GsoBatch::new(&packets(&[4, 1472])), None);
}

#[test]
fn gso_rejections_disable_only_this_transfer() {
    let batch = GsoBatch::new(&packets(&[1472; 8])).unwrap();
    for error in [
        Errno::ENOPROTOOPT,
        Errno::EOPNOTSUPP,
        Errno::EINVAL,
        Errno::EMSGSIZE,
        Errno::EIO,
    ] {
        let mut state = GsoState::new(true);
        assert_eq!(state.complete(&batch, Err(error)).unwrap(), None);
        assert!(state.disabled);
        assert!(!GsoState::new(true).disabled);
    }
}

#[test]
fn gso_short_or_failed_sends_never_replay_an_accepted_prefix() {
    let batch = GsoBatch::new(&packets(&[1472; 8])).unwrap();
    let mut state = GsoState::new(true);
    assert_eq!(
        state.complete(&batch, Ok(batch.wire_bytes)).unwrap(),
        Some(8)
    );
    for sent in [0, 1472, batch.wire_bytes - 1, batch.wire_bytes + 1] {
        assert_eq!(
            state.complete(&batch, Ok(sent)).unwrap_err().kind(),
            io::ErrorKind::WriteZero
        );
        assert!(!state.disabled);
    }
    for error in [
        Errno::EAGAIN,
        Errno::EINTR,
        Errno::ENOBUFS,
        Errno::EACCES,
        Errno::ECONNREFUSED,
    ] {
        assert_eq!(
            state
                .complete(&batch, Err(error))
                .unwrap_err()
                .raw_os_error(),
            Some(error as i32)
        );
        assert!(!state.disabled);
    }
}

async fn receive_packets(
    receiver: &UdpSocket,
    sender: &UdpSocket,
    artifact: &[u8],
    packets: &[WindowDataPacket],
) {
    let mut buffer = vec![0; 65_536];
    for packet in packets {
        let (length, peer) = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            receiver.recv_from(&mut buffer),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(peer, sender.local_addr().unwrap());
        assert_eq!(length, packet.wire_len());
        assert_eq!(&buffer[..4], &packet.header);
        assert_eq!(&buffer[4..length], &artifact[packet.payload.clone()]);
    }
    assert_eq!(
        receiver.try_recv_from(&mut buffer).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(sender.peer_addr().is_err());
}

async fn bind_loopback_if_available(bind: &str) -> Option<UdpSocket> {
    match UdpSocket::bind(bind).await {
        Ok(socket) => Some(socket),
        Err(error)
            if bind == "[::1]:0"
                && matches!(
                    error.kind(),
                    io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported
                ) =>
        {
            eprintln!("IPv6 loopback is unavailable on this test runner: {error}");
            None
        }
        Err(error) => panic!("failed to bind UDP loopback {bind}: {error}"),
    }
}

#[tokio::test]
async fn gso_disabled_retains_sendmmsg_windows_and_governor_accounting() {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        for mut state in [
            DataWindowSendState::default(),
            DataWindowSendState::new(false),
        ] {
            let Some(sender) = bind_loopback_if_available(bind).await else {
                break;
            };
            let receiver = UdpSocket::bind(bind).await.unwrap();
            let artifact = b"abcdefghijkl";
            let packets = [
                WindowDataPacket::new(u16::MAX, 0..4),
                WindowDataPacket::new(0, 4..8),
                WindowDataPacket::new(1, 8..12),
                WindowDataPacket::new(2, 12..12),
            ];
            let governor = crate::features::bandwidth_governor::BandwidthGovernor::new(1_000, true);
            let tokens = governor.available_tokens();
            send_data_window(
                &sender,
                receiver.local_addr().unwrap(),
                artifact,
                &packets,
                Some(&governor),
                &mut state,
            )
            .await
            .unwrap();
            assert!(state.gso.disabled);
            assert_eq!(governor.available_tokens(), tokens - 28);
            receive_packets(&receiver, &sender, artifact, &packets).await;
        }
    }
}

#[tokio::test]
async fn gso_fallback_preserves_datagrams_and_charges_governor_once() {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        for error in [Errno::EOPNOTSUPP, Errno::EIO] {
            let Some(sender) = bind_loopback_if_available(bind).await else {
                break;
            };
            let receiver = UdpSocket::bind(bind).await.unwrap();
            let artifact = b"abcdefghijkl";
            let packets = [
                WindowDataPacket::new(u16::MAX, 0..4),
                WindowDataPacket::new(0, 4..8),
                WindowDataPacket::new(1, 8..12),
                WindowDataPacket::new(2, 12..12),
            ];
            let mut state = DataWindowSendState::new(true);
            let batch = GsoBatch::new(&packets).unwrap();
            assert_eq!(state.gso.complete(&batch, Err(error)).unwrap(), None);
            assert_eq!(
                state
                    .gso
                    .try_send(&sender, receiver.local_addr().unwrap(), &[], &packets)
                    .unwrap(),
                None
            );
            let governor = crate::features::bandwidth_governor::BandwidthGovernor::new(1_000, true);
            let tokens = governor.available_tokens();
            send_data_window(
                &sender,
                receiver.local_addr().unwrap(),
                artifact,
                &packets,
                Some(&governor),
                &mut state,
            )
            .await
            .unwrap();
            assert_eq!(governor.available_tokens(), tokens - 28);
            assert!(state.gso.disabled);
            receive_packets(&receiver, &sender, artifact, &packets).await;
        }
    }
}

#[tokio::test]
async fn gso_multiple_chunks_preserve_bytes_limits_and_order() {
    for (count, block_size) in [(64, 1468), (64, 96), (3, 32_750)] {
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket2::SockRef::from(&receiver)
            .set_recv_buffer_size(1024 * 1024)
            .unwrap();
        let artifact: Vec<u8> = (0..count * block_size - 13)
            .map(|index| (index % 251) as u8)
            .collect();
        let packets: Vec<_> = (0..count)
            .map(|index| {
                WindowDataPacket::new(
                    u16::MAX.wrapping_add(index as u16),
                    index * block_size..((index + 1) * block_size).min(artifact.len()),
                )
            })
            .collect();
        let mut state = DataWindowSendState::new(true);
        let send = send_data_window_batch(
            &sender,
            receiver.local_addr().unwrap(),
            &artifact,
            &packets,
            &mut state,
        );
        let receive = receive_packets(&receiver, &sender, &artifact, &packets);
        let (result, ()) = tokio::join!(send, receive);
        result.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires Linux UDP_SEGMENT; run explicitly for GSO qualification"]
async fn gso_kernel_preserves_ipv4_ipv6_datagrams_and_tid() {
    for bind in ["127.0.0.1:0", "[::1]:0"] {
        for tail in [0, 17, 1468] {
            let sender = UdpSocket::bind(bind).await.unwrap();
            let receiver = UdpSocket::bind(bind).await.unwrap();
            let mut state = GsoState::new(true);
            let artifact: Vec<u8> = (0..1468 * 2 + tail)
                .map(|index| (index % 251) as u8)
                .collect();
            let packets = [
                WindowDataPacket::new(u16::MAX, 0..1468),
                WindowDataPacket::new(0, 1468..2936),
                WindowDataPacket::new(1, 2936..2936 + tail),
            ];
            let sent = sender
                .async_io(tokio::io::Interest::WRITABLE, || {
                    state.try_send(&sender, receiver.local_addr().unwrap(), &artifact, &packets)
                })
                .await
                .unwrap();
            assert_eq!(sent, Some(3), "GSO must actually execute, not fall back");
            assert!(!state.disabled);
            receive_packets(&receiver, &sender, &artifact, &packets).await;
        }
    }
}

#[tokio::test]
#[ignore = "requires Linux UDP_SEGMENT; run explicitly for GSO qualification"]
async fn gso_kernel_accepted_prefix_is_not_replayed_when_suffix_falls_back() {
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let artifact = vec![0xa7; 64 * 1468];
    let packets: Vec<_> = (0..64)
        .map(|index| WindowDataPacket::new(index as u16 + 1, index * 1468..(index + 1) * 1468))
        .collect();
    let mut state = DataWindowSendState::new(true);
    let sent = sender
        .async_io(tokio::io::Interest::WRITABLE, || {
            state
                .gso
                .try_send(&sender, receiver.local_addr().unwrap(), &artifact, &packets)
        })
        .await
        .unwrap()
        .expect("must accept a real GSO prefix");
    assert_eq!(sent, 44);
    receive_packets(&receiver, &sender, &artifact, &packets[..sent]).await;
    let suffix = &packets[sent..];
    let batch = GsoBatch::new(suffix).unwrap();
    assert_eq!(
        state.gso.complete(&batch, Err(Errno::EMSGSIZE)).unwrap(),
        None
    );
    send_data_window_batch(
        &sender,
        receiver.local_addr().unwrap(),
        &artifact,
        suffix,
        &mut state,
    )
    .await
    .unwrap();
    receive_packets(&receiver, &sender, &artifact, suffix).await;
}

#[tokio::test]
async fn gso_governor_wait_can_be_cancelled_before_any_send() {
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let governor = crate::features::bandwidth_governor::BandwidthGovernor::new(1_000, true);
    governor.acquire(governor.burst_cap() as usize).await;
    let artifact = b"abcdefghijkl";
    let packets = [
        WindowDataPacket::new(1, 0..4),
        WindowDataPacket::new(2, 4..8),
    ];
    let mut state = DataWindowSendState::new(true);
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            send_data_window(
                &sender,
                receiver.local_addr().unwrap(),
                artifact,
                &packets,
                Some(&governor),
                &mut state
            ),
        )
        .await
        .is_err()
    );
    assert_eq!(
        receiver.try_recv_from(&mut [0; 64]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    assert_eq!(governor.available_tokens(), 0);
    assert!(!state.gso.disabled);
}
