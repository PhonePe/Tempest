// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::features::boot_phase::BootPhase;
use crate::protocol::packet::{RequestPacket, TransferMode};
use crate::protocol::transfer::TransferMetrics;
use std::net::{Ipv4Addr, Ipv6Addr};

#[test]
fn coordinated_deletion_defaults_off_and_builder_requires_sql() {
    let config = TempestConfig::default();
    assert!(!config.persistence.coordinated_deletion);
    let parsed: crate::config::PersistenceConfig = toml::from_str("enabled = false").unwrap();
    assert!(!parsed.coordinated_deletion);
    let mut config = config;
    config.persistence.coordinated_deletion = true;
    let error = match TftpServer::builder(config).build() {
        Ok(_) => panic!("a runtime-only deletion flag must not silently enable memory deletion"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("attached SQL store"));
}

#[tokio::test]
async fn cancelled_artifact_io_retains_its_worker_permit() {
    let state = TftpServer::new(TempestConfig::default()).state();
    let _other_workers = state.artifact_io_budget.acquire_many(31).await.unwrap();
    let (started, running) = tokio::sync::oneshot::channel();
    let (release, finish) = std::sync::mpsc::channel();
    let worker_state = state.clone();
    let worker = tokio::spawn(async move {
        worker_state
            .artifact_io(move || {
                started.send(()).unwrap();
                finish.recv().unwrap();
                Ok(())
            })
            .await
    });
    running.await.unwrap();
    worker.abort();
    let _ = worker.await;
    assert_eq!(state.artifact_io_budget.available_permits(), 0);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(10),
            state.artifact_io::<()>(|| panic!("worker budget bypassed"))
        )
        .await
        .is_err()
    );
    release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(30), state.artifact_io(|| Ok(())))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.artifact_io_budget.available_permits(), 1);
}

#[tokio::test]
async fn tftp_socket_buffer_configuration_is_applied() {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    configure_udp_socket_buffers(&socket, 128 * 1024, Some(256 * 1024)).unwrap();
    let socket = socket2::SockRef::from(&socket);
    let receive_bytes = socket.recv_buffer_size().unwrap();
    let send_bytes = socket.send_buffer_size().unwrap();

    assert!(receive_bytes > 0);
    assert!(send_bytes > 0);
}

#[tokio::test]
async fn zero_transfer_socket_buffer_keeps_operating_system_defaults() {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let socket_ref = socket2::SockRef::from(&socket);
    let before = (
        socket_ref.recv_buffer_size().unwrap(),
        socket_ref.send_buffer_size().unwrap(),
    );

    configure_transfer_socket_buffers(&socket, 0).unwrap();

    assert_eq!(
        (
            socket_ref.recv_buffer_size().unwrap(),
            socket_ref.send_buffer_size().unwrap(),
        ),
        before
    );
}

#[tokio::test]
async fn ipv6_tftp_listener_receives_datagrams() {
    let listener = match bind_tftp_listener(SocketAddr::from((Ipv6Addr::LOCALHOST, 0)), false) {
        Ok(listener) => listener,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
            ) =>
        {
            eprintln!("IPv6 loopback is unavailable on this test runner: {error}");
            return;
        }
        Err(error) => panic!("failed to bind IPv6 TFTP listener: {error}"),
    };
    let client = match UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).await {
        Ok(client) => client,
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::Unsupported
            ) =>
        {
            eprintln!("IPv6 loopback client is unavailable on this test runner: {error}");
            return;
        }
        Err(error) => panic!("failed to bind IPv6 TFTP client: {error}"),
    };
    let packet = TftpPacket::rrq("artifact.bin", "octet");

    client
        .send_to(&packet, listener.local_addr().unwrap())
        .await
        .unwrap();

    let mut received = [0u8; 128];
    let (length, peer) =
        tokio::time::timeout(Duration::from_secs(30), listener.recv_from(&mut received))
            .await
            .unwrap()
            .unwrap();

    assert!(peer.is_ipv6());
    assert_eq!(&received[..length], &packet[..]);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn reuse_port_listener_shards_bind_the_same_endpoint() {
    let first = bind_tftp_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), true).unwrap();
    let bound_addr = first.local_addr().unwrap();
    let second = bind_tftp_listener(bound_addr, true).unwrap();

    assert_eq!(second.local_addr().unwrap(), bound_addr);
}

#[test]
fn builder_rejects_invalid_session_capacity_before_metrics_initialization() {
    for capacity in [0, 1_000_001, usize::MAX / 2, usize::MAX] {
        let mut config = TempestConfig::default();
        config.server.max_boot_sessions = capacity;
        let error = match TftpServer::builder(config).build() {
            Ok(_) => panic!("builder accepted invalid session capacity {capacity}"),
            Err(error) => error,
        };
        assert!(matches!(error, TempestError::Config(_)));
        assert!(error.to_string().contains("max_boot_sessions"));
    }
    let mut config = TempestConfig::default();
    config.server.max_boot_sessions = 1;
    assert!(TftpServer::builder(config).build().is_ok());
}

#[test]
fn builder_rejects_unbounded_socket_memory_configuration() {
    let mut config = TempestConfig::default();
    config.server.transfer_socket_buffer_bytes = usize::MAX;

    let error = match TftpServer::builder(config).build() {
        Ok(_) => panic!("builder must reject an unbounded transfer socket buffer"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("transfer_socket_buffer_bytes"));

    let mut config = TempestConfig::default();
    config.server.max_concurrent_transfers = 10_000;
    config.server.transfer_socket_buffer_bytes = 4 * 1024 * 1024;
    let error = match TftpServer::builder(config).build() {
        Ok(_) => panic!("builder must reject an excessive aggregate socket budget"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("multiplied"));
}

#[test]
fn socket_memory_budget_counts_send_and_receive_buffers() {
    let mut config = TempestConfig::default();
    config.server.max_concurrent_transfers = 10_000;
    config.server.transfer_socket_buffer_bytes = 64 * 1024;

    let error = match TftpServer::builder(config).build() {
        Ok(_) => panic!("aggregate send and receive buffers must fit the budget"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("send and receive"));
}

#[test]
fn matching_phase_applies_its_window_ceiling_and_internal_rto() {
    let mut config = TempestConfig::default();
    let phase = config
        .boot_phases
        .iter_mut()
        .find(|phase| phase.name == "OS_IMAGE")
        .unwrap();
    phase.max_window_size = 8;
    phase.retransmit_interval_ms = 1_000;
    phase.min_retransmit_interval_ms = 250;
    phase.max_retransmit_interval_ms = 4_000;

    let server = TftpServer::builder(config).build().unwrap();
    let state = server.state();
    let profile = state.phase_classifier.profile("loadtest/file-1m.img");
    let defaults = option_defaults_for_profile(&state, profile);
    let (options, acknowledged) = crate::protocol::options::negotiate_options(
        &[("windowsize".into(), "16".into())],
        &defaults,
    );

    assert_eq!(options.window_size, 8);
    assert_eq!(acknowledged, vec![("windowsize".into(), "8".into())]);
    assert_eq!(
        options.retransmission_policy.initial_rto(),
        Duration::from_secs(1)
    );
    assert_eq!(
        options.retransmission_policy.min_rto(),
        Duration::from_millis(250)
    );
}

#[test]
fn server_timeout_policy_declines_only_the_requested_timeout() {
    let mut config = TempestConfig::default();
    config.server.accept_client_timeout = false;
    config.server.default_block_size = 1468;

    let server = TftpServer::builder(config).build().unwrap();
    let state = server.state();
    let defaults = option_defaults_for_profile(&state, None);
    let options = negotiate_options_only_for_request(
        &[
            ("blksize".into(), "1468".into()),
            ("windowsize".into(), "8".into()),
            ("timeout".into(), "5".into()),
        ],
        &defaults,
        OptionRequestKind::Read,
        state.config.server.accept_client_timeout,
        state.config.server.max_client_timeout_secs,
    );

    assert_eq!(options.block_size, 1468);
    assert_eq!(options.window_size, 8);
    assert!(!options.timeout_requested);
    assert!(options.retransmission_policy.is_adaptive());
}

#[test]
fn transfer_ids_are_uuid_shaped_and_unique_under_contention() {
    let generator = Arc::new(TransferIdGenerator::new());
    let workers: Vec<_> = (0..8)
        .map(|_| {
            let generator = generator.clone();
            std::thread::spawn(move || {
                (0..1_024)
                    .map(|_| generator.next().unwrap())
                    .collect::<Vec<_>>()
            })
        })
        .collect();
    let ids: Vec<_> = workers
        .into_iter()
        .flat_map(|worker| worker.join().unwrap())
        .collect();
    let unique: std::collections::HashSet<_> = ids.iter().copied().collect();

    assert_eq!(unique.len(), ids.len());
    assert!(ids.iter().all(|id| (id.as_u128() >> 76) & 0xf == 4));
    assert!(ids.iter().all(|id| (id.as_u128() >> 62) & 0x3 == 2));
}

async fn download_with_gate(
    server: SocketAddr,
    arrived: Arc<tokio::sync::Barrier>,
    release: Arc<tokio::sync::Barrier>,
) -> Vec<u8> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    socket
        .send_to(&TftpPacket::rrq("artifact.bin", "octet"), server)
        .await
        .unwrap();
    let mut result = Vec::new();
    let mut expected = 1u16;
    let mut buffer = [0u8; 1024];
    loop {
        let (len, peer) = socket.recv_from(&mut buffer).await.unwrap();
        let TftpPacket::Data(data) = TftpPacket::parse(&buffer[..len], peer).unwrap() else {
            panic!("expected DATA packet");
        };
        if data.block == expected {
            if expected == 1 {
                arrived.wait().await;
                release.wait().await;
            }
            let complete = data.data.len() < 512;
            result.extend_from_slice(&data.data);
            expected = expected.wrapping_add(1);
            socket
                .send_to(&TftpPacket::ack(data.block), peer)
                .await
                .unwrap();
            if complete {
                return result;
            }
        } else {
            socket
                .send_to(&TftpPacket::ack(data.block), peer)
                .await
                .unwrap();
        }
    }
}

fn pending_transfer(filename: &str, phase_weight: f64, arrived_at: Instant) -> PendingTransfer {
    let entry_budget = Arc::new(Semaphore::new(1));
    let byte_budget = Arc::new(Semaphore::new(4096));
    let active = Arc::new(AtomicUsize::new(0));
    let client_addr = SocketAddr::from(([10, 0, 0, 1], 40100));
    PendingTransfer {
        client_addr,
        request: RequestPacket {
            filename: filename.to_string(),
            mode: TransferMode::Octet,
            options: Vec::new(),
        },
        is_write: false,
        arrived_at,
        phase_weight,
        queue_entry_permit: entry_budget.try_acquire_owned().unwrap(),
        queue_byte_permit: byte_budget.try_acquire_many_owned(512).unwrap(),
        audit_reservation: None,
        client_tid_guard: InflightTftpTidGuard::claim(Arc::new(DashMap::new()), client_addr)
            .unwrap(),
        queue_count_guard: QueuedTransferGuard::new(
            Arc::new(AtomicUsize::new(0)),
            Arc::new(ServerMetrics::new(active)),
        ),
    }
}

#[test]
fn test_release_active_transfer_counter_saturates_at_zero() {
    let active = AtomicUsize::new(1);
    assert_eq!(release_active_transfer_counter(&active), 1);
    assert_eq!(active.load(Ordering::Acquire), 0);
    assert_eq!(release_active_transfer_counter(&active), 0);
    assert_eq!(active.load(Ordering::Acquire), 0);
}

#[test]
fn server_uses_configured_tftp_per_ip_request_limit() {
    let mut config = TempestConfig::default();
    config.server.tftp_requests_per_ip_per_second = 1;
    let state = TftpServer::new(config).state();
    let client = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    // One instant: a stalled thread must not cross the one-second window.
    let now = Instant::now();

    assert!(state.tftp_rate_limiter.check_at(client, now));
    assert!(!state.tftp_rate_limiter.check_at(client, now));
}

#[test]
fn server_uses_configured_http_per_ip_request_limit() {
    let mut config = TempestConfig::default();
    config.server.http_requests_per_ip_per_second = 1;
    let state = TftpServer::new(config).state();
    let client = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    let now = Instant::now();

    assert!(state.http_rate_limiter.check_at(client, now));
    assert!(!state.http_rate_limiter.check_at(client, now));
}

#[test]
fn test_reserved_transfer_slot_guard_releases_without_handoff() {
    let state = TftpServer::new(TempestConfig::default()).state();
    state.active_transfers.store(1, Ordering::Release);
    {
        let _guard = ReservedTransferSlotGuard::new(&state);
    }

    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
}

#[test]
fn test_reserved_transfer_slot_guard_handoff_preserves_slot() {
    let state = TftpServer::new(TempestConfig::default()).state();
    state.active_transfers.store(1, Ordering::Release);
    {
        let mut guard = ReservedTransferSlotGuard::new(&state);
        guard.hand_off();
    }

    assert_eq!(state.active_transfers.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn concurrent_client_tid_claims_have_exactly_one_owner() {
    const CLAIMANTS: usize = 16;
    let inflight = Arc::new(DashMap::new());
    let start = Arc::new(tokio::sync::Barrier::new(CLAIMANTS));
    let attempted = Arc::new(tokio::sync::Barrier::new(CLAIMANTS));
    let winners = Arc::new(AtomicUsize::new(0));
    let client_addr = SocketAddr::from(([192, 0, 2, 10], 40100));
    let mut tasks = Vec::with_capacity(CLAIMANTS);

    for _ in 0..CLAIMANTS {
        let inflight = inflight.clone();
        let start = start.clone();
        let attempted = attempted.clone();
        let winners = winners.clone();
        tasks.push(tokio::spawn(async move {
            start.wait().await;
            let guard = InflightTftpTidGuard::claim(inflight, client_addr);
            winners.fetch_add(usize::from(guard.is_some()), Ordering::AcqRel);
            attempted.wait().await;
            drop(guard);
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }

    assert_eq!(winners.load(Ordering::Acquire), 1);
    assert!(inflight.is_empty());
    assert!(InflightTftpTidGuard::claim(inflight.clone(), client_addr).is_some());
}

#[test]
fn test_prune_expired_pending_transfers_preserves_priority_order() {
    let now = Instant::now();
    let cutoff = now - Duration::from_secs(60);
    let mut heap = BinaryHeap::new();
    heap.push(pending_transfer(
        "expired",
        100.0,
        cutoff - Duration::from_secs(1),
    ));
    heap.push(pending_transfer("fresh-low", 1.0, cutoff));
    heap.push(pending_transfer("fresh-high", 10.0, now));

    let dropped = prune_expired_pending_transfers(&mut heap, cutoff);

    assert_eq!(dropped, 1);
    assert_eq!(heap.len(), 2);
    assert_eq!(heap.pop().unwrap().request.filename, "fresh-high");
    assert_eq!(heap.pop().unwrap().request.filename, "fresh-low");
}

#[test]
fn tftp_client_limit_multithreaded_contention_never_overshoots() {
    const WORKERS: usize = 24;
    const LIMIT: usize = 4;
    const ROUNDS: usize = 32;
    let limits = Arc::new(TftpClientLimits::new(LIMIT));
    let barrier = Arc::new(std::sync::Barrier::new(WORKERS + 1));
    let admitted = Arc::new(AtomicUsize::new(0));
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let mut observations = Vec::new();
    std::thread::scope(|scope| {
        for _ in 0..WORKERS {
            let limits = limits.clone();
            let barrier = barrier.clone();
            let admitted = admitted.clone();
            scope.spawn(move || {
                for _ in 0..ROUNDS {
                    barrier.wait();
                    let permit = limits.try_acquire(ip);
                    admitted.fetch_add(usize::from(permit.is_some()), Ordering::SeqCst);
                    barrier.wait();
                    barrier.wait();
                    drop(permit);
                    barrier.wait();
                }
            });
        }
        for _ in 0..ROUNDS {
            admitted.store(0, Ordering::SeqCst);
            barrier.wait();
            barrier.wait();
            let held = (
                admitted.load(Ordering::SeqCst),
                limits.try_acquire(ip).is_none(),
                limits.identities(),
            );
            barrier.wait();
            barrier.wait();
            observations.push((held, limits.identities()));
        }
    });
    assert!(observations.iter().all(|row| *row == ((LIMIT, true, 1), 0)));
}

#[test]
fn tftp_client_limit_distinct_ips_and_ipv4_mapped_ipv6() {
    let limits = Arc::new(TftpClientLimits::new(1));
    let v4 = IpAddr::from([192, 0, 2, 1]);
    let mapped = "::ffff:192.0.2.1".parse().unwrap();
    let first = limits.try_acquire(v4).unwrap();
    assert!(limits.try_acquire(mapped).is_none());
    let second = limits.try_acquire(IpAddr::from([192, 0, 2, 2])).unwrap();
    let v6 = limits.try_acquire("2001:db8::1".parse().unwrap()).unwrap();
    assert!(limits.try_acquire("2001:db8::1".parse().unwrap()).is_none());
    // IPv4-compatible IPv6 is not IPv4-mapped and must stay a distinct identity.
    let compatible = limits.try_acquire("::192.0.2.1".parse().unwrap()).unwrap();
    assert_eq!(limits.identities(), 4);
    drop(first);
    let remapped = limits.try_acquire(mapped).unwrap();
    assert!(limits.try_acquire(v4).is_none());
    drop((second, v6, compatible, remapped));
    assert_eq!(limits.identities(), 0);
}

#[test]
fn tftp_client_limit_identity_bound_fails_closed_and_reclaims() {
    let limits = Arc::new(TftpClientLimits::new(2));
    let mut permits = Vec::new();
    for n in 0..client_limit::MAX_TFTP_CLIENT_IDENTITIES {
        permits.push(
            limits
                .try_acquire(IpAddr::V4(Ipv4Addr::from(n as u32)))
                .unwrap(),
        );
    }
    assert_eq!(
        limits.identities(),
        client_limit::MAX_TFTP_CLIENT_IDENTITIES
    );
    let overflow = IpAddr::V4(Ipv4Addr::from(u32::MAX));
    assert!(limits.try_acquire(overflow).is_none());
    // Full identity capacity does not evict live entries or block existing IPs
    // below their own quota.
    let existing = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    let extra = limits.try_acquire(existing).unwrap();
    assert!(limits.try_acquire(existing).is_none());
    drop(extra);
    drop(permits.pop());
    let replacement = limits.try_acquire(overflow).unwrap();
    assert_eq!(
        limits.identities(),
        client_limit::MAX_TFTP_CLIENT_IDENTITIES
    );
    drop((permits, replacement));
    assert_eq!(limits.identities(), 0);
}

#[test]
fn tftp_client_limit_queue_owns_permit_through_channel_heap_expiry_and_drop() {
    let limits = Arc::new(TftpClientLimits::new(1));
    let now = Instant::now();
    let make_pending = |arrived_at| {
        let mut pending = pending_transfer("artifact.bin", 1.0, arrived_at);
        pending.client_tid_guard.client_limit =
            Some(limits.try_acquire(pending.client_addr.ip()).unwrap());
        pending
    };
    let pending = make_pending(now - Duration::from_secs(5));
    let ip = pending.client_addr.ip();
    let (tx, mut rx) = mpsc::channel(1);
    tx.try_send(pending).unwrap();
    assert!(limits.try_acquire(ip).is_none());
    let mut heap = BinaryHeap::new();
    heap.push(rx.try_recv().unwrap());
    assert!(limits.try_acquire(ip).is_none());
    assert_eq!(prune_expired_pending_transfers(&mut heap, now), 1);
    assert_eq!(limits.identities(), 0);
    heap.push(make_pending(now));
    assert_eq!(prune_expired_pending_transfers(&mut heap, now), 0);
    assert!(limits.try_acquire(ip).is_none());
    drop(heap);
    assert_eq!(limits.identities(), 0);
    tx.try_send(make_pending(now)).unwrap();
    drop(rx);
    assert_eq!(limits.identities(), 0);
    assert!(tx.try_send(make_pending(now)).is_err());
    assert_eq!(limits.identities(), 0);
}

#[test]
fn histogram_observation_updates_cumulative_buckets() {
    let h = DurationHistogram::new();
    h.observe(0.05);
    let (buckets, sum, count) = h.snapshot();
    assert_eq!(buckets[0], 0);
    assert_eq!(buckets[1], 0);
    assert_eq!(buckets[2], 0);
    assert_eq!(buckets[3], 1);
    assert_eq!(buckets[4], 1);
    assert_eq!(count, 1);
    assert!((sum - 0.05).abs() < 1e-10);
}

#[test]
fn test_histogram_cumulative_zero() {
    let h = DurationHistogram::new();
    h.observe(0.0);
    let (buckets, _, count) = h.snapshot();
    for b in &buckets {
        assert_eq!(*b, 1);
    }
    assert_eq!(count, 1);
}

#[test]
fn histogram_sum_tracks_all_observations() {
    let h = DurationHistogram::new();
    h.observe(1.0);
    h.observe(2.0);
    let (_, sum, count) = h.snapshot();
    assert!((sum - 3.0).abs() < 1e-10);
    assert_eq!(count, 2);
}

#[test]
fn test_histogram_nan_guard() {
    let h = DurationHistogram::new();
    h.observe(f64::NAN);
    let (buckets, sum, count) = h.snapshot();
    assert_eq!(count, 1);
    assert!((sum - 0.0).abs() < 1e-10);
    for b in &buckets {
        assert_eq!(*b, 1);
    }
}

#[test]
fn test_histogram_infinite_guard() {
    let h = DurationHistogram::new();
    h.observe(f64::INFINITY);
    h.observe(f64::NEG_INFINITY);
    let (buckets, sum, count) = h.snapshot();
    assert_eq!(count, 2);
    assert_eq!(sum, 0.0);
    for b in &buckets {
        assert_eq!(*b, 2);
    }
}

#[test]
fn test_histogram_negative_guard() {
    let h = DurationHistogram::new();
    h.observe(-5.0);
    let (_, sum, count) = h.snapshot();
    assert_eq!(count, 1);
    assert!((sum - 0.0).abs() < 1e-10);
}

#[test]
fn test_histogram_concurrent_writes() {
    use std::thread;
    let h = Arc::new(DurationHistogram::new());
    let mut handles = vec![];
    for _ in 0..4 {
        let hc = h.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..1000 {
                hc.observe(1.0);
            }
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }
    let (_, sum, count) = h.snapshot();
    assert_eq!(count, 4000);
    assert!((sum - 4000.0).abs() < 1e-6);
}

#[test]
fn concurrent_profile_metrics_never_exceed_the_exact_cap() {
    use std::thread;

    let metrics = Arc::new(ServerMetrics::new(Arc::new(AtomicUsize::new(0))));
    let mut workers = Vec::new();
    for worker in 0..16 {
        let metrics = metrics.clone();
        workers.push(thread::spawn(move || {
            for profile in 0..700 {
                let name = format!("profile-{worker}-{profile}");
                metrics.with_profile_metrics(&name, |profile| {
                    profile.totals.transfers.fetch_add(1, Ordering::Relaxed);
                });
            }
        }));
    }
    for worker in workers {
        worker.join().unwrap();
    }

    assert_eq!(metrics.profile_metrics.len(), MAX_PROFILE_METRICS);
    assert_eq!(
        metrics.profile_metrics_count.load(Ordering::Acquire),
        MAX_PROFILE_METRICS
    );
}

#[test]
fn inactive_profile_metrics_release_capacity() {
    let metrics = ServerMetrics::new(Arc::new(AtomicUsize::new(0)));
    metrics.with_profile_metrics("inactive", |_| {});
    assert_eq!(metrics.profile_metrics_count.load(Ordering::Acquire), 1);

    // Force expiry without assuming the profile was touched at elapsed second zero.
    metrics.evict_inactive_profiles_at(u64::MAX);

    assert!(metrics.profile_metrics.is_empty());
    assert_eq!(metrics.profile_metrics_count.load(Ordering::Acquire), 0);
}

#[test]
fn fixed_metric_dimensions_preserve_phase_transport_and_default_profile_counts() {
    let active = Arc::new(AtomicUsize::new(1));
    let metrics = ServerMetrics::new(active.clone());

    metrics.transfer_started_for_transport(
        &BootPhase::Kernel,
        DEFAULT_BOOT_PROFILE,
        TRANSPORT_HTTP,
    );
    metrics.transfer_failed_for_transport(&BootPhase::Kernel, DEFAULT_BOOT_PROFILE, TRANSPORT_HTTP);

    assert_eq!(active.load(Ordering::Acquire), 0);
    assert_eq!(
        metrics.phase_metrics_snapshot(),
        vec![("KERNEL", (1, 0, 1))]
    );
    assert_eq!(
        metrics.transport_metrics_snapshot(),
        vec![(TRANSPORT_HTTP, (1, 0, 1))]
    );
    assert_eq!(
        metrics.transport_phase_metrics_snapshot(),
        vec![((TRANSPORT_HTTP, "KERNEL"), (1, 0, 1))]
    );
    let profiles = metrics.profile_metrics_snapshot();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].0, DEFAULT_BOOT_PROFILE);
    assert_eq!(profiles[0].1.totals, (1, 0, 1));
    assert!(metrics.profile_metrics.is_empty());
}

#[test]
fn profile_metric_snapshots_are_reused_until_the_next_update() {
    let metrics = ServerMetrics::new(Arc::new(AtomicUsize::new(0)));
    metrics.with_profile_metrics("cached", |profile| {
        profile.totals.transfers.fetch_add(1, Ordering::Relaxed);
    });

    let first = metrics.shared_profile_metrics_snapshot();
    let second = metrics.shared_profile_metrics_snapshot();
    assert!(Arc::ptr_eq(&first, &second));

    metrics.with_profile_metrics("cached", |profile| {
        profile.totals.transfers.fetch_add(1, Ordering::Relaxed);
    });
    let updated = metrics.shared_profile_metrics_snapshot();
    assert!(!Arc::ptr_eq(&first, &updated));
    assert_eq!(updated[0].1.totals, (2, 0, 0));
}

#[test]
fn native_histograms_retain_lifetime_events_when_business_profiles_expire() {
    let server = TftpServer::new(TempestConfig::default());
    let state = server.state();
    let complete = || {
        state.active_transfers.fetch_add(1, Ordering::Relaxed);
        state
            .metrics
            .transfer_started(&BootPhase::Kernel, "expired");
        let start = Instant::now();
        state.metrics.transfer_completed(
            &BootPhase::Kernel,
            "expired",
            &TransferMetrics {
                bytes_sent: 5,
                start_time: Some(start),
                end_time: Some(start + Duration::from_millis(500)),
                ..TransferMetrics::default()
            },
        );
    };
    let scrape = || {
        crate::api::metrics::refresh_metrics_snapshot(&state);
        String::from_utf8(state.metrics.snapshot.load_full().unwrap().to_vec()).unwrap()
    };
    complete();
    let first = scrape();
    assert!(first.contains("tempest_transfers_by_profile_total{boot_profile=\"expired\"} 1\n"));
    // Rendering or CI scheduling may take seconds; expire regardless of last-seen time.
    state.metrics.evict_inactive_profiles_at(u64::MAX);
    assert!(state.metrics.profile_metrics.is_empty());
    let expired = scrape();
    assert!(!expired.contains("tempest_transfers_by_profile_total{boot_profile=\"expired\"}"));
    assert!(expired.contains(
        "tempest_transfer_duration_by_profile_seconds_count{boot_profile=\"expired\"} 1\n"
    ));
    complete();
    let returned = scrape();
    assert!(returned.contains("tempest_transfers_by_profile_total{boot_profile=\"expired\"} 1\n"));
    assert!(returned.contains(
        "tempest_transfer_duration_by_profile_seconds_count{boot_profile=\"expired\"} 2\n"
    ));
    assert!(returned.contains(
        "tempest_transfer_duration_by_profile_seconds_sum{boot_profile=\"expired\"} 1\n"
    ));
}

#[test]
fn malformed_warning_sampling_keeps_unsampled_metrics() {
    let server = TftpServer::new(TempestConfig::default());
    let state = server.state();
    let client = SocketAddr::from(([192, 0, 2, 9], 40_000));

    for _ in 0..3 {
        record_malformed_packet(&state, client, &"bad packet", false);
        record_unexpected_opcode(&state, client, false);
    }

    assert_eq!(
        state
            .metrics
            .malformed_packets_total
            .load(Ordering::Relaxed),
        3
    );
    assert_eq!(
        state
            .metrics
            .unexpected_opcodes_total
            .load(Ordering::Relaxed),
        3
    );
    assert_eq!(state.malformed_log_limiter.rejected_count(), 1);
    assert_eq!(state.unexpected_log_limiter.rejected_count(), 1);
}

#[test]
fn test_histogram_monotone_buckets() {
    let h = DurationHistogram::new();
    h.observe(0.003);
    h.observe(0.5);
    h.observe(50.0);
    let (buckets, _, _) = h.snapshot();
    // Prometheus requires cumulative buckets: bucket[i] >= bucket[i-1]
    for i in 1..buckets.len() {
        assert!(
            buckets[i] >= buckets[i - 1],
            "Buckets not monotone at index {i}"
        );
    }
}

#[test]
fn test_histogram_large_value_beyond_buckets() {
    let h = DurationHistogram::new();
    h.observe(999.0);
    let (buckets, sum, count) = h.snapshot();
    for b in &buckets {
        assert_eq!(*b, 0);
    }
    assert_eq!(count, 1);
    assert!((sum - 999.0).abs() < 1e-10);
}

#[test]
fn test_active_boot_session_persists_until_expiry() {
    let server = TftpServer::new(TempestConfig::default());
    let state = server.state();
    let client_ip: IpAddr = "10.0.0.5".parse().unwrap();

    state.insert_boot_session(
        client_ip,
        BootSessionEntry {
            trace_id: Some("trace-123".into()),
            boot_profile: "ubuntu-focal".into(),
            client_mac: Some("aa:bb:cc:dd:ee:ff".into()),
            serial: Some("SN-123".into()),
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(60),
        },
    );

    let first = active_boot_session(&state, client_ip).unwrap();
    let second = active_boot_session(&state, client_ip).unwrap();
    assert_eq!(first.boot_profile, "ubuntu-focal");
    assert_eq!(second.trace_id.as_deref(), Some("trace-123"));
    assert!(state.boot_sessions.contains_key(&client_ip));

    state.boot_sessions.insert(
        client_ip,
        BootSessionEntry {
            trace_id: None,
            boot_profile: "rhel9".into(),
            client_mac: None,
            serial: None,
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: Instant::now() - Duration::from_secs(1),
        },
    );

    assert!(active_boot_session(&state, client_ip).is_none());
    assert!(!state.boot_sessions.contains_key(&client_ip));
}

#[test]
fn stale_expiry_cleanup_does_not_remove_a_replacement_session() {
    let state = TftpServer::new(TempestConfig::default()).state();
    let client_ip = IpAddr::from([10, 0, 0, 6]);
    let observed_at = Instant::now();
    state.insert_boot_session(
        client_ip,
        BootSessionEntry {
            trace_id: None,
            boot_profile: "old".into(),
            client_mac: None,
            serial: None,
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: observed_at - Duration::from_secs(1),
        },
    );
    state.insert_boot_session(
        client_ip,
        BootSessionEntry {
            trace_id: None,
            boot_profile: "replacement".into(),
            client_mac: None,
            serial: None,
            boot_epoch: 2,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: observed_at + Duration::from_secs(60),
        },
    );

    assert!(
        state
            .remove_boot_session_if(client_ip, |_, session| session.expires_at <= observed_at)
            .is_none()
    );
    assert_eq!(
        active_boot_session(&state, client_ip).unwrap().boot_profile,
        "replacement"
    );
}

#[tokio::test]
async fn stale_bearer_index_cannot_authorize_a_replacement_session() {
    let state = TftpServer::new(TempestConfig::default()).state();
    let client_ip = IpAddr::from([10, 0, 0, 7]);
    let old_token = [1; 32];
    let replacement_token = [2; 32];
    state.insert_boot_session(
        client_ip,
        BootSessionEntry {
            trace_id: None,
            boot_profile: "replacement".into(),
            client_mac: None,
            serial: None,
            boot_epoch: 2,
            artifact_token_hash: Some(replacement_token),
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(60),
        },
    );
    state.http_session_tokens.insert(old_token, client_ip);

    assert!(state.boot_session_for_artifact_token(&old_token).is_none());
    assert!(matches!(
        state
            .resolve_file_for_authorized_boot_session(client_ip, &old_token, "kernel")
            .await,
        Err(TempestError::Protocol(ProtocolError::AccessViolation(_)))
    ));
    assert!(
        state
            .boot_session_for_artifact_token(&replacement_token)
            .is_some()
    );

    // Force stale index hits to exercise the authorization digest comparison.
    for index in 0..replacement_token.len() {
        let mut near_match = replacement_token;
        near_match[index] ^= 1;
        state.http_session_tokens.insert(near_match, client_ip);
        assert!(state.boot_session_for_artifact_token(&near_match).is_none());
        assert!(matches!(
            state
                .resolve_file_for_authorized_boot_session(client_ip, &near_match, "kernel")
                .await,
            Err(TempestError::Protocol(ProtocolError::AccessViolation(_)))
        ));
        state.http_session_tokens.remove(&near_match);
    }

    // A session without an HTTP token must not be authorized by a stale index.
    state
        .boot_sessions
        .get_mut(&client_ip)
        .unwrap()
        .artifact_token_hash = None;
    assert!(
        state
            .boot_session_for_artifact_token(&replacement_token)
            .is_none()
    );
    assert!(matches!(
        state
            .resolve_file_for_authorized_boot_session(client_ip, &replacement_token, "kernel")
            .await,
        Err(TempestError::Protocol(ProtocolError::AccessViolation(_)))
    ));
}

#[test]
fn test_session_reconciliation_preserves_entries_and_pin_counts() {
    let state = TftpServer::new(TempestConfig::default()).state();
    let first = IpAddr::from([10, 0, 0, 1]);
    let stale = IpAddr::from([10, 0, 0, 2]);
    let added = IpAddr::from([10, 0, 0, 3]);
    let pin_a = BootChainPin {
        boot_profile: "focal".into(),
        group_id: "a".into(),
        version_id: 1,
        manifest_digest: "aa".repeat(32),
    };
    let pin_b = BootChainPin {
        boot_profile: "focal".into(),
        group_id: "b".into(),
        version_id: 2,
        manifest_digest: "bb".repeat(32),
    };
    let session = |pin| BootSessionEntry {
        trace_id: None,
        boot_profile: "focal".into(),
        client_mac: None,
        serial: None,
        boot_epoch: 1,
        artifact_token_hash: None,
        pinned_boot_chain: Some(pin),
        expires_at: Instant::now() + Duration::from_secs(60),
    };
    state.insert_boot_session(first, session(pin_a.clone()));
    state.insert_boot_session(stale, session(pin_a.clone()));

    state.reconcile_boot_sessions(vec![
        (first, session(pin_a.clone())),
        (added, session(pin_b.clone())),
    ]);

    assert!(state.boot_sessions.contains_key(&first));
    assert!(!state.boot_sessions.contains_key(&stale));
    assert!(state.boot_sessions.contains_key(&added));
    assert_eq!(state.version_store.pinned_boot_chain_count(&pin_a), 1);
    assert_eq!(state.version_store.pinned_boot_chain_count(&pin_b), 1);
}

#[tokio::test]
async fn test_control_plane_mutations_are_serialized() {
    let state = TftpServer::new(TempestConfig::default()).state();
    let guard = state.control_plane_lock.lock().await;
    let waiting_state = state.clone();
    let waiter = tokio::spawn(async move {
        let _guard = waiting_state.control_plane_lock.lock().await;
    });

    tokio::task::yield_now().await;
    assert!(!waiter.is_finished());
    drop(guard);
    tokio::time::timeout(Duration::from_secs(30), waiter)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn duplicate_rrq_uses_one_transfer_tid() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("artifact.bin"), b"artifact").unwrap();
    let mut config = TempestConfig::default();
    config.server.bind = IpAddr::V4(Ipv4Addr::LOCALHOST);
    config.server.port = 0;
    config.server.root = root.path().to_path_buf();
    hold_retransmissions(&mut config);
    let server = Arc::new(TftpServer::new(config));
    let state = server.state();
    state
        .version_store
        .atomic_switch(
            "default-release".into(),
            vec![("artifact.bin".into(), root.path().join("artifact.bin"))],
        )
        .unwrap();
    let running = server.clone();
    let mut server_task = tokio::spawn(async move { running.run().await });
    tokio::time::timeout(Duration::from_secs(30), async {
        tokio::select! {
            result = &mut server_task => panic!("server exited before readiness: {result:?}"),
            _ = async {
                while !state.tftp_ready.load(Ordering::Acquire) {
                    tokio::task::yield_now().await;
                }
            } => {}
        }
    })
    .await
    .unwrap();
    let server_addr = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        state.tftp_bound_port.load(Ordering::Acquire),
    ));
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let request = TftpPacket::rrq("artifact.bin", "octet");

    client.send_to(&request, server_addr).await.unwrap();
    client.send_to(&request, server_addr).await.unwrap();

    let mut buffer = [0u8; 512];
    let (length, transfer_peer) =
        tokio::time::timeout(Duration::from_secs(30), client.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert!(matches!(
        TftpPacket::parse(&buffer[..length], transfer_peer).unwrap(),
        TftpPacket::Data(data) if data.block == 1 && data.data == b"artifact"
    ));
    // Hold the transfer open until the listener has classified the duplicate.
    tftp_client_limit_wait(|| {
        state
            .metrics
            .duplicate_requests_total
            .load(Ordering::Acquire)
            == 1
    })
    .await;
    client
        .send_to(&TftpPacket::ack(1), transfer_peer)
        .await
        .unwrap();

    tokio::time::timeout(Duration::from_secs(30), async {
        while state.active_transfers.load(Ordering::Acquire) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        state
            .metrics
            .duplicate_requests_total
            .load(Ordering::Acquire),
        1
    );
    assert_eq!(
        state.metrics.listener_shard_requests[..state.config.server.effective_listener_shards()]
            .iter()
            .map(|counter| counter.load(Ordering::Acquire))
            .sum::<u64>(),
        1
    );
    assert!(state.inflight_tftp_tids.is_empty());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), client.recv_from(&mut buffer))
            .await
            .is_err(),
        "duplicate RRQ created another transfer socket"
    );

    server_task.abort();
    let _ = server_task.await;
}

async fn tftp_client_limit_receive(client: &UdpSocket) -> (Vec<u8>, SocketAddr) {
    let mut buffer = [0u8; 2048];
    let (length, peer) =
        tokio::time::timeout(Duration::from_secs(30), client.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    (buffer[..length].to_vec(), peer)
}

async fn tftp_client_limit_wait(mut ready: impl FnMut() -> bool) {
    // A hang detector: it returns as soon as the condition holds.
    tokio::time::timeout(Duration::from_secs(30), async {
        while !ready() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

async fn tftp_client_limit_listener(
    server: TftpServer,
    queue: Option<AdmissionQueue>,
) -> (SocketAddr, BackgroundTaskGuard) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = socket.local_addr().unwrap();
    let task = BackgroundTaskGuard(tokio::spawn(async move {
        server.run_listener(0, socket, queue).await.unwrap();
    }));
    (addr, task)
}

fn tftp_client_limit_config(root: &Path) -> TempestConfig {
    let mut config = TempestConfig::default();
    config.server.bind = Ipv4Addr::LOCALHOST.into();
    config.server.root = root.to_path_buf();
    config.server.max_tftp_transfers_per_ip = 1;
    config.server.tftp_requests_per_ip_per_second = 0;
    config
}

/// Pins the server retransmission timer far beyond any CI scheduling delay.
///
/// Wire tests read the next datagram and assert its type or that nothing was
/// retransmitted. With the 1s default, a client delayed by a loaded runner
/// receives a correct retransmission where it expects the next packet.
fn hold_retransmissions(config: &mut TempestConfig) {
    config.server.retransmit_interval_ms = 30_000;
    config.server.min_retransmit_interval_ms = 30_000;
    config.server.max_retransmit_interval_ms = 30_000;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sequential_rrqs_on_one_client_tid_do_not_wait_for_retransmission() {
    let root = tempfile::tempdir().unwrap();
    let artifact = root.path().join("artifact.bin");
    std::fs::write(&artifact, b"artifact").unwrap();
    let mut config = tftp_client_limit_config(root.path());
    // Source quotas have dedicated tests. Each completed transfer releases its
    // permit only after the server task processes the final ACK, which can lag
    // the client's next RRQ on a loaded host, so allow every iteration's permit.
    config.server.max_tftp_transfers_per_ip = 128;
    config.audit.enabled = false;
    hold_retransmissions(&mut config);
    let server = TftpServer::new(config);
    let state = server.state();
    state
        .version_store
        .atomic_switch("release".into(), vec![("artifact.bin".into(), artifact)])
        .unwrap();
    let (listener, _task) = tftp_client_limit_listener(server, None).await;
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let request = TftpPacket::rrq_with_options(
        "artifact.bin",
        "octet",
        &[
            ("blksize".into(), "1468".into()),
            ("windowsize".into(), "8".into()),
        ],
    );
    let mut buffer = [0u8; 2048];
    // The client never retransmits, so an RRQ dropped as a duplicate of a
    // still-registered TID stalls indefinitely. A generous bound still detects
    // that while tolerating cold starts and loaded CI runners.
    let reply_bound = Duration::from_secs(30);

    for iteration in 0..128 {
        client.send_to(&request, listener).await.unwrap();
        let (length, peer) = tokio::time::timeout(reply_bound, client.recv_from(&mut buffer))
            .await
            .unwrap_or_else(|_| panic!("next RRQ stalled at iteration {iteration}"))
            .unwrap();
        assert!(matches!(
            TftpPacket::parse(&buffer[..length], peer).unwrap(),
            TftpPacket::Oack(_)
        ));
        client.send_to(&TftpPacket::ack(0), peer).await.unwrap();
        let (length, data_peer) = tokio::time::timeout(reply_bound, client.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(data_peer, peer);
        assert!(matches!(
            TftpPacket::parse(&buffer[..length], peer).unwrap(),
            TftpPacket::Data(data) if data.block == 1 && data.data == b"artifact"
        ));
        client.send_to(&TftpPacket::ack(1), peer).await.unwrap();
    }
    tftp_client_limit_wait(|| {
        state.active_transfers.load(Ordering::Acquire) == 0
            && state.tftp_client_limits.identities() == 0
    })
    .await;
    assert!(state.inflight_tftp_tids.is_empty());
    assert_eq!(state.tftp_client_limits.identities(), 0);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn negotiated_rrq_handoff_preserves_handshake_and_source_quota() {
    let root = tempfile::tempdir().unwrap();
    let artifact = root.path().join("artifact.bin");
    std::fs::write(&artifact, b"artifact").unwrap();
    let mut config = tftp_client_limit_config(root.path());
    config.audit.enabled = false;
    hold_retransmissions(&mut config);
    let server = TftpServer::new(config);
    let state = server.state();
    state
        .version_store
        .atomic_switch("release".into(), vec![("artifact.bin".into(), artifact)])
        .unwrap();
    let (listener, _task) = tftp_client_limit_listener(server, None).await;
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let request = TftpPacket::rrq_with_options(
        "artifact.bin",
        "octet",
        &[
            ("blksize".into(), "1468".into()),
            ("windowsize".into(), "8".into()),
        ],
    );
    client.send_to(&request, listener).await.unwrap();
    let (oack, peer) = tftp_client_limit_receive(&client).await;
    assert!(matches!(
        TftpPacket::parse(&oack, peer).unwrap(),
        TftpPacket::Oack(_)
    ));
    client.send_to(&request, listener).await.unwrap();
    let (duplicate, duplicate_peer) = tftp_client_limit_receive(&client).await;
    assert_eq!(duplicate_peer, peer);
    assert_eq!(duplicate, oack);
    assert_eq!(state.inflight_tftp_tids.len(), 1);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 1);

    client.send_to(&TftpPacket::ack(0), peer).await.unwrap();
    let (data, data_peer) = tftp_client_limit_receive(&client).await;
    assert_eq!(data_peer, peer);
    assert_eq!(&data[..4], &[0, 3, 0, 1]);
    assert!(state.inflight_tftp_tids.is_empty());
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 1);
    assert_eq!(state.tftp_client_limits.identities(), 1);
    assert!(state.tftp_client_limits.try_acquire(peer.ip()).is_none());

    client.send_to(&request, listener).await.unwrap();
    let (error, error_peer) = tftp_client_limit_receive(&client).await;
    assert_eq!(error_peer, listener);
    assert_eq!(
        error,
        TftpPacket::error(TftpErrorCode::NotDefined, "Client transfer limit reached")
    );
    assert_eq!(
        state
            .metrics
            .duplicate_requests_total
            .load(Ordering::Acquire),
        1
    );
    client.send_to(&TftpPacket::ack(1), peer).await.unwrap();
    tftp_client_limit_wait(|| state.tftp_client_limits.identities() == 0).await;
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
}

async fn tftp_client_policy_wire_exchange(is_write: bool, timeout: u8, accept: bool) {
    let root = tempfile::tempdir().unwrap();
    let payload = b"wire-policy";
    let artifact = root.path().join("artifact.bin");
    std::fs::write(&artifact, payload).unwrap();
    let mut config = tftp_client_limit_config(root.path());
    config.server.max_client_timeout_secs = 5;
    config.server.accept_client_timeout = accept;
    config.server.write_enabled = true;
    config.server.write_require_session = true;
    config.server.default_block_size = 16;
    config.server.max_window_size = 2;
    config.boot_phases.clear();
    config.audit.enabled = false;
    hold_retransmissions(&mut config);
    let server = TftpServer::new(config);
    let state = server.state();
    let group = state
        .version_store
        .atomic_switch("release".into(), vec![("artifact.bin".into(), artifact)])
        .unwrap();
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let client_addr = client.local_addr().unwrap();
    if is_write {
        state.insert_boot_session(
            client_addr.ip(),
            BootSessionEntry {
                trace_id: None,
                boot_profile: DEFAULT_BOOT_PROFILE.into(),
                client_mac: None,
                serial: None,
                boot_epoch: 1,
                artifact_token_hash: None,
                pinned_boot_chain: None,
                expires_at: Instant::now() + Duration::from_secs(30),
            },
        );
    }
    let (listener, _task) = tftp_client_limit_listener(server, None).await;
    let requested = vec![
        ("blksize".into(), "16".into()),
        ("windowsize".into(), "2".into()),
        ("timeout".into(), timeout.to_string()),
        (
            "tsize".into(),
            if is_write { payload.len() } else { 0 }.to_string(),
        ),
    ];
    let mut request = TftpPacket::rrq_with_options(
        if is_write {
            "upload.bin"
        } else {
            "artifact.bin"
        },
        "octet",
        &requested,
    );
    if is_write {
        // RRQ and WRQ share the request layout; only the opcode differs.
        request[1] = 2;
    }
    client.send_to(&request, listener).await.unwrap();
    let (wire, peer) = tftp_client_limit_receive(&client).await;
    assert_eq!(peer.ip(), listener.ip());
    assert_ne!(
        peer.port(),
        listener.port(),
        "the listener must not own the transfer TID"
    );
    let TftpPacket::Oack(packet) = TftpPacket::parse(&wire, peer).unwrap() else {
        panic!("requested non-timeout options must still receive OACK");
    };
    let mut expected = vec![
        ("blksize".into(), "16".into()),
        ("windowsize".into(), "2".into()),
        ("tsize".into(), payload.len().to_string()),
    ];
    if accept && timeout <= 5 {
        expected.push(("timeout".into(), timeout.to_string()));
    }
    let mut actual = packet.options;
    actual.sort();
    expected.sort();
    assert_eq!(
        actual, expected,
        "omit only a declined timeout; never counteroffer it"
    );
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 1);
    assert!(state.inflight_tftp_tids.contains_key(&client_addr));
    assert_eq!(state.tftp_client_limits.identities(), 1);

    // RRQ acknowledges OACK with ACK(0); WRQ responds directly with DATA(1).
    if is_write {
        client
            .send_to(&TftpPacket::data(1, payload), peer)
            .await
            .unwrap();
        let (ack, ack_peer) = tftp_client_limit_receive(&client).await;
        assert_eq!(ack_peer, peer);
        assert_eq!(ack, TftpPacket::ack(1));
        assert_eq!(
            std::fs::read(root.path().join("upload.bin")).unwrap(),
            payload
        );
        // Publication is complete. End receiver dally explicitly rather than
        // waiting twice the accepted five-second timeout in a wire test.
        client
            .send_to(&TftpPacket::error(TftpErrorCode::NotDefined, "done"), peer)
            .await
            .unwrap();
    } else {
        client.send_to(&TftpPacket::ack(0), peer).await.unwrap();
        let (data, data_peer) = tftp_client_limit_receive(&client).await;
        assert_eq!(data_peer, peer);
        assert!(matches!(TftpPacket::parse(&data, peer).unwrap(),
            TftpPacket::Data(packet) if packet.block == 1 && packet.data == payload));
        client.send_to(&TftpPacket::ack(1), peer).await.unwrap();
    }
    tftp_client_limit_wait(|| {
        state.active_transfers.load(Ordering::Acquire) == 0
            && state.tftp_client_limits.identities() == 0
    })
    .await;
    assert!(state.inflight_tftp_tids.is_empty());
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
    assert_eq!(state.tftp_client_limits.identities(), 0);
    assert_eq!(
        state
            .version_store
            .pinned_count("artifact.bin", group.version_id),
        0
    );
    assert_eq!(
        state.metrics.retransmissions_total.load(Ordering::Acquire),
        0
    );
}

#[tokio::test]
async fn tftp_client_policy_wire_rrq_over_ceiling_omits_only_timeout() {
    tftp_client_policy_wire_exchange(false, 255, true).await;
}

#[tokio::test]
async fn tftp_client_policy_wire_wrq_over_ceiling_omits_only_timeout() {
    tftp_client_policy_wire_exchange(true, 255, true).await;
}

#[tokio::test]
async fn tftp_client_policy_wire_rrq_accepts_timeout_at_ceiling_exactly() {
    tftp_client_policy_wire_exchange(false, 5, true).await;
}

#[tokio::test]
async fn tftp_client_policy_wire_wrq_accepts_timeout_at_ceiling_exactly() {
    tftp_client_policy_wire_exchange(true, 5, true).await;
}

#[tokio::test]
async fn tftp_client_policy_wire_rrq_disabled_overrides_ceiling() {
    tftp_client_policy_wire_exchange(false, 5, false).await;
}

#[tokio::test]
async fn tftp_client_policy_wire_wrq_disabled_overrides_ceiling() {
    tftp_client_policy_wire_exchange(true, 5, false).await;
}

#[tokio::test]
async fn tftp_client_limit_listener_rejects_rotating_ports_and_readmits_after_failure() {
    let root = tempfile::tempdir().unwrap();
    let artifact = root.path().join("artifact.bin");
    std::fs::write(&artifact, b"artifact").unwrap();
    let server = TftpServer::new(tftp_client_limit_config(root.path()));
    let state = server.state();
    state
        .version_store
        .atomic_switch("release".into(), vec![("artifact.bin".into(), artifact)])
        .unwrap();
    let (listener, _task) = tftp_client_limit_listener(server, None).await;
    let holder = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let request = TftpPacket::rrq("artifact.bin", "octet");
    holder.send_to(&request, listener).await.unwrap();
    let (data, transfer_peer) = tftp_client_limit_receive(&holder).await;
    assert_eq!(&data[..4], &[0, 3, 0, 1]);
    assert_ne!(transfer_peer, listener);

    // An established, silent client owns one permit, regardless of new ports.
    for _ in 0..3 {
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        client.send_to(&request, listener).await.unwrap();
        let (error, peer) = tftp_client_limit_receive(&client).await;
        assert_eq!(peer, listener);
        assert_eq!(
            error,
            TftpPacket::error(TftpErrorCode::NotDefined, "Client transfer limit reached")
        );
    }
    assert_eq!(
        state
            .metrics
            .capacity_rejected_total
            .load(Ordering::Acquire),
        3
    );
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 1);
    assert_eq!(state.inflight_tftp_tids.len(), 1);

    // The same TID notifies the existing owner before consulting source quota.
    holder.send_to(&request, listener).await.unwrap();
    tftp_client_limit_wait(|| {
        state
            .metrics
            .duplicate_requests_total
            .load(Ordering::Acquire)
            == 1
    })
    .await;
    assert_eq!(
        state
            .metrics
            .capacity_rejected_total
            .load(Ordering::Acquire),
        3
    );
    assert_eq!(state.inflight_tftp_tids.len(), 1);

    holder
        .send_to(
            &TftpPacket::error(TftpErrorCode::NotDefined, "cancel"),
            transfer_peer,
        )
        .await
        .unwrap();
    tftp_client_limit_wait(|| state.inflight_tftp_tids.is_empty()).await;
    assert_eq!(state.tftp_client_limits.identities(), 0);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);

    let next = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    next.send_to(&request, listener).await.unwrap();
    let (data, peer) = tftp_client_limit_receive(&next).await;
    assert_eq!(&data[..4], &[0, 3, 0, 1]);
    next.send_to(&TftpPacket::ack(1), peer).await.unwrap();
    tftp_client_limit_wait(|| state.inflight_tftp_tids.is_empty()).await;
    assert_eq!(state.tftp_client_limits.identities(), 0);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
}

struct TftpClientLimitQueuePolicy;

impl AdmissionPolicy for TftpClientLimitQueuePolicy {
    fn queue_capacity(&self) -> usize {
        2
    }
    fn max_queue_age(&self) -> Duration {
        Duration::from_secs(10)
    }
    fn priority(&self, _: &AdmissionContext) -> f64 {
        1.0
    }
    fn launch_delay(&self, _: u64) -> Duration {
        Duration::from_millis(100)
    }
}

#[tokio::test]
async fn tftp_client_limit_queue_promotion_retains_permit_through_stagger_and_transfer() {
    let root = tempfile::tempdir().unwrap();
    let artifact = root.path().join("artifact.bin");
    std::fs::write(&artifact, b"artifact").unwrap();
    let mut config = tftp_client_limit_config(root.path());
    config.server.max_concurrent_transfers = 1;
    let server = TftpServer::builder(config)
        .with_admission_policy(Arc::new(TftpClientLimitQueuePolicy))
        .build()
        .unwrap();
    let state = server.state();
    state
        .version_store
        .atomic_switch("release".into(), vec![("artifact.bin".into(), artifact)])
        .unwrap();
    // A non-TFTP global reservation consumes no source quota.
    state.active_transfers.store(1, Ordering::Release);
    let global_slot = ReservedTransferSlotGuard::new(&state);
    assert_eq!(state.tftp_client_limits.identities(), 0);
    let (sender, receiver) = mpsc::channel(2);
    let queue = AdmissionQueue {
        sender,
        entry_budget: Arc::new(Semaphore::new(2)),
        byte_budget: Arc::new(Semaphore::new(8192)),
    };
    let drain = BackgroundTaskGuard(tokio::spawn(run_admission_drain_task(
        state.clone(),
        receiver,
    )));
    let (listener, _task) = tftp_client_limit_listener(server, Some(queue.clone())).await;
    let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let request = TftpPacket::rrq("artifact.bin", "octet");
    client.send_to(&request, listener).await.unwrap();
    tftp_client_limit_wait(|| state.queued_transfers.load(Ordering::Acquire) == 1).await;
    let ip = client.local_addr().unwrap().ip();
    assert!(state.tftp_client_limits.try_acquire(ip).is_none());
    client.send_to(&request, listener).await.unwrap();
    tftp_client_limit_wait(|| {
        state
            .metrics
            .duplicate_requests_total
            .load(Ordering::Acquire)
            == 1
    })
    .await;
    let excess = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    excess.send_to(&request, listener).await.unwrap();
    let (error, _) = tftp_client_limit_receive(&excess).await;
    assert_eq!(
        error,
        TftpPacket::error(TftpErrorCode::NotDefined, "Client transfer limit reached")
    );
    assert_eq!(state.queued_transfers.load(Ordering::Acquire), 1);
    assert_eq!(
        state.metrics.admission_queued_total.load(Ordering::Acquire),
        1
    );
    assert_eq!(queue.entry_budget.available_permits(), 1);

    drop(global_slot);
    tftp_client_limit_wait(|| {
        state
            .metrics
            .admission_started_total
            .load(Ordering::Acquire)
            == 1
    })
    .await;
    assert_eq!(state.queued_transfers.load(Ordering::Acquire), 0);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 1);
    assert_eq!(queue.entry_budget.available_permits(), 2);
    assert!(state.tftp_client_limits.try_acquire(ip).is_none());
    let (data, peer) = tftp_client_limit_receive(&client).await;
    assert_eq!(&data[..4], &[0, 3, 0, 1]);
    assert!(state.tftp_client_limits.try_acquire(ip).is_none());
    client.send_to(&TftpPacket::ack(1), peer).await.unwrap();
    tftp_client_limit_wait(|| state.inflight_tftp_tids.is_empty()).await;
    assert_eq!(state.tftp_client_limits.identities(), 0);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
    drop(drain);
}

#[tokio::test]
async fn tftp_client_limit_malformed_global_and_audit_admission_failures_release() {
    for audit in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let mut config = tftp_client_limit_config(root.path());
        config.server.max_concurrent_transfers = 1;
        config.audit.enabled = audit;
        config.audit.log_path = Some(root.path().join("audit.jsonl"));
        let server = TftpServer::new(config);
        let state = server.state();
        let (listener, _task) = tftp_client_limit_listener(server, None).await;
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        client.send_to(&[0, 1, 0], listener).await.unwrap();
        tftp_client_limit_wait(|| {
            state
                .metrics
                .malformed_packets_total
                .load(Ordering::Acquire)
                == 1
                && state.inflight_tftp_tids.is_empty()
        })
        .await;
        assert_eq!(state.tftp_client_limits.identities(), 0);
        assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);

        let mut reservations = Vec::new();
        if let Some(writer) = &state.audit_writer {
            while let Ok(reservation) = writer.try_reserve() {
                reservations.push(reservation);
            }
        } else {
            state.active_transfers.store(1, Ordering::Release);
        }
        let request = TftpPacket::rrq("missing.bin", "octet");
        client.send_to(&request, listener).await.unwrap();
        let (error, _) = tftp_client_limit_receive(&client).await;
        assert_eq!(
            error,
            TftpPacket::error(
                TftpErrorCode::NotDefined,
                if audit {
                    "Audit service is at capacity"
                } else {
                    "Server at capacity"
                }
            )
        );
        tftp_client_limit_wait(|| state.inflight_tftp_tids.is_empty()).await;
        assert_eq!(state.tftp_client_limits.identities(), 0);
        drop(reservations);
        if !audit {
            state.release_reserved_transfer_slot();
        }

        // Handler failure (missing managed artifact) must also permit re-admission.
        for _ in 0..2 {
            client.send_to(&request, listener).await.unwrap();
            let (error, _) = tftp_client_limit_receive(&client).await;
            assert_eq!(&error[..4], &[0, 5, 0, 1]);
            tftp_client_limit_wait(|| state.inflight_tftp_tids.is_empty()).await;
            assert_eq!(state.tftp_client_limits.identities(), 0);
            assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
        }
    }
}

#[tokio::test]
async fn tftp_client_limit_cancelled_rrq_and_wrq_handlers_release() {
    for is_write in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let artifact = root.path().join("artifact.bin");
        std::fs::write(&artifact, b"artifact").unwrap();
        let mut config = tftp_client_limit_config(root.path());
        config.server.write_enabled = true;
        config.server.write_require_session = false;
        let state = TftpServer::new(config).state();
        state
            .version_store
            .atomic_switch("release".into(), vec![("artifact.bin".into(), artifact)])
            .unwrap();
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = client.local_addr().unwrap();
        let mut tid = InflightTftpTidGuard::claim(state.inflight_tftp_tids.clone(), addr).unwrap();
        tid.client_limit = Some(state.tftp_client_limits.try_acquire(addr.ip()).unwrap());
        state.active_transfers.store(1, Ordering::Release);
        let task_state = state.clone();
        let task = tokio::spawn(async move {
            let request = RequestPacket {
                filename: if is_write {
                    "upload.bin"
                } else {
                    "artifact.bin"
                }
                .into(),
                mode: TransferMode::Octet,
                options: Vec::new(),
            };
            if is_write {
                handle_wrq(task_state, addr, request, None, tid).await
            } else {
                handle_rrq(task_state, addr, request, None, tid).await
            }
        });
        let (packet, _) = tftp_client_limit_receive(&client).await;
        assert_eq!(
            &packet[..4],
            if is_write {
                &[0, 4, 0, 0]
            } else {
                &[0, 3, 0, 1]
            }
        );
        assert!(state.tftp_client_limits.try_acquire(addr.ip()).is_none());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(state.tftp_client_limits.identities(), 0);
        assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
        assert!(state.inflight_tftp_tids.is_empty());
        assert!(state.tftp_client_limits.try_acquire(addr.ip()).is_some());
    }
}

#[test]
fn tftp_client_limit_released_while_terminal_audit_waits() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let root = tempfile::tempdir().unwrap();
        let artifact = root.path().join("artifact.bin");
        std::fs::write(&artifact, b"artifact").unwrap();
        let next_artifact = root.path().join("next.bin");
        std::fs::write(&next_artifact, b"next artifact").unwrap();
        let mut config = tftp_client_limit_config(root.path());
        hold_retransmissions(&mut config);
        let server = TftpServer::new(config);
        // Exercise the awaited legacy audit path without changing the writer API.
        // Unwrap permits the metrics observer's weak reference to remain unused.
        let mut state = Arc::try_unwrap(server.state).unwrap_or_else(|_| panic!("shared state"));
        state.audit_log = Some(Arc::new(
            AuditLog::new(root.path().join("audit.jsonl")).unwrap(),
        ));
        let state = Arc::new(state);
        assert!(state.audit_writer.is_none());
        assert_eq!(state.config.server.max_tftp_transfers_per_ip, 1);
        state
            .version_store
            .atomic_switch(
                "release".into(),
                vec![
                    ("artifact.bin".into(), artifact),
                    ("next.bin".into(), next_artifact),
                ],
            )
            .unwrap();
        let (listener, _listener_task) = tftp_client_limit_listener(
            TftpServer {
                state: state.clone(),
            },
            None,
        )
        .await;
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = client.local_addr().unwrap();
        let mut tid = InflightTftpTidGuard::claim(state.inflight_tftp_tids.clone(), addr).unwrap();
        tid.client_limit = Some(state.tftp_client_limits.try_acquire(addr.ip()).unwrap());
        state.active_transfers.store(1, Ordering::Release);
        let task_state = state.clone();
        let task = tokio::spawn(handle_rrq(
            task_state,
            addr,
            RequestPacket {
                filename: "artifact.bin".into(),
                mode: TransferMode::Octet,
                options: Vec::new(),
            },
            None,
            tid,
        ));
        let (data, peer) = tftp_client_limit_receive(&client).await;
        assert_eq!(&data[..4], &[0, 3, 0, 1]);
        let (started, running) = tokio::sync::oneshot::channel();
        let (release, finish) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            let _ = finish.recv();
        });
        running.await.unwrap();
        client.send_to(&TftpPacket::ack(1), peer).await.unwrap();
        tftp_client_limit_wait(|| state.active_transfers.load(Ordering::Acquire) == 0).await;
        assert!(!task.is_finished());
        assert!(state.inflight_tftp_tids.is_empty());
        assert_eq!(state.tftp_client_limits.identities(), 0);
        assert!(state.tftp_client_limits.try_acquire(addr.ip()).is_some());
        let audit = state.audit_log.as_ref().unwrap();
        assert!(audit.recent_entries(None, 2).unwrap().is_empty());

        // The fallback audit is queued behind the sole blocking worker. A new
        // filename from the same UDP endpoint must reach transport admission,
        // not be suppressed as a duplicate or rejected by the cap of one.
        client
            .send_to(&TftpPacket::rrq("next.bin", "octet"), listener)
            .await
            .unwrap();
        tftp_client_limit_wait(|| state.active_transfers.load(Ordering::Acquire) == 1).await;
        assert!(state.inflight_tftp_tids.contains_key(&addr));
        assert_eq!(state.tftp_client_limits.identities(), 1);
        assert!(state.tftp_client_limits.try_acquire(addr.ip()).is_none());
        assert_eq!(
            state
                .metrics
                .duplicate_requests_total
                .load(Ordering::Acquire),
            0
        );
        assert!(!task.is_finished());
        assert!(audit.recent_entries(None, 2).unwrap().is_empty());

        // Artifact preparation also needs the blocking pool; release it only
        // after proving the next transport was admitted while the old audit waited.
        release.send(()).unwrap();
        blocker.await.unwrap();
        let (data, next_peer) = tftp_client_limit_receive(&client).await;
        assert!(matches!(TftpPacket::parse(&data, next_peer).unwrap(),
            TftpPacket::Data(packet) if packet.block == 1 && packet.data == b"next artifact"));
        client
            .send_to(&TftpPacket::ack(1), next_peer)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        tftp_client_limit_wait(|| {
            state.inflight_tftp_tids.is_empty() && audit.recent_entries(None, 2).unwrap().len() == 2
        })
        .await;
        assert!(state.inflight_tftp_tids.is_empty());
        assert_eq!(state.tftp_client_limits.identities(), 0);
        assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
        let entries = audit.recent_entries(None, 2).unwrap();
        for filename in ["artifact.bin", "next.bin"] {
            assert!(entries.iter().any(|entry| {
                entry.file_path == filename && matches!(entry.outcome, TransferOutcome::Completed)
            }));
        }
    });
}

#[tokio::test]
async fn test_integration_concurrent_release_delivery_and_audit() {
    const CLIENTS: usize = 8;
    let root = tempfile::tempdir().unwrap();
    let artifact = vec![42; 32 * 1024];
    let artifact_path = root.path().join("artifact-v1.bin");
    let audit_path = root.path().join("audit.jsonl");
    std::fs::write(&artifact_path, &artifact).unwrap();

    let mut config = TempestConfig::default();
    config.server.bind = IpAddr::V4(Ipv4Addr::LOCALHOST);
    config.server.port = 0;
    config.server.root = root.path().to_path_buf();
    config.audit.enabled = true;
    config.audit.log_path = Some(audit_path);
    let server = Arc::new(TftpServer::new(config));
    let state = server.state();
    let group = state
        .version_store
        .atomic_switch(
            "load-v1".into(),
            vec![("artifact.bin".into(), artifact_path)],
        )
        .unwrap();
    state.insert_boot_session(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        BootSessionEntry {
            trace_id: Some("integration-load".into()),
            boot_profile: DEFAULT_BOOT_PROFILE.into(),
            client_mac: Some("aa:bb:cc:dd:ee:ff".into()),
            serial: None,
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(30),
        },
    );

    let running = server.clone();
    let server_task = tokio::spawn(async move { running.run().await });
    tokio::time::timeout(Duration::from_secs(30), async {
        while !state.tftp_ready.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let server_addr = SocketAddr::from((
        Ipv4Addr::LOCALHOST,
        state.tftp_bound_port.load(Ordering::Acquire),
    ));
    let arrived = Arc::new(tokio::sync::Barrier::new(CLIENTS + 1));
    let release = Arc::new(tokio::sync::Barrier::new(CLIENTS + 1));
    let clients: Vec<_> = (0..CLIENTS)
        .map(|_| {
            tokio::spawn(download_with_gate(
                server_addr,
                arrived.clone(),
                release.clone(),
            ))
        })
        .collect();
    arrived.wait().await;
    assert_eq!(state.active_transfers.load(Ordering::Acquire), CLIENTS);
    release.wait().await;
    for client in clients {
        assert_eq!(client.await.unwrap(), artifact);
    }
    state
        .audit_writer
        .as_ref()
        .unwrap()
        .wait_idle()
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let entries = state
                .audit_log
                .as_ref()
                .unwrap()
                .recent_entries(None, CLIENTS);
            if entries
                .as_ref()
                .is_ok_and(|entries| entries.len() == CLIENTS)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let entries = state
        .audit_log
        .as_ref()
        .unwrap()
        .recent_entries(None, CLIENTS)
        .unwrap();
    assert!(entries.iter().all(|entry| {
        matches!(
            entry.outcome,
            crate::features::audit::TransferOutcome::Completed
        ) && entry.delivery.as_ref().is_some_and(|delivery| {
            delivery.group_id.as_deref() == Some(group.group_id.as_str())
                && delivery.transport == TRANSPORT_TFTP
        })
    }));
    state.remove_boot_session(IpAddr::V4(Ipv4Addr::LOCALHOST));
    server_task.abort();
    let _ = server_task.await;
    assert!(!state.tftp_ready.load(Ordering::Acquire));
    assert_eq!(state.tftp_bound_port.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn test_handle_rrq_quarantine_releases_reserved_slot() {
    let server = TftpServer::new(TempestConfig::default());
    let state = server.state();
    state.active_transfers.store(1, Ordering::Release);
    state.quarantined_files.insert("blocked.bin".to_string());

    let client_addr = "127.0.0.1:40100".parse().unwrap();
    let client_tid_guard =
        InflightTftpTidGuard::claim(state.inflight_tftp_tids.clone(), client_addr).unwrap();
    let result = handle_rrq(
        state.clone(),
        client_addr,
        crate::protocol::packet::RequestPacket {
            filename: "blocked.bin".to_string(),
            mode: crate::protocol::packet::TransferMode::Octet,
            options: Vec::new(),
        },
        None,
        client_tid_guard,
    )
    .await;

    assert!(matches!(
        result,
        Err(TempestError::Protocol(
            crate::error::ProtocolError::AccessViolation(_)
        ))
    ));
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
    assert!(state.inflight_tftp_tids.is_empty());
}

#[test]
fn core_integrity_failures_cannot_grow_quarantine_past_its_limit() {
    let state = TftpServer::new(TempestConfig::default()).state();

    for index in 0..=MAX_QUARANTINED_FILES {
        state.quarantine_artifact(format!("artifact-{index}"));
    }

    assert_eq!(state.quarantined_files.len(), MAX_QUARANTINED_FILES);
}

#[tokio::test]
async fn unsuccessful_rrq_audit_retains_release_identity_and_progress() {
    for abort in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let artifact = root.path().join("kernel");
        std::fs::write(&artifact, [0x41; 1024]).unwrap();
        let mut config = TempestConfig::default();
        config.server.bind = IpAddr::V4(Ipv4Addr::LOCALHOST);
        config.server.root = root.path().to_path_buf();
        // The abort case asserts no retransmission, so its ERROR must never race
        // the timer; the timeout case needs one quick retry before giving up.
        let rto_ms = if abort { 30_000 } else { 1_000 };
        config.server.retransmit_interval_ms = rto_ms;
        config.server.min_retransmit_interval_ms = rto_ms;
        config.server.max_retransmit_interval_ms = rto_ms;
        config.server.max_retries = 1;
        config.boot_phases.clear();
        config.audit.enabled = true;
        config.audit.log_path = Some(root.path().join("audit.jsonl"));
        let state = TftpServer::new(config).state();
        let group = state
            .version_store
            .atomic_switch("release".into(), vec![("kernel".into(), artifact)])
            .unwrap();
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let client_addr = client.local_addr().unwrap();
        state.active_transfers.store(1, Ordering::Release);
        let tid =
            InflightTftpTidGuard::claim(state.inflight_tftp_tids.clone(), client_addr).unwrap();
        let reservation = state.audit_writer.as_ref().unwrap().try_reserve().unwrap();
        let task_state = state.clone();
        let transfer = tokio::spawn(async move {
            handle_rrq(
                task_state,
                client_addr,
                crate::protocol::packet::RequestPacket {
                    filename: "kernel".into(),
                    mode: crate::protocol::packet::TransferMode::Octet,
                    options: vec![],
                },
                Some(reservation),
                tid,
            )
            .await
        });
        let mut packet = [0u8; 1024];
        let (length, peer) =
            tokio::time::timeout(Duration::from_secs(30), client.recv_from(&mut packet))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(length, 516);
        assert_eq!(&packet[..4], &[0, 3, 0, 1]);
        if abort {
            client
                .send_to(
                    &TftpPacket::error(TftpErrorCode::NotDefined, "client abort"),
                    peer,
                )
                .await
                .unwrap();
        }
        let result = tokio::time::timeout(Duration::from_secs(30), transfer)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(
                result,
                Err(TempestError::Protocol(ProtocolError::ClientAbort { .. }))
            ) == abort
        );
        if !abort {
            assert!(matches!(
                result,
                Err(TempestError::Protocol(ProtocolError::Timeout { .. }))
            ));
        }
        state
            .audit_writer
            .as_ref()
            .unwrap()
            .wait_idle()
            .await
            .unwrap();
        let entries = state
            .audit_log
            .as_ref()
            .unwrap()
            .recent_entries(None, 10)
            .unwrap();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.file_sha256, group.files[0].content_hash);
        assert!(entry.blocks_sent >= 1);
        assert_eq!(entry.retransmissions > 0, !abort);
        assert_eq!(matches!(entry.outcome, TransferOutcome::Aborted), abort);
        assert_eq!(matches!(entry.outcome, TransferOutcome::TimedOut), !abort);
        let identity = entry.delivery.as_ref().unwrap();
        assert_eq!(identity.group_id.as_deref(), Some("release"));
        assert_eq!(identity.artifact_version_id, Some(group.version_id));
        assert_eq!(
            identity.manifest_digest.as_deref(),
            Some(group.manifest.manifest_digest.as_str())
        );
        assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
        assert_eq!(
            state.version_store.pinned_count("kernel", group.version_id),
            0
        );
        assert!(state.critical_services_healthy.load(Ordering::Acquire));
    }
}

#[tokio::test]
async fn test_handle_rrq_missing_file_sends_error_and_releases_slot() {
    let root = tempfile::tempdir().unwrap();
    let mut config = TempestConfig::default();
    config.server.bind = IpAddr::V4(Ipv4Addr::LOCALHOST);
    config.server.root = root.path().to_path_buf();
    let server = TftpServer::new(config);
    let state = server.state();
    state.active_transfers.store(1, Ordering::Release);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    let client_addr = client.local_addr().unwrap();
    let client_tid_guard =
        InflightTftpTidGuard::claim(state.inflight_tftp_tids.clone(), client_addr).unwrap();
    let result = handle_rrq(
        state.clone(),
        client_addr,
        crate::protocol::packet::RequestPacket {
            filename: "missing.bin".to_string(),
            mode: crate::protocol::packet::TransferMode::Octet,
            options: Vec::new(),
        },
        None,
        client_tid_guard,
    )
    .await;

    assert!(matches!(
        result,
        Err(TempestError::Protocol(
            crate::error::ProtocolError::FileNotFound(_)
        ))
    ));
    let mut buffer = [0u8; 512];
    let (length, peer) =
        tokio::time::timeout(Duration::from_secs(30), client.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    assert_ne!(peer.port(), state.config.server.port);
    assert!(matches!(
        TftpPacket::parse(&buffer[..length], peer).unwrap(),
        TftpPacket::Error(error) if error.code == u16::from(TftpErrorCode::FileNotFound)
    ));
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
    assert!(state.inflight_tftp_tids.is_empty());
}

#[tokio::test]
async fn handle_rrq_rejects_readable_unmanaged_file_without_leaking_resources() {
    for with_default_release in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let raw = root.path().join("raw.bin");
        std::fs::write(&raw, b"readable but unmanaged").unwrap();
        assert_eq!(std::fs::read(&raw).unwrap(), b"readable but unmanaged");
        // Hold a real listener endpoint so the transfer cannot reuse its port.
        let listener = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let mut config = TempestConfig::default();
        config.server.bind = listener_addr.ip();
        config.server.port = listener_addr.port();
        config.server.root = root.path().to_path_buf();
        let state = TftpServer::new(config).state();
        let default_pin = if with_default_release {
            let other = root.path().join("other.bin");
            std::fs::write(&other, b"managed").unwrap();
            state
                .version_store
                .atomic_switch("default-release".into(), vec![("other.bin".into(), other)])
                .unwrap();
            Some(
                state
                    .version_store
                    .active_boot_chain_for_profile(DEFAULT_BOOT_PROFILE)
                    .unwrap()
                    .unwrap(),
            )
        } else {
            None
        };
        let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let client_addr = client.local_addr().unwrap();
        state.active_transfers.store(1, Ordering::Release);
        let client_tid_guard =
            InflightTftpTidGuard::claim(state.inflight_tftp_tids.clone(), client_addr).unwrap();

        // Own both operations in the timeout: even an unexpected DATA transfer
        // is cancelled on expiry, with no spawned task surviving an assertion.
        let outcome = tokio::time::timeout(Duration::from_secs(30), async {
            let result = handle_rrq(
                state.clone(),
                client_addr,
                RequestPacket {
                    filename: "raw.bin".into(),
                    mode: TransferMode::Octet,
                    options: Vec::new(),
                },
                None,
                client_tid_guard,
            )
            .await;
            let mut buffer = [0u8; 512];
            let (length, peer) = client.recv_from(&mut buffer).await.unwrap();
            (result, buffer, length, peer)
        })
        .await;

        assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
        assert!(state.inflight_tftp_tids.is_empty());
        assert!(state.boot_sessions.is_empty());
        if let Some(pin) = default_pin {
            assert_eq!(state.version_store.pinned_boot_chain_count(&pin), 0);
            for filename in ["raw.bin", "other.bin"] {
                assert_eq!(
                    state.version_store.pinned_count(filename, pin.version_id),
                    0
                );
            }
        }
        let (result, buffer, length, peer) = outcome.expect("RRQ rejection must finish promptly");
        assert!(matches!(
            result,
            Err(TempestError::Protocol(ProtocolError::FileNotFound(filename)))
                if filename == "raw.bin"
        ));
        assert_eq!(peer.ip(), listener_addr.ip());
        assert_ne!(peer.port(), 0);
        assert_ne!(peer.port(), listener_addr.port());
        assert_ne!(peer.port(), client_addr.port());
        assert!(matches!(
            TftpPacket::parse(&buffer[..length], peer).unwrap(),
            TftpPacket::Error(error) if error.code == u16::from(TftpErrorCode::FileNotFound)
        ));
        assert_eq!(
            &buffer[..length],
            &TftpPacket::error(TftpErrorCode::FileNotFound, "File not found")[..]
        );
    }
}

#[tokio::test]
async fn tftp_resolution_requires_managed_membership_and_default_without_session() {
    let root = tempfile::tempdir().unwrap();
    let raw = root.path().join("raw.bin");
    let public = root.path().join("public.bin");
    let private = root.path().join("private.bin");
    std::fs::write(&raw, b"raw").unwrap();
    std::fs::write(&public, b"public").unwrap();
    std::fs::write(&private, b"private").unwrap();
    let mut config = TempestConfig::default();
    config.server.root = root.path().to_path_buf();
    let state = TftpServer::new(config).state();
    let ip: IpAddr = "127.0.0.1".parse().unwrap();

    let assert_missing =
        |result: Result<crate::features::versioning::ResolvedFile, TempestError>| {
            assert!(matches!(
                result,
                Err(TempestError::Protocol(ProtocolError::FileNotFound(_)))
            ));
        };
    assert_missing(
        state
            .resolve_file_for_boot_session(ip, "default", "raw.bin")
            .await,
    );
    let default_group = state
        .version_store
        .atomic_switch(
            "public-release".into(),
            vec![("boot.bin".into(), public.clone())],
        )
        .unwrap();
    let private_group = state
        .version_store
        .atomic_switch_for_profile(
            "private".into(),
            "private-release".into(),
            vec![
                ("boot.bin".into(), private.clone()),
                ("private-only.bin".into(), private.clone()),
            ],
        )
        .unwrap();
    assert_missing(
        state
            .resolve_file_for_boot_session(ip, "default", "raw.bin")
            .await,
    );
    assert_missing(
        state
            .resolve_file_for_boot_session(ip, "private", "private-only.bin")
            .await,
    );
    let resolved = state
        .resolve_file_for_boot_session(ip, "private", "boot.bin")
        .await
        .unwrap();
    assert_eq!(resolved.path, public);
    drop(PinnedVersionGuard::new(
        &state.version_store,
        resolved.pinned_version,
    ));
    assert_eq!(
        state
            .version_store
            .pinned_count("boot.bin", default_group.version_id),
        0
    );

    let private_session = || BootSessionEntry {
        trace_id: None,
        boot_profile: "private".into(),
        client_mac: None,
        serial: None,
        boot_epoch: 1,
        artifact_token_hash: None,
        pinned_boot_chain: None,
        expires_at: Instant::now() + Duration::from_secs(60),
    };
    state.insert_boot_session(ip, private_session());
    // An unpinned session is not permission to bypass managed membership.
    assert_missing(
        state
            .resolve_file_for_boot_session(ip, "default", "raw.bin")
            .await,
    );
    assert!(
        state
            .boot_sessions
            .get(&ip)
            .unwrap()
            .pinned_boot_chain
            .is_none()
    );
    // Keep the authenticated HTTP compatibility resolver separate.
    let raw_http = state
        .resolve_file_for_required_boot_session(ip, "raw.bin")
        .await
        .unwrap();
    assert_eq!(raw_http.path, raw);
    assert!(raw_http.pinned_version.is_none());
    let resolved = state
        .resolve_file_for_boot_session(ip, "default", "boot.bin")
        .await
        .unwrap();
    assert_eq!(resolved.path, private);
    drop(PinnedVersionGuard::new(
        &state.version_store,
        resolved.pinned_version,
    ));
    let pin = state
        .boot_sessions
        .get(&ip)
        .unwrap()
        .pinned_boot_chain
        .clone()
        .unwrap();
    assert_eq!(pin.version_id, private_group.version_id);
    assert_missing(
        state
            .resolve_file_for_boot_session(ip, "default", "raw.bin")
            .await,
    );
    assert_missing(
        state
            .resolve_file_for_required_boot_session(ip, "raw.bin")
            .await,
    );
    state.remove_boot_session(ip);
    assert_eq!(state.version_store.pinned_boot_chain_count(&pin), 0);

    for expire_while_waiting in [false, true] {
        for filename in ["boot.bin", "private-only.bin", "raw.bin"] {
            let result = tokio::time::timeout(Duration::from_secs(30), async {
                state.insert_boot_session(ip, private_session());
                let control_guard = state.control_plane_lock.lock().await;
                let mut resolution =
                    Box::pin(state.resolve_file_for_boot_session(ip, "private", filename));
                if expire_while_waiting {
                    // Poll exactly once to prove this live, unpinned session
                    // reached the held lock before expiring it deterministically.
                    std::future::poll_fn(|cx| {
                        assert!(std::future::Future::poll(resolution.as_mut(), cx).is_pending());
                        std::task::Poll::Ready(())
                    })
                    .await;
                }
                state.boot_sessions.get_mut(&ip).unwrap().expires_at =
                    Instant::now() - Duration::from_secs(1);
                drop(control_guard);
                resolution.await
            })
            .await
            .expect("expired session resolution must not hang");

            if filename == "boot.bin" {
                let resolved = result.unwrap();
                let transfer_pin =
                    PinnedVersionGuard::new(&state.version_store, resolved.pinned_version);
                assert_eq!(resolved.path, public);
                let chain = resolved.boot_chain.unwrap();
                assert_eq!(chain.boot_profile, DEFAULT_BOOT_PROFILE);
                assert_eq!(chain.version_id, default_group.version_id);
                assert_eq!(state.version_store.pinned_boot_chain_count(&chain), 0);
                drop(transfer_pin);
            } else {
                assert!(matches!(
                    result,
                    Err(TempestError::Protocol(ProtocolError::FileNotFound(missing)))
                        if missing == filename
                ));
            }
            assert!(!state.boot_sessions.contains_key(&ip));
            assert_eq!(state.version_store.pinned_boot_chain_count(&pin), 0);
            assert_eq!(
                state
                    .version_store
                    .pinned_count("boot.bin", default_group.version_id),
                0
            );
            for private_name in ["boot.bin", "private-only.bin"] {
                assert_eq!(
                    state.version_store.pinned_count_for_profile(
                        "private",
                        private_name,
                        private_group.version_id,
                    ),
                    0
                );
            }
        }
    }
}

#[tokio::test]
async fn test_boot_session_pins_release_across_profile_cutover() {
    let root = tempfile::tempdir().unwrap();
    let mut config = TempestConfig::default();
    config.server.root = root.path().to_path_buf();
    let server = TftpServer::new(config);
    let state = server.state();
    let client_ip: IpAddr = "10.0.0.42".parse().unwrap();

    let kernel_v1 = root.path().join("focal-v1-kernel");
    let initrd_v1 = root.path().join("focal-v1-initrd");
    let kernel_v2 = root.path().join("focal-v2-kernel");
    let initrd_v2 = root.path().join("focal-v2-initrd");
    std::fs::write(&kernel_v1, b"kernel-v1").unwrap();
    std::fs::write(&initrd_v1, b"initrd-v1").unwrap();
    std::fs::write(&kernel_v2, b"kernel-v2").unwrap();
    std::fs::write(&initrd_v2, b"initrd-v2").unwrap();

    let release_v1 = state
        .version_store
        .atomic_switch_for_profile(
            "ubuntu-focal".into(),
            "focal-v1".into(),
            vec![
                ("vmlinuz".into(), kernel_v1.clone()),
                ("initrd.img".into(), initrd_v1.clone()),
            ],
        )
        .unwrap();

    state.boot_sessions.insert(
        client_ip,
        BootSessionEntry {
            trace_id: Some("trace-boot".into()),
            boot_profile: "ubuntu-focal".into(),
            client_mac: None,
            serial: None,
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(60),
        },
    );

    let first = state
        .resolve_file_for_boot_session(client_ip, DEFAULT_BOOT_PROFILE, "vmlinuz")
        .await
        .unwrap();
    assert_eq!(first.path, kernel_v1);
    let session_pin = state
        .boot_sessions
        .get(&client_ip)
        .and_then(|session| session.pinned_boot_chain.clone())
        .unwrap();
    assert_eq!(session_pin.group_id, release_v1.group_id);
    assert_eq!(state.version_store.pinned_boot_chain_count(&session_pin), 1);

    state
        .version_store
        .atomic_switch_for_profile(
            "ubuntu-focal".into(),
            "focal-v2".into(),
            vec![
                ("vmlinuz".into(), kernel_v2),
                ("initrd.img".into(), initrd_v2),
            ],
        )
        .unwrap();

    let later = state
        .resolve_file_for_boot_session(client_ip, DEFAULT_BOOT_PROFILE, "initrd.img")
        .await
        .unwrap();
    assert_eq!(later.path, initrd_v1);
    state.remove_boot_session(client_ip);
    assert_eq!(state.version_store.pinned_boot_chain_count(&session_pin), 0);
}

#[test]
fn histogram_buckets_remain_cumulative_across_ranges() {
    let h = DurationHistogram::new();
    h.observe(0.0001);
    h.observe(0.01); // Between 0.005 and 0.025
    h.observe(1.5); // Between 1.0 and 5.0
    let (buckets, _, count) = h.snapshot();
    assert_eq!(count, 3);
    assert_eq!(buckets[0], 1);
    assert_eq!(buckets[2], 2);
    assert_eq!(buckets[7], 3);
    for i in 1..buckets.len() {
        assert!(
            buckets[i] >= buckets[i - 1],
            "Bucket {} < bucket {}",
            i,
            i - 1
        );
    }
}

#[test]
fn test_configured_manifest_signing_keys_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let signing = dir.path().join("manifest.key");
    std::fs::write(&signing, [1; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&signing, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut config = TempestConfig::default();
    config.audit.manifest_signing_key_path = Some(signing);
    config.audit.manifest_verifying_key = Some(hex::encode(
        SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes(),
    ));
    assert!(
        TftpServer::try_new_with_quarantine_and_persistence(
            config,
            Arc::new(DashSet::new()),
            None,
        )
        .is_err()
    );

    let mut config = TempestConfig::default();
    config.audit.require_signed_manifests = true;
    assert!(
        TftpServer::try_new_with_quarantine_and_persistence(
            config,
            Arc::new(DashSet::new()),
            None,
        )
        .is_err()
    );
}

#[test]
fn test_transfer_completed_fires_drain_notify() {
    let active = Arc::new(AtomicUsize::new(1));
    let metrics = Arc::new(ServerMetrics::new(active.clone()));
    let transfer_metrics = crate::protocol::transfer::TransferMetrics {
        bytes_sent: 1000,
        blocks_sent: 10,
        retransmissions: 0,
        start_time: Some(Instant::now()),
        end_time: Some(Instant::now()),
        content_hash: None,
        artifact_version_id: None,
        boot_chain: None,
        redirected: false,
    };
    metrics.transfer_completed(
        &crate::features::boot_phase::BootPhase::Unknown,
        DEFAULT_BOOT_PROFILE,
        &transfer_metrics,
    );
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[test]
fn test_transfer_failed_fires_drain_notify() {
    let active = Arc::new(AtomicUsize::new(1));
    let metrics = Arc::new(ServerMetrics::new(active.clone()));
    metrics.transfer_failed(
        &crate::features::boot_phase::BootPhase::Unknown,
        DEFAULT_BOOT_PROFILE,
    );
    assert_eq!(active.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn wait_for_drain_includes_accepted_queue_work() {
    let server = TftpServer::new(TempestConfig::default());
    let state = server.state();
    let queued = QueuedTransferGuard::new(state.queued_transfers.clone(), state.metrics.clone());
    server.drain();

    let waiter = tokio::spawn({
        let server = server.clone();
        async move { server.wait_for_drain().await }
    });
    tokio::task::yield_now().await;
    assert!(!waiter.is_finished());

    drop(queued);
    tokio::time::timeout(Duration::from_secs(30), waiter)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn metrics_text_maintenance_skips_disabled_metrics() {
    let mut config = TempestConfig::default();
    config.api.enable_metrics = false;
    let server = TftpServer::new(config);
    let state = server.state();
    refresh_maintenance_metrics(&state).await;
    assert!(state.metrics.snapshot.load_full().is_none());
}

#[tokio::test]
async fn metrics_text_maintenance_refreshes_on_blocking_pool_and_releases_on_cancel() {
    let server = TftpServer::new(TempestConfig::default());
    let state = server.state();
    let cache = Arc::downgrade(&state.metrics.snapshot);
    let weak_state = Arc::downgrade(&state);
    assert!(state.metrics.snapshot.load_full().is_none());
    let task = tokio::spawn(run_maintenance_task(state.clone()));
    let first = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(snapshot) = state.metrics.snapshot.load_full() {
                break snapshot;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    state
        .metrics
        .retransmissions_total
        .store(42, Ordering::Relaxed);
    // A refresh already in flight may predate the store; wait for one that observed it.
    let second = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(snapshot) = state.metrics.snapshot.load_full() {
                if !Arc::ptr_eq(&first, &snapshot)
                    && std::str::from_utf8(&snapshot)
                        .unwrap()
                        .contains("tempest_retransmissions_total 42\n")
                {
                    break snapshot;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        std::str::from_utf8(&second)
            .unwrap()
            .contains("tempest_retransmissions_total 42\n")
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    drop(state);
    drop(server);
    // Aborting cannot interrupt a refresh already running on the blocking
    // pool; it releases its upgraded state when the render returns.
    tokio::time::timeout(Duration::from_secs(30), async {
        while weak_state.upgrade().is_some() || cache.upgrade().is_some() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cancelled maintenance must release server state");
}
