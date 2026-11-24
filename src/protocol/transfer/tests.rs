// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::extension::ReadProtocolEncodeFuture;
use std::io::{Cursor, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::io::ReadBuf;

// Real UDP tests normally use wall-clock time: paused Tokio time can race
// socket readiness. The extended-lifetime fixture explicitly prevents automatic
// time advancement. Exchanges are bounded without spawning a transfer that
// could survive a failing assertion.
#[derive(Default)]
struct TransferDeadlineScheduler {
    registrations: AtomicUsize,
    removals: AtomicUsize,
}

impl TransferScheduler for TransferDeadlineScheduler {
    fn register_transfer(
        &self,
        _: TransferId,
        _: crate::features::boot_phase::BootPhase,
        _: u64,
        _: Option<f64>,
    ) {
        self.registrations.fetch_add(1, Ordering::SeqCst);
    }

    fn unregister_transfer(&self, _: &TransferId) {
        self.removals.fetch_add(1, Ordering::SeqCst);
    }

    fn phase_adjusted_ceiling(&self, _: &TransferId) -> Option<f64> {
        None
    }

    fn send_packet(
        &self,
        _: TransferId,
        socket: Arc<UdpSocket>,
        data: BytesMut,
        destination: SocketAddr,
    ) -> crate::extension::PacketSendFuture<'_> {
        Box::pin(async move {
            socket.send_to(&data, destination).await?;
            Ok(())
        })
    }
}

fn transfer_deadline_config(root: &Path, seconds: u64) -> crate::config::TempestConfig {
    let mut config = crate::config::TempestConfig::default();
    config.server.root = root.to_path_buf();
    config.server.max_transfer_duration_secs = seconds;
    config.server.write_enabled = true;
    config.server.write_require_session = false;
    config.boot_phases.clear();
    config.audit.enabled = false;
    config
}

struct TransferDeadlineReadFixture {
    _directory: tempfile::TempDir,
    state: Arc<ServerState>,
    version_id: u64,
    scheduler: Arc<TransferDeadlineScheduler>,
}

impl TransferDeadlineReadFixture {
    fn new(bytes: &[u8], seconds: u64, scheduled: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let artifact = directory.path().join("kernel");
        std::fs::write(&artifact, bytes).unwrap();
        let scheduler = Arc::new(TransferDeadlineScheduler::default());
        let mut builder =
            crate::server::TftpServer::builder(transfer_deadline_config(directory.path(), seconds));
        if scheduled {
            builder = builder.with_scheduler(scheduler.clone());
        }
        let state = builder.build().unwrap().state();
        let group = state
            .version_store
            .atomic_switch("deadline-release".into(), vec![("kernel".into(), artifact)])
            .unwrap();
        state.active_transfers.store(1, Ordering::Release);
        Self {
            _directory: directory,
            state,
            version_id: group.version_id,
            scheduler,
        }
    }

    fn assert_owned(&self, scheduled: bool) {
        assert_eq!(self.state.active_transfers.load(Ordering::Acquire), 1);
        assert_eq!(
            self.state
                .version_store
                .pinned_count("kernel", self.version_id),
            1
        );
        assert_eq!(
            self.scheduler.registrations.load(Ordering::SeqCst),
            usize::from(scheduled)
        );
        assert_eq!(self.scheduler.removals.load(Ordering::SeqCst), 0);
    }

    fn assert_released(&self, scheduled: bool) {
        assert_eq!(self.state.active_transfers.load(Ordering::Acquire), 0);
        assert_eq!(
            self.state
                .version_store
                .pinned_count("kernel", self.version_id),
            0
        );
        assert_eq!(
            self.scheduler.registrations.load(Ordering::SeqCst),
            usize::from(scheduled)
        );
        assert_eq!(
            self.scheduler.removals.load(Ordering::SeqCst),
            usize::from(scheduled)
        );
    }
}

fn assert_transfer_deadline<T>(result: Result<T, TempestError>, peer: SocketAddr) {
    let error = result.err().expect("transfer must expire, not complete");
    assert!(
        matches!(
            error,
            TempestError::Protocol(ProtocolError::TransferDeadline { addr }) if addr == peer
        ),
        "unexpected terminal error: {error:?}"
    );
    assert!(matches!(
        crate::features::audit::TransferOutcome::from_error(&error),
        crate::features::audit::TransferOutcome::TimedOut
    ));
}

async fn transfer_deadline_receive(client: &UdpSocket, peer: SocketAddr) -> TftpPacket {
    let mut wire = [0u8; 2048];
    let (length, actual_peer) = client.recv_from(&mut wire).await.unwrap();
    assert_eq!(
        actual_peer, peer,
        "all responses must retain the transfer TID"
    );
    TftpPacket::parse(&wire[..length], actual_peer).unwrap()
}

#[tokio::test(start_paused = true)]
async fn transfer_deadline_expired_timer_wins_over_always_ready_work() {
    let peer = "127.0.0.1:12345".parse().unwrap();
    let deadline = TransferDeadline(tokio::time::Instant::now() + Duration::from_secs(1));
    tokio::time::advance(Duration::from_secs(1)).await;
    let polls = AtomicUsize::new(0);
    for _ in 0..128 {
        let result = deadline
            .run(peer, async {
                polls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            })
            .await;
        assert_transfer_deadline(result, peer);
    }
    assert_eq!(polls.load(Ordering::Relaxed), 0);
}

#[tokio::test(start_paused = true)]
async fn transfer_deadline_multiple_phases_share_the_original_budget() {
    let peer = "127.0.0.1:12345".parse().unwrap();
    let start = tokio::time::Instant::now();
    let deadline = TransferDeadline(start + Duration::from_secs(1));
    for _ in 0..2 {
        deadline
            .run(peer, async {
                tokio::time::sleep(Duration::from_millis(300)).await;
                Ok(())
            })
            .await
            .unwrap();
    }
    let result = deadline
        .run(peer, async {
            tokio::time::sleep(Duration::from_millis(600)).await;
            Ok(())
        })
        .await;
    assert_transfer_deadline(result, peer);
    assert_eq!(start.elapsed(), Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn transfer_deadline_extended_phases_use_configured_budget_without_renewal() {
    let directory = tempfile::tempdir().unwrap();
    let state =
        crate::server::TftpServer::new(transfer_deadline_config(directory.path(), 1800)).state();
    let peer = "127.0.0.1:12345".parse().unwrap();
    let start = tokio::time::Instant::now();
    let deadline = TransferDeadline::new(&state);
    let mut completed_phases = 0;
    for seconds in [120, 240, 600] {
        deadline
            .run(peer, async {
                tokio::time::sleep(Duration::from_secs(seconds)).await;
                Ok(())
            })
            .await
            .unwrap();
        completed_phases += 1;
    }
    assert_eq!(completed_phases, 3);
    assert_eq!(start.elapsed(), Duration::from_secs(960));
    // Productive phases may exceed the default 300s, but cannot replenish
    // the explicitly configured 1800s absolute budget.
    let result = deadline
        .run(peer, async {
            tokio::time::sleep(Duration::from_secs(1000)).await;
            Ok(())
        })
        .await;
    assert_transfer_deadline(result, peer);
    assert_eq!(start.elapsed(), Duration::from_secs(1800));
}

#[tokio::test(start_paused = true)]
async fn transfer_deadline_extended_productive_rrq_completes_after_default_lifetime() {
    let bytes: Vec<u8> = (0..1300).map(|index| (index % 251) as u8).collect();
    let fixture = TransferDeadlineReadFixture::new(&bytes, 1800, true);
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let peer = server.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let options = NegotiatedOptions {
        timeout: 255,
        timeout_requested: true,
        retransmission_policy: RetransmissionPolicy::fixed(Duration::from_secs(255)),
        ..NegotiatedOptions::default()
    };
    let start = tokio::time::Instant::now();
    let transfer = run_read_transfer(
        server,
        client.local_addr().unwrap(),
        "kernel".into(),
        "default".into(),
        None,
        options,
        vec![],
        fixture.state.clone(),
        TransferId::new_v4(),
    );
    let client_flow = async {
        assert!(matches!(transfer_deadline_receive(&client, peer).await,
            TftpPacket::Oack(packet) if packet.options == vec![("timeout".into(), "255".into())]));
        // The slot and version pin are owned during OACK; scheduler
        // registration starts only after ACK(0) completes negotiation.
        fixture.assert_owned(false);
        tokio::time::advance(Duration::from_secs(120)).await;
        client.send_to(&TftpPacket::ack(0), peer).await.unwrap();
        let mut downloaded = Vec::new();
        for block in 1..=3 {
            let TftpPacket::Data(packet) = transfer_deadline_receive(&client, peer).await else {
                panic!("productive RRQ must not expire at the default 300s limit");
            };
            assert_eq!(packet.block, block);
            assert_eq!(packet.data.len(), if block == 3 { 276 } else { 512 });
            downloaded.extend_from_slice(&packet.data);
            tokio::time::advance(Duration::from_secs(120)).await;
            fixture.assert_owned(true);
            client.send_to(&TftpPacket::ack(block), peer).await.unwrap();
        }
        assert_eq!(downloaded, bytes);
    };
    // Unlike the wall-clock UDP fixtures, keep a task runnable to prevent
    // paused time auto-jumping to an RTO while real socket/file I/O is pending.
    // Only the client advances virtual time, after receiving each response.
    // A wall-clock watchdog bounds failures without advancing virtual time.
    let watchdog = async {
        let start = Instant::now();
        loop {
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "virtual-time UDP fixture stalled"
            );
            tokio::task::yield_now().await;
        }
    };
    let (result, ()) = tokio::select! {
        result = async { tokio::join!(transfer, client_flow) } => result,
        _ = watchdog => unreachable!(),
    };
    let metrics = result.unwrap();
    assert_eq!(start.elapsed(), Duration::from_secs(480));
    assert_eq!(metrics.bytes_sent, bytes.len() as u64);
    assert_eq!(metrics.blocks_sent, 3);
    assert_eq!(metrics.retransmissions, 0);
    // TransferMetrics uses std::time::Instant: it is not a virtual duration.
    fixture.assert_released(true);
}

#[tokio::test]
async fn transfer_deadline_rrq_timeout255_oack_data_and_final_ack_release_ownership() {
    // No ACK(0); negotiated DATA and final DATA; then ordinary no-option DATA
    // and final DATA with a long internal RTO (no timeout option is emitted).
    for (size, negotiate_timeout, acknowledge_oack) in [
        (1024, true, false),
        (1024, true, true),
        (4, true, true),
        (1024, false, false),
        (4, false, false),
    ] {
        // In-flight ownership is asserted before expiry; keep it seconds away.
        let fixture = TransferDeadlineReadFixture::new(&vec![0x41; size], 3, false);
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let options = NegotiatedOptions {
            timeout: 255,
            timeout_requested: negotiate_timeout,
            retransmission_policy: RetransmissionPolicy::fixed(Duration::from_secs(255)),
            ..NegotiatedOptions::default()
        };
        let transfer = run_read_transfer(
            server,
            client_addr,
            "kernel".into(),
            "default".into(),
            None,
            options,
            vec![],
            fixture.state.clone(),
            TransferId::new_v4(),
        );
        let client_flow = async {
            if negotiate_timeout {
                assert!(matches!(transfer_deadline_receive(&client, peer).await,
                    TftpPacket::Oack(packet) if packet.options == vec![("timeout".into(), "255".into())]));
                fixture.assert_owned(false);
                if !acknowledge_oack {
                    return;
                }
                client.send_to(&TftpPacket::ack(0), peer).await.unwrap();
            }
            assert!(matches!(transfer_deadline_receive(&client, peer).await,
                TftpPacket::Data(packet) if packet.block == 1 && packet.data == vec![0x41; size.min(512)]));
            fixture.assert_owned(false);
            // Intentionally withhold ACK(1), including for the terminal block.
        };
        let start = Instant::now();
        let (result, ()) = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::join!(transfer, client_flow)
        })
        .await
        .expect("255-second retry interval must not defeat the deadline");
        assert_transfer_deadline(result, client_addr);
        assert!(start.elapsed() >= Duration::from_secs(3));
        fixture.assert_released(false);
        // The deadline terminates; it must not shorten the negotiated RTO by
        // emitting another OACK/DATA before 255 seconds. Send only a standard
        // terminal ERROR from the transfer TID so the peer need not wait 255s.
        let terminal = tokio::time::timeout(
            Duration::from_secs(30),
            transfer_deadline_receive(&client, peer),
        )
        .await
        .expect("deadline expiry must notify the peer without another retry");
        assert!(matches!(terminal, TftpPacket::Error(packet)
            if packet.code == TftpErrorCode::NotDefined as u16
                && packet.message == "Transfer time limit exceeded"));
        let mut wire = [0u8; 2048];
        assert_eq!(
            client.try_recv_from(&mut wire).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[tokio::test]
async fn transfer_deadline_progress_acks_reset_retries_but_not_lifetime() {
    let fixture = TransferDeadlineReadFixture::new(&vec![0x42; 512 * 128], 6, true);
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let peer = server.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let options = NegotiatedOptions {
        // Each window spends one retry; the rest tolerate a 1.5s client stall,
        // and six windows fit the budget with about a second each to spare.
        retransmission_policy: RetransmissionPolicy::fixed(Duration::from_millis(300)),
        max_retries: 5,
        ..NegotiatedOptions::default()
    };
    let transfer = run_read_transfer(
        server,
        client_addr,
        "kernel".into(),
        "default".into(),
        None,
        options,
        vec![],
        fixture.state.clone(),
        TransferId::new_v4(),
    );
    let acknowledged = AtomicUsize::new(0);
    let retransmitted = AtomicUsize::new(0);
    let client_flow = async {
        let mut expected = 1;
        loop {
            let mut copies = 0;
            while copies < 2 {
                let TftpPacket::Data(packet) = transfer_deadline_receive(&client, peer).await
                else {
                    panic!("read transfer must send only DATA");
                };
                // A late ACK lets the server retransmit again; drain that stale copy.
                if packet.block != expected {
                    assert_eq!(packet.block, expected - 1);
                    continue;
                }
                assert_eq!(packet.data, vec![0x42; 512]);
                fixture.assert_owned(true);
                copies += 1;
                if copies == 2 {
                    retransmitted.fetch_add(1, Ordering::Relaxed);
                }
            }
            // Every window incurs a real RTO, then advances before its retries
            // are exhausted. More windows than retries prove the retry reset.
            tokio::time::sleep(Duration::from_millis(30)).await;
            client
                .send_to(&TftpPacket::ack(expected), peer)
                .await
                .unwrap();
            acknowledged.fetch_add(1, Ordering::Relaxed);
            expected += 1;
        }
    };
    let start = Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::select! {
            result = transfer => result,
            _ = client_flow => unreachable!(),
        }
    })
    .await
    .expect("valid progress must not renew the absolute deadline");
    assert_transfer_deadline(result, client_addr);
    assert!(start.elapsed() >= Duration::from_secs(6));
    assert!(acknowledged.load(Ordering::Relaxed) > 5);
    assert!(retransmitted.load(Ordering::Relaxed) > 5);
    fixture.assert_released(true);
}

#[tokio::test]
async fn transfer_deadline_ordinary_download_completes_before_expiry() {
    let bytes: Vec<u8> = (0..1300).map(|index| (index % 251) as u8).collect();
    let fixture = TransferDeadlineReadFixture::new(&bytes, 30, false);
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let peer = server.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let transfer = run_read_transfer(
        server,
        client.local_addr().unwrap(),
        "kernel".into(),
        "default".into(),
        None,
        // The adaptive default can fall to 250ms; a slow client must not see
        // retransmissions in a test that asserts there are none.
        NegotiatedOptions {
            retransmission_policy: RetransmissionPolicy::fixed(Duration::from_secs(30)),
            ..NegotiatedOptions::default()
        },
        vec![],
        fixture.state.clone(),
        TransferId::new_v4(),
    );
    let client_flow = async {
        let mut downloaded = Vec::new();
        for block in 1..=3 {
            let TftpPacket::Data(packet) = transfer_deadline_receive(&client, peer).await else {
                panic!("ordinary RRQ must start with DATA, not OACK");
            };
            assert_eq!(packet.block, block);
            fixture.assert_owned(false);
            downloaded.extend_from_slice(&packet.data);
            client.send_to(&TftpPacket::ack(block), peer).await.unwrap();
        }
        assert_eq!(downloaded, bytes);
    };
    let (result, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(transfer, client_flow)
    })
    .await
    .unwrap();
    let metrics = result.unwrap();
    assert_eq!(metrics.bytes_sent, bytes.len() as u64);
    assert_eq!(metrics.blocks_sent, 3);
    assert_eq!(metrics.retransmissions, 0);
    assert!(metrics.duration().unwrap() < Duration::from_secs(30));
    fixture.assert_released(false);
}

#[tokio::test]
async fn transfer_deadline_wrq_silence_slow_data_and_duplicates_remove_temporary_file() {
    for (send_data, advance_blocks) in [(false, false), (true, false), (true, true)] {
        let directory = tempfile::tempdir().unwrap();
        let state =
            crate::server::TftpServer::new(transfer_deadline_config(directory.path(), 3)).state();
        state.active_transfers.store(1, Ordering::Release);
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let duplicate_request = tokio::sync::Notify::new();
        let options = NegotiatedOptions {
            timeout: 255,
            timeout_requested: true,
            retransmission_policy: RetransmissionPolicy::fixed(Duration::from_secs(255)),
            ..NegotiatedOptions::default()
        };
        let transfer = run_write_transfer_with_duplicate_request(
            server,
            client_addr,
            "upload.bin".into(),
            "default".into(),
            options,
            state.clone(),
            TransferId::new_v4(),
            Some(&duplicate_request),
        );
        let rounds = AtomicUsize::new(0);
        let client_flow = async {
            assert!(matches!(transfer_deadline_receive(&client, peer).await,
                TftpPacket::Oack(packet) if packet.options == vec![("timeout".into(), "255".into())]));
            assert_eq!(state.active_transfers.load(Ordering::Acquire), 1);
            assert_eq!(
                std::fs::read_dir(directory.path()).unwrap().count(),
                1,
                "a private temporary file must exist before cancellation"
            );
            if !send_data {
                std::future::pending::<()>().await;
            }
            let mut block = 1;
            loop {
                tokio::time::sleep(Duration::from_millis(20)).await;
                // Full blocks only: an incomplete upload must never publish.
                client
                    .send_to(&TftpPacket::data(block, &[0x43; 512]), peer)
                    .await
                    .unwrap();
                assert!(matches!(transfer_deadline_receive(&client, peer).await,
                    TftpPacket::Ack(packet) if packet.block == block));
                client
                    .send_to(&TftpPacket::data(block, &[0x43; 512]), peer)
                    .await
                    .unwrap();
                assert!(matches!(transfer_deadline_receive(&client, peer).await,
                    TftpPacket::Ack(packet) if packet.block == block));
                duplicate_request.notify_one();
                assert!(matches!(transfer_deadline_receive(&client, peer).await,
                    TftpPacket::Ack(packet) if packet.block == block));
                rounds.fetch_add(1, Ordering::Relaxed);
                if advance_blocks {
                    block += 1;
                }
            }
        };
        let result = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::select! {
                result = transfer => result,
                _ = client_flow => unreachable!(),
            }
        })
        .await
        .expect("WRQ silence, progress and duplicates must all be bounded");
        assert_transfer_deadline(result, client_addr);
        if send_data {
            assert!(rounds.load(Ordering::Relaxed) >= 3);
        } else {
            let terminal = tokio::time::timeout(
                Duration::from_secs(30),
                transfer_deadline_receive(&client, peer),
            )
            .await
            .expect("an incomplete upload must receive a terminal ERROR");
            assert!(matches!(terminal, TftpPacket::Error(packet)
                if packet.code == TftpErrorCode::NotDefined as u16
                    && packet.message == "Transfer time limit exceeded"));
        }
        assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
        assert!(!directory.path().join("upload.bin").exists());
        assert_eq!(
            std::fs::read_dir(directory.path()).unwrap().count(),
            0,
            "deadline cancellation must remove the private upload temporary file"
        );
    }
}

#[tokio::test]
async fn transfer_deadline_committed_write_ack_survives_expired_budget() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = server.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    // Establish writable readiness so the expired-budget case exercises the
    // nonblocking final ACK, not a platform-dependent initial WouldBlock.
    server.writable().await.unwrap();
    for expired in [false, true] {
        let now = tokio::time::Instant::now();
        let deadline = TransferDeadline(if expired {
            now - Duration::from_secs(1)
        } else {
            now + Duration::from_secs(1)
        });
        tokio::time::timeout(Duration::from_secs(30), async {
            deadline
                .acknowledge_committed_write(&server, client_addr, &TftpPacket::ack(7))
                .await
                .expect("publication must not be reclassified as deadline failure");
            assert!(matches!(transfer_deadline_receive(&client, peer).await,
                TftpPacket::Ack(packet) if packet.block == 7));
        })
        .await
        .expect("final ACK must remain bounded even after publication crosses expiry");
    }
    let mut wire = [0u8; 128];
    assert_eq!(
        client.try_recv_from(&mut wire).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "a committed write must not receive a terminal ERROR"
    );
}

#[tokio::test]
async fn transfer_deadline_wrq_timeout255_dally_uses_remaining_budget_and_succeeds() {
    // The client's two rounds must finish inside BUDGET - RECEIVE_DELAY, and a
    // budget restarted at publication cannot end before RECEIVE_DELAY + BUDGET.
    // Both margins are whole seconds so loaded CI runners cannot cross them.
    const BUDGET: Duration = Duration::from_secs(7);
    const RECEIVE_DELAY: Duration = Duration::from_secs(3);
    let directory = tempfile::tempdir().unwrap();
    let state = crate::server::TftpServer::new(transfer_deadline_config(
        directory.path(),
        BUDGET.as_secs(),
    ))
    .state();
    state.active_transfers.store(1, Ordering::Release);
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let peer = server.local_addr().unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let options = NegotiatedOptions {
        timeout: 255,
        timeout_requested: true,
        retransmission_policy: RetransmissionPolicy::fixed(Duration::from_secs(255)),
        ..NegotiatedOptions::default()
    };
    let transfer = run_write_transfer(
        server,
        client.local_addr().unwrap(),
        "upload.bin".into(),
        "default".into(),
        options,
        state.clone(),
        TransferId::new_v4(),
    );
    let client_flow = async {
        assert!(matches!(transfer_deadline_receive(&client, peer).await,
            TftpPacket::Oack(packet) if packet.options == vec![("timeout".into(), "255".into())]));
        // Spend part of the original budget receiving before publication.
        tokio::time::sleep(RECEIVE_DELAY).await;
        for _ in 0..2 {
            client
                .send_to(&TftpPacket::data(1, b"done"), peer)
                .await
                .unwrap();
            assert!(matches!(transfer_deadline_receive(&client, peer).await,
                TftpPacket::Ack(packet) if packet.block == 1));
            assert_eq!(
                std::fs::read(directory.path().join("upload.bin")).unwrap(),
                b"done"
            );
            assert_eq!(state.active_transfers.load(Ordering::Acquire), 1);
        }
    };
    let start = Instant::now();
    let (result, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(transfer, client_flow)
    })
    .await
    .expect("dally must use the remaining deadline, not 510 seconds");
    assert!(
        start.elapsed() < RECEIVE_DELAY + BUDGET,
        "dally must use the remaining deadline, not a fresh budget"
    );
    let metrics = result.expect("a durably published upload must succeed at the dally deadline");
    assert_eq!(metrics.bytes_sent, 4);
    assert_eq!(metrics.blocks_sent, 1);
    assert_eq!(metrics.retransmissions, 1);
    assert!(metrics.duration().unwrap() >= BUDGET);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
    assert_eq!(
        std::fs::read(directory.path().join("upload.bin")).unwrap(),
        b"done"
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[tokio::test(start_paused = true)]
async fn packet_pacer_bounds_bursts_and_credits_elapsed_time() {
    let mut pacer = PacketPacer::new();
    let interval = Duration::from_millis(10);
    let start = tokio::time::Instant::now();
    for _ in 0..4 {
        pacer.before_send(Some(interval), 4).await;
    }
    assert_eq!(tokio::time::Instant::now(), start);
    pacer.before_send(Some(interval), 4).await;
    assert!(start.elapsed() >= interval);
    tokio::time::advance(Duration::from_secs(1)).await;
    let after_ack = tokio::time::Instant::now();
    for _ in 0..4 {
        pacer.before_send(Some(interval), 4).await;
    }
    assert_eq!(tokio::time::Instant::now(), after_ack);
    pacer.before_send(Some(interval), 4).await;
    assert!(
        after_ack.elapsed() >= interval,
        "idle time must not accumulate unbounded credit"
    );
}

#[tokio::test(start_paused = true)]
async fn packet_pacer_handles_rate_changes_and_disabled_pacing() {
    let mut pacer = PacketPacer::new();
    pacer.before_send(Some(Duration::from_secs(10)), 1).await;
    let changed = tokio::time::Instant::now();
    pacer.before_send(Some(Duration::from_millis(1)), 1).await;
    assert_eq!(changed, tokio::time::Instant::now());
    pacer.before_send(None, 1).await;
    pacer.before_send(Some(Duration::from_secs(10)), 1).await;
    assert_eq!(changed, tokio::time::Instant::now());
}

#[cfg(unix)]
struct UnrequestedProtocol;

#[cfg(unix)]
impl crate::extension::ReadProtocolExtension for UnrequestedProtocol {
    fn requires_preparation(&self, options: &[(String, String)]) -> bool {
        !options.is_empty()
    }
    fn prepare(&self, _: ReadProtocolContext) -> crate::extension::ReadProtocolFuture<'_> {
        Box::pin(async { panic!("unrequested protocol must not bypass the standard cache") })
    }
}

#[cfg(unix)]
#[tokio::test]
async fn unrequested_protocol_preserves_the_core_cached_source() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("kernel");
    std::fs::write(&path, b"verified bytes").unwrap();
    let mut config = crate::config::TempestConfig::default();
    config.server.root = directory.path().to_path_buf();
    let state = crate::server::TftpServer::builder(config)
        .with_read_protocol(Arc::new(UnrequestedProtocol))
        .build()
        .unwrap()
        .state();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let source = prepare_read_source(
        &socket,
        socket.local_addr().unwrap(),
        path.clone(),
        None,
        None,
        &[],
        &NegotiatedOptions::default(),
        &state,
    )
    .await
    .unwrap();
    assert!(matches!(source.source, CoreReadSource::Memory(_)));
    assert!(source.protocol_session.is_none());
    let second = prepare_read_source(
        &socket,
        socket.local_addr().unwrap(),
        path,
        None,
        None,
        &[],
        &NegotiatedOptions::default(),
        &state,
    )
    .await
    .unwrap();
    let (CoreReadSource::Memory(first), CoreReadSource::Memory(second)) =
        (source.source, second.source)
    else {
        panic!("cache bypassed")
    };
    assert!(Arc::ptr_eq(&first, &second));
}

struct RetransmissionProbe {
    count: Arc<AtomicU64>,
}

struct CountingReader {
    inner: Cursor<Vec<u8>>,
    read_calls: Arc<AtomicUsize>,
}

struct FailingPacketScheduler;

impl TransferScheduler for FailingPacketScheduler {
    fn register_transfer(
        &self,
        _transfer_id: TransferId,
        _phase: crate::features::boot_phase::BootPhase,
        _total_bytes: u64,
        _provisioning_priority: Option<f64>,
    ) {
    }

    fn unregister_transfer(&self, _transfer_id: &TransferId) {}

    fn phase_adjusted_ceiling(&self, _transfer_id: &TransferId) -> Option<f64> {
        None
    }

    fn send_packet(
        &self,
        _transfer_id: TransferId,
        _socket: Arc<UdpSocket>,
        _data: BytesMut,
        _destination: SocketAddr,
    ) -> crate::extension::PacketSendFuture<'_> {
        Box::pin(async { Err(TempestError::Io(std::io::Error::other("scheduler failed"))) })
    }
}

impl AsyncRead for CountingReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.read_calls.fetch_add(1, Ordering::Relaxed);
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncSeek for CountingReader {
    fn start_seek(mut self: Pin<&mut Self>, position: SeekFrom) -> std::io::Result<()> {
        Pin::new(&mut self.inner).start_seek(position)
    }

    fn poll_complete(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<u64>> {
        Pin::new(&mut self.inner).poll_complete(context)
    }
}

impl ReadProtocolSession for RetransmissionProbe {
    fn oack_options(&self) -> Vec<(String, String)> {
        Vec::new()
    }

    fn encode_packet(
        &mut self,
        wire_block: u16,
        payload: &[u8],
    ) -> Result<EncodedDataPacket, TempestError> {
        Ok(EncodedDataPacket {
            packet: TftpPacket::data(wire_block, payload),
            accounted_bytes: payload.len() as u64,
        })
    }

    fn encode_packet_async<'a>(
        &'a mut self,
        _wire_block: u16,
        _payload: ReadProtocolPayload<'a>,
    ) -> ReadProtocolEncodeFuture<'a> {
        panic!("lightweight protocol sessions must stay on the synchronous packet path")
    }

    fn record_retransmission(&mut self) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn test_artifact_read_buffer_is_bounded_and_payload_sized() {
    assert_eq!(
        artifact_read_buffer_capacity(1024 * 1024, 1468, true, 1),
        TFTP_LOW_PRESSURE_READ_AHEAD_BYTES
    );
    assert_eq!(artifact_read_buffer_capacity(1024, 1468, true, 1), 1468);
    assert_eq!(
        artifact_read_buffer_capacity(u64::MAX, 65_464, true, usize::MAX),
        TFTP_READ_AHEAD_BYTES
    );
    for active in [0, 1, 7, 8, 64, usize::MAX] {
        assert_eq!(
            artifact_read_buffer_capacity(u64::MAX, 1468, false, active),
            1468
        );
        assert_eq!(
            artifact_read_buffer_capacity(u64::MAX, 1468, true, active),
            if active < 8 {
                TFTP_LOW_PRESSURE_READ_AHEAD_BYTES
            } else {
                TFTP_READ_AHEAD_BYTES
            }
        );
    }
}

#[test]
fn standard_window_batching_adapts_to_live_transfer_pressure() {
    assert!(!use_standard_window_batching(0, 8));
    assert!(!use_standard_window_batching(1, 8));
    assert_eq!(
        use_standard_window_batching(2, 8),
        cfg!(target_os = "linux")
    );
    assert_eq!(
        use_standard_window_batching(7, 8),
        cfg!(target_os = "linux")
    );
    assert!(use_standard_window_batching(8, 8));
    assert!(use_standard_window_batching(500, 64));
    assert!(!use_standard_window_batching(1, 1));
    assert!(!use_standard_window_batching(500, 1));
}

#[test]
fn test_standard_data_packet_buffer_reuses_exact_wire_storage() {
    let first_payload = [0x5a; 1468];
    let second_payload = [0xa5; 512];
    let mut packet = BytesMut::with_capacity(first_payload.len() + 4);

    TftpPacket::data_into(&mut packet, 7, &first_payload);
    let allocation = packet.as_ptr();
    assert_eq!(&packet[..4], &[0, 3, 0, 7]);
    assert_eq!(&packet[4..], first_payload);

    TftpPacket::data_into(&mut packet, 8, &second_payload);
    assert_eq!(packet.as_ptr(), allocation);
    assert_eq!(&packet[..4], &[0, 3, 0, 8]);
    assert_eq!(&packet[4..], second_payload);
}

#[tokio::test]
async fn cached_data_packet_uses_vectored_wire_format() {
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();

    send_cached_data_packet(&sender, receiver.local_addr().unwrap(), 7, b"cached")
        .await
        .unwrap();

    let mut wire = [0u8; 64];
    let (length, peer) = receiver.recv_from(&mut wire).await.unwrap();
    assert_eq!(peer, sender.local_addr().unwrap());
    assert!(matches!(
        TftpPacket::parse(&wire[..length], peer).unwrap(),
        TftpPacket::Data(packet) if packet.block == 7 && packet.data == b"cached"
    ));

    send_cached_data_packet(&sender, receiver.local_addr().unwrap(), 8, b"")
        .await
        .unwrap();
    let (length, peer) = receiver.recv_from(&mut wire).await.unwrap();
    assert!(matches!(
        TftpPacket::parse(&wire[..length], peer).unwrap(),
        TftpPacket::Data(packet) if packet.block == 8 && packet.data.is_empty()
    ));
}

#[tokio::test]
async fn scheduler_send_error_increments_only_its_extension_failure_counter() {
    let sender = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let metrics = ServerMetrics::new(Arc::new(AtomicUsize::new(0)));
    let scheduler = FailingPacketScheduler;

    let result = send_data_packet(
        &sender,
        Some(&scheduler),
        &metrics,
        uuid::Uuid::new_v4(),
        receiver.local_addr().unwrap(),
        BytesMut::from(&b"packet"[..]),
    )
    .await;

    assert!(result.is_err());
    let failures = metrics.extension_failure_snapshot();
    assert!(failures.contains(&("scheduler", "send_packet", 1)));
    assert!(
        failures
            .iter()
            .filter(|(_, operation, _)| *operation != "send_packet")
            .all(|(_, _, count)| *count == 0)
    );
}

#[tokio::test]
async fn opted_in_windows_recover_loss_and_reject_wrong_tids() {
    async fn receive_range(
        client: &UdpSocket,
        peer: SocketAddr,
        bytes: &[u8],
        blocks: std::ops::RangeInclusive<u16>,
    ) {
        for block in blocks {
            let TftpPacket::Data(packet) = transfer_deadline_receive(client, peer).await else {
                panic!("expected ordinary DATA");
            };
            let offset = (usize::from(block) - 1) * 512;
            assert_eq!(packet.block, block);
            assert_eq!(packet.data, bytes[offset..(offset + 512).min(bytes.len())]);
        }
    }

    // Each case waits for two real RTOs; run them concurrently.
    async fn run_case(memory: bool, tail: usize) {
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let peer = server.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bytes = Bytes::from(
            (0..10 * 512 + tail)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>(),
        );
        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(&bytes).unwrap();
        let input = if memory {
            CoreReadSource::Memory(Arc::new(bytes.clone()))
        } else {
            CoreReadSource::File(File::open(source.path()).await.unwrap())
        };
        let mut file = ArtifactReader::new(input, bytes.len() as u64, 512, true, 8);
        let mut config = crate::config::TempestConfig::default();
        config.server.udp_segmentation_offload = true;
        let state = crate::server::TftpServer::new(config).state();
        state.active_transfers.store(8, Ordering::Release);
        let scheduler = SchedulerTransferGuard {
            scheduler: None,
            transfer_id: TransferId::nil(),
        };
        let options = NegotiatedOptions {
            window_size: 8,
            // Exact retransmission counts need an RTO far above scheduling jitter.
            retransmission_policy: RetransmissionPolicy::fixed(Duration::from_secs(3)),
            ..Default::default()
        };
        let mut protocol = None;
        let mut pacing = None;
        let mut metrics = TransferMetrics::default();
        let transfer = run_read_data_loop(
            ReadDataLoop {
                socket: &server,
                client_addr: client.local_addr().unwrap(),
                transfer_id: TransferId::nil(),
                state: &state,
                scheduler: &scheduler,
                shared_blocks: None,
                options: &options,
                core_payload_size: 512,
                fallback_pacing_delay: None,
            },
            &mut file,
            &mut protocol,
            &mut pacing,
            &mut metrics,
        );
        let receive = async {
            receive_range(&client, peer, &bytes, 1..=8).await;
            let wrong_port = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            wrong_port.send_to(&TftpPacket::ack(8), peer).await.unwrap();
            assert!(matches!(
                transfer_deadline_receive(&wrong_port, peer).await,
                TftpPacket::Error(packet) if packet.code == TftpErrorCode::UnknownTransferId as u16
            ));
            #[cfg(target_os = "linux")]
            {
                let wrong_ip = UdpSocket::bind((
                    std::net::Ipv4Addr::new(127, 0, 0, 2),
                    client.local_addr().unwrap().port(),
                ))
                .await
                .unwrap();
                wrong_ip.send_to(&TftpPacket::ack(8), peer).await.unwrap();
                assert!(matches!(
                    transfer_deadline_receive(&wrong_ip, peer).await,
                    TftpPacket::Error(packet) if packet.code == TftpErrorCode::UnknownTransferId as u16
                ));
            }
            receive_range(&client, peer, &bytes, 1..=8).await;
            client.send_to(&TftpPacket::ack(8), peer).await.unwrap();
            receive_range(&client, peer, &bytes, 9..=11).await;
            for packet in [
                TftpPacket::ack(9),
                TftpPacket::ack(9),
                BytesMut::from(&b"\0\x04\0"[..]),
            ] {
                client.send_to(&packet, peer).await.unwrap();
            }
            assert!(
                tokio::time::timeout(Duration::from_millis(20), client.recv_from(&mut [0; 2048]))
                    .await
                    .is_err()
            );
            receive_range(&client, peer, &bytes, 10..=11).await;
            client.send_to(&TftpPacket::ack(11), peer).await.unwrap();
        };
        tokio::time::timeout(Duration::from_secs(30), async {
            let (result, ()) = tokio::join!(transfer, receive);
            result.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(metrics.retransmissions, 2);
        assert_eq!(metrics.blocks_sent, 21);
        assert_eq!(metrics.bytes_sent, (19 * 512 + 2 * tail) as u64);
        assert!(server.peer_addr().is_err());
    }

    tokio::join!(
        run_case(false, 0),
        run_case(false, 17),
        run_case(true, 0),
        run_case(true, 17)
    );
}

#[tokio::test]
async fn cached_data_window_preserves_datagram_boundaries_and_order() {
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let artifact = Bytes::from_static(b"abcdefghijkl");
    let packets = [
        WindowDataPacket::new(41, 0..4),
        WindowDataPacket::new(42, 4..8),
        WindowDataPacket::new(43, 8..12),
    ];

    send_data_window(
        &sender,
        receiver.local_addr().unwrap(),
        &artifact,
        &packets,
        None,
        &mut DataWindowSendState::default(),
    )
    .await
    .unwrap();

    let mut wire = [0u8; 64];
    for (block, expected) in [(41, b"abcd"), (42, b"efgh"), (43, b"ijkl")] {
        let (length, peer) = receiver.recv_from(&mut wire).await.unwrap();
        assert!(matches!(
            TftpPacket::parse(&wire[..length], peer).unwrap(),
            TftpPacket::Data(packet)
                if packet.block == block && packet.data == expected
        ));
    }
}

#[test]
fn governed_window_groups_never_exceed_the_burst_cap() {
    let packets = [
        WindowDataPacket::new(1, 0..4),
        WindowDataPacket::new(2, 4..8),
        WindowDataPacket::new(3, 8..12),
    ];

    assert_eq!(governed_batch_len(&packets, 24), 3);
    assert_eq!(governed_batch_len(&packets, 16), 2);
    // A single datagram remains atomic even when its wire size exceeds the cap.
    assert_eq!(governed_batch_len(&packets, 7), 1);
}

#[tokio::test]
async fn governed_data_window_charges_exact_wire_bytes() {
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let artifact = Bytes::from_static(b"abcdefghijkl");
    let packets = [
        WindowDataPacket::new(41, 0..4),
        WindowDataPacket::new(42, 4..8),
        WindowDataPacket::new(43, 8..12),
    ];
    let governor = crate::features::bandwidth_governor::BandwidthGovernor::new(1_000, true);
    let initial_tokens = governor.available_tokens();

    send_data_window(
        &sender,
        receiver.local_addr().unwrap(),
        &artifact,
        &packets,
        Some(&governor),
        &mut DataWindowSendState::default(),
    )
    .await
    .unwrap();

    assert_eq!(governor.available_tokens(), initial_tokens - 24);
    let mut wire = [0u8; 64];
    for (block, expected) in [(41, b"abcd"), (42, b"efgh"), (43, b"ijkl")] {
        let (length, peer) = receiver.recv_from(&mut wire).await.unwrap();
        assert!(matches!(
            TftpPacket::parse(&wire[..length], peer).unwrap(),
            TftpPacket::Data(packet)
                if packet.block == block && packet.data == expected
        ));
    }
}

#[test]
fn data_window_description_preserves_eof_and_wire_rollover() {
    let mut packets = Vec::new();

    assert!(describe_data_window(&mut packets, u16::MAX, 10, 4, 8, true));
    assert_eq!(packets.len(), 3);
    assert_eq!(packets[0].payload, 0..4);
    assert_eq!(packets[1].payload, 4..8);
    assert_eq!(packets[2].payload, 8..10);
    assert_eq!(&packets[0].header[2..], &u16::MAX.to_be_bytes());
    assert_eq!(&packets[1].header[2..], &0u16.to_be_bytes());
    assert_eq!(&packets[2].header[2..], &1u16.to_be_bytes());

    assert!(describe_data_window(&mut packets, 7, 8, 4, 8, true));
    assert_eq!(packets.len(), 3);
    assert_eq!(packets[2].payload, 8..8);

    assert!(!describe_data_window(&mut packets, 11, 8, 4, 2, false));
    assert_eq!(packets.len(), 2);
    assert_eq!(packets[1].payload, 4..8);
}

#[tokio::test]
async fn file_backed_window_batches_payload_and_empty_final_packet() {
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut source = tempfile::NamedTempFile::new().unwrap();
    source.write_all(b"abcdefgh").unwrap();
    let file = File::open(source.path()).await.unwrap();
    let mut file = ArtifactReader::File(BufferedArtifactReader::new(file, 8, 4, true, 1));
    let mut file_buffer = Vec::new();
    let mut packets = Vec::new();

    let sent = send_standard_data_window(
        StandardWindowExchange {
            socket: &sender,
            client_addr: receiver.local_addr().unwrap(),
            payload_size: 4,
            file: &mut file,
            retained_artifact: None,
            file_buffer: &mut file_buffer,
            packets: &mut packets,
            governor: None,
            send_state: &mut DataWindowSendState::default(),
        },
        1,
        7,
        8,
    )
    .await
    .unwrap();

    assert!(sent.transfer_complete);
    assert_eq!(sent.blocks, 3);
    assert_eq!(sent.payload_bytes, 8);
    let mut wire = [0u8; 64];
    for (block, expected) in [(7, &b"abcd"[..]), (8, &b"efgh"[..]), (9, &b""[..])] {
        let (length, peer) = receiver.recv_from(&mut wire).await.unwrap();
        assert!(matches!(
            TftpPacket::parse(&wire[..length], peer).unwrap(),
            TftpPacket::Data(packet)
                if packet.block == block && packet.data == expected
        ));
    }
}

#[test]
fn memory_artifact_blocks_borrow_retained_bytes() {
    let retained = Arc::new(Bytes::from_static(b"0123456789"));
    let expected = retained[3..7].as_ptr();
    let mut reader = MemoryArtifactReader {
        bytes: retained,
        position: 0,
    };

    let block = reader.block_slice(3, 4);

    assert_eq!(block, b"3456");
    assert_eq!(block.as_ptr(), expected);
    assert_eq!(reader.position, 7);
}

#[tokio::test]
async fn test_buffered_artifact_reader_preserves_bytes_with_bounded_reads() {
    let data: Vec<u8> = (0..1024 * 1024).map(|index| (index % 251) as u8).collect();
    let expected = data.clone();
    let read_calls = Arc::new(AtomicUsize::new(0));
    let source = CountingReader {
        inner: Cursor::new(data),
        read_calls: read_calls.clone(),
    };
    let mut reader = BufferedArtifactReader::new(source, expected.len() as u64, 1468, true, 1);
    let mut block = vec![0; 1468];
    let mut output = Vec::with_capacity(expected.len());
    let mut offset = 0;

    loop {
        let bytes_read = reader.read_block(offset, &mut block).await.unwrap();
        output.extend_from_slice(&block[..bytes_read]);
        if bytes_read < block.len() {
            break;
        }
        offset += bytes_read as u64;
    }

    assert_eq!(output.len(), expected.len());
    assert!(output.iter().eq(expected.iter()));
    assert_eq!(read_calls.load(Ordering::Relaxed), 9);
}

#[tokio::test]
async fn test_buffered_artifact_reader_rewinds_after_retransmission() {
    let data: Vec<u8> = (0..128 * 1024).map(|index| (index % 239) as u8).collect();
    let read_calls = Arc::new(AtomicUsize::new(0));
    let source = CountingReader {
        inner: Cursor::new(data),
        read_calls: read_calls.clone(),
    };
    let mut reader = BufferedArtifactReader::new(source, 128 * 1024, 1468, true, 1);
    let mut first = vec![0; 1468];
    let mut replay = vec![0; 1468];

    assert_eq!(reader.read_block(0, &mut first).await.unwrap(), first.len());
    assert_eq!(read_calls.load(Ordering::Relaxed), 1);

    reader.seek_to(0).await.unwrap();
    assert_eq!(
        reader.read_block(0, &mut replay).await.unwrap(),
        replay.len()
    );
    assert_eq!(replay, first);
    assert_eq!(read_calls.load(Ordering::Relaxed), 2);
}

#[test]
fn test_normalize_rejects_parent_traversal() {
    let root = PathBuf::from("/tftpboot");
    assert!(normalize_path_secure(&root, "../etc/passwd").is_err());
}

#[test]
fn test_normalize_rejects_deep_traversal() {
    let root = PathBuf::from("/tftpboot");
    assert!(normalize_path_secure(&root, "subdir/../../etc/shadow").is_err());
}

#[test]
fn test_normalize_rejects_absolute_path() {
    let root = PathBuf::from("/tftpboot");
    assert!(normalize_path_secure(&root, "/etc/passwd").is_err());
}

#[test]
fn test_normalize_rejects_empty() {
    let root = PathBuf::from("/tftpboot");
    assert!(normalize_path_secure(&root, "").is_err());
}

#[test]
fn test_normalize_allows_simple_filename() {
    let root = PathBuf::from("/tftpboot");
    let result = normalize_path_secure(&root, "vmlinuz").unwrap();
    assert_eq!(result, PathBuf::from("/tftpboot/vmlinuz"));
}

#[test]
fn test_normalize_allows_subdirectory() {
    let root = PathBuf::from("/tftpboot");
    let result = normalize_path_secure(&root, "images/ubuntu/kernel").unwrap();
    assert_eq!(result, PathBuf::from("/tftpboot/images/ubuntu/kernel"));
}

#[test]
fn test_normalize_skips_current_dir() {
    let root = PathBuf::from("/tftpboot");
    let result = normalize_path_secure(&root, "./vmlinuz").unwrap();
    assert_eq!(result, PathBuf::from("/tftpboot/vmlinuz"));
}

#[test]
fn test_transfer_metrics_throughput() {
    let start_time = Instant::now();
    let m = TransferMetrics {
        start_time: Some(start_time),
        end_time: Some(start_time + Duration::from_secs(1)),
        bytes_sent: 1_000_000,
        ..Default::default()
    };
    let bps = m.throughput_bps().unwrap();
    assert!((bps - 8_000_000.0).abs() < 100.0);
}

#[test]
fn test_transfer_metrics_zero_duration() {
    let mut m = TransferMetrics::default();
    let now = Instant::now();
    m.start_time = Some(now);
    m.end_time = Some(now);
    m.bytes_sent = 100;
    let bps = m.throughput_bps().unwrap();
    assert_eq!(bps, 0.0);
}

#[test]
fn test_supported_transfer_mode_is_octet_only() {
    assert!(supported_transfer_mode(TransferMode::Octet));
    assert!(!supported_transfer_mode(TransferMode::Netascii));
}

#[tokio::test]
async fn test_recv_from_transfer_peer_replies_unknown_tid() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let good_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let wrong_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let good_addr = good_client.local_addr().unwrap();
    let mut unknown_tid_responder = UnknownTidResponder::default();

    wrong_client
        .send_to(&TftpPacket::ack(1), server_addr)
        .await
        .unwrap();
    good_client
        .send_to(&TftpPacket::ack(0), server_addr)
        .await
        .unwrap();

    let mut recv_buf = [0u8; 64];
    let mut err_buf = [0u8; 64];
    let ((len, _), (err_len, _)) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(
            async {
                let len = recv_from_transfer_peer(
                    &server,
                    good_addr,
                    &mut recv_buf,
                    &mut unknown_tid_responder,
                )
                .await
                .unwrap();
                (len, ())
            },
            async {
                let (len, peer) = wrong_client.recv_from(&mut err_buf).await.unwrap();
                (len, peer)
            }
        )
    })
    .await
    .unwrap();

    assert!(matches!(
        TftpPacket::parse(&recv_buf[..len], good_addr).unwrap(),
        TftpPacket::Ack(ack) if ack.block == 0
    ));
    assert!(matches!(
        TftpPacket::parse(&err_buf[..err_len], good_addr).unwrap(),
        TftpPacket::Error(err) if err.code == u16::from(TftpErrorCode::UnknownTransferId)
    ));
}

#[tokio::test]
async fn unknown_tid_responses_stop_at_the_exchange_budget() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let good_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let wrong_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let good_addr = good_client.local_addr().unwrap();

    for _ in 0..usize::from(MAX_UNKNOWN_TID_RESPONSES_PER_EXCHANGE) + 2 {
        wrong_client
            .send_to(&TftpPacket::ack(1), server_addr)
            .await
            .unwrap();
    }
    good_client
        .send_to(&TftpPacket::ack(0), server_addr)
        .await
        .unwrap();

    let mut responder = UnknownTidResponder::default();
    let mut recv_buf = [0u8; 64];
    let len = tokio::time::timeout(
        Duration::from_secs(30),
        recv_from_transfer_peer(&server, good_addr, &mut recv_buf, &mut responder),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(matches!(
        TftpPacket::parse(&recv_buf[..len], good_addr).unwrap(),
        TftpPacket::Ack(ack) if ack.block == 0
    ));
    assert_eq!(responder.responses_remaining, 0);

    let mut err_buf = [0u8; 64];
    for _ in 0..MAX_UNKNOWN_TID_RESPONSES_PER_EXCHANGE {
        let (err_len, peer) = tokio::time::timeout(
            Duration::from_secs(30),
            wrong_client.recv_from(&mut err_buf),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(peer, server_addr);
        assert!(matches!(
            TftpPacket::parse(&err_buf[..err_len], peer).unwrap(),
            TftpPacket::Error(err)
                if err.code == u16::from(TftpErrorCode::UnknownTransferId)
        ));
    }
    assert!(
        tokio::time::timeout(
            Duration::from_millis(50),
            wrong_client.recv_from(&mut err_buf),
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn closed_unknown_tid_peer_does_not_abort_the_transfer_receive() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let good_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let good_addr = good_client.local_addr().unwrap();
    {
        let stray = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        stray
            .send_to(&TftpPacket::ack(1), server_addr)
            .await
            .unwrap();
    }
    good_client
        .send_to(&TftpPacket::ack(0), server_addr)
        .await
        .unwrap();

    // The unknown-TID ERROR goes to the closed stray port. On Windows the
    // resulting ICMP surfaces as ConnectionReset on the next receive.
    let mut responder = UnknownTidResponder::default();
    let mut buffer = [0u8; 64];
    let len = tokio::time::timeout(
        Duration::from_secs(30),
        recv_from_transfer_peer(&server, good_addr, &mut buffer, &mut responder),
    )
    .await
    .unwrap()
    .expect("a reset from a closed foreign port must not abort the transfer");
    assert!(matches!(
        TftpPacket::parse(&buffer[..len], good_addr).unwrap(),
        TftpPacket::Ack(ack) if ack.block == 0
    ));
    assert_eq!(
        responder.responses_remaining,
        MAX_UNKNOWN_TID_RESPONSES_PER_EXCHANGE - 1
    );
}

#[test]
fn ack_spin_is_limited_to_an_idle_linux_server_and_stops_after_misses() {
    let mut spin = AckSpin::default();
    assert_eq!(spin.when_idle(0).is_some(), cfg!(target_os = "linux"));
    assert_eq!(spin.when_idle(1).is_some(), cfg!(target_os = "linux"));
    assert!(spin.when_idle(2).is_none());
    assert!(spin.when_idle(usize::MAX).is_none());

    spin.consecutive_misses = AckSpin::MAX_CONSECUTIVE_MISSES - 1;
    assert_eq!(spin.when_idle(1).is_some(), cfg!(target_os = "linux"));
    spin.consecutive_misses = AckSpin::MAX_CONSECUTIVE_MISSES;
    assert!(spin.when_idle(0).is_none());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn ack_spin_consumes_only_a_pending_datagram_from_the_peer() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let client_addr = client.local_addr().unwrap();
    let mut buffer = [0u8; 64];

    let started = Instant::now();
    assert_eq!(
        spin_for_peer_datagram(&server, client_addr, &mut buffer, Duration::from_millis(5)),
        None
    );
    assert!(started.elapsed() < Duration::from_secs(5));

    client
        .send_to(&TftpPacket::ack(7), server_addr)
        .await
        .unwrap();
    let length = spin_for_peer_datagram(
        &server,
        client_addr,
        &mut buffer,
        Duration::from_millis(500),
    )
    .unwrap();
    assert!(matches!(
        TftpPacket::parse(&buffer[..length], client_addr).unwrap(),
        TftpPacket::Ack(ack) if ack.block == 7
    ));
    assert_eq!(
        spin_for_peer_datagram(&server, client_addr, &mut buffer, Duration::from_millis(5)),
        None
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn ack_spin_leaves_foreign_tids_for_the_unknown_tid_responder() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let foreign = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let client_addr = client.local_addr().unwrap();
    let mut buffer = [0u8; 64];

    foreign
        .send_to(&TftpPacket::ack(1), server_addr)
        .await
        .unwrap();
    client
        .send_to(&TftpPacket::ack(2), server_addr)
        .await
        .unwrap();
    assert_eq!(
        spin_for_peer_datagram(&server, client_addr, &mut buffer, Duration::from_millis(50)),
        None
    );

    let mut responder = UnknownTidResponder::default();
    let length = recv_from_transfer_peer(&server, client_addr, &mut buffer, &mut responder)
        .await
        .unwrap();
    assert!(matches!(
        TftpPacket::parse(&buffer[..length], client_addr).unwrap(),
        TftpPacket::Ack(ack) if ack.block == 2
    ));
    assert_eq!(responder.responses_remaining, 3);
    let mut reply = [0u8; 64];
    let (length, peer) =
        tokio::time::timeout(Duration::from_secs(30), foreign.recv_from(&mut reply))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(peer, server_addr);
    assert!(matches!(
        TftpPacket::parse(&reply[..length], peer).unwrap(),
        TftpPacket::Error(error) if error.code == u16::from(TftpErrorCode::UnknownTransferId)
    ));
}

#[tokio::test]
async fn ack_spin_acknowledges_a_pending_window_and_falls_back_when_empty() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let source = tempfile::NamedTempFile::new().unwrap();
    let file = File::open(source.path()).await.unwrap();
    let mut file = ArtifactReader::File(BufferedArtifactReader::new(file, 0, 512, true, 1));
    let mut protocol_session: Option<Box<dyn ReadProtocolSession>> = None;
    let mut pacing_session: Option<Box<dyn TransferPacingSession>> = None;
    let mut metrics = TransferMetrics::default();
    let mut unknown_tid_responder = UnknownTidResponder::default();
    // await_read_ack checks its deadline before the socket, and a queued ACK
    // still needs a reactor readiness round trip; keep that step's RTO long.
    let mut window = WindowState::new(1, Duration::from_secs(10), 1);
    let mut spin = AckSpin::default();
    let deadline = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(deadline);

    window.block_sent();
    client
        .send_to(&TftpPacket::ack(1), server.local_addr().unwrap())
        .await
        .unwrap();
    let acknowledged = await_read_ack(
        ReadAcknowledgment {
            socket: &server,
            client_addr,
            transfer_id: TransferId::nil(),
            ack_spin: Some(&mut spin),
            core_payload_size: 512,
            file: &mut file,
            protocol_session: &mut protocol_session,
            pacing_session: &mut pacing_session,
            metrics: &mut metrics,
            unknown_tid_responder: &mut unknown_tid_responder,
        },
        &mut window,
        false,
        deadline.as_mut(),
    )
    .await
    .unwrap();
    assert_eq!(acknowledged, ReadAckAction::Continue);
    assert_eq!(window.window_start(), 2);
    #[cfg(target_os = "linux")]
    assert_eq!(spin.consecutive_misses, 0);

    // Only the empty-socket step needs a short timer.
    let mut window = WindowState::new(1, Duration::from_millis(30), 1);
    window.block_sent();
    let timed_out = await_read_ack(
        ReadAcknowledgment {
            socket: &server,
            client_addr,
            transfer_id: TransferId::nil(),
            ack_spin: Some(&mut spin),
            core_payload_size: 512,
            file: &mut file,
            protocol_session: &mut protocol_session,
            pacing_session: &mut pacing_session,
            metrics: &mut metrics,
            unknown_tid_responder: &mut unknown_tid_responder,
        },
        &mut window,
        false,
        deadline.as_mut(),
    )
    .await
    .unwrap();
    assert_eq!(timed_out, ReadAckAction::Retransmit);
    assert_eq!(metrics.retransmissions, 1);
    #[cfg(target_os = "linux")]
    assert_eq!(spin.consecutive_misses, 1);
}

#[tokio::test]
async fn test_duplicate_ack_is_not_a_retransmission_event() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let source = tempfile::NamedTempFile::new().unwrap();
    let file = File::open(source.path()).await.unwrap();
    let mut file = ArtifactReader::File(BufferedArtifactReader::new(file, 0, 512, true, 1));
    let retransmission_callbacks = Arc::new(AtomicU64::new(0));
    let mut protocol_session: Option<Box<dyn ReadProtocolSession>> =
        Some(Box::new(RetransmissionProbe {
            count: retransmission_callbacks.clone(),
        }));
    let mut pacing_session: Option<Box<dyn TransferPacingSession>> = None;
    let mut metrics = TransferMetrics::default();
    let mut unknown_tid_responder = UnknownTidResponder::default();
    // The deadline is polled before the socket; it must not beat queued ACKs.
    let mut window = WindowState::new(1, Duration::from_secs(10), 1);
    window.block_sent();

    client
        .send_to(&TftpPacket::ack(0), server.local_addr().unwrap())
        .await
        .unwrap();
    client
        .send_to(&TftpPacket::ack(1), server.local_addr().unwrap())
        .await
        .unwrap();
    let deadline = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(deadline);
    let action = await_read_ack(
        ReadAcknowledgment {
            socket: &server,
            client_addr,
            transfer_id: TransferId::nil(),
            ack_spin: None,
            core_payload_size: 512,
            file: &mut file,
            protocol_session: &mut protocol_session,
            pacing_session: &mut pacing_session,
            metrics: &mut metrics,
            unknown_tid_responder: &mut unknown_tid_responder,
        },
        &mut window,
        false,
        deadline.as_mut(),
    )
    .await
    .unwrap();

    assert_eq!(action, ReadAckAction::Continue);
    assert_eq!(metrics.retransmissions, 0);
    assert_eq!(retransmission_callbacks.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn test_timeout_records_one_retransmission_event() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let source = tempfile::NamedTempFile::new().unwrap();
    let file = File::open(source.path()).await.unwrap();
    let mut file = ArtifactReader::File(BufferedArtifactReader::new(file, 0, 512, true, 1));
    let retransmission_callbacks = Arc::new(AtomicU64::new(0));
    let mut protocol_session: Option<Box<dyn ReadProtocolSession>> =
        Some(Box::new(RetransmissionProbe {
            count: retransmission_callbacks.clone(),
        }));
    let mut pacing_session: Option<Box<dyn TransferPacingSession>> = None;
    let mut metrics = TransferMetrics::default();
    let mut unknown_tid_responder = UnknownTidResponder::default();
    let mut window = WindowState::new(1, Duration::from_millis(20), 1);
    window.block_sent();

    let deadline = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(deadline);
    let action = await_read_ack(
        ReadAcknowledgment {
            socket: &server,
            client_addr: client.local_addr().unwrap(),
            transfer_id: TransferId::nil(),
            ack_spin: None,
            core_payload_size: 512,
            file: &mut file,
            protocol_session: &mut protocol_session,
            pacing_session: &mut pacing_session,
            metrics: &mut metrics,
            unknown_tid_responder: &mut unknown_tid_responder,
        },
        &mut window,
        false,
        deadline.as_mut(),
    )
    .await
    .unwrap();

    assert_eq!(action, ReadAckAction::Retransmit);
    assert_eq!(metrics.retransmissions, 1);
    assert_eq!(retransmission_callbacks.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn final_window_requires_the_last_cumulative_ack() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let source = tempfile::NamedTempFile::new().unwrap();
    let file = File::open(source.path()).await.unwrap();
    let mut file = ArtifactReader::File(BufferedArtifactReader::new(file, 0, 512, true, 1));
    let mut protocol_session: Option<Box<dyn ReadProtocolSession>> = None;
    let mut pacing_session: Option<Box<dyn TransferPacingSession>> = None;
    let mut metrics = TransferMetrics::default();
    let mut unknown_tid_responder = UnknownTidResponder::default();
    // The deadline is polled before the socket; it must not beat queued ACKs.
    let mut window = WindowState::new(2, Duration::from_secs(10), 1);
    window.block_sent();
    window.block_sent();
    let deadline = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(deadline);

    client
        .send_to(&TftpPacket::ack(1), server.local_addr().unwrap())
        .await
        .unwrap();
    let partial = await_read_ack(
        ReadAcknowledgment {
            socket: &server,
            client_addr,
            transfer_id: TransferId::nil(),
            ack_spin: None,
            core_payload_size: 512,
            file: &mut file,
            protocol_session: &mut protocol_session,
            pacing_session: &mut pacing_session,
            metrics: &mut metrics,
            unknown_tid_responder: &mut unknown_tid_responder,
        },
        &mut window,
        true,
        deadline.as_mut(),
    )
    .await
    .unwrap();
    assert_eq!(partial, ReadAckAction::Continue);

    client
        .send_to(&TftpPacket::ack(2), server.local_addr().unwrap())
        .await
        .unwrap();
    let final_ack = await_read_ack(
        ReadAcknowledgment {
            socket: &server,
            client_addr,
            transfer_id: TransferId::nil(),
            ack_spin: None,
            core_payload_size: 512,
            file: &mut file,
            protocol_session: &mut protocol_session,
            pacing_session: &mut pacing_session,
            metrics: &mut metrics,
            unknown_tid_responder: &mut unknown_tid_responder,
        },
        &mut window,
        true,
        deadline.as_mut(),
    )
    .await
    .unwrap();
    assert_eq!(final_ack, ReadAckAction::Complete);
}

fn oack_test_options(max_retries: u8) -> NegotiatedOptions {
    NegotiatedOptions {
        // Long enough that a delayed client cannot exhaust retries it does not intend to.
        retransmission_policy: RetransmissionPolicy::fixed(Duration::from_secs(3)),
        max_retries,
        ..NegotiatedOptions::default()
    }
}

async fn receive_oack(socket: &UdpSocket) -> SocketAddr {
    let mut buffer = [0u8; 512];
    let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
    assert!(matches!(
        TftpPacket::parse(&buffer[..length], peer).unwrap(),
        TftpPacket::Oack(_)
    ));
    peer
}

#[tokio::test]
async fn test_oack_retries_from_same_transfer_socket() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let options = oack_test_options(2);
    let oack_options = vec![("blksize".into(), "1468".into())];
    let oack_packet = TftpPacket::oack(&oack_options);

    let exchange = exchange_oack(
        &server,
        client_addr,
        &options,
        Some(&oack_packet),
        TransferId::nil(),
        None,
    );
    let client_flow = async {
        let first_peer = receive_oack(&client).await;
        // Simulate a lost ACK(0); the next OACK must retain the transfer TID.
        let retry_peer = receive_oack(&client).await;
        assert_eq!(retry_peer, first_peer);
        client
            .send_to(&TftpPacket::ack(0), retry_peer)
            .await
            .unwrap();
    };

    let (result, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(exchange, client_flow)
    })
    .await
    .unwrap();
    result.unwrap();
}

#[tokio::test]
async fn duplicate_request_resends_oack_without_waiting_for_rto() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let mut options = oack_test_options(2);
    options.retransmission_policy = RetransmissionPolicy::fixed(Duration::from_secs(60));
    let oack_options = vec![("blksize".into(), "1468".into())];
    let oack_packet = TftpPacket::oack(&oack_options);
    let duplicate_request = tokio::sync::Notify::new();

    let exchange = exchange_oack(
        &server,
        client_addr,
        &options,
        Some(&oack_packet),
        TransferId::nil(),
        Some(&duplicate_request),
    );
    let client_flow = async {
        let peer = receive_oack(&client).await;
        duplicate_request.notify_one();
        // Far below the 60s RTO, so only the duplicate can explain the resend.
        let retry_peer = tokio::time::timeout(Duration::from_secs(10), receive_oack(&client))
            .await
            .expect("duplicate RRQ should trigger immediate OACK resend");
        assert_eq!(retry_peer, peer);
        client
            .send_to(&TftpPacket::ack(0), retry_peer)
            .await
            .unwrap();
    };

    let (result, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(exchange, client_flow)
    })
    .await
    .unwrap();
    result.unwrap();
}

/// Repeated RRQs without ACK(0) must not keep an option handshake alive: each
/// duplicate-triggered resend consumes the same budget as a timer retry.
#[tokio::test]
async fn duplicate_rrq_retries_count_against_oack_budget() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let mut options = oack_test_options(1);
    // Far beyond the test bound: only duplicate-triggered retries can end it.
    options.retransmission_policy = RetransmissionPolicy::fixed(Duration::from_secs(60));
    let oack_options = vec![("blksize".into(), "1468".into())];
    let oack_packet = TftpPacket::oack(&oack_options);
    let duplicate_request = tokio::sync::Notify::new();

    let exchange = exchange_oack(
        &server,
        client_addr,
        &options,
        Some(&oack_packet),
        TransferId::nil(),
        Some(&duplicate_request),
    );
    let client_flow = async {
        let peer = receive_oack(&client).await;

        duplicate_request.notify_one();
        let retry_peer = tokio::time::timeout(Duration::from_secs(10), receive_oack(&client))
            .await
            .expect("duplicate RRQ must trigger an immediate OACK resend");
        assert_eq!(retry_peer, peer);

        duplicate_request.notify_one();
        assert!(
            tokio::time::timeout(Duration::from_millis(150), receive_oack(&client))
                .await
                .is_err(),
            "duplicate RRQ retries must exhaust the configured OACK budget"
        );
    };

    let (result, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(exchange, client_flow)
    })
    .await
    .unwrap();
    assert!(matches!(
        result,
        Err(TempestError::Protocol(ProtocolError::Timeout {
            block: 0,
            ..
        }))
    ));
}

/// Every option-handshake outcome releases the transfer slot and version pin,
/// so an unacknowledged OACK cannot retain capacity after it ends.
#[tokio::test]
async fn oack_handshake_outcomes_always_release_slot_and_pin() {
    for outcome in ["timeout", "ack_after_retry", "client_error", "cancel"] {
        // The absolute deadline is far away, so it cannot end the handshake.
        let fixture = TransferDeadlineReadFixture::new(b"artifact", 60, false);
        let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let options = NegotiatedOptions {
            transfer_size: Some(0),
            ..oack_test_options(1)
        };
        let state = fixture.state.clone();
        let task = tokio::spawn(async move {
            run_read_transfer(
                server,
                client_addr,
                "kernel".into(),
                "default".into(),
                None,
                options,
                vec![("tsize".into(), "0".into())],
                state,
                TransferId::new_v4(),
            )
            .await
        });
        let tid = tokio::time::timeout(Duration::from_secs(30), receive_oack(&client))
            .await
            .expect("tsize negotiation must send an OACK");
        fixture.assert_owned(false);
        match outcome {
            "timeout" => {
                let result = tokio::time::timeout(Duration::from_secs(30), task)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(
                    matches!(
                        result,
                        Err(TempestError::Protocol(ProtocolError::Timeout {
                            block: 0,
                            ..
                        }))
                    ),
                    "retry exhaustion, not the absolute deadline, must end the handshake"
                );
            }
            "ack_after_retry" => {
                let retry_tid =
                    tokio::time::timeout(Duration::from_secs(30), receive_oack(&client))
                        .await
                        .unwrap();
                assert_eq!(tid, retry_tid);
                client.send_to(&TftpPacket::ack(0), tid).await.unwrap();
                let mut buffer = [0; 512];
                let (length, data_tid) =
                    tokio::time::timeout(Duration::from_secs(30), client.recv_from(&mut buffer))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(data_tid, tid);
                assert_eq!(&buffer[..length], b"\x00\x03\x00\x01artifact");
                client.send_to(&TftpPacket::ack(1), tid).await.unwrap();
                tokio::time::timeout(Duration::from_secs(30), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap();
            }
            "client_error" => {
                client
                    .send_to(&TftpPacket::error(TftpErrorCode::NotDefined, "cancel"), tid)
                    .await
                    .unwrap();
                assert!(
                    tokio::time::timeout(Duration::from_secs(30), task)
                        .await
                        .unwrap()
                        .unwrap()
                        .is_err()
                );
            }
            "cancel" => {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            }
            _ => unreachable!(),
        }
        fixture.assert_released(false);
    }
}

#[tokio::test]
async fn wrq_retries_preserve_oack_and_duplicate_signal() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = crate::config::TempestConfig::default();
    config.server.root = directory.path().to_path_buf();
    config.server.write_enabled = true;
    config.server.write_require_session = false;
    let state = crate::server::TftpServer::new(config).state();
    state.active_transfers.fetch_add(1, Ordering::Release);

    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let duplicate_request = tokio::sync::Notify::new();
    let mut options = NegotiatedOptions {
        block_size: 1024,
        max_retries: 2,
        ..NegotiatedOptions::default()
    };
    // The client must act within one RTO after each resend; keep that far above jitter.
    options.retransmission_policy = RetransmissionPolicy::fixed(Duration::from_secs(6));

    let transfer = run_write_transfer_with_duplicate_request(
        server,
        client_addr,
        "upload.bin".to_owned(),
        "test".to_owned(),
        options,
        state.clone(),
        TransferId::nil(),
        Some(&duplicate_request),
    );
    let client_flow = async {
        let peer = receive_oack(&client).await;
        let retry_peer = tokio::time::timeout(Duration::from_secs(30), receive_oack(&client))
            .await
            .expect("WRQ timeout must repeat the negotiated OACK");
        assert_eq!(retry_peer, peer);

        duplicate_request.notify_one();
        // Below the 6s RTO, so only the duplicate can explain the resend.
        let duplicate_peer = tokio::time::timeout(Duration::from_secs(5), receive_oack(&client))
            .await
            .expect("duplicate WRQ must trigger an immediate OACK resend");
        assert_eq!(duplicate_peer, peer);

        client
            .send_to(&TftpPacket::data(1, b"done"), peer)
            .await
            .unwrap();
        let mut buffer = [0u8; 64];
        let (length, response_peer) = client.recv_from(&mut buffer).await.unwrap();
        assert_eq!(response_peer, peer);
        assert!(matches!(
            TftpPacket::parse(&buffer[..length], response_peer).unwrap(),
            TftpPacket::Ack(ack) if ack.block == 1
        ));
    };

    let (result, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(transfer, client_flow)
    })
    .await
    .unwrap();
    let metrics = result.unwrap();
    assert_eq!(metrics.bytes_sent, 4);
    assert_eq!(metrics.retransmissions, 2);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
    assert_eq!(
        std::fs::read(directory.path().join("upload.bin")).unwrap(),
        b"done"
    );
}

#[tokio::test]
async fn wrq_reacknowledges_duplicate_final_data_after_publish() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = crate::config::TempestConfig::default();
    config.server.root = directory.path().to_path_buf();
    config.server.write_enabled = true;
    config.server.write_require_session = false;
    let state = crate::server::TftpServer::new(config).state();
    state.active_transfers.fetch_add(1, Ordering::Release);

    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let options = NegotiatedOptions {
        // Dally lasts two RTOs; the duplicate final DATA must arrive within it.
        retransmission_policy: RetransmissionPolicy::fixed(Duration::from_secs(3)),
        max_retries: 1,
        ..NegotiatedOptions::default()
    };

    let transfer = run_write_transfer(
        server,
        client_addr,
        "upload.bin".to_owned(),
        "test".to_owned(),
        options,
        state.clone(),
        TransferId::nil(),
    );
    let client_flow = async {
        let mut buffer = [0u8; 64];
        let (length, peer) = client.recv_from(&mut buffer).await.unwrap();
        assert!(matches!(
            TftpPacket::parse(&buffer[..length], peer).unwrap(),
            TftpPacket::Ack(ack) if ack.block == 0
        ));
        let final_data = TftpPacket::data(1, b"done");
        client.send_to(&final_data, peer).await.unwrap();

        let (length, response_peer) = client.recv_from(&mut buffer).await.unwrap();
        assert_eq!(response_peer, peer);
        assert!(matches!(
            TftpPacket::parse(&buffer[..length], response_peer).unwrap(),
            TftpPacket::Ack(ack) if ack.block == 1
        ));

        // Model a lost final ACK: the writer retransmits its terminal DATA and
        // must receive the same ACK from the established transfer TID.
        client.send_to(&final_data, peer).await.unwrap();
        let (length, response_peer) =
            tokio::time::timeout(Duration::from_secs(30), client.recv_from(&mut buffer))
                .await
                .expect("WRQ receiver must dally and re-ACK duplicate final DATA")
                .unwrap();
        assert_eq!(response_peer, peer);
        assert!(matches!(
            TftpPacket::parse(&buffer[..length], response_peer).unwrap(),
            TftpPacket::Ack(ack) if ack.block == 1
        ));
    };

    let (result, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(transfer, client_flow)
    })
    .await
    .unwrap();
    assert!(result.is_ok());
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
    assert_eq!(
        std::fs::read(directory.path().join("upload.bin")).unwrap(),
        b"done"
    );
}

#[tokio::test]
async fn wrq_publish_failure_releases_active_transfer_slot() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("upload.bin");
    std::fs::write(&destination, b"existing").unwrap();
    let mut config = crate::config::TempestConfig::default();
    config.server.root = directory.path().to_path_buf();
    config.server.write_enabled = true;
    config.server.write_require_session = false;
    config.server.write_allow_overwrite = false;
    let state = crate::server::TftpServer::new(config).state();
    state.active_transfers.fetch_add(1, Ordering::Release);

    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let transfer = run_write_transfer(
        server,
        client_addr,
        "upload.bin".to_owned(),
        "test".to_owned(),
        NegotiatedOptions::default(),
        state.clone(),
        TransferId::nil(),
    );
    let client_flow = async {
        let mut buffer = [0u8; 64];
        let (length, peer) = client.recv_from(&mut buffer).await.unwrap();
        assert!(matches!(
            TftpPacket::parse(&buffer[..length], peer).unwrap(),
            TftpPacket::Ack(ack) if ack.block == 0
        ));
        client
            .send_to(&TftpPacket::data(1, b"replacement"), peer)
            .await
            .unwrap();
    };

    let (result, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(transfer, client_flow)
    })
    .await
    .unwrap();
    assert!(result.is_err());
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
    assert_eq!(std::fs::read(destination).unwrap(), b"existing");
}

#[tokio::test]
async fn wrq_rejects_data_larger_than_the_negotiated_block_size() {
    let directory = tempfile::tempdir().unwrap();
    let mut config = crate::config::TempestConfig::default();
    config.server.root = directory.path().to_path_buf();
    config.server.write_enabled = true;
    config.server.write_require_session = false;
    let state = crate::server::TftpServer::new(config).state();
    state.active_transfers.fetch_add(1, Ordering::Release);

    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let transfer = run_write_transfer(
        server,
        client_addr,
        "upload.bin".to_owned(),
        "test".to_owned(),
        // A late DATA(1) must not be answered by a retransmitted ACK(0).
        NegotiatedOptions {
            retransmission_policy: RetransmissionPolicy::fixed(Duration::from_secs(30)),
            ..NegotiatedOptions::default()
        },
        state.clone(),
        TransferId::nil(),
    );
    let client_flow = async {
        let mut buffer = [0u8; 64];
        let (length, peer) = client.recv_from(&mut buffer).await.unwrap();
        assert!(matches!(
            TftpPacket::parse(&buffer[..length], peer).unwrap(),
            TftpPacket::Ack(ack) if ack.block == 0
        ));
        client
            .send_to(&TftpPacket::data(1, &vec![0; 513]), peer)
            .await
            .unwrap();
        let (length, response_peer) = client.recv_from(&mut buffer).await.unwrap();
        assert_eq!(response_peer, peer);
        assert!(matches!(
            TftpPacket::parse(&buffer[..length], response_peer).unwrap(),
            TftpPacket::Error(error) if error.code == TftpErrorCode::IllegalOperation as u16
        ));
    };

    let (result, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(transfer, client_flow)
    })
    .await
    .unwrap();
    assert!(matches!(
        result,
        Err(TempestError::Protocol(
            ProtocolError::MalformedPacket { .. }
        ))
    ));
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
    assert!(!directory.path().join("upload.bin").exists());
}

#[tokio::test]
async fn test_oack_ignores_non_ack_zero_and_malformed_packets() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let options = oack_test_options(1);
    let oack_options = vec![("windowsize".into(), "8".into())];
    let oack_packet = TftpPacket::oack(&oack_options);

    let exchange = exchange_oack(
        &server,
        client_addr,
        &options,
        Some(&oack_packet),
        TransferId::nil(),
        None,
    );
    let client_flow = async {
        let peer = receive_oack(&client).await;
        client.send_to(&TftpPacket::ack(1), peer).await.unwrap();
        client.send_to(&[0], peer).await.unwrap();

        let retry_peer = receive_oack(&client).await;
        assert_eq!(retry_peer, peer);
        client
            .send_to(&TftpPacket::ack(0), retry_peer)
            .await
            .unwrap();
    };

    let (result, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(exchange, client_flow)
    })
    .await
    .unwrap();
    result.unwrap();
}

#[tokio::test]
async fn test_oack_exhausts_configured_retry_budget() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();
    let options = oack_test_options(2);
    let oack_options = vec![("blksize".into(), "1468".into())];
    let oack_packet = TftpPacket::oack(&oack_options);

    let exchange = exchange_oack(
        &server,
        client_addr,
        &options,
        Some(&oack_packet),
        TransferId::nil(),
        None,
    );
    let client_flow = async {
        for _ in 0..=options.max_retries {
            receive_oack(&client).await;
        }
    };

    let (result, ()) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(exchange, client_flow)
    })
    .await
    .unwrap();
    assert!(matches!(
        result,
        Err(TempestError::Protocol(ProtocolError::Timeout {
            block: 0,
            ..
        }))
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(80), receive_oack(&client))
            .await
            .is_err(),
        "server sent more OACKs than the configured retry budget"
    );
}

#[test]
fn test_normalize_path_components_counted() {
    let root = PathBuf::from("/tftpboot");
    let result = normalize_path_secure(&root, "a/b/c/d/e/f/g/h/i/j/file.bin").unwrap();
    let depth = result.strip_prefix(&root).unwrap().components().count();
    assert_eq!(depth, 11);
}

#[test]
fn test_normalize_rejects_dots_only() {
    let root = PathBuf::from("/tftpboot");
    assert!(normalize_path_secure(&root, ".").is_err());
}

#[test]
fn test_temp_file_path_format() {
    let file_path = PathBuf::from("/tftpboot/test.bin");
    let transfer_id = uuid::Uuid::nil();
    let temp_suffix = format!(".tempest.{}", transfer_id.as_simple());
    let temp_path = file_path.with_extension(
        file_path
            .extension()
            .map(|e| format!("{}.{}", e.to_string_lossy(), &temp_suffix[1..]))
            .unwrap_or_else(|| temp_suffix[1..].to_string()),
    );
    assert!(temp_path.to_string_lossy().contains("tempest"));
    assert_ne!(temp_path, file_path);
}

#[test]
fn test_transfer_metrics_has_both_times() {
    let start_time = Instant::now();
    std::thread::sleep(Duration::from_millis(10));
    let m = TransferMetrics {
        start_time: Some(start_time),
        end_time: Some(Instant::now()),
        ..Default::default()
    };
    let duration = m.duration().unwrap();
    assert!(duration.as_millis() >= 10);
}

#[test]
fn test_oack_echoes_only_requested_timeout() {
    let mut options = NegotiatedOptions::default();
    assert!(base_oack_options(&options).is_empty());
    options.timeout = 9;
    options.timeout_requested = true;
    assert_eq!(
        base_oack_options(&options),
        vec![("timeout".into(), "9".into())]
    );
}

#[test]
fn final_oack_serialization_includes_standard_size_and_extension_values() {
    let options = NegotiatedOptions {
        block_size: 1468,
        window_size: 8,
        timeout: 9,
        timeout_requested: true,
        ..NegotiatedOptions::default()
    };
    let extension = vec![("x-tempest-test".into(), "yes".into())];
    let packet = build_oack_packet(&options, Some(1_048_576), &extension).unwrap();
    let TftpPacket::Oack(parsed) =
        TftpPacket::parse(&packet, "127.0.0.1:40100".parse().unwrap()).unwrap()
    else {
        panic!("expected OACK");
    };
    assert_eq!(
        parsed.options,
        vec![
            ("blksize".into(), "1468".into()),
            ("windowsize".into(), "8".into()),
            ("timeout".into(), "9".into()),
            ("tsize".into(), "1048576".into()),
            ("x-tempest-test".into(), "yes".into()),
        ]
    );
}

#[test]
fn test_normalize_rejects_null_byte() {
    let root = PathBuf::from("/tftpboot");
    let filename = "valid\x00exploit";
    assert!(normalize_path_secure(&root, filename).is_err());
}

#[test]
fn test_transfer_slot_guard_decrements_on_drop() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let counter = Arc::new(AtomicUsize::new(1));
    {
        let guard = TransferSlotGuard::new(counter.clone());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        drop(guard);
    }
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}

#[test]
fn test_transfer_slot_guard_no_decrement_after_handoff() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let counter = Arc::new(AtomicUsize::new(1));
    {
        let mut guard = TransferSlotGuard::new(counter.clone());
        guard.hand_off();
        drop(guard);
    }
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[test]
fn test_pinned_version_guard_unpins_on_drop() {
    let store = crate::features::versioning::VersionStore::new();
    let dir = tempfile::tempdir().unwrap();
    let file_path = dir.path().join("kernel.bin");
    std::fs::write(&file_path, b"kernel").unwrap();
    let group = store
        .atomic_switch("release_guard".into(), vec![("kernel".into(), file_path)])
        .unwrap();
    let resolved = store
        .resolve_file_for_transfer("kernel", Path::new("."))
        .unwrap();
    assert_eq!(store.pinned_count("kernel", group.version_id), 1);
    {
        let _guard = PinnedVersionGuard::new(&store, resolved.pinned_version);
    }
    assert_eq!(store.pinned_count("kernel", group.version_id), 0);
}

#[test]
fn test_shared_cache_identity_includes_stable_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.bin");
    std::fs::write(&path, b"abc").unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    let key = ArtifactIdentity::new(&path, &metadata).shared_cache_key();
    #[cfg(not(unix))]
    assert!(key.starts_with("uncached:"));
    assert!(key.contains(":3:"));
}

#[test]
fn test_quarantine_key_for_resolved_versioned_path() {
    let root = PathBuf::from("/tftpboot");
    let path = PathBuf::from("/tftpboot/releases/v2/vmlinuz");
    let key = quarantine_key_for_resolved_path(&path, &root).unwrap();
    assert_eq!(key, "releases/v2/vmlinuz");
}

#[test]
fn test_temp_file_guard_removes_on_drop() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tempest_test_guard_remove.tmp");
    let root = Arc::new(ArtifactRoot::open(dir.path()).unwrap());
    std::fs::write(&path, b"test").unwrap();
    assert!(path.exists());
    {
        let guard = TempFileGuard::new(root, PathBuf::from("tempest_test_guard_remove.tmp"));
        drop(guard);
    }
    assert!(!path.exists(), "temporary file survived guard cleanup");
}

#[test]
fn test_temp_file_guard_keeps_after_commit() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tempest_test_guard_keep.tmp");
    let root = Arc::new(ArtifactRoot::open(dir.path()).unwrap());
    std::fs::write(&path, b"test").unwrap();
    assert!(path.exists());
    {
        let mut guard = TempFileGuard::new(root, PathBuf::from("tempest_test_guard_keep.tmp"));
        guard.commit();
        drop(guard);
    }
    assert!(path.exists(), "committed temporary file was removed");
    std::fs::remove_file(&path).ok();
}

#[test]
fn test_symlink_escape_check_non_symlink() {
    let temp_root = tempfile::tempdir().unwrap();
    let dir = temp_root.path().to_path_buf();
    let file_path = dir.join("regular.bin");
    std::fs::write(&file_path, b"test").unwrap();
    let result = check_symlink_escape(&file_path, &dir);
    assert!(result.is_ok());
}

#[cfg(unix)]
#[test]
fn test_symlink_inside_root_ok() {
    let temp_root = tempfile::tempdir().unwrap();
    let dir = temp_root.path().to_path_buf();
    let target = dir.join("target.bin");
    std::fs::write(&target, b"data").unwrap();
    let link = dir.join("link.bin");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let result = check_symlink_escape(&link, &dir);
    assert!(result.is_ok());
}

#[cfg(unix)]
#[test]
fn test_symlink_escape_root_rejected() {
    let temp_root = tempfile::tempdir().unwrap();
    let dir = temp_root.path().to_path_buf();
    let link = dir.join("evil_link");
    std::os::unix::fs::symlink("/etc/hosts", &link).unwrap();
    let result = check_symlink_escape(&link, &dir);
    assert!(result.is_err());
}

#[test]
fn test_wrq_file_size_limit_constant() {
    let config = crate::config::ServerConfig::default();
    assert!(config.max_write_file_size <= 4 * 1024 * 1024 * 1024);
    assert!(config.max_write_file_size > 0);
}

#[test]
fn routed_request_identity_must_match_verified_release() {
    let identity = ReadRequestIdentity {
        boot_profile: "default".into(),
        group_id: "release-1".into(),
        artifact_version_id: 9,
        manifest_digest: "a".repeat(64),
        content_hash: "b".repeat(64),
    };
    let mut options = vec![
        (
            EXTENSION_PROTOCOL_VERSION_OPTION.into(),
            EXTENSION_PROTOCOL_VERSION.into(),
        ),
        (ROUTE_BOOT_PROFILE_OPTION.into(), "default".into()),
        (ROUTE_GROUP_OPTION.into(), "release-1".into()),
        (ROUTE_ARTIFACT_VERSION_OPTION.into(), "9".into()),
        (ROUTE_MANIFEST_DIGEST_OPTION.into(), "a".repeat(64)),
        (ROUTE_CONTENT_HASH_OPTION.into(), "b".repeat(64)),
    ];
    validate_requested_read_identity(&options, Some(&identity)).unwrap();

    options
        .iter_mut()
        .find(|(name, _)| name == ROUTE_ARTIFACT_VERSION_OPTION)
        .unwrap()
        .1 = "10".into();
    assert!(validate_requested_read_identity(&options, Some(&identity)).is_err());
    assert!(validate_requested_read_identity(&options, None).is_err());
}

#[tokio::test]
async fn test_opened_managed_artifact_is_verified_and_rewound() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kernel");
    std::fs::write(&path, b"kernel").unwrap();
    let pinned = PinnedVersion {
        boot_profile: "default".into(),
        logical_name: "kernel".into(),
        version_id: 1,
        content_hash: hex::encode(Sha256::digest(b"kernel")),
        size: 6,
    };
    let mut file = File::open(&path).await.unwrap();
    let store = crate::features::versioning::VersionStore::new();
    let metadata = std::fs::metadata(&path).unwrap();
    let verification = store.artifact_verification(&path, &metadata, &pinned.content_hash);
    assert!(Arc::ptr_eq(
        &verification,
        &store.artifact_verification(&path, &metadata, &pinned.content_hash),
    ));
    verify_opened_artifact(&mut file, &path, Some(&pinned), &store)
        .await
        .unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).await.unwrap();
    assert_eq!(bytes, b"kernel");

    // Managed artifacts are immutable and deployments replace their directory
    // entries. Use that contract here so cache invalidation does not depend on
    // the backing filesystem exposing sub-second timestamps for an in-place
    // write. The replacement also uses a different length so the identity key
    // (which includes file size on all platforms) differs deterministically,
    // independent of timestamp granularity (2 s on Windows NTFS).
    drop(file);
    let replacement = dir.path().join("kernel.replacement");
    std::fs::write(&replacement, b"broken-content").unwrap();
    #[cfg(not(unix))]
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(replacement, &path).unwrap();

    let replacement_metadata = std::fs::metadata(&path).unwrap();
    assert!(!Arc::ptr_eq(
        &verification,
        &store.artifact_verification(&path, &replacement_metadata, &pinned.content_hash),
    ));
    let mut file = File::open(&path).await.unwrap();
    // The size check (14 != 6) rejects the artifact before any cache lookup,
    // so this fails on every platform regardless of timestamp granularity.
    assert!(
        verify_opened_artifact(&mut file, &path, Some(&pinned), &store)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn test_managed_artifact_hash_requires_exact_match() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kernel");
    std::fs::write(&path, b"kernel").unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    let bytes = Arc::new(Bytes::from_static(b"kernel"));
    let expected = hex::encode(Sha256::digest(bytes.as_ref()));
    let mut hashes = vec![
        expected.clone(),
        String::new(),
        expected[..63].to_owned(),
        format!("{expected}0"),
    ];
    for index in 0..expected.len() {
        let mut hash = expected.as_bytes().to_vec();
        hash[index] = if hash[index] == b'0' { b'1' } else { b'0' };
        hashes.push(String::from_utf8(hash).unwrap());
    }
    for content_hash in hashes {
        let matches = content_hash == expected;
        let pinned = PinnedVersion {
            boot_profile: "default".into(),
            logical_name: "kernel".into(),
            version_id: 1,
            content_hash,
            size: 6,
        };
        // Independent stores ensure each path performs its own verification.
        let store = crate::features::versioning::VersionStore::new();
        let mut file = File::open(&path).await.unwrap();
        let opened = verify_opened_artifact(&mut file, &path, Some(&pinned), &store).await;
        let store = crate::features::versioning::VersionStore::new();
        let cached = verify_cached_artifact(&bytes, &path, &metadata, Some(&pinned), &store).await;
        for result in [opened, cached] {
            if matches {
                assert!(result.is_ok());
            } else {
                assert!(matches!(
                    result,
                    Err(TempestError::Protocol(
                        ProtocolError::VersionMismatch { .. }
                    ))
                ));
            }
        }
    }
}

#[tokio::test]
async fn transfer_hashing_waits_for_capacity_and_cached_hits_do_not() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kernel");
    std::fs::write(&path, b"kernel").unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    let pinned = PinnedVersion {
        boot_profile: "default".into(),
        logical_name: "kernel".into(),
        version_id: 1,
        content_hash: hex::encode(Sha256::digest(b"kernel")),
        size: 6,
    };
    let store = crate::features::versioning::VersionStore::new();
    let permit = store.artifact_hash_budget.acquire_many(4).await.unwrap();
    let bytes = Arc::new(Bytes::from_static(b"kernel"));
    assert!(
        tokio::time::timeout(
            Duration::from_millis(10),
            verify_cached_artifact(&bytes, &path, &metadata, Some(&pinned), &store)
        )
        .await
        .is_err()
    );
    drop(permit);
    verify_cached_artifact(&bytes, &path, &metadata, Some(&pinned), &store)
        .await
        .unwrap();
    let _permit = store.artifact_hash_budget.acquire_many(4).await.unwrap();
    // A cached hit that waited for capacity would block until this bound.
    tokio::time::timeout(
        Duration::from_secs(30),
        verify_cached_artifact(&bytes, &path, &metadata, Some(&pinned), &store),
    )
    .await
    .unwrap()
    .unwrap();
}

#[test]
fn test_transfer_slot_guard_wrq_early_return() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let counter = Arc::new(AtomicUsize::new(5));

    {
        let _guard = TransferSlotGuard::new(counter.clone());
    }
    assert_eq!(counter.load(Ordering::SeqCst), 4);
}

#[test]
fn test_transfer_slot_guard_wrq_handoff() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let counter = Arc::new(AtomicUsize::new(5));

    {
        let mut guard = TransferSlotGuard::new(counter.clone());
        guard.hand_off();
    }
    assert_eq!(counter.load(Ordering::SeqCst), 5);
}

#[cfg(unix)]
#[test]
fn write_temp_is_private_and_exclusive() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let root = ArtifactRoot::open(directory.path()).unwrap();
    let (_file, temp_relative, _) = root.create_write_temp("test.bin", "fixed").unwrap();
    let metadata = std::fs::metadata(directory.path().join(&temp_relative)).unwrap();
    let perms = metadata.permissions().mode() & 0o777;
    assert_eq!(perms, 0o600);
    assert!(root.create_write_temp("test.bin", "fixed").is_err());
}

#[test]
fn pacing_delay_rejects_invalid_rates_and_clamps_extremes() {
    assert_eq!(pacing_delay(1024, 0.0, None), None);
    assert_eq!(pacing_delay(1024, f64::NAN, None), None);
    assert_eq!(
        pacing_delay(1024, f64::INFINITY, None),
        None,
        "an unbounded non-finite rate must not create a duration"
    );
    assert_eq!(pacing_delay(1024, 1.0, None), Some(Duration::from_secs(10)));
    assert_eq!(
        pacing_delay(1024, 1.0e20, None),
        Some(Duration::from_micros(10))
    );
}

#[test]
fn pacing_delay_applies_a_finite_positive_ceiling() {
    assert_eq!(
        pacing_delay(1024, 4096.0, Some(2048.0)),
        Some(Duration::from_millis(500))
    );
    assert_eq!(
        pacing_delay(1024, 4096.0, Some(f64::NAN)),
        Some(Duration::from_millis(250))
    );
}

struct BatchProtocol {
    calls: Arc<AtomicUsize>,
    invalid: bool,
}
impl ReadProtocolSession for BatchProtocol {
    fn oack_options(&self) -> Vec<(String, String)> {
        Vec::new()
    }
    fn encoding_batch_size(&self) -> usize {
        32
    }
    fn encode_packet(
        &mut self,
        block: u16,
        payload: &[u8],
    ) -> Result<EncodedDataPacket, TempestError> {
        Ok(EncodedDataPacket {
            packet: TftpPacket::data(block, payload),
            accounted_bytes: payload.len() as u64,
        })
    }
    fn encode_packets_async(
        &mut self,
        packets: Vec<(u16, Bytes)>,
    ) -> crate::extension::ReadProtocolBatchEncodeFuture<'_> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Box::pin(async move {
            if self.invalid {
                return Ok(Vec::new());
            }
            packets
                .into_iter()
                .map(|(block, data)| self.encode_packet(block, &data))
                .collect()
        })
    }
}

#[tokio::test]
async fn encoded_lookahead_bounds_input_preserves_bytes_and_rejects_invalid_batches() {
    let bytes = Bytes::from(vec![42; 100_000]);
    let mut file = ArtifactReader::new(
        CoreReadSource::Memory(Arc::new(bytes.clone())),
        bytes.len() as u64,
        4096,
        true,
        1,
    );
    let mut session = BatchProtocol {
        calls: Arc::new(AtomicUsize::new(0)),
        invalid: false,
    };
    let batch = encode_file_batch(&mut file, &mut session, &mut None, 1, 4096, 4096)
        .await
        .unwrap();
    assert_eq!(batch.len(), 16);
    assert_eq!(batch.iter().map(|(len, _)| len).sum::<usize>(), 64 * 1024);
    for (index, (len, encoded)) in batch.into_iter().enumerate() {
        assert_eq!(len, 4096);
        assert_eq!(
            encoded.packet,
            TftpPacket::data(index as u16 + 1, &bytes[..4096])
        );
    }
    session.invalid = true;
    assert!(
        encode_file_batch(&mut file, &mut session, &mut None, 1, 512, 512)
            .await
            .is_err()
    );
    session.invalid = false;
    assert!(
        encode_file_batch(&mut file, &mut session, &mut None, 1, 512, 8)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn encoded_lookahead_respects_window_and_rewinds_after_lost_ack() {
    let server = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let bytes = Bytes::from((0..1300).map(|n| (n % 251) as u8).collect::<Vec<_>>());
    let mut file = ArtifactReader::new(
        CoreReadSource::Memory(Arc::new(bytes.clone())),
        bytes.len() as u64,
        512,
        true,
        1,
    );
    let state = crate::server::TftpServer::new(crate::config::TempestConfig::default()).state();
    let scheduler = SchedulerTransferGuard {
        scheduler: None,
        transfer_id: TransferId::nil(),
    };
    let options = NegotiatedOptions {
        // The quiet check and exact retransmission count need an RTO far above jitter.
        retransmission_policy: RetransmissionPolicy::fixed(Duration::from_secs(3)),
        ..Default::default()
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let mut protocol: Option<Box<dyn ReadProtocolSession>> = Some(Box::new(BatchProtocol {
        calls: calls.clone(),
        invalid: false,
    }));
    let mut metrics = TransferMetrics::default();
    let mut pacing = None;
    let transfer = run_read_data_loop(
        ReadDataLoop {
            socket: &server,
            client_addr: client.local_addr().unwrap(),
            transfer_id: TransferId::nil(),
            state: &state,
            scheduler: &scheduler,
            shared_blocks: None,
            options: &options,
            core_payload_size: 512,
            fallback_pacing_delay: None,
        },
        &mut file,
        &mut protocol,
        &mut pacing,
        &mut metrics,
    );
    let receive = async {
        let mut buffer = [0; 1024];
        // Lose the first ACK. The retry must discard previously encoded blocks 2/3.
        for block in [1u16, 1, 2, 3] {
            let (len, peer) = client.recv_from(&mut buffer).await.unwrap();
            assert_eq!(peer, server.local_addr().unwrap());
            let offset = (usize::from(block) - 1) * 512;
            assert_eq!(
                &buffer[..len],
                &TftpPacket::data(block, &bytes[offset..(offset + 512).min(bytes.len())])
            );
            if calls.load(Ordering::Relaxed) == 1 && block == 1 {
                assert!(
                    tokio::time::timeout(Duration::from_millis(20), client.recv_from(&mut buffer))
                        .await
                        .is_err()
                );
            } else {
                client.send_to(&TftpPacket::ack(block), peer).await.unwrap();
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(30), async {
        let (result, ()) = tokio::join!(transfer, receive);
        result.unwrap();
    })
    .await
    .unwrap();
    assert_eq!(
        calls.load(Ordering::Relaxed),
        2,
        "three DATA packets share each encoding dispatch"
    );
    assert_eq!(metrics.retransmissions, 1);
}
