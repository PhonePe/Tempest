// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use std::time::Instant;

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use tempest::features::boot_phase::BootPhase;
use tempest::protocol::options::{OptionDefaults, negotiate_options};
use tempest::protocol::packet::TftpPacket;
use tempest::protocol::transfer::TransferMetrics;
use tempest::protocol::window::{RetransmissionPolicy, WindowState};
use tempest::server::ServerMetrics;

fn packet_parsing(criterion: &mut Criterion) {
    let peer = SocketAddr::from(([192, 0, 2, 1], 49_152));
    let rrq = {
        let mut packet = TftpPacket::rrq("releases/current/vmlinuz", "octet");
        packet.extend_from_slice(b"blksize\x001468\x00windowsize\x0016\x00timeout\x003\x00");
        packet
    };
    let data = TftpPacket::data(65_535, &[0x5a; 8192]);
    let mut group = criterion.benchmark_group("packet_parse");
    group.throughput(Throughput::Bytes(rrq.len() as u64));
    group.bench_function("rrq_options", |bencher| {
        bencher.iter(|| TftpPacket::parse(black_box(&rrq), peer).unwrap())
    });
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("data_8k", |bencher| {
        bencher.iter(|| TftpPacket::parse(black_box(&data), peer).unwrap())
    });
    group.finish();
}

fn option_negotiation(criterion: &mut Criterion) {
    let requested = vec![
        ("blksize".into(), "8192".into()),
        ("windowsize".into(), "32".into()),
        ("timeout".into(), "3".into()),
        ("tsize".into(), "0".into()),
        ("x-trace-id".into(), "benchmark".into()),
    ];
    let defaults = OptionDefaults::default();
    criterion.bench_function("option_negotiation/five_options", |bencher| {
        bencher.iter(|| negotiate_options(black_box(&requested), black_box(&defaults)))
    });
}

fn window_progression(criterion: &mut Criterion) {
    criterion.bench_function("window/full_32_block_cycle", |bencher| {
        bencher.iter(|| {
            let mut window = WindowState::with_policy(
                32,
                RetransmissionPolicy::adaptive(
                    Duration::from_secs(1),
                    Duration::from_millis(250),
                    Duration::from_secs(4),
                ),
                5,
            );
            for _ in 0..32 {
                window.block_sent();
            }
            black_box(window.process_ack(32))
        })
    });
}

fn metric_accounting(criterion: &mut Criterion) {
    let active = Arc::new(AtomicUsize::new(0));
    let metrics = ServerMetrics::new(active.clone());
    let started = Instant::now();
    let transfer = TransferMetrics {
        bytes_sent: 1_024,
        start_time: Some(started),
        end_time: Some(started + Duration::from_micros(500)),
        ..TransferMetrics::default()
    };

    criterion.bench_function("metrics/default_tftp_start_complete", |bencher| {
        bencher.iter(|| {
            active.store(1, Ordering::Relaxed);
            metrics.transfer_started(&BootPhase::PxeRom, "default");
            metrics.transfer_completed(&BootPhase::PxeRom, "default", black_box(&transfer));
        })
    });
}

criterion_group!(
    name = protocol_benches;
    config = Criterion::default()
        .sample_size(50)
        .measurement_time(Duration::from_secs(2))
        .warm_up_time(Duration::from_secs(1));
    targets = packet_parsing, option_negotiation, window_progression, metric_accounting
);
criterion_main!(protocol_benches);
