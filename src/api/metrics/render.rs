// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Native instrument definitions. Each asynchronous callback reads only its
//! own family; histograms record events at the lifecycle call sites instead.

use std::collections::BTreeMap;
use std::sync::{Arc, atomic::Ordering};

use opentelemetry::{
    KeyValue,
    metrics::{AsyncInstrument, Histogram, Meter},
};

use crate::server::{DURATION_BUCKETS, ServerState};

/// Metadata only, for HELP/TYPE lines even before a family has observations.
/// Values always come from standard SDK ResourceMetrics, never a custom model.
pub(super) type Definition = (&'static str, &'static str, &'static str);

struct Registration<'a> {
    state: &'a Arc<ServerState>,
    meter: &'a Meter,
    definitions: Vec<Definition>,
}

impl Registration<'_> {
    fn u64(
        &mut self,
        name: &'static str,
        help: &'static str,
        counter: bool,
        observe: impl Fn(&ServerState, &dyn AsyncInstrument<u64>) + Send + Sync + 'static,
    ) {
        self.definitions
            .push((name, help, if counter { "counter" } else { "gauge" }));
        let weak = Arc::downgrade(self.state);
        let callback = move |instrument: &dyn AsyncInstrument<u64>| {
            if let Some(state) = weak.upgrade() {
                observe(&state, instrument);
            }
        };
        if counter {
            self.meter
                .u64_observable_counter(name)
                .with_description(help)
                .with_callback(callback)
                .build();
        } else {
            self.meter
                .u64_observable_gauge(name)
                .with_description(help)
                .with_callback(callback)
                .build();
        }
    }

    fn f64_counter(
        &mut self,
        name: &'static str,
        help: &'static str,
        observe: impl Fn(&ServerState, &dyn AsyncInstrument<f64>) + Send + Sync + 'static,
    ) {
        self.definitions.push((name, help, "counter"));
        let weak = Arc::downgrade(self.state);
        self.meter
            .f64_observable_counter(name)
            .with_description(help)
            .with_callback(move |instrument| {
                if let Some(state) = weak.upgrade() {
                    observe(&state, instrument);
                }
            })
            .build();
    }

    fn histogram(&mut self, name: &'static str, help: &'static str) -> Histogram<f64> {
        self.definitions.push((name, help, "histogram"));
        self.meter
            .f64_histogram(name)
            .with_description(help)
            .with_boundaries(DURATION_BUCKETS.to_vec())
            .build()
    }
}

pub(super) struct Registered {
    pub definitions: Vec<Definition>,
    pub phase: Histogram<f64>,
    pub profile: Histogram<f64>,
    pub cutover: Histogram<f64>,
}

pub(super) fn register(state: &Arc<ServerState>, meter: &Meter) -> Registered {
    let mut r = Registration {
        state,
        meter,
        definitions: Vec::new(),
    };
    // Capture the serving runtime at construction. Exporter threads need not
    // enter Tokio, and construction outside Tokio simply omits these samples.
    let runtime = tokio::runtime::Handle::try_current().ok();

    macro_rules! scalar {
        ($name:literal, $help:literal, $counter:expr, $state:ident, $value:expr) => {
            r.u64($name, $help, $counter, |$state, i| i.observe($value, &[]));
        };
    }
    scalar!(
        "tempest_active_transfers",
        "Number of currently active transfers",
        false,
        s,
        s.active_transfers.load(Ordering::Relaxed) as u64
    );
    scalar!(
        "tempest_tftp_udp_segmentation_batches_total",
        "Process-wide UDP segmentation batches successfully sent",
        true,
        _s,
        crate::protocol::transfer::udp_segmentation_counters().0
    );
    scalar!(
        "tempest_tftp_udp_segmentation_fallbacks_total",
        "Process-wide UDP segmentation syscall rejections falling back to datagrams",
        true,
        _s,
        crate::protocol::transfer::udp_segmentation_counters().1
    );
    for (dimension, definitions) in [
        (
            0,
            [
                (
                    "tempest_transfers_total",
                    "Total transfers started by phase",
                ),
                (
                    "tempest_transfer_bytes_total",
                    "Total bytes transferred by phase",
                ),
                (
                    "tempest_transfer_failures_total",
                    "Total failed transfers by phase",
                ),
            ],
        ),
        (
            1,
            [
                (
                    "tempest_transfers_by_profile_total",
                    "Total transfers started by boot profile",
                ),
                (
                    "tempest_transfer_bytes_by_profile_total",
                    "Total bytes transferred by boot profile",
                ),
                (
                    "tempest_transfer_failures_by_profile_total",
                    "Total failed transfers by boot profile",
                ),
            ],
        ),
        (
            2,
            [
                (
                    "tempest_transfers_by_transport_total",
                    "Total transfers started by transport",
                ),
                (
                    "tempest_transfer_bytes_by_transport_total",
                    "Total bytes transferred by transport",
                ),
                (
                    "tempest_transfer_failures_by_transport_total",
                    "Total failed transfers by transport",
                ),
            ],
        ),
        (
            3,
            [
                (
                    "tempest_transfers_by_transport_phase_total",
                    "Total transfers started by transport and boot phase",
                ),
                (
                    "tempest_transfer_bytes_by_transport_phase_total",
                    "Total bytes transferred by transport and boot phase",
                ),
                (
                    "tempest_transfer_failures_by_transport_phase_total",
                    "Total failed transfers by transport and boot phase",
                ),
            ],
        ),
        (
            4,
            [
                (
                    "tempest_transfers_by_profile_transport_total",
                    "Total transfers started by boot profile and transport",
                ),
                (
                    "tempest_transfer_bytes_by_profile_transport_total",
                    "Total bytes transferred by boot profile and transport",
                ),
                (
                    "tempest_transfer_failures_by_profile_transport_total",
                    "Total failed transfers by boot profile and transport",
                ),
            ],
        ),
    ] {
        for (index, (name, help)) in definitions.into_iter().enumerate() {
            r.u64(name, help, true, move |s, i| {
                let value = |v: (u64, u64, u64)| [v.0, v.1, v.2][index];
                match dimension {
                    0 => {
                        for (phase, totals) in s.metrics.phase_metrics_snapshot() {
                            i.observe(value(totals), &[KeyValue::new("phase", phase)]);
                        }
                    }
                    1 => {
                        for (profile, metrics) in s.metrics.shared_profile_metrics_snapshot().iter()
                        {
                            i.observe(
                                value(metrics.totals),
                                &[KeyValue::new("boot_profile", profile.clone())],
                            );
                        }
                    }
                    2 => {
                        for (transport, totals) in s.metrics.transport_metrics_snapshot() {
                            i.observe(value(totals), &[KeyValue::new("transport", transport)]);
                        }
                    }
                    3 => {
                        for ((transport, phase), totals) in
                            s.metrics.transport_phase_metrics_snapshot()
                        {
                            i.observe(
                                value(totals),
                                &[
                                    KeyValue::new("transport", transport),
                                    KeyValue::new("phase", phase),
                                ],
                            );
                        }
                    }
                    _ => {
                        for (profile, metrics) in s.metrics.shared_profile_metrics_snapshot().iter()
                        {
                            for (transport, totals) in [
                                ("TFTP", metrics.tftp),
                                ("HTTP", metrics.http),
                                ("HTTP_NATIVE", metrics.http_native),
                            ] {
                                if totals != (0, 0, 0) {
                                    i.observe(
                                        value(totals),
                                        &[
                                            KeyValue::new("boot_profile", profile.clone()),
                                            KeyValue::new("transport", transport),
                                        ],
                                    );
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    scalar!(
        "tempest_retransmissions_total",
        "Retransmission events observed on completed transfers",
        true,
        s,
        s.metrics.retransmissions_total.load(Ordering::Relaxed)
    );
    scalar!(
        "tempest_malformed_packets_total",
        "Malformed TFTP packets observed before log sampling",
        true,
        s,
        s.metrics.malformed_packets_total.load(Ordering::Relaxed)
    );
    scalar!(
        "tempest_unexpected_opcodes_total",
        "Non-request opcodes received by the TFTP listener",
        true,
        s,
        s.metrics.unexpected_opcodes_total.load(Ordering::Relaxed)
    );
    scalar!(
        "tempest_duplicate_requests_total",
        "Retransmitted RRQ or WRQ packets coalesced by client TID",
        true,
        s,
        s.metrics.duplicate_requests_total.load(Ordering::Relaxed)
    );
    scalar!(
        "tempest_oack_timeouts_total",
        "Option handshakes abandoned before ACK(0)",
        true,
        s,
        s.metrics.oack_timeouts_total.load(Ordering::Relaxed)
    );
    scalar!(
        "tempest_drain_mode",
        "Whether the server is in drain mode",
        false,
        s,
        u64::from(s.drain_mode.load(Ordering::Relaxed))
    );
    scalar!(
        "tempest_uptime_seconds",
        "Seconds since the server started",
        false,
        s,
        s.start_time.elapsed().as_secs()
    );
    scalar!(
        "tempest_capacity_rejected_total",
        "TFTP requests rejected because the server was at max concurrent transfers",
        true,
        s,
        s.metrics.capacity_rejected_total.load(Ordering::Relaxed)
    );
    scalar!(
        "tempest_admission_queued_total",
        "Requests placed into the admission queue",
        true,
        s,
        s.metrics.admission_queued_total.load(Ordering::Relaxed)
    );
    scalar!(
        "tempest_admission_started_total",
        "Requests dequeued and started from the admission queue",
        true,
        s,
        s.metrics.admission_started_total.load(Ordering::Relaxed)
    );
    scalar!(
        "tempest_admission_dropped_total",
        "Requests dropped from the admission queue (TTL or overflow)",
        true,
        s,
        s.metrics.admission_dropped_total.load(Ordering::Relaxed)
    );

    r.u64(
        "tempest_rate_limit_rejected_total",
        "Requests rejected by the per-IP rate limiter",
        true,
        |s, i| {
            i.observe(
                s.tftp_rate_limiter.rejected_count(),
                &[KeyValue::new("layer", "TFTP")],
            );
            i.observe(
                s.http_rate_limiter.rejected_count(),
                &[KeyValue::new("layer", "API")],
            );
        },
    );
    r.u64(
        "tempest_extension_failures_total",
        "Explicit extension errors or provider output rejected by core",
        true,
        |s, i| {
            for (contract, operation, count) in s.metrics.extension_failure_snapshot() {
                i.observe(
                    count,
                    &[
                        KeyValue::new("contract", contract),
                        KeyValue::new("operation", operation),
                    ],
                );
            }
        },
    );
    r.u64(
        "tempest_audit_admission_rejected_total",
        "Transfers rejected by fixed audit-admission failure classes",
        true,
        |s, i| {
            let audit = s
                .audit_writer
                .as_ref()
                .map(|w| w.metrics_snapshot())
                .unwrap_or_default();
            for (reason, value) in [
                ("byte_capacity", audit.byte_capacity_rejected_total),
                ("writer_queue", audit.queue_capacity_rejected_total),
                ("writer_failure", audit.writer_failed_rejected_total),
            ] {
                i.observe(value, &[KeyValue::new("reason", reason)]);
            }
        },
    );
    macro_rules! audit {
        ($name:literal, $help:literal, $counter:expr, $field:ident) => {
            scalar!(
                $name,
                $help,
                $counter,
                s,
                s.audit_writer
                    .as_ref()
                    .map(|w| w.metrics_snapshot())
                    .unwrap_or_default()
                    .$field as u64
            );
        };
    }
    audit!(
        "tempest_audit_queue_outstanding_records",
        "Audit reservations not yet durably synced to JSONL",
        false,
        outstanding_records
    );
    audit!(
        "tempest_audit_queue_reserved_bytes",
        "Bytes reserved by audit records not yet durably synced",
        false,
        reserved_bytes
    );
    audit!(
        "tempest_audit_jsonl_batches_total",
        "Successful durable JSONL group commits",
        true,
        jsonl_batches_total
    );
    audit!(
        "tempest_audit_jsonl_records_total",
        "Terminal records included in durable JSONL group commits",
        true,
        jsonl_records_total
    );
    audit!(
        "tempest_audit_jsonl_bytes_total",
        "Bytes included in durable JSONL group commits",
        true,
        jsonl_bytes_total
    );
    r.f64_counter(
        "tempest_audit_jsonl_commit_seconds_total",
        "Time spent serializing, writing, and syncing JSONL batches",
        |s, i| {
            i.observe(
                s.audit_writer
                    .as_ref()
                    .map(|w| w.metrics_snapshot())
                    .unwrap_or_default()
                    .jsonl_commit_nanoseconds_total as f64
                    / 1_000_000_000.0,
                &[],
            );
        },
    );
    macro_rules! cache {
        ($name:literal, $help:literal, $counter:expr, $field:ident) => {
            scalar!(
                $name,
                $help,
                $counter,
                s,
                s.hot_artifact_cache.stats().$field as u64
            );
        };
    }
    cache!(
        "tempest_hot_artifact_cache_hits_total",
        "Small-artifact requests served from retained bytes",
        true,
        hits
    );
    cache!(
        "tempest_hot_artifact_cache_verified_hits_total",
        "Managed artifact requests served from an already digest-verified snapshot",
        true,
        verified_hits
    );
    cache!(
        "tempest_hot_artifact_cache_freshness_hits_total",
        "Unmanaged artifact requests served within the configured validation interval",
        true,
        freshness_hits
    );
    cache!(
        "tempest_hot_artifact_cache_misses_total",
        "Small-artifact identities admitted for cache fill",
        true,
        misses
    );
    cache!(
        "tempest_hot_artifact_cache_coalesced_total",
        "Requests joined to an in-progress artifact fill",
        true,
        coalesced
    );
    cache!(
        "tempest_hot_artifact_cache_bypasses_total",
        "Artifacts bypassing cache size or capacity bounds",
        true,
        bypasses
    );
    cache!(
        "tempest_hot_artifact_cache_fills_total",
        "Completed small-artifact cache fills",
        true,
        fills
    );
    cache!(
        "tempest_hot_artifact_cache_resident_bytes",
        "Bytes currently reserved by the hot-artifact cache",
        false,
        resident_bytes
    );
    cache!(
        "tempest_hot_artifact_cache_entries",
        "Current hot-artifact cache entries",
        false,
        entries
    );
    r.u64(
        "tempest_listener_shard_requests_total",
        "Valid TFTP requests accepted by each SO_REUSEPORT listener shard",
        true,
        |s, i| {
            for (shard, requests) in s
                .metrics
                .listener_shard_requests
                .iter()
                .enumerate()
                .take(s.config.server.effective_listener_shards())
            {
                i.observe(
                    requests.load(Ordering::Relaxed),
                    &[KeyValue::new("shard", shard.to_string())],
                );
            }
        },
    );
    let queue_runtime = runtime.clone();
    r.u64(
        "tempest_runtime_global_queue_depth",
        "Tasks currently waiting in Tokio's global queue",
        false,
        move |_, i| {
            if let Some(runtime) = &queue_runtime {
                i.observe(runtime.metrics().global_queue_depth() as u64, &[]);
            }
        },
    );
    #[cfg(target_pointer_width = "64")]
    r.f64_counter(
        "tempest_runtime_worker_busy_seconds_total",
        "Cumulative busy time for each Tokio runtime worker",
        move |_, i| {
            if let Some(runtime) = &runtime {
                let metrics = runtime.metrics();
                for worker in 0..metrics.num_workers() {
                    i.observe(
                        metrics.worker_total_busy_duration(worker).as_secs_f64(),
                        &[KeyValue::new("worker", worker.to_string())],
                    );
                }
            }
        },
    );

    scalar!(
        "tempest_version_groups_total",
        "Number of registered version groups",
        false,
        s,
        s.version_store.list_groups().len() as u64
    );
    scalar!(
        "tempest_active_versions",
        "Number of active file versions",
        false,
        s,
        s.version_store.list_versions().len() as u64
    );
    scalar!(
        "tempest_active_boot_sessions_total",
        "Number of active boot sessions",
        false,
        s,
        s.boot_sessions.len() as u64
    );
    scalar!(
        "tempest_quarantined_files",
        "Number of files currently quarantined by integrity policy",
        false,
        s,
        s.quarantined_files.len() as u64
    );
    r.u64(
        "tempest_release_control_events_total",
        "Release cutover, rollback, integrity, and signature events",
        true,
        |s, i| {
            for event in &s.metrics.release_control_events {
                i.observe(*event.value(), &[KeyValue::new("event", *event.key())]);
            }
        },
    );
    for (dimension, name, help) in [
        (
            0,
            "tempest_version_groups_by_profile",
            "Number of registered version groups by boot profile",
        ),
        (
            1,
            "tempest_active_versions_by_profile",
            "Number of active file versions by boot profile",
        ),
        (
            2,
            "tempest_active_boot_sessions",
            "Number of active boot sessions by boot profile",
        ),
    ] {
        r.u64(name, help, false, move |s, i| {
            let mut counts = BTreeMap::<String, u64>::new();
            match dimension {
                0 => {
                    for group in s.version_store.list_groups() {
                        *counts.entry(group.boot_profile).or_default() += 1;
                    }
                }
                1 => {
                    for version in s.version_store.list_versions() {
                        *counts.entry(version.boot_profile).or_default() += 1;
                    }
                }
                _ => {
                    for session in s.boot_sessions.iter() {
                        *counts.entry(session.boot_profile.clone()).or_default() += 1;
                    }
                }
            }
            for (profile, count) in counts {
                i.observe(count, &[KeyValue::new("boot_profile", profile)]);
            }
        });
    }
    let phase = r.histogram(
        "tempest_transfer_duration_seconds",
        "Transfer duration distribution by boot phase",
    );
    let profile = r.histogram(
        "tempest_transfer_duration_by_profile_seconds",
        "Transfer duration distribution by boot profile",
    );
    let cutover = r.histogram(
        "tempest_release_cutover_duration_seconds",
        "Release cutover duration",
    );
    Registered {
        definitions: r.definitions,
        phase,
        profile,
        cutover,
    }
}
