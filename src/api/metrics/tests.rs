// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::time::Instant;

use axum::body::to_bytes;
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, HistogramDataPoint, Metric, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, PeriodicReader};

use super::*;
use crate::config::TempestConfig;
use crate::features::boot_phase::BootPhase;
use crate::protocol::transfer::TransferMetrics;
use crate::server::{
    DURATION_BUCKETS, TRANSPORT_HTTP, TRANSPORT_HTTP_NATIVE, TRANSPORT_TFTP, TftpServer,
};

fn collect(state: &ServerState) -> ResourceMetrics {
    state.metrics.telemetry.get().unwrap().collect().unwrap()
}

fn find<'a>(metrics: &'a ResourceMetrics, name: &str) -> &'a Metric {
    metrics
        .scope_metrics()
        .flat_map(|s| s.metrics())
        .find(|m| m.name() == name)
        .unwrap_or_else(|| panic!("missing {name}"))
}

fn labels_match<'a>(
    attributes: impl Iterator<Item = &'a KeyValue>,
    labels: &[(&str, &str)],
) -> bool {
    let attrs: Vec<_> = attributes.collect();
    attrs.len() == labels.len()
        && labels.iter().all(|(key, value)| {
            attrs
                .iter()
                .any(|kv| kv.key.as_str() == *key && kv.value.to_string() == *value)
        })
}

fn value(metrics: &ResourceMetrics, name: &str, labels: &[(&str, &str)]) -> u64 {
    match find(metrics, name).data() {
        AggregatedMetrics::U64(MetricData::Sum(sum)) => {
            assert!(sum.is_monotonic(), "{name}");
            assert_eq!(sum.temporality(), Temporality::Cumulative);
            sum.data_points()
                .find(|p| labels_match(p.attributes(), labels))
                .unwrap()
                .value()
        }
        AggregatedMetrics::U64(MetricData::Gauge(gauge)) => gauge
            .data_points()
            .find(|p| labels_match(p.attributes(), labels))
            .unwrap()
            .value(),
        other => panic!("{name}: {other:?}"),
    }
}

fn histogram<'a>(
    metrics: &'a ResourceMetrics,
    name: &str,
    labels: &[(&str, &str)],
) -> &'a HistogramDataPoint<f64> {
    let AggregatedMetrics::F64(MetricData::Histogram(hist)) = find(metrics, name).data() else {
        panic!("expected histogram: {name}")
    };
    assert_eq!(hist.temporality(), Temporality::Cumulative);
    hist.data_points()
        .find(|p| labels_match(p.attributes(), labels))
        .unwrap()
}

fn completed(
    state: &ServerState,
    profile: &str,
    phase: BootPhase,
    transport: &'static str,
    bytes: u64,
    seconds: f64,
) {
    let started = Instant::now();
    state.active_transfers.fetch_add(1, Ordering::Relaxed);
    state
        .metrics
        .transfer_started_for_transport(&phase, profile, transport);
    state.metrics.transfer_completed_for_transport(
        &phase,
        profile,
        &TransferMetrics {
            bytes_sent: bytes,
            retransmissions: 1,
            start_time: Some(started),
            end_time: Some(started + Duration::from_secs_f64(seconds)),
            ..TransferMetrics::default()
        },
        transport,
    );
}

fn seed_transfers(state: &ServerState) {
    for (transport, profile, phase, bytes, seconds) in [
        (TRANSPORT_TFTP, "alpha", BootPhase::Kernel, 123, 0.5),
        (TRANSPORT_HTTP, "alpha", BootPhase::Kernel, 456, 2.0),
        (
            TRANSPORT_HTTP_NATIVE,
            "beta",
            BootPhase::Unknown,
            789,
            301.0,
        ),
    ] {
        completed(state, profile, phase, transport, bytes, seconds);
    }
    state.active_transfers.fetch_add(1, Ordering::Relaxed);
    state.metrics.transfer_started(&BootPhase::Kernel, "alpha");
    state.metrics.transfer_failed(&BootPhase::Kernel, "alpha");
    state.metrics.release_event("cutover_success");
    for seconds in [0.0, 0.5, 0.75, 301.0] {
        state.metrics.cutover_duration.observe(seconds);
    }
    state
        .metrics
        .malformed_packets_total
        .store(u64::MAX, Ordering::Relaxed);
    state.drain_mode.store(true, Ordering::Relaxed);
}

fn assert_values(metrics: &ResourceMetrics) {
    for (name, labels, expected) in [
        ("tempest_active_transfers", vec![], 0),
        ("tempest_transfers_total", vec![("phase", "KERNEL")], 3),
        (
            "tempest_transfer_bytes_total",
            vec![("phase", "KERNEL")],
            579,
        ),
        (
            "tempest_transfer_failures_total",
            vec![("phase", "KERNEL")],
            1,
        ),
        (
            "tempest_transfers_by_profile_total",
            vec![("boot_profile", "alpha")],
            3,
        ),
        (
            "tempest_transfer_bytes_by_profile_total",
            vec![("boot_profile", "alpha")],
            579,
        ),
        (
            "tempest_transfer_failures_by_profile_total",
            vec![("boot_profile", "alpha")],
            1,
        ),
        (
            "tempest_transfers_by_transport_total",
            vec![("transport", "TFTP")],
            2,
        ),
        (
            "tempest_transfer_bytes_by_transport_total",
            vec![("transport", "HTTP_NATIVE")],
            789,
        ),
        (
            "tempest_transfer_failures_by_transport_total",
            vec![("transport", "TFTP")],
            1,
        ),
        (
            "tempest_transfers_by_transport_phase_total",
            vec![("transport", "HTTP"), ("phase", "KERNEL")],
            1,
        ),
        (
            "tempest_transfer_bytes_by_transport_phase_total",
            vec![("transport", "HTTP"), ("phase", "KERNEL")],
            456,
        ),
        (
            "tempest_transfer_failures_by_transport_phase_total",
            vec![("transport", "TFTP"), ("phase", "KERNEL")],
            1,
        ),
        (
            "tempest_transfers_by_profile_transport_total",
            vec![("boot_profile", "alpha"), ("transport", "TFTP")],
            2,
        ),
        (
            "tempest_transfer_bytes_by_profile_transport_total",
            vec![("boot_profile", "alpha"), ("transport", "HTTP")],
            456,
        ),
        (
            "tempest_transfer_failures_by_profile_transport_total",
            vec![("boot_profile", "alpha"), ("transport", "TFTP")],
            1,
        ),
        ("tempest_malformed_packets_total", vec![], u64::MAX),
        ("tempest_retransmissions_total", vec![], 3),
        ("tempest_drain_mode", vec![], 1),
        (
            "tempest_release_control_events_total",
            vec![("event", "cutover_success")],
            1,
        ),
        (
            "tempest_listener_shard_requests_total",
            vec![("shard", "0")],
            0,
        ),
        (
            "tempest_audit_admission_rejected_total",
            vec![("reason", "writer_queue")],
            0,
        ),
        (
            "tempest_extension_failures_total",
            vec![("contract", "scheduler"), ("operation", "send_packet")],
            0,
        ),
    ] {
        assert_eq!(value(metrics, name, &labels), expected, "{name}");
    }
    for name in [
        "tempest_version_groups_total",
        "tempest_active_boot_sessions_total",
    ] {
        assert!(matches!(
            find(metrics, name).data(),
            AggregatedMetrics::U64(MetricData::Gauge(_))
        ));
    }
    let AggregatedMetrics::F64(MetricData::Sum(sum)) =
        find(metrics, "tempest_audit_jsonl_commit_seconds_total").data()
    else {
        panic!("fractional counter")
    };
    assert_eq!(sum.data_points().next().unwrap().value(), 0.0);
    #[cfg(target_pointer_width = "64")]
    assert!(matches!(
        find(metrics, "tempest_runtime_worker_busy_seconds_total").data(),
        AggregatedMetrics::F64(MetricData::Sum(_))
    ));
}

#[tokio::test]
async fn listener_shard_metrics_preserve_labels_counts_and_limit() {
    let mut config = TempestConfig::default();
    config.server.listener_shards = if cfg!(target_os = "linux") { 2 } else { 1 };
    let expected_shards = config.server.effective_listener_shards();
    let server = TftpServer::new(config);
    let state = server.state();
    for (shard, requests) in state.metrics.listener_shard_requests.iter().enumerate() {
        requests.store(shard as u64 + 1, Ordering::Relaxed);
    }
    let metrics = collect(&state);
    let name = "tempest_listener_shard_requests_total";
    let AggregatedMetrics::U64(MetricData::Sum(sum)) = find(&metrics, name).data() else {
        panic!("expected shard counter");
    };
    assert_eq!(sum.data_points().count(), expected_shards);
    for shard in 0..expected_shards {
        assert_eq!(
            value(&metrics, name, &[("shard", &shard.to_string())]),
            shard as u64 + 1
        );
    }
}

#[tokio::test]
async fn native_dimensions_values_schema_and_precision() {
    let server = TftpServer::new(TempestConfig::default());
    let state = server.state();
    seed_transfers(&state);
    let metrics = collect(&state);
    assert_values(&metrics);
    let definitions = &state.metrics.telemetry.get().unwrap().definitions;
    let mut schema: Vec<_> = definitions
        .iter()
        .map(|(name, help, kind)| format!("{name} {kind} {help}"))
        .collect();
    schema.sort();
    let expected: Vec<_> = include_str!("schema.txt")
        .lines()
        .filter(|line| {
            cfg!(target_pointer_width = "64")
                || !line.starts_with("tempest_runtime_worker_busy_seconds_total ")
        })
        .collect();
    assert_eq!(schema, expected);
    assert_eq!(
        definitions
            .iter()
            .map(|d| d.0)
            .collect::<BTreeSet<_>>()
            .len(),
        definitions.len()
    );
    for metric in metrics.scope_metrics().flat_map(|s| s.metrics()) {
        let definition = definitions.iter().find(|d| d.0 == metric.name()).unwrap();
        assert_eq!(metric.description(), definition.1);
        let kind = match metric.data() {
            AggregatedMetrics::U64(MetricData::Gauge(_)) => "gauge",
            AggregatedMetrics::U64(MetricData::Sum(_))
            | AggregatedMetrics::F64(MetricData::Sum(_)) => "counter",
            AggregatedMetrics::F64(MetricData::Histogram(_)) => "histogram",
            other => panic!("unexpected aggregation: {other:?}"),
        };
        assert_eq!(kind, definition.2, "{}", metric.name());
    }
    let text = String::from_utf8(exposition::render(&metrics, definitions).to_vec()).unwrap();
    assert!(text.contains("tempest_malformed_packets_total 18446744073709551615\n"));
    assert!(text.contains(
        "tempest_transfer_bytes_by_transport_phase_total{transport=\"HTTP\",phase=\"KERNEL\"} 456\n"
    ));
    assert!(text.contains("tempest_transfer_duration_seconds_sum{phase=\"KERNEL\"} 2.5\n"));
    assert!(!text.contains("_total_total"));
    assert!(!text.contains("otel_scope"));
    assert!(!text.contains("target_info"));
}

#[tokio::test]
async fn histograms_record_real_events_without_replay_on_collection() {
    let server = TftpServer::new(TempestConfig::default());
    let state = server.state();
    seed_transfers(&state);
    for _ in 0..3 {
        let metrics = collect(&state);
        assert_values(&metrics);
        let h = histogram(&metrics, "tempest_release_cutover_duration_seconds", &[]);
        assert_eq!(h.count(), 4);
        assert_eq!(h.sum(), 302.25);
        assert_eq!(h.bounds().collect::<Vec<_>>(), DURATION_BUCKETS);
        assert_eq!(
            h.bucket_counts().collect::<Vec<_>>(),
            [1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(h.bucket_counts().sum::<u64>(), h.count());
        let phase = histogram(
            &metrics,
            "tempest_transfer_duration_seconds",
            &[("phase", "KERNEL")],
        );
        assert_eq!((phase.count(), phase.sum()), (2, 2.5));
        let profile = histogram(
            &metrics,
            "tempest_transfer_duration_by_profile_seconds",
            &[("boot_profile", "beta")],
        );
        assert_eq!((profile.count(), profile.sum()), (1, 301.0));
        let text = String::from_utf8(
            exposition::render(
                &metrics,
                &state.metrics.telemetry.get().unwrap().definitions,
            )
            .to_vec(),
        )
        .unwrap();
        assert!(text.contains("tempest_release_cutover_duration_seconds_bucket{le=\"0.5\"} 2\n"));
        assert!(text.contains("tempest_release_cutover_duration_seconds_bucket{le=\"+Inf\"} 4\n"));
        assert!(text.contains("tempest_transfer_duration_by_profile_seconds_bucket{boot_profile=\"beta\",le=\"300\"} 0\n"));
    }
}

#[test]
fn histogram_exact_boundaries_invalid_values_and_cutover_finished() {
    let server = TftpServer::new(TempestConfig::default());
    let state = server.state();
    for &bound in DURATION_BUCKETS {
        state.metrics.cutover_duration.observe(bound);
    }
    for invalid in [f64::NAN, f64::INFINITY, -1.0] {
        state.metrics.cutover_duration.observe(invalid);
    }
    state.metrics.cutover_duration.observe(301.0);
    let metrics = collect(&state);
    let h = histogram(&metrics, "tempest_release_cutover_duration_seconds", &[]);
    assert_eq!(h.bounds().collect::<Vec<_>>(), DURATION_BUCKETS);
    assert_eq!(h.count(), 16);
    assert_eq!(
        h.bucket_counts().collect::<Vec<_>>(),
        [4, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
    );
    assert_eq!(h.sum(), DURATION_BUCKETS.iter().sum::<f64>() + 301.0);
    assert_eq!(state.metrics.cutover_duration.snapshot().2, 16);
    state
        .metrics
        .cutover_finished(Instant::now(), "cutover_success");
    assert_eq!(
        histogram(
            &collect(&state),
            "tempest_release_cutover_duration_seconds",
            &[]
        )
        .count(),
        17
    );
}

#[tokio::test]
async fn external_in_memory_export_parity_disabled_http_and_weak_lifetime() {
    let exporter = InMemoryMetricExporter::default();
    let provider = SdkMeterProvider::builder()
        .with_reader(
            PeriodicReader::builder(exporter.clone())
                .with_interval(Duration::from_secs(3600))
                .build(),
        )
        .build();
    let mut config = TempestConfig::default();
    config.api.enable_metrics = false;
    let server = TftpServer::builder(config)
        .with_meter(provider.meter("test-external"))
        .build()
        .unwrap();
    let state = server.state();
    seed_transfers(&state);
    // Force flush executes callbacks on the reader thread, without Tokio.
    for _ in 0..2 {
        provider.force_flush().unwrap();
        let exported = exporter.get_finished_metrics().unwrap();
        let metrics = exported.last().unwrap();
        assert_values(metrics);
        assert_eq!(
            histogram(metrics, "tempest_release_cutover_duration_seconds", &[]).count(),
            4
        );
        assert_eq!(
            histogram(
                metrics,
                "tempest_transfer_duration_seconds",
                &[("phase", "KERNEL")]
            )
            .bounds()
            .collect::<Vec<_>>(),
            DURATION_BUCKETS
        );
    }
    // The local provider remains independent of the supplied external meter.
    assert_values(&collect(&state));
    provider.shutdown().unwrap();
    state
        .metrics
        .retransmissions_total
        .store(91, Ordering::Relaxed);
    assert_eq!(
        value(&collect(&state), "tempest_retransmissions_total", &[]),
        91
    );
    let weak = Arc::downgrade(&state);
    drop(server);
    drop(state);
    assert!(weak.upgrade().is_none());
}

#[test]
fn external_callbacks_do_not_retain_state_or_require_tokio_or_globals() {
    let (provider, reader) = local_provider(LOCAL_CARDINALITY_LIMIT, LOCAL_CARDINALITY_LIMIT);
    let server = TftpServer::builder(TempestConfig::default())
        .with_meter(provider.meter("outside-runtime"))
        .build()
        .unwrap();
    let state = server.state();
    let other = TftpServer::new(TempestConfig::default());
    state
        .metrics
        .retransmissions_total
        .store(29, Ordering::Relaxed);
    let weak = Arc::downgrade(&state);
    let collected = std::thread::spawn(move || {
        let mut metrics = ResourceMetrics::default();
        reader.collect(&mut metrics).unwrap();
        (metrics, reader)
    })
    .join()
    .unwrap();
    assert_eq!(
        value(&collected.0, "tempest_retransmissions_total", &[]),
        29
    );
    assert_eq!(
        value(
            &collect(&other.state()),
            "tempest_retransmissions_total",
            &[]
        ),
        0
    );
    assert!(
        !collected
            .0
            .scope_metrics()
            .flat_map(|s| s.metrics())
            .any(|m| m.name().starts_with("tempest_runtime_"))
    );
    drop(state);
    drop(server);
    assert!(
        weak.upgrade().is_none(),
        "external provider still alive must not retain server"
    );
    let mut metrics = ResourceMetrics::default();
    collected.1.collect(&mut metrics).unwrap();
    assert!(
        !metrics
            .scope_metrics()
            .flat_map(|s| s.metrics())
            .any(|m| m.name() == "tempest_retransmissions_total")
    );
    drop(provider);
}

#[tokio::test]
async fn http_cache_is_text_only_and_refreshes_atomically() {
    let server = TftpServer::new(TempestConfig::default());
    let state = server.state();
    assert!(state.metrics.snapshot.load_full().is_none());
    let response = metrics_handler(State(state.clone())).await.into_response();
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "text/plain; version=0.0.4; charset=utf-8"
    );
    let first = state.metrics.snapshot.load_full().unwrap();
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        *first
    );
    state
        .metrics
        .retransmissions_total
        .store(77, Ordering::Relaxed);
    let response = metrics_handler(State(state.clone())).await.into_response();
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        *first
    );
    assert!(Arc::ptr_eq(
        &first,
        &state.metrics.snapshot.load_full().unwrap()
    ));
    refresh_metrics_snapshot(&state);
    let second = state.metrics.snapshot.load_full().unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert!(
        std::str::from_utf8(&second)
            .unwrap()
            .contains("tempest_retransmissions_total 77\n")
    );
    assert!(
        std::str::from_utf8(&first)
            .unwrap()
            .contains("tempest_retransmissions_total 0\n")
    );
}

#[test]
fn standard_data_exposition_preserves_fractions_and_escaped_labels() {
    let (provider, reader) = local_provider(10, 10);
    let meter = provider.meter("exposition");
    let _counter = meter
        .f64_observable_counter("example_seconds_total")
        .with_description("Cumulative seconds")
        .with_callback(|i| i.observe(0.125, &[KeyValue::new("label", "a\"b\\c\nd")]))
        .build();
    let mut metrics = ResourceMetrics::default();
    reader.collect(&mut metrics).unwrap();
    assert_eq!(
        std::str::from_utf8(&exposition::render(
            &metrics,
            &[("example_seconds_total", "Cumulative seconds", "counter")]
        ))
        .unwrap(),
        "# HELP example_seconds_total Cumulative seconds\n# TYPE example_seconds_total counter\nexample_seconds_total{label=\"a\\\"b\\\\c\\nd\"} 0.125\n\n"
    );
}

#[tokio::test]
async fn concurrent_scrapes_exports_and_events_do_not_double_count() {
    let (provider, reader) = local_provider(LOCAL_CARDINALITY_LIMIT, LOCAL_CARDINALITY_LIMIT);
    let server = TftpServer::builder(TempestConfig::default())
        .with_meter(provider.meter("concurrent"))
        .build()
        .unwrap();
    let state = server.state();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for _ in 0..80 {
                completed(&state, "alpha", BootPhase::Kernel, TRANSPORT_TFTP, 1, 0.5);
            }
        });
        scope.spawn(|| {
            for _ in 0..40 {
                refresh_metrics_snapshot(&state);
            }
        });
        scope.spawn(|| {
            for _ in 0..40 {
                let mut metrics = ResourceMetrics::default();
                reader.collect(&mut metrics).unwrap();
                for metric in metrics.scope_metrics().flat_map(|s| s.metrics()) {
                    if let AggregatedMetrics::F64(MetricData::Histogram(h)) = metric.data() {
                        for point in h.data_points() {
                            assert_eq!(point.bucket_counts().sum::<u64>(), point.count());
                        }
                    }
                }
            }
        });
    });
    let local = collect(&state);
    let mut external = ResourceMetrics::default();
    reader.collect(&mut external).unwrap();
    for metrics in [&local, &external] {
        assert_eq!(
            value(metrics, "tempest_transfers_total", &[("phase", "KERNEL")]),
            80
        );
        assert_eq!(value(metrics, "tempest_retransmissions_total", &[]), 80);
        let h = histogram(
            metrics,
            "tempest_transfer_duration_seconds",
            &[("phase", "KERNEL")],
        );
        assert_eq!((h.count(), h.sum()), (80, 40.0));
    }
}

#[test]
fn low_external_cardinality_reports_overflow_without_losing_histogram_events() {
    let (provider, reader) = local_provider(2, 2);
    let server = TftpServer::builder(TempestConfig::default())
        .with_meter(provider.meter("low-limit"))
        .build()
        .unwrap();
    let state = server.state();
    for profile in ["a", "b", "c", "d"] {
        completed(&state, profile, BootPhase::Kernel, TRANSPORT_TFTP, 1, 0.5);
    }
    let mut metrics = ResourceMetrics::default();
    reader.collect(&mut metrics).unwrap();
    let AggregatedMetrics::F64(MetricData::Histogram(h)) =
        find(&metrics, "tempest_transfer_duration_by_profile_seconds").data()
    else {
        panic!("histogram")
    };
    assert_eq!(h.data_points().map(|p| p.count()).sum::<u64>(), 4);
    assert!(h.data_points().count() <= 3);
    assert!(h.data_points().any(|p| {
        p.attributes()
            .any(|kv| kv.key.as_str() == "otel.metric.overflow" && kv.value.to_string() == "true")
    }));
    let AggregatedMetrics::U64(MetricData::Sum(sum)) =
        find(&metrics, "tempest_transfers_by_profile_total").data()
    else {
        panic!("sum")
    };
    // SDK 0.32 asynchronous overflow is last-value, NOT additive. Two
    // retained series plus one overflow value each report 1 here. A caller
    // using an undersized view loses business-counter information; do not
    // promise histogram-style conservation for observable instruments.
    assert_eq!(sum.data_points().map(|p| p.value()).sum::<u64>(), 3);
    assert!(sum.data_points().any(|p| {
        p.attributes()
            .any(|kv| kv.key.as_str() == "otel.metric.overflow")
    }));
    // Local export is not truncated by the caller's deliberately small view.
    let local = collect(&state);
    for profile in ["a", "b", "c", "d"] {
        assert_eq!(
            histogram(
                &local,
                "tempest_transfer_duration_by_profile_seconds",
                &[("boot_profile", profile)]
            )
            .count(),
            1
        );
    }
    reader.collect(&mut metrics).unwrap();
    let AggregatedMetrics::F64(MetricData::Histogram(h)) =
        find(&metrics, "tempest_transfer_duration_by_profile_seconds").data()
    else {
        panic!("histogram")
    };
    assert_eq!(h.data_points().map(|p| p.count()).sum::<u64>(), 4);
}

#[test]
fn local_view_preserves_more_than_default_sdk_2000_profiles() {
    let server = TftpServer::new(TempestConfig::default());
    let state = server.state();
    for profile in 0..2100 {
        completed(
            &state,
            &format!("profile-{profile}"),
            BootPhase::Kernel,
            TRANSPORT_TFTP,
            1,
            0.5,
        );
    }
    let metrics = collect(&state);
    let AggregatedMetrics::F64(MetricData::Histogram(h)) =
        find(&metrics, "tempest_transfer_duration_by_profile_seconds").data()
    else {
        panic!("histogram")
    };
    assert_eq!(h.data_points().count(), 2100);
    assert_eq!(h.data_points().map(|p| p.count()).sum::<u64>(), 2100);
    assert!(!h.data_points().any(|p| {
        p.attributes()
            .any(|kv| kv.key.as_str() == "otel.metric.overflow")
    }));
}

#[test]
fn local_session_profiles_preserve_configured_capacity_and_churn() {
    use crate::server::BootSessionEntry;
    use std::net::{IpAddr, Ipv6Addr};

    for capacity in [3, 40_000] {
        let mut config = TempestConfig::default();
        config.server.max_boot_sessions = capacity;
        let server = TftpServer::new(config);
        let state = server.state();
        for generation in 0..3 {
            state.boot_sessions.clear();
            for index in 0..capacity {
                state.boot_sessions.insert(
                    IpAddr::V6(Ipv6Addr::from(index as u128 + 1)),
                    BootSessionEntry {
                        trace_id: None,
                        boot_profile: format!("generation-{generation}-profile-{index}"),
                        client_mac: None,
                        serial: None,
                        boot_epoch: 1,
                        artifact_token_hash: None,
                        pinned_boot_chain: None,
                        expires_at: Instant::now() + Duration::from_secs(600),
                    },
                );
            }
            let metrics = collect(&state);
            let AggregatedMetrics::U64(MetricData::Gauge(gauge)) =
                find(&metrics, "tempest_active_boot_sessions").data()
            else {
                panic!("expected session gauge");
            };
            assert_eq!(gauge.data_points().count(), capacity);
            assert_eq!(
                gauge.data_points().map(|p| p.value()).sum::<u64>(),
                capacity as u64
            );
            for point in gauge.data_points() {
                assert_eq!(point.value(), 1);
                let attributes: Vec<_> = point.attributes().collect();
                assert_eq!(attributes.len(), 1);
                assert_eq!(attributes[0].key.as_str(), "boot_profile");
                assert!(
                    attributes[0]
                        .value
                        .to_string()
                        .starts_with(&format!("generation-{generation}-"))
                );
            }
            assert_eq!(
                value(&metrics, "tempest_active_boot_sessions_total", &[]),
                capacity as u64
            );
            let text = exposition::render(
                &metrics,
                &state.metrics.telemetry.get().unwrap().definitions,
            );
            let text = std::str::from_utf8(&text).unwrap();
            assert_eq!(
                text.lines()
                    .filter(|line| line.starts_with("tempest_active_boot_sessions{"))
                    .count(),
                capacity
            );
            assert!(!text.contains("otel_metric_overflow"));
        }
    }
}

#[test]
fn local_profile_transport_churn_preserves_current_labels_without_overflow() {
    let server = TftpServer::new(TempestConfig::default());
    let state = server.state();
    for generation in 0..2 {
        for profile in 0..10_000 {
            let profile = format!("generation-{generation}-profile-{profile}");
            for transport in [TRANSPORT_TFTP, TRANSPORT_HTTP, TRANSPORT_HTTP_NATIVE] {
                completed(&state, &profile, BootPhase::Kernel, transport, 1, 0.5);
            }
        }
        let metrics = collect(&state);
        let AggregatedMetrics::U64(MetricData::Sum(sum)) =
            find(&metrics, "tempest_transfers_by_profile_transport_total").data()
        else {
            panic!("expected profile transport counter");
        };
        assert_eq!(sum.data_points().count(), 30_000);
        assert!(!sum.data_points().any(|point| {
            point
                .attributes()
                .any(|kv| kv.key.as_str() == "otel.metric.overflow")
        }));
        state.metrics.evict_inactive_profiles_at(24 * 60 * 60 + 1);
    }
}
