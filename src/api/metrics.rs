// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::sync::{Arc, Weak};
use std::time::Duration;

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use bytes::Bytes;
use opentelemetry::metrics::{Meter, MeterProvider};
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::metrics::{
    Aggregation, InstrumentKind, ManualReader, Pipeline, SdkMeterProvider, Stream, Temporality,
    data::ResourceMetrics, reader::MetricReader,
};

use crate::server::ServerState;

mod exposition;
mod render;

// Fits two consecutive collections of three transports × (10,000 tracked
// profiles + default). The SDK may additionally emit one overflow series.
// Cumulative histogram series are lifetime-bounded, not TTL-evicted by the SDK.
const LOCAL_CARDINALITY_LIMIT: usize = 60_007;

/// Arc adapter lets the server collect its own reader without a global provider.
#[derive(Debug, Clone)]
struct SharedReader(Arc<ManualReader>);

impl MetricReader for SharedReader {
    fn register_pipeline(&self, pipeline: Weak<Pipeline>) {
        self.0.register_pipeline(pipeline);
    }
    fn collect(&self, metrics: &mut ResourceMetrics) -> OTelSdkResult {
        self.0.collect(metrics)
    }
    fn force_flush(&self) -> OTelSdkResult {
        self.0.force_flush()
    }
    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.0.shutdown_with_timeout(timeout)
    }
    fn temporality(&self, kind: InstrumentKind) -> Temporality {
        self.0.temporality(kind)
    }
}

pub(crate) struct LocalMetrics {
    // Provider must live as long as the server, not just initialize().
    _provider: SdkMeterProvider,
    reader: SharedReader,
    definitions: Vec<render::Definition>,
}

impl LocalMetrics {
    fn collect(&self) -> Result<ResourceMetrics, opentelemetry_sdk::error::OTelSdkError> {
        let mut metrics = ResourceMetrics::default();
        self.reader.collect(&mut metrics)?;
        Ok(metrics)
    }
}

fn local_provider(limit: usize, session_limit: usize) -> (SdkMeterProvider, SharedReader) {
    let reader = SharedReader(Arc::new(
        ManualReader::builder()
            .with_temporality(Temporality::Cumulative)
            .build(),
    ));
    let provider = SdkMeterProvider::builder()
        .with_reader(reader.clone())
        .with_view(move |instrument: &opentelemetry_sdk::metrics::Instrument| {
            // Session profiles are bounded by session capacity, independently of
            // the smaller transfer-profile cache. Each live session can have its
            // own profile. SDK gauges retain the previous collection's labels
            // until after the next callback, so allow old + new at full churn.
            let cardinality = if instrument.name() == "tempest_active_boot_sessions" {
                session_limit * 2
            } else {
                limit
            };
            let mut stream = Stream::builder().with_cardinality_limit(cardinality);
            if instrument.kind() == InstrumentKind::Histogram {
                stream = stream.with_aggregation(Aggregation::ExplicitBucketHistogram {
                    boundaries: crate::server::DURATION_BUCKETS.to_vec(),
                    record_min_max: true,
                });
            }
            Some(stream.build().expect("validated local metrics view"))
        })
        .build();
    (provider, reader)
}

pub(crate) fn initialize(state: &Arc<ServerState>, external: Option<Meter>) {
    let (provider, reader) = local_provider(
        LOCAL_CARDINALITY_LIMIT,
        state.config.server.max_boot_sessions,
    );
    let local = render::register(state, &provider.meter("tempest"));
    let mut transfer = vec![(local.phase, local.profile)];
    let mut cutover = vec![local.cutover];
    if let Some(meter) = external {
        let registered = render::register(state, &meter);
        transfer.push((registered.phase, registered.profile));
        cutover.push(registered.cutover);
    }
    assert!(state.metrics.transfer_histograms.set(transfer).is_ok());
    assert!(
        state
            .metrics
            .cutover_duration
            .instruments
            .set(cutover)
            .is_ok()
    );
    assert!(
        state
            .metrics
            .telemetry
            .set(LocalMetrics {
                _provider: provider,
                reader,
                definitions: local.definitions,
            })
            .is_ok()
    );
}

/// Serves the most recent pre-rendered Prometheus snapshot.
pub async fn metrics_handler(State(state): State<Arc<ServerState>>) -> impl IntoResponse {
    let content_type = header::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8");
    let snapshot = match state.metrics.snapshot.load_full() {
        Some(snapshot) => snapshot,
        None => metrics_snapshot_async(&state, false).await,
    };
    ([(header::CONTENT_TYPE, content_type)], (*snapshot).clone())
}

/// Collects and renders a snapshot outside Tokio's async worker pool.
pub(crate) async fn refresh_metrics_snapshot_async(state: &Arc<ServerState>) -> Arc<Bytes> {
    metrics_snapshot_async(state, true).await
}

async fn metrics_snapshot_async(state: &Arc<ServerState>, force: bool) -> Arc<Bytes> {
    let refresh = state.metrics.snapshot_refresh.clone().lock_owned().await;
    if !force {
        if let Some(snapshot) = state.metrics.snapshot.load_full() {
            return snapshot;
        }
    }
    let weak_state = Arc::downgrade(state);
    match tokio::task::spawn_blocking(move || {
        let _refresh = refresh;
        let Some(state) = weak_state.upgrade() else {
            return Arc::new(Bytes::new());
        };
        publish_snapshot(&state)
    })
    .await
    {
        Ok(snapshot) => snapshot,
        Err(error) => {
            tracing::warn!(%error, "metrics snapshot task failed");
            state.metrics.snapshot.load_full().unwrap_or_default()
        }
    }
}

/// Collects the local OTel reader and atomically publishes text only.
#[cfg(test)]
pub(crate) fn refresh_metrics_snapshot(state: &ServerState) {
    publish_snapshot(state);
}

fn publish_snapshot(state: &ServerState) -> Arc<Bytes> {
    let telemetry = state
        .metrics
        .telemetry
        .get()
        .expect("server telemetry initialized");
    let metrics = match telemetry.collect() {
        Ok(metrics) => metrics,
        Err(error) => {
            tracing::warn!(%error, "local OpenTelemetry collection failed");
            return state.metrics.snapshot.load_full().unwrap_or_default();
        }
    };
    let snapshot = Arc::new(exposition::render(&metrics, &telemetry.definitions));
    state.metrics.snapshot.store(Some(snapshot.clone()));
    snapshot
}

#[cfg(test)]
mod tests;
