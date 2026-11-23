// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use dashmap::DashMap;

use crate::features::boot_phase::BootPhase;
use crate::features::versioning::DEFAULT_BOOT_PROFILE;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Histogram;

use super::{
    TRANSPORT_HTTP, TRANSPORT_HTTP_NATIVE, TRANSPORT_TFTP, release_active_transfer_counter,
};

pub(super) const MAX_PROFILE_METRICS: usize = 10_000;
pub(super) const PROFILE_METRICS_TTL: Duration = Duration::from_secs(24 * 60 * 60);
pub(crate) const MAX_LISTENER_SHARDS: usize = 64;
const TRANSPORT_COUNT: usize = 3;
const TRANSPORTS: [&str; TRANSPORT_COUNT] = [TRANSPORT_TFTP, TRANSPORT_HTTP, TRANSPORT_HTTP_NATIVE];

/// Fixed-cardinality extension failures recorded by core-owned call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum ExtensionFailure {
    SchedulerScheduleWindow,
    SchedulerSendPacket,
    ReadProtocolPrepare,
    ReadProtocolEncodePacket,
    RouterHandle,
}

impl ExtensionFailure {
    const COUNT: usize = 5;
    const ALL: [Self; Self::COUNT] = [
        Self::SchedulerScheduleWindow,
        Self::SchedulerSendPacket,
        Self::ReadProtocolPrepare,
        Self::ReadProtocolEncodePacket,
        Self::RouterHandle,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    pub(crate) const fn labels(self) -> (&'static str, &'static str) {
        match self {
            Self::SchedulerScheduleWindow => ("scheduler", "schedule_window"),
            Self::SchedulerSendPacket => ("scheduler", "send_packet"),
            Self::ReadProtocolPrepare => ("read_protocol", "prepare"),
            Self::ReadProtocolEncodePacket => ("read_protocol", "encode_packet"),
            Self::RouterHandle => ("router", "handle"),
        }
    }
}

fn transport_index(transport: &'static str) -> usize {
    match transport {
        TRANSPORT_HTTP => 1,
        TRANSPORT_HTTP_NATIVE => 2,
        _ => {
            debug_assert_eq!(transport, TRANSPORT_TFTP);
            0
        }
    }
}

/// Bucket boundaries for the transfer duration histogram (seconds).
/// Covers sub-ms PXE ROM grabs through 5-minute OS image transfers over WAN.
pub const DURATION_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.025, 0.1, 0.5, 1.0, 5.0, 15.0, 30.0, 60.0, 120.0, 300.0,
];

/// Compatibility duration accumulator with optional native OTel recording.
///
/// Observations update one exclusive bucket. Snapshots form the cumulative
/// counts for existing readers. Once attached to server telemetry, each observe
/// also records that event in the local and optional external OTel instruments.
/// Exporters consume the SDK aggregation, never replay this bookkeeping.
pub struct DurationHistogram {
    buckets: Box<[AtomicU64]>,
    sum_bits: AtomicU64,
    count: AtomicU64,
    pub(crate) instruments: OnceLock<Vec<Histogram<f64>>>,
}

impl DurationHistogram {
    /// Creates an empty histogram using [`DURATION_BUCKETS`].
    pub fn new() -> Self {
        let buckets: Vec<AtomicU64> = (0..DURATION_BUCKETS.len())
            .map(|_| AtomicU64::new(0))
            .collect();
        Self {
            buckets: buckets.into_boxed_slice(),
            sum_bits: AtomicU64::new(0),
            count: AtomicU64::new(0),
            instruments: OnceLock::new(),
        }
    }
}

impl Default for DurationHistogram {
    fn default() -> Self {
        Self::new()
    }
}

impl DurationHistogram {
    /// Record an observation. Guards against NaN/negative values.
    pub fn observe(&self, secs: f64) {
        let secs = if !secs.is_finite() || secs < 0.0 {
            0.0
        } else {
            secs
        };

        if let Some(index) = DURATION_BUCKETS.iter().position(|bound| secs <= *bound) {
            self.buckets[index].fetch_add(1, Ordering::Relaxed);
        }

        // Lock-free f64 sum via CAS loop
        loop {
            let old_bits = self.sum_bits.load(Ordering::Relaxed);
            let old_f = f64::from_bits(old_bits);
            let new_f = old_f + secs;
            match self.sum_bits.compare_exchange_weak(
                old_bits,
                new_f.to_bits(),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }

        self.count.fetch_add(1, Ordering::Relaxed);
        if let Some(instruments) = self.instruments.get() {
            for instrument in instruments {
                instrument.record(secs, &[]);
            }
        }
    }

    /// Compatibility snapshot: (cumulative bucket counts, sum, count).
    pub fn snapshot(&self) -> (Vec<u64>, f64, u64) {
        let mut cumulative = 0u64;
        let buckets = self
            .buckets
            .iter()
            .map(|bucket| {
                cumulative = cumulative.saturating_add(bucket.load(Ordering::Relaxed));
                cumulative
            })
            .collect();
        let sum = f64::from_bits(self.sum_bits.load(Ordering::Relaxed));
        let count = self.count.load(Ordering::Relaxed);
        (buckets, sum, count)
    }
}

#[derive(Default)]
pub(super) struct ProfileCounterSet {
    pub(super) transfers: AtomicU64,
    bytes: AtomicU64,
    failures: AtomicU64,
}

impl ProfileCounterSet {
    fn started(&self) {
        self.transfers.fetch_add(1, Ordering::Relaxed);
    }

    fn completed(&self, bytes: u64) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    fn failed(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.transfers.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
            self.failures.load(Ordering::Relaxed),
        )
    }
}

pub(super) struct ProfileMetrics {
    pub(super) totals: ProfileCounterSet,
    tftp: ProfileCounterSet,
    http: ProfileCounterSet,
    http_native: ProfileCounterSet,
    last_seen_secs: AtomicU64,
}

impl ProfileMetrics {
    fn new(now_secs: u64) -> Self {
        Self {
            totals: ProfileCounterSet::default(),
            tftp: ProfileCounterSet::default(),
            http: ProfileCounterSet::default(),
            http_native: ProfileCounterSet::default(),
            last_seen_secs: AtomicU64::new(now_secs),
        }
    }

    fn transport(&self, transport: &'static str) -> &ProfileCounterSet {
        match transport {
            TRANSPORT_HTTP => &self.http,
            TRANSPORT_HTTP_NATIVE => &self.http_native,
            _ => {
                debug_assert_eq!(transport, TRANSPORT_TFTP);
                &self.tftp
            }
        }
    }

    fn touch(&self, now_secs: u64) {
        self.last_seen_secs.store(now_secs, Ordering::Relaxed);
    }

    fn snapshot(&self) -> ProfileMetricsSnapshot {
        ProfileMetricsSnapshot {
            totals: self.totals.snapshot(),
            tftp: self.tftp.snapshot(),
            http: self.http.snapshot(),
            http_native: self.http_native.snapshot(),
        }
    }
}

pub(crate) struct ProfileMetricsSnapshot {
    pub(crate) totals: (u64, u64, u64),
    pub(crate) tftp: (u64, u64, u64),
    pub(crate) http: (u64, u64, u64),
    pub(crate) http_native: (u64, u64, u64),
}

pub(crate) type CounterSnapshot = (u64, u64, u64);
pub(crate) type PhaseCounterSnapshot = (&'static str, CounterSnapshot);
pub(crate) type TransportCounterSnapshot = (&'static str, CounterSnapshot);
pub(crate) type TransportPhaseCounterSnapshot = ((&'static str, &'static str), CounterSnapshot);
type ProfileMetricSnapshots = Vec<(String, ProfileMetricsSnapshot)>;

/// Server-wide metrics for Prometheus exposure.
pub struct ServerMetrics {
    /// Fixed-cardinality counters indexed by [`BootPhase`].
    phase_metrics: [ProfileCounterSet; BootPhase::COUNT],
    /// Consolidated, bounded transfer counters keyed by boot profile.
    pub(super) profile_metrics: DashMap<String, ProfileMetrics>,
    pub(super) profile_metrics_count: AtomicUsize,
    profile_metrics_started: Instant,
    default_profile_metrics: ProfileMetrics,
    default_profile_seen: AtomicBool,
    profile_snapshot_generation: AtomicU64,
    profile_snapshot_cache: parking_lot::RwLock<Option<(u64, Arc<ProfileMetricSnapshots>)>>,
    /// Fixed-cardinality counters indexed by stable transport.
    transport_metrics: [ProfileCounterSet; TRANSPORT_COUNT],
    /// Fixed-cardinality counters indexed by stable transport and phase.
    transport_phase_metrics: [[ProfileCounterSet; BootPhase::COUNT]; TRANSPORT_COUNT],
    /// Shared active-transfer gauge decremented by terminal lifecycle methods.
    pub active_transfers: Arc<AtomicUsize>,
    /// Total TFTP retransmission events.
    pub retransmissions_total: AtomicU64,
    /// Malformed TFTP packets observed before warning sampling.
    pub malformed_packets_total: AtomicU64,
    /// Non-request TFTP opcodes received by the listener.
    pub unexpected_opcodes_total: AtomicU64,
    /// Retransmitted RRQ or WRQ packets coalesced by client transfer ID.
    pub duplicate_requests_total: AtomicU64,
    /// Accepted requests attributed to each bounded SO_REUSEPORT listener.
    pub(crate) listener_shard_requests: [AtomicU64; MAX_LISTENER_SHARDS],
    /// Option handshakes abandoned before the client acknowledged OACK.
    pub oack_timeouts_total: AtomicU64,
    /// Requests rejected because the server was at max_concurrent_transfers
    pub capacity_rejected_total: AtomicU64,
    /// Requests successfully queued in the admission queue (instead of rejected)
    pub admission_queued_total: AtomicU64,
    /// Requests dequeued from the admission queue and started
    pub admission_started_total: AtomicU64,
    /// Requests dropped from the admission queue (TTL expired / queue full)
    pub admission_dropped_total: AtomicU64,
    /// Explicit provider errors and rejected provider output by fixed operation.
    extension_failures: [AtomicU64; ExtensionFailure::COUNT],
    /// Real-event histograms, fanned out to local and optional external meters.
    pub(crate) transfer_histograms: OnceLock<Vec<(Histogram<f64>, Histogram<f64>)>>,
    /// Release-control outcomes keyed by bounded static event labels.
    pub release_control_events: DashMap<&'static str, u64>,
    /// Release cutover latency histogram measured in seconds.
    pub cutover_duration: DurationHistogram,
    /// Text-only Prometheus publication, initially absent.
    pub(crate) snapshot: Arc<ArcSwapOption<bytes::Bytes>>,
    /// Per-server provider; callbacks hold only weak server references.
    pub(crate) telemetry: OnceLock<crate::api::metrics::LocalMetrics>,
    /// Deduplicates cold HTTP initialization and periodic publication before
    /// either caller submits work to Tokio's blocking pool.
    pub(crate) snapshot_refresh: Arc<tokio::sync::Mutex<()>>,
    /// Per-server wakeup for a pending admission when a slot is released.
    pub(crate) admission_notify: tokio::sync::Notify,
    /// Per-server wakeup for waiters observing complete drain.
    pub(crate) drain_notify: tokio::sync::Notify,
}

impl ServerMetrics {
    /// Creates zeroed metrics sharing the authoritative active-transfer gauge.
    pub fn new(active_transfers: Arc<AtomicUsize>) -> Self {
        Self {
            phase_metrics: std::array::from_fn(|_| ProfileCounterSet::default()),
            profile_metrics: DashMap::new(),
            profile_metrics_count: AtomicUsize::new(0),
            profile_metrics_started: Instant::now(),
            default_profile_metrics: ProfileMetrics::new(0),
            default_profile_seen: AtomicBool::new(false),
            profile_snapshot_generation: AtomicU64::new(0),
            profile_snapshot_cache: parking_lot::RwLock::new(None),
            transport_metrics: std::array::from_fn(|_| ProfileCounterSet::default()),
            transport_phase_metrics: std::array::from_fn(|_| {
                std::array::from_fn(|_| ProfileCounterSet::default())
            }),
            active_transfers,
            retransmissions_total: AtomicU64::new(0),
            malformed_packets_total: AtomicU64::new(0),
            unexpected_opcodes_total: AtomicU64::new(0),
            duplicate_requests_total: AtomicU64::new(0),
            listener_shard_requests: std::array::from_fn(|_| AtomicU64::new(0)),
            oack_timeouts_total: AtomicU64::new(0),
            capacity_rejected_total: AtomicU64::new(0),
            admission_queued_total: AtomicU64::new(0),
            admission_started_total: AtomicU64::new(0),
            admission_dropped_total: AtomicU64::new(0),
            extension_failures: std::array::from_fn(|_| AtomicU64::new(0)),
            transfer_histograms: OnceLock::new(),
            release_control_events: DashMap::new(),
            cutover_duration: DurationHistogram::new(),
            snapshot: Arc::new(ArcSwapOption::empty()),
            snapshot_refresh: Arc::new(tokio::sync::Mutex::new(())),
            telemetry: OnceLock::new(),
            admission_notify: tokio::sync::Notify::new(),
            drain_notify: tokio::sync::Notify::new(),
        }
    }

    fn profile_now_secs(&self) -> u64 {
        self.profile_metrics_started.elapsed().as_secs()
    }

    fn reserve_profile_slot(&self) -> bool {
        #[allow(
            deprecated,
            reason = "try_update requires Rust 1.95; retain fetch_update for MSRV 1.85"
        )]
        let reservation =
            self.profile_metrics_count
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    (count < MAX_PROFILE_METRICS).then_some(count + 1)
                });
        reservation.is_ok()
    }

    pub(super) fn with_profile_metrics(
        &self,
        boot_profile: &str,
        update: impl FnOnce(&ProfileMetrics),
    ) {
        let now_secs = self.profile_now_secs();
        if boot_profile == DEFAULT_BOOT_PROFILE {
            self.default_profile_seen.store(true, Ordering::Relaxed);
            self.default_profile_metrics.touch(now_secs);
            update(&self.default_profile_metrics);
            self.profile_snapshot_generation
                .fetch_add(1, Ordering::Release);
            return;
        }
        if let Some(metrics) = self.profile_metrics.get(boot_profile) {
            metrics.touch(now_secs);
            update(&metrics);
            self.profile_snapshot_generation
                .fetch_add(1, Ordering::Release);
            return;
        }
        if !self.reserve_profile_slot() {
            return;
        }

        use dashmap::mapref::entry::Entry;
        match self.profile_metrics.entry(boot_profile.to_owned()) {
            Entry::Occupied(entry) => {
                self.profile_metrics_count.fetch_sub(1, Ordering::AcqRel);
                entry.get().touch(now_secs);
                update(entry.get());
            }
            Entry::Vacant(entry) => {
                let metrics = entry.insert(ProfileMetrics::new(now_secs));
                update(&metrics);
            }
        }
        self.profile_snapshot_generation
            .fetch_add(1, Ordering::Release);
    }

    /// Remove inactive profile series so metrics cardinality remains bounded.
    pub(crate) fn evict_inactive_profiles(&self) {
        self.evict_inactive_profiles_at(self.profile_now_secs());
    }

    pub(crate) fn evict_inactive_profiles_at(&self, now_secs: u64) {
        let ttl_secs = PROFILE_METRICS_TTL.as_secs();
        let mut removed = 0usize;
        self.profile_metrics.retain(|_, metrics| {
            let keep =
                now_secs.saturating_sub(metrics.last_seen_secs.load(Ordering::Relaxed)) <= ttl_secs;
            removed += usize::from(!keep);
            keep
        });
        if removed > 0 {
            self.profile_metrics_count
                .fetch_sub(removed, Ordering::AcqRel);
            self.profile_snapshot_generation
                .fetch_add(1, Ordering::Release);
        }
    }

    /// Snapshot consolidated profile metrics for background rendering.
    pub(crate) fn profile_metrics_snapshot(&self) -> ProfileMetricSnapshots {
        let mut profiles: Vec<_> = self
            .profile_metrics
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().snapshot()))
            .collect();
        if self.default_profile_seen.load(Ordering::Relaxed) {
            profiles.push((
                DEFAULT_BOOT_PROFILE.to_owned(),
                self.default_profile_metrics.snapshot(),
            ));
        }
        profiles
    }

    /// Reuses one immutable profile snapshot until a transfer update or eviction.
    pub(crate) fn shared_profile_metrics_snapshot(&self) -> Arc<ProfileMetricSnapshots> {
        let generation = self.profile_snapshot_generation.load(Ordering::Acquire);
        if let Some((_, snapshot)) = self
            .profile_snapshot_cache
            .read()
            .as_ref()
            .filter(|(cached, _)| *cached == generation)
        {
            return snapshot.clone();
        }
        let snapshot = Arc::new(self.profile_metrics_snapshot());
        if self.profile_snapshot_generation.load(Ordering::Acquire) == generation {
            *self.profile_snapshot_cache.write() = Some((generation, snapshot.clone()));
        }
        snapshot
    }

    pub(crate) fn phase_metrics_snapshot(&self) -> Vec<PhaseCounterSnapshot> {
        BootPhase::ALL
            .into_iter()
            .filter_map(|phase| {
                let counters = self.phase_metrics[phase.index()].snapshot();
                (counters != (0, 0, 0)).then_some((phase.as_str(), counters))
            })
            .collect()
    }

    pub(crate) fn transport_metrics_snapshot(&self) -> Vec<TransportCounterSnapshot> {
        TRANSPORTS
            .into_iter()
            .enumerate()
            .filter_map(|(index, transport)| {
                let counters = self.transport_metrics[index].snapshot();
                (counters != (0, 0, 0)).then_some((transport, counters))
            })
            .collect()
    }

    pub(crate) fn transport_phase_metrics_snapshot(&self) -> Vec<TransportPhaseCounterSnapshot> {
        TRANSPORTS
            .into_iter()
            .enumerate()
            .flat_map(|(transport_index, transport)| {
                BootPhase::ALL.into_iter().filter_map(move |phase| {
                    let counters =
                        self.transport_phase_metrics[transport_index][phase.index()].snapshot();
                    (counters != (0, 0, 0)).then_some(((transport, phase.as_str()), counters))
                })
            })
            .collect()
    }

    /// Records one explicit extension error or rejected provider output.
    pub(crate) fn extension_failed(&self, failure: ExtensionFailure) {
        self.extension_failures[failure.index()].fetch_add(1, Ordering::Relaxed);
    }

    /// Returns all fixed extension failure series, including zero values.
    pub(crate) fn extension_failure_snapshot(
        &self,
    ) -> [(&'static str, &'static str, u64); ExtensionFailure::COUNT] {
        ExtensionFailure::ALL.map(|failure| {
            let (contract, operation) = failure.labels();
            let count = self.extension_failures[failure.index()].load(Ordering::Relaxed);
            (contract, operation, count)
        })
    }

    /// Increments a release-control event counter using a static bounded label.
    pub fn release_event(&self, event: &'static str) {
        self.release_control_events
            .entry(event)
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
    }

    /// Records a cutover outcome and elapsed duration since `started`.
    pub fn cutover_finished(&self, started: Instant, event: &'static str) {
        self.release_event(event);
        self.cutover_duration
            .observe(started.elapsed().as_secs_f64());
    }

    /// Records a started TFTP transfer; admission already owns the active slot.
    pub fn transfer_started(
        &self,
        phase: &crate::features::boot_phase::BootPhase,
        boot_profile: &str,
    ) {
        self.transfer_started_for_transport(phase, boot_profile, TRANSPORT_TFTP);
    }

    /// Records a started transfer for the supplied stable transport label.
    pub fn transfer_started_for_transport(
        &self,
        phase: &crate::features::boot_phase::BootPhase,
        boot_profile: &str,
        transport: &'static str,
    ) {
        // active_transfers already incremented atomically in the main loop
        self.phase_metrics[phase.index()].started();
        self.with_profile_metrics(boot_profile, |metrics| {
            metrics.totals.started();
            metrics.transport(transport).started();
        });
        let transport_index = transport_index(transport);
        self.transport_metrics[transport_index].started();
        self.transport_phase_metrics[transport_index][phase.index()].started();
    }

    /// Completes TFTP lifecycle accounting and releases one active slot.
    pub fn transfer_completed(
        &self,
        phase: &crate::features::boot_phase::BootPhase,
        boot_profile: &str,
        metrics: &crate::protocol::transfer::TransferMetrics,
    ) {
        self.transfer_completed_for_transport(phase, boot_profile, metrics, TRANSPORT_TFTP);
    }

    /// Records bytes, retries, duration, and releases one active transfer slot.
    ///
    /// This terminal method must be called at most once for a reserved slot.
    pub fn transfer_completed_for_transport(
        &self,
        phase: &crate::features::boot_phase::BootPhase,
        boot_profile: &str,
        metrics: &crate::protocol::transfer::TransferMetrics,
        transport: &'static str,
    ) {
        let prev = release_active_transfer_counter(&self.active_transfers);
        self.phase_metrics[phase.index()].completed(metrics.bytes_sent);
        self.with_profile_metrics(boot_profile, |profile| {
            profile.totals.completed(metrics.bytes_sent);
            profile.transport(transport).completed(metrics.bytes_sent);
            if let Some(instruments) = self.transfer_histograms.get() {
                let labels = [KeyValue::new("boot_profile", boot_profile.to_owned())];
                for (_, instrument) in instruments {
                    instrument.record(metrics.duration().map_or(0.0, |d| d.as_secs_f64()), &labels);
                }
            }
        });
        let transport_index = transport_index(transport);
        self.transport_metrics[transport_index].completed(metrics.bytes_sent);
        self.transport_phase_metrics[transport_index][phase.index()].completed(metrics.bytes_sent);
        self.retransmissions_total
            .fetch_add(metrics.retransmissions, Ordering::Relaxed);

        // Record transfer duration in histogram
        let secs = metrics.duration().map_or(0.0, |d| d.as_secs_f64());
        if let Some(instruments) = self.transfer_histograms.get() {
            let labels = [KeyValue::new("phase", phase.as_str())];
            for (instrument, _) in instruments {
                instrument.record(secs, &labels);
            }
        }

        self.admission_notify.notify_one();

        if prev == 1 {
            self.drain_notify.notify_waiters();
        }
    }

    /// Records a failed TFTP transfer and releases one active slot.
    pub fn transfer_failed(
        &self,
        phase: &crate::features::boot_phase::BootPhase,
        boot_profile: &str,
    ) {
        self.transfer_failed_for_transport(phase, boot_profile, TRANSPORT_TFTP);
    }

    /// Records failure dimensions and releases one active transfer slot.
    ///
    /// This terminal method must be called at most once for a reserved slot.
    pub fn transfer_failed_for_transport(
        &self,
        phase: &crate::features::boot_phase::BootPhase,
        boot_profile: &str,
        transport: &'static str,
    ) {
        let prev = release_active_transfer_counter(&self.active_transfers);
        self.phase_metrics[phase.index()].failed();
        self.with_profile_metrics(boot_profile, |metrics| {
            metrics.totals.failed();
            metrics.transport(transport).failed();
        });
        let transport_index = transport_index(transport);
        self.transport_metrics[transport_index].failed();
        self.transport_phase_metrics[transport_index][phase.index()].failed();

        self.admission_notify.notify_one();

        if prev == 1 {
            self.drain_notify.notify_waiters();
        }
    }
}
