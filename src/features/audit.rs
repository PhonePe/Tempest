// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError, sync_channel};
use std::thread;
use std::time::{Duration, Instant};

use jiff::Timestamp;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::{ProtocolError, TempestError};

/// One durable transfer-delivery audit entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    /// Monotonically increasing sequence within this local audit log.
    pub sequence: u64,
    /// Optional client MAC address supplied by the provisioning control plane.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Optional hardware serial supplied by the provisioning control plane.
    pub client_serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// Boot profile used to resolve the delivered release.
    pub boot_profile: Option<String>,
    /// Text form of the transfer peer IP address.
    pub client_ip: String,
    /// Logical or root-relative artifact path recorded for the transfer.
    pub file_path: String,
    /// Managed content digest; consult the outcome before treating it as delivered.
    pub file_sha256: String,
    /// Number of DATA blocks sent during the transfer.
    pub blocks_sent: u64,
    /// Number of retransmission events observed.
    pub retransmissions: u64,
    /// Final transfer status.
    pub outcome: TransferOutcome,
    /// UTC time at which the entry was created.
    /// JSON retains the existing UTC and fractional-precision encoding.
    #[serde(with = "crate::timestamp")]
    pub timestamp: Timestamp,
    /// Upstream provisioning trace ID, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Release and transport identity associated with the delivery.
    pub delivery: Option<DeliveryIdentity>,
}

fn validate_audit_record(record: &AuditRecord) -> Result<(), TempestError> {
    validate_audit_fields(
        &record.client_ip,
        record.client_mac.as_deref(),
        record.client_serial.as_deref(),
        record.boot_profile.as_deref(),
        &record.file_path,
        &record.file_sha256,
        &record.outcome,
        record.trace_id.as_deref(),
        record.delivery.as_ref(),
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_audit_fields(
    client_ip: &str,
    client_mac: Option<&str>,
    client_serial: Option<&str>,
    boot_profile: Option<&str>,
    file_path: &str,
    file_sha256: &str,
    outcome: &TransferOutcome,
    trace_id: Option<&str>,
    delivery: Option<&DeliveryIdentity>,
) -> Result<(), TempestError> {
    if client_ip.len() > 256
        || file_path.len() > 1024
        || file_sha256.len() > 128
        || client_mac.is_some_and(|value| value.len() > 128)
        || client_serial.is_some_and(|value| value.len() > 128)
        || boot_profile.is_some_and(|value| value.len() > 64)
        || outcome.detail_len() > 512
        || trace_id.is_some_and(|value| value.len() > 128)
        || delivery.is_some_and(|value| {
            value.transfer_id.len() > 128
                || value.group_id.as_ref().is_some_and(|id| id.len() > 128)
                || value
                    .manifest_digest
                    .as_ref()
                    .is_some_and(|digest| digest.len() > 128)
                || value.phase.len() > 64
                || value.transport.len() > 16
        })
    {
        return Err(TempestError::Audit(
            "Audit field value too long".to_string(),
        ));
    }
    if [
        Some(client_ip),
        client_mac,
        client_serial,
        boot_profile,
        Some(file_path),
        Some(file_sha256),
        trace_id,
    ]
    .into_iter()
    .flatten()
    .any(contains_control_character)
        || outcome
            .failure_detail()
            .is_some_and(contains_control_character)
        || delivery.is_some_and(|value| {
            [
                Some(value.transfer_id.as_str()),
                value.group_id.as_deref(),
                value.manifest_digest.as_deref(),
                Some(value.phase.as_str()),
                Some(value.transport.as_str()),
            ]
            .into_iter()
            .flatten()
            .any(contains_control_character)
        })
    {
        return Err(TempestError::Audit(
            "Audit field value contains a control character".to_string(),
        ));
    }
    Ok(())
}

fn contains_control_character(value: &str) -> bool {
    value.chars().any(char::is_control)
}

/// Release, artifact, phase, and transport identity for one delivery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeliveryIdentity {
    /// UUID identifying the transfer lifecycle.
    pub transfer_id: String,
    /// Release group ID when resolution used a managed release.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
    /// Release-local artifact version ID when managed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_version_id: Option<u64>,
    /// Manifest digest binding the release contents.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifest_digest: Option<String>,
    /// Stable boot-phase label used for policy and metrics.
    pub phase: String,
    /// Stable transport label: `TFTP`, `HTTP`, or `HTTP_NATIVE`.
    pub transport: String,
}

/// Fully owned terminal audit record queued after transfer admission reserved capacity.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuditRecord {
    pub(crate) client_ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) client_mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) client_serial: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) boot_profile: Option<String>,
    pub(crate) file_path: String,
    pub(crate) file_sha256: String,
    pub(crate) blocks_sent: u64,
    pub(crate) retransmissions: u64,
    pub(crate) outcome: TransferOutcome,
    /// Transfer terminal time, preserved while the JSONL group commit waits.
    #[serde(with = "crate::timestamp")]
    pub(crate) timestamp: Timestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) delivery: Option<DeliveryIdentity>,
}

struct AuditCommand {
    record_json: Vec<u8>,
    estimated_bytes: usize,
    _queue_permit: OwnedSemaphorePermit,
    _byte_permit: AuditBytePermit,
}

/// Maximum JSONL bytes one validated audit entry may occupy, including newline.
/// Admission reserves this bound before transfer work starts, then shrinks the
/// reservation to the encoded upper bound when the terminal record is queued.
const MAX_AUDIT_ENTRY_BYTES: usize = 8 * 1024;
/// Maximum entries included in one durable JSONL group commit.
const AUDIT_WRITER_MAX_BATCH_RECORDS: usize = 16_384;
/// Maximum encoded bytes included in one durable JSONL group commit.
const AUDIT_WRITER_MAX_BATCH_BYTES: usize = 16 * 1024 * 1024;
/// At most four full batches may be reserved or waiting for the writer.
const AUDIT_WRITER_QUEUE_BATCHES: usize = 4;
const AUDIT_WRITER_MAX_QUEUE_RECORDS: usize =
    AUDIT_WRITER_MAX_BATCH_RECORDS * AUDIT_WRITER_QUEUE_BATCHES;
/// Maximum sequence prefix and newline overhead relative to a serialized
/// `AuditRecord`. The writer replaces the record's opening `{` with this
/// prefix, so this deliberately remains a conservative upper bound.
const AUDIT_ENTRY_ENVELOPE_BYTES: usize = 64;
/// Maximum time spent collecting a partial batch. A fixed deadline prevents
/// sustained traffic from delaying an already busy writer.
const AUDIT_WRITER_BATCH_DELAY: Duration = Duration::from_millis(10);

#[derive(Debug)]
struct AuditByteBudget {
    limit: usize,
    used: AtomicUsize,
}

#[derive(Debug)]
struct AuditBytePermit {
    budget: Arc<AuditByteBudget>,
    held: usize,
}

impl AuditByteBudget {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            used: AtomicUsize::new(0),
        }
    }

    fn try_reserve(self: &Arc<Self>, bytes: usize) -> Option<AuditBytePermit> {
        let mut observed = self.used.load(Ordering::Acquire);
        loop {
            let next = observed.checked_add(bytes)?;
            if next > self.limit {
                return None;
            }
            match self.used.compare_exchange_weak(
                observed,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(AuditBytePermit {
                        budget: self.clone(),
                        held: bytes,
                    });
                }
                Err(actual) => observed = actual,
            }
        }
    }

    fn release(&self, bytes: usize) {
        #[allow(
            deprecated,
            reason = "try_update requires Rust 1.95; retain fetch_update for MSRV 1.85"
        )]
        let result = self
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_sub(bytes)
            });
        debug_assert!(result.is_ok(), "audit byte budget underflow");
    }

    fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
}

impl AuditBytePermit {
    fn shrink_to(&mut self, bytes: usize) -> Result<(), TempestError> {
        if bytes > self.held {
            return Err(TempestError::Audit(
                "Encoded audit record exceeded its admission reservation".into(),
            ));
        }
        self.budget.release(self.held - bytes);
        self.held = bytes;
        Ok(())
    }
}

impl Drop for AuditBytePermit {
    fn drop(&mut self) {
        self.budget.release(self.held);
    }
}

#[derive(Debug)]
struct AuditWriterStatus {
    failed: AtomicBool,
    critical_services_healthy: Arc<AtomicBool>,
}

impl AuditWriterStatus {
    fn new(critical_services_healthy: Arc<AtomicBool>) -> Self {
        Self {
            failed: AtomicBool::new(false),
            critical_services_healthy,
        }
    }

    fn fail(&self) {
        self.failed.store(true, Ordering::Release);
        self.critical_services_healthy
            .store(false, Ordering::Release);
    }

    fn is_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }
}

#[derive(Default)]
struct AuditPipelineMetrics {
    byte_capacity_rejected_total: AtomicU64,
    queue_capacity_rejected_total: AtomicU64,
    writer_failed_rejected_total: AtomicU64,
    jsonl_batches_total: AtomicU64,
    jsonl_records_total: AtomicU64,
    jsonl_bytes_total: AtomicU64,
    jsonl_commit_nanoseconds_total: AtomicU64,
}

/// Fixed-cardinality audit pipeline snapshot exported through Prometheus.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct AuditPipelineMetricsSnapshot {
    pub(crate) byte_capacity_rejected_total: u64,
    pub(crate) queue_capacity_rejected_total: u64,
    pub(crate) writer_failed_rejected_total: u64,
    pub(crate) outstanding_records: usize,
    pub(crate) reserved_bytes: usize,
    pub(crate) jsonl_batches_total: u64,
    pub(crate) jsonl_records_total: u64,
    pub(crate) jsonl_bytes_total: u64,
    pub(crate) jsonl_commit_nanoseconds_total: u64,
}

fn duration_nanoseconds(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// Bounded single-writer service for durable audit records.
pub(crate) struct AuditWriter {
    sender: SyncSender<AuditCommand>,
    queue_capacity: Arc<Semaphore>,
    max_outstanding: u32,
    byte_budget: Arc<AuditByteBudget>,
    status: Arc<AuditWriterStatus>,
    metrics: Arc<AuditPipelineMetrics>,
}

/// Transfer-owned capacity for exactly one terminal audit record.
#[derive(Debug)]
pub(crate) struct AuditReservation {
    sender: SyncSender<AuditCommand>,
    queue_permit: OwnedSemaphorePermit,
    byte_permit: AuditBytePermit,
    status: Arc<AuditWriterStatus>,
}

impl AuditWriter {
    /// Derives the record queue solely from byte capacity and batch bounds.
    fn queue_capacity_for(queue_max_bytes: usize) -> usize {
        (queue_max_bytes / MAX_AUDIT_ENTRY_BYTES).clamp(1, AUDIT_WRITER_MAX_QUEUE_RECORDS)
    }

    /// Start the dedicated JSONL writer with byte- and batch-bounded capacity.
    pub(crate) fn start(
        log: Arc<AuditLog>,
        queue_max_bytes: u64,
        critical_services_healthy: Arc<AtomicBool>,
    ) -> Result<Arc<Self>, TempestError> {
        let queue_max_bytes = usize::try_from(queue_max_bytes).map_err(|_| {
            TempestError::Audit("Audit queue byte capacity exceeds this platform".into())
        })?;
        Self::start_with_queue_capacity(
            log,
            queue_max_bytes,
            Self::queue_capacity_for(queue_max_bytes),
            critical_services_healthy,
        )
    }

    fn start_with_queue_capacity(
        log: Arc<AuditLog>,
        queue_max_bytes: usize,
        queue_capacity: usize,
        critical_services_healthy: Arc<AtomicBool>,
    ) -> Result<Arc<Self>, TempestError> {
        let queue_capacity = queue_capacity.clamp(1, AUDIT_WRITER_MAX_QUEUE_RECORDS);
        let max_outstanding = u32::try_from(queue_capacity).map_err(|_| {
            TempestError::Audit("Audit writer capacity exceeds supported limit".into())
        })?;
        let metrics = Arc::new(AuditPipelineMetrics::default());
        let status = Arc::new(AuditWriterStatus::new(critical_services_healthy));
        let byte_budget = Arc::new(AuditByteBudget::new(queue_max_bytes));
        let (sender, receiver) = sync_channel(queue_capacity);
        let writer_status = status.clone();
        let writer_metrics = metrics.clone();
        thread::Builder::new()
            .name("tempest-audit-jsonl".into())
            .spawn(move || run_audit_writer(log, receiver, writer_status, writer_metrics))
            .map_err(|error| {
                TempestError::Audit(format!("Failed to start audit JSONL writer: {error}"))
            })?;
        Ok(Arc::new(Self {
            sender,
            queue_capacity: Arc::new(Semaphore::new(queue_capacity)),
            max_outstanding,
            byte_budget,
            status,
            metrics,
        }))
    }

    /// Reserve terminal-record capacity before admitting transfer work.
    pub(crate) fn try_reserve(&self) -> Result<AuditReservation, TempestError> {
        if self.status.is_failed() {
            self.metrics
                .writer_failed_rejected_total
                .fetch_add(1, Ordering::Relaxed);
            return Err(TempestError::Audit("Audit JSONL writer stopped".into()));
        }
        let byte_permit = match self.byte_budget.try_reserve(MAX_AUDIT_ENTRY_BYTES) {
            Some(permit) => permit,
            None => {
                self.metrics
                    .byte_capacity_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(TempestError::Audit("Audit byte capacity exhausted".into()));
            }
        };
        let queue_permit = match self.queue_capacity.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.metrics
                    .queue_capacity_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                return Err(TempestError::Audit("Audit writer queue exhausted".into()));
            }
        };
        Ok(AuditReservation {
            sender: self.sender.clone(),
            queue_permit,
            byte_permit,
            status: self.status.clone(),
        })
    }

    /// Wait until every reserved terminal record has either synced or failed.
    pub(crate) async fn wait_idle(&self) -> Result<(), TempestError> {
        let permits = self
            .queue_capacity
            .clone()
            .acquire_many_owned(self.max_outstanding)
            .await
            .map_err(|_| TempestError::Audit("Audit writer stopped".into()))?;
        drop(permits);
        if self.status.is_failed() {
            return Err(TempestError::Audit("Audit JSONL writer stopped".into()));
        }
        Ok(())
    }

    pub(crate) fn metrics_snapshot(&self) -> AuditPipelineMetricsSnapshot {
        let outstanding_records = self
            .max_outstanding
            .saturating_sub(self.queue_capacity.available_permits() as u32)
            as usize;
        AuditPipelineMetricsSnapshot {
            byte_capacity_rejected_total: self
                .metrics
                .byte_capacity_rejected_total
                .load(Ordering::Relaxed),
            queue_capacity_rejected_total: self
                .metrics
                .queue_capacity_rejected_total
                .load(Ordering::Relaxed),
            writer_failed_rejected_total: self
                .metrics
                .writer_failed_rejected_total
                .load(Ordering::Relaxed),
            outstanding_records,
            reserved_bytes: self.byte_budget.used(),
            jsonl_batches_total: self.metrics.jsonl_batches_total.load(Ordering::Relaxed),
            jsonl_records_total: self.metrics.jsonl_records_total.load(Ordering::Relaxed),
            jsonl_bytes_total: self.metrics.jsonl_bytes_total.load(Ordering::Relaxed),
            jsonl_commit_nanoseconds_total: self
                .metrics
                .jsonl_commit_nanoseconds_total
                .load(Ordering::Relaxed),
        }
    }
}

impl AuditReservation {
    /// Queues one terminal record. The command retains both admission permits
    /// until the writer has durably synced its JSONL group.
    pub(crate) fn record(mut self, record: AuditRecord) -> Result<(), TempestError> {
        let (record_json, estimated_bytes) = match encode_audit_record(&record) {
            Ok(encoded) => encoded,
            Err(error) => {
                self.status.fail();
                return Err(error);
            }
        };
        if let Err(error) = self.byte_permit.shrink_to(estimated_bytes) {
            self.status.fail();
            return Err(error);
        }
        let command = AuditCommand {
            record_json,
            estimated_bytes,
            _queue_permit: self.queue_permit,
            _byte_permit: self.byte_permit,
        };
        if let Err(error) = self.sender.try_send(command) {
            self.status.fail();
            let detail = match error {
                TrySendError::Full(_) => "reserved audit queue unexpectedly became full",
                TrySendError::Disconnected(_) => "audit JSONL writer stopped",
            };
            return Err(TempestError::Audit(detail.into()));
        }
        Ok(())
    }
}

/// Validates and serializes a terminal record exactly once. The writer retains
/// these bytes until their group is durable instead of cloning every field and
/// serializing the record again on the writer thread.
fn encode_audit_record(record: &AuditRecord) -> Result<(Vec<u8>, usize), TempestError> {
    validate_audit_record(record)?;
    let record_json = serde_json::to_vec(record)
        .map_err(|error| TempestError::Audit(format!("Serialization error: {error}")))?;
    if record_json.first() != Some(&b'{') || record_json.last() != Some(&b'}') {
        return Err(TempestError::Audit(
            "Serialized audit record is not a JSON object".into(),
        ));
    }
    let estimated = record_json
        .len()
        .checked_add(AUDIT_ENTRY_ENVELOPE_BYTES)
        .ok_or_else(|| TempestError::Audit("Audit entry length overflow".into()))?;
    if estimated > MAX_AUDIT_ENTRY_BYTES {
        return Err(TempestError::Audit(format!(
            "Validated audit entry exceeds {MAX_AUDIT_ENTRY_BYTES} bytes"
        )));
    }
    Ok((record_json, estimated))
}

fn run_audit_writer(
    log: Arc<AuditLog>,
    receiver: Receiver<AuditCommand>,
    status: Arc<AuditWriterStatus>,
    metrics: Arc<AuditPipelineMetrics>,
) {
    let mut deferred = None;
    let mut batch = Vec::with_capacity(64);
    let mut encoded = Vec::new();
    loop {
        let first = match deferred.take() {
            Some(command) => command,
            None => match receiver.recv() {
                Ok(command) => command,
                Err(_) => return,
            },
        };
        let deadline = Instant::now() + AUDIT_WRITER_BATCH_DELAY;
        let mut estimated_bytes = first.estimated_bytes;
        batch.push(first);
        while batch.len() < AUDIT_WRITER_MAX_BATCH_RECORDS {
            let command = match receiver.try_recv() {
                Ok(command) => command,
                Err(TryRecvError::Disconnected) => break,
                Err(TryRecvError::Empty) => {
                    let now = Instant::now();
                    if now >= deadline {
                        break;
                    }
                    match receiver.recv_timeout(deadline - now) {
                        Ok(command) => command,
                        Err(_) => break,
                    }
                }
            };
            let next_bytes = estimated_bytes.saturating_add(command.estimated_bytes);
            if next_bytes > AUDIT_WRITER_MAX_BATCH_BYTES {
                deferred = Some(command);
                break;
            }
            estimated_bytes = next_bytes;
            batch.push(command);
        }

        let records: Vec<_> = batch
            .iter()
            .map(|command| command.record_json.as_slice())
            .collect();
        let commit_started = Instant::now();
        let commit = match log.append_serialized_record_batch(&records, &mut encoded) {
            Ok(commit) => commit,
            Err(error) => {
                status.fail();
                tracing::error!(%error, "audit JSONL writer failed; rejecting new transfers");
                return;
            }
        };
        metrics.jsonl_batches_total.fetch_add(1, Ordering::Relaxed);
        metrics
            .jsonl_records_total
            .fetch_add(commit.records as u64, Ordering::Relaxed);
        metrics
            .jsonl_bytes_total
            .fetch_add(commit.bytes as u64, Ordering::Relaxed);
        metrics.jsonl_commit_nanoseconds_total.fetch_add(
            duration_nanoseconds(commit_started.elapsed()),
            Ordering::Relaxed,
        );

        // Each command owns its byte and queue permits through the JSONL sync.
        // Dropping the durable group is what releases audit admission capacity.
        batch.clear();
    }
}

/// Terminal state recorded for an audited transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferOutcome {
    /// Delivery completed normally.
    Completed,
    /// A signed redirect was emitted; this server did not deliver artifact bytes.
    Redirected,
    /// Delivery failed with a sanitized diagnostic.
    Failed(String),
    /// The client terminated or abandoned the transfer.
    Aborted,
    /// The acknowledgement retry budget or absolute transfer lifetime expired.
    TimedOut,
}

impl TransferOutcome {
    /// Keep filesystem/provider diagnostics within the terminal-record contract.
    pub(crate) fn from_error(error: &TempestError) -> Self {
        match error {
            TempestError::Protocol(
                ProtocolError::Timeout { .. } | ProtocolError::TransferDeadline { .. },
            ) => Self::TimedOut,
            TempestError::Protocol(ProtocolError::ClientAbort { .. }) => Self::Aborted,
            _ => {
                let mut detail = error.to_string();
                let mut end = detail.len().min(512);
                while !detail.is_char_boundary(end) {
                    end -= 1;
                }
                detail.truncate(end);
                if detail.chars().any(char::is_control) {
                    detail = detail
                        .chars()
                        .map(|c| if c.is_control() { '_' } else { c })
                        .collect();
                }
                Self::Failed(detail)
            }
        }
    }

    fn detail_len(&self) -> usize {
        match self {
            Self::Failed(message) => message.len(),
            Self::Completed | Self::Redirected | Self::Aborted | Self::TimedOut => 0,
        }
    }

    fn failure_detail(&self) -> Option<&str> {
        match self {
            Self::Failed(message) => Some(message),
            Self::Completed | Self::Redirected | Self::Aborted | Self::TimedOut => None,
        }
    }
}

/// Durable JSON-lines audit log with size-based rotation.
pub struct AuditLog {
    log_path: PathBuf,
    inner: Mutex<AuditLogInner>,
    rotate_max_bytes: Option<u64>,
    rotate_keep_segments: usize,
    #[cfg(test)]
    durable_syncs: AtomicU64,
}

/// Next local sequence protected by the append lock.
struct AuditLogInner {
    sequence: u64,
}

struct AuditBatchCommit {
    records: usize,
    bytes: usize,
}

impl AuditLog {
    #[cfg(test)]
    fn next_sequence(&self) -> u64 {
        self.inner.lock().sequence
    }

    /// Opens or resumes an audit log from its bounded tail state.
    pub fn new(log_path: PathBuf) -> Result<Self, TempestError> {
        Self::new_with_rotation(log_path, None, 0)
    }

    /// Opens an audit log with size-based rotation and bounded retention.
    pub fn new_with_rotation(
        log_path: PathBuf,
        rotate_max_bytes: Option<u64>,
        rotate_keep_segments: usize,
    ) -> Result<Self, TempestError> {
        validate_audit_locations(&[&log_path])?;
        let log = Self {
            log_path,
            inner: Mutex::new(AuditLogInner { sequence: 0 }),
            rotate_max_bytes,
            rotate_keep_segments,
            #[cfg(test)]
            durable_syncs: AtomicU64::new(0),
        };

        truncate_incomplete_audit_tail(&log.log_path)?;
        log.inner.lock().sequence = Self::recover_next_sequence(&log.log_path)?;
        ensure_appendable_audit_file(&log.log_path)?;
        Ok(log)
    }

    /// Recovers only the last durable sequence. Startup cost is independent of
    /// retained history size; older JSONL records are not re-verified.
    fn recover_next_sequence(log_path: &Path) -> Result<u64, TempestError> {
        if let Some(sequence) = Self::recover_next_sequence_from_file(log_path)? {
            return Ok(sequence);
        }

        let rotated_paths = Self::rotated_log_paths(log_path);
        for path in rotated_paths.iter().rev() {
            if let Some(sequence) = Self::recover_next_sequence_from_file(path)? {
                return Ok(sequence);
            }
        }
        Ok(0)
    }

    /// Recovers the next sequence from at most the final 64 KiB of one segment.
    fn recover_next_sequence_from_file(log_path: &Path) -> Result<Option<u64>, TempestError> {
        use std::io::{Read, Seek, SeekFrom};
        const TAIL_BYTES: u64 = 64 * 1024;
        let mut file = match fs::symlink_metadata(log_path) {
            Ok(_) => open_existing_audit_file(log_path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let file_len = file.metadata()?.len();
        if file_len == 0 {
            return Ok(None);
        }
        let seek_pos = file_len.saturating_sub(TAIL_BYTES);
        file.seek(SeekFrom::Start(seek_pos))?;
        let mut tail = Vec::with_capacity((file_len - seek_pos) as usize);
        file.read_to_end(&mut tail)?;
        let end = tail
            .iter()
            .rposition(|byte| !matches!(byte, b'\n' | b'\r'))
            .map(|index| index + 1)
            .ok_or_else(|| {
                TempestError::Audit("Audit log tail contains no complete record".to_string())
            })?;
        let start = tail[..end]
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |index| index + 1);
        if seek_pos != 0 && start == 0 {
            return Err(TempestError::Audit(
                "Final audit record exceeds the 64 KiB recovery bound".to_string(),
            ));
        }
        let entry: AuditEntry = serde_json::from_slice(&tail[start..end]).map_err(|error| {
            TempestError::Audit(format!("Failed to parse final audit record: {error}"))
        })?;
        entry
            .sequence
            .checked_add(1)
            .map(Some)
            .ok_or_else(|| TempestError::Audit("Audit sequence exhausted".to_string()))
    }

    /// Lists rotated segments in filename order.
    fn rotated_log_paths(log_path: &Path) -> Vec<PathBuf> {
        let Some(file_name) = log_path.file_name().and_then(|name| name.to_str()) else {
            return Vec::new();
        };
        let prefix = format!("{file_name}.rotated.");
        let parent = log_path.parent().unwrap_or_else(|| Path::new("."));
        let mut paths: Vec<PathBuf> = match fs::read_dir(parent) {
            Ok(entries) => entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| name.starts_with(&prefix))
                })
                .collect(),
            Err(_) => Vec::new(),
        };
        paths.sort();
        paths
    }

    /// Returns rotated segments followed by the current log.
    fn ordered_log_paths(log_path: &Path) -> Vec<PathBuf> {
        let mut paths = Self::rotated_log_paths(log_path);
        if log_path.exists() {
            paths.push(log_path.to_path_buf());
        }
        paths
    }

    /// Rotates the current log before an append would exceed its size limit.
    fn rotate_if_needed(&self, incoming_bytes: usize) -> Result<(), TempestError> {
        let Some(limit) = self.rotate_max_bytes else {
            return Ok(());
        };
        let metadata = match fs::metadata(&self.log_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(TempestError::Audit(format!(
                    "Failed to stat audit log for rotation: {error}"
                )));
            }
        };

        if metadata.len() == 0 {
            return Ok(());
        }

        if metadata.len().saturating_add(incoming_bytes as u64) <= limit {
            return Ok(());
        }

        self.rotate_current_log()
    }

    /// Durably renames the current non-empty log segment.
    fn rotate_current_log(&self) -> Result<(), TempestError> {
        let metadata = match fs::metadata(&self.log_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(TempestError::Audit(format!(
                    "Failed to stat audit log for rotation: {error}"
                )));
            }
        };
        if metadata.len() == 0 {
            return Ok(());
        }

        let next_sequence = Self::recover_next_sequence_from_file(&self.log_path)?
            .ok_or_else(|| TempestError::Audit("Audit log tail is not recoverable".to_string()))?;
        let rotated_path = self.rotated_log_path(next_sequence)?;
        fs::rename(&self.log_path, &rotated_path).map_err(|e| {
            TempestError::Audit(format!(
                "Failed to rotate audit log {} to {}: {e}",
                self.log_path.display(),
                rotated_path.display()
            ))
        })?;
        sync_parent_directory(&self.log_path)?;
        self.enforce_rotation_retention()?;
        // The next group opens an existing file, so make the replacement name
        // durable here rather than syncing the parent directory on every batch.
        ensure_appendable_audit_file(&self.log_path)
    }

    /// Builds the timestamped path for a rotated segment.
    fn rotated_log_path(&self, next_sequence: u64) -> Result<PathBuf, TempestError> {
        let parent = self.log_path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = self
            .log_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| TempestError::Audit("Invalid audit log path".to_string()))?;
        let timestamp = Timestamp::now().strftime("%Y%m%dT%H%M%S%.fZ");
        Ok(parent.join(format!(
            "{file_name}.rotated.{timestamp}.seq{next_sequence}"
        )))
    }

    /// Removes the oldest rotated segments beyond the retention limit.
    fn enforce_rotation_retention(&self) -> Result<(), TempestError> {
        if self.rotate_keep_segments == 0 {
            return Ok(());
        }

        let mut paths = Self::rotated_log_paths(&self.log_path);
        if paths.len() <= self.rotate_keep_segments {
            return Ok(());
        }
        while paths.len() > self.rotate_keep_segments {
            let path = paths[0].clone();
            if let Err(error) = fs::remove_file(&path) {
                if error.kind() != std::io::ErrorKind::NotFound {
                    return Err(TempestError::Audit(format!(
                        "Failed to remove old audit segment {}: {error}",
                        path.display()
                    )));
                }
            }
            sync_parent_directory(&path)?;
            paths.remove(0);
        }

        Ok(())
    }

    /// Append an entry to the audit log.
    #[allow(clippy::too_many_arguments)]
    /// Appends a legacy-compatible transfer record and returns the stored entry.
    ///
    /// # Errors
    ///
    /// Returns [`TempestError::Audit`] or an I/O error if validation,
    /// serialization, rotation, or durable append fails.
    pub fn append(
        &self,
        client_ip: String,
        client_mac: Option<String>,
        file_path: String,
        file_sha256: String,
        blocks_sent: u64,
        retransmissions: u64,
        outcome: TransferOutcome,
        trace_id: Option<String>,
    ) -> Result<AuditEntry, TempestError> {
        self.append_with_identity(
            client_ip,
            client_mac,
            None,
            None,
            file_path,
            file_sha256,
            blocks_sent,
            retransmissions,
            outcome,
            trace_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    /// Appends a transfer record carrying provisioning identity metadata.
    pub fn append_with_identity(
        &self,
        client_ip: String,
        client_mac: Option<String>,
        client_serial: Option<String>,
        boot_profile: Option<String>,
        file_path: String,
        file_sha256: String,
        blocks_sent: u64,
        retransmissions: u64,
        outcome: TransferOutcome,
        trace_id: Option<String>,
    ) -> Result<AuditEntry, TempestError> {
        self.append_entry(
            client_ip,
            client_mac,
            client_serial,
            boot_profile,
            file_path,
            file_sha256,
            blocks_sent,
            retransmissions,
            outcome,
            trace_id,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    /// Appends a record carrying release and transport delivery identity.
    pub fn append_delivery(
        &self,
        client_ip: String,
        client_mac: Option<String>,
        client_serial: Option<String>,
        boot_profile: Option<String>,
        file_path: String,
        file_sha256: String,
        blocks_sent: u64,
        retransmissions: u64,
        outcome: TransferOutcome,
        trace_id: Option<String>,
        delivery: DeliveryIdentity,
    ) -> Result<AuditEntry, TempestError> {
        self.append_entry(
            client_ip,
            client_mac,
            client_serial,
            boot_profile,
            file_path,
            file_sha256,
            blocks_sent,
            retransmissions,
            outcome,
            trace_id,
            Some(delivery),
        )
    }

    /// Appends one complete JSONL transaction with one file write and sync.
    fn append_serialized_record_batch(
        &self,
        records: &[&[u8]],
        encoded: &mut Vec<u8>,
    ) -> Result<AuditBatchCommit, TempestError> {
        if records.is_empty() {
            return Ok(AuditBatchCommit {
                records: 0,
                bytes: 0,
            });
        }
        // Reuse bounded writer storage across commits, including sparse batches.
        encoded.clear();
        let mut inner = self.inner.lock();
        let mut sequence = inner.sequence;
        for record in records {
            if record.first() != Some(&b'{') || record.last() != Some(&b'}') {
                return Err(TempestError::Audit(
                    "Encoded audit record is not a JSON object".into(),
                ));
            }
            write!(encoded, "{{\"sequence\":{sequence},")
                .map_err(|error| TempestError::Audit(format!("Serialization error: {error}")))?;
            encoded.extend_from_slice(&record[1..]);
            encoded.push(b'\n');
            sequence = sequence
                .checked_add(1)
                .ok_or_else(|| TempestError::Audit("Audit sequence exhausted".into()))?;
        }
        if encoded.len() > AUDIT_WRITER_MAX_BATCH_BYTES {
            return Err(TempestError::Audit(format!(
                "Encoded audit batch exceeds {AUDIT_WRITER_MAX_BATCH_BYTES} bytes"
            )));
        }
        self.rotate_if_needed(encoded.len())?;
        let mut file = open_audit_append_file(&self.log_path)?;
        file.write_all(encoded).map_err(|error| {
            TempestError::Audit(format!("Failed to write audit batch: {error}"))
        })?;
        file.sync_data()
            .map_err(|error| TempestError::Audit(format!("Failed to sync audit batch: {error}")))?;
        #[cfg(test)]
        self.durable_syncs.fetch_add(1, Ordering::Relaxed);
        inner.sequence = sequence;
        Ok(AuditBatchCommit {
            records: records.len(),
            bytes: encoded.len(),
        })
    }

    #[cfg(test)]
    fn append_record_batch(
        &self,
        records: &[&AuditRecord],
    ) -> Result<AuditBatchCommit, TempestError> {
        let encoded: Result<Vec<_>, _> = records
            .iter()
            .map(|record| encode_audit_record(record).map(|(json, _)| json))
            .collect();
        let encoded = encoded?;
        let references: Vec<_> = encoded.iter().map(Vec::as_slice).collect();
        self.append_serialized_record_batch(&references, &mut Vec::new())
    }

    /// Validates, durably appends, and advances one audit entry.
    #[allow(clippy::too_many_arguments)]
    fn append_entry(
        &self,
        client_ip: String,
        client_mac: Option<String>,
        client_serial: Option<String>,
        boot_profile: Option<String>,
        file_path: String,
        file_sha256: String,
        blocks_sent: u64,
        retransmissions: u64,
        outcome: TransferOutcome,
        trace_id: Option<String>,
        delivery: Option<DeliveryIdentity>,
    ) -> Result<AuditEntry, TempestError> {
        let mut inner = self.inner.lock();
        let entry = self.build_entry_at(
            client_ip,
            client_mac,
            client_serial,
            boot_profile,
            file_path,
            file_sha256,
            blocks_sent,
            retransmissions,
            outcome,
            trace_id,
            delivery,
            inner.sequence,
        )?;
        let json = serde_json::to_string(&entry)
            .map_err(|error| TempestError::Audit(format!("Serialization error: {error}")))?;
        if json.len() + 1 > MAX_AUDIT_ENTRY_BYTES {
            return Err(TempestError::Audit(format!(
                "Validated audit entry exceeds {MAX_AUDIT_ENTRY_BYTES} bytes"
            )));
        }
        self.rotate_if_needed(json.len() + 1)?;
        let mut file = open_audit_append_file(&self.log_path)?;
        writeln!(file, "{json}").map_err(|error| {
            TempestError::Audit(format!("Failed to write audit entry: {error}"))
        })?;
        file.sync_data()
            .map_err(|error| TempestError::Audit(format!("Failed to sync audit entry: {error}")))?;
        #[cfg(test)]
        self.durable_syncs.fetch_add(1, Ordering::Relaxed);
        inner.sequence = inner
            .sequence
            .checked_add(1)
            .ok_or_else(|| TempestError::Audit("Audit sequence exhausted".to_string()))?;
        Ok(entry)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_entry_at(
        &self,
        client_ip: String,
        client_mac: Option<String>,
        client_serial: Option<String>,
        boot_profile: Option<String>,
        file_path: String,
        file_sha256: String,
        blocks_sent: u64,
        retransmissions: u64,
        outcome: TransferOutcome,
        trace_id: Option<String>,
        delivery: Option<DeliveryIdentity>,
        sequence: u64,
    ) -> Result<AuditEntry, TempestError> {
        if sequence == u64::MAX {
            return Err(TempestError::Audit("Audit sequence exhausted".to_string()));
        }
        validate_audit_fields(
            &client_ip,
            client_mac.as_deref(),
            client_serial.as_deref(),
            boot_profile.as_deref(),
            &file_path,
            &file_sha256,
            &outcome,
            trace_id.as_deref(),
            delivery.as_ref(),
        )?;

        Ok(AuditEntry {
            sequence,
            client_mac,
            client_serial,
            boot_profile,
            client_ip,
            file_path,
            file_sha256,
            blocks_sent,
            retransmissions,
            outcome,
            timestamp: Timestamp::now(),
            trace_id,
            delivery,
        })
    }

    /// Returns up to `limit` newest entries, optionally filtered by MAC address.
    ///
    /// Reads at most 16 MiB across the active and retained rotated segments.
    ///
    /// # Errors
    ///
    /// Returns an audit or I/O error if a segment cannot be read or decoded.
    pub fn recent_entries(
        &self,
        client_mac: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEntry>, TempestError> {
        let mut remaining = 16 * 1024 * 1024u64;
        let mut entries = Vec::with_capacity(limit);
        for path in Self::ordered_log_paths(&self.log_path).into_iter().rev() {
            if entries.len() == limit || remaining == 0 {
                break;
            }
            let mut file = open_existing_audit_file(&path)?;
            let len = file.metadata()?.len();
            read_recent_segment(
                &mut file,
                len,
                &mut remaining,
                client_mac,
                limit,
                &mut entries,
            )?;
        }
        Ok(entries)
    }
}

/// Scan backward a chunk at a time, retaining only the line crossing a boundary.
/// The shared byte budget also bounds malformed segments containing no newlines.
fn read_recent_segment(
    reader: &mut (impl std::io::Read + std::io::Seek),
    mut end: u64,
    remaining: &mut u64,
    client_mac: Option<&str>,
    limit: usize,
    entries: &mut Vec<AuditEntry>,
) -> std::io::Result<()> {
    const CHUNK_BYTES: u64 = 64 * 1024;
    let mut partial: Vec<Vec<u8>> = Vec::new();
    let mut chunk = Vec::new();
    while end > 0 && *remaining > 0 && entries.len() < limit {
        let count = end.min(*remaining).min(CHUNK_BYTES);
        let start = end - count;
        reader.seek(std::io::SeekFrom::Start(start))?;
        chunk.resize(count as usize, 0);
        reader.read_exact(&mut chunk)?;
        *remaining -= count;
        // Keep long/torn lines as fragments until a boundary arrives, avoiding
        // quadratic copying when a malformed segment contains no newlines.
        if start != 0 && !chunk.contains(&b'\n') {
            partial.push(std::mem::take(&mut chunk));
            end = start;
            continue;
        }
        for fragment in partial.drain(..).rev() {
            chunk.extend_from_slice(&fragment);
        }
        let boundary = if start == 0 {
            0
        } else {
            chunk
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(chunk.len(), |i| i + 1)
        };
        for line in String::from_utf8_lossy(&chunk[boundary..]).lines().rev() {
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(line) {
                if client_mac.is_none_or(|mac| entry.client_mac.as_deref() == Some(mac)) {
                    entries.push(entry);
                    if entries.len() == limit {
                        return Ok(());
                    }
                }
            }
        }
        if boundary != 0 {
            partial.push(chunk[..boundary].to_vec());
        }
        end = start;
    }
    Ok(())
}

fn validate_audit_locations(paths: &[&Path]) -> Result<(), TempestError> {
    for path in paths {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let metadata = fs::symlink_metadata(parent).map_err(|error| {
            TempestError::Audit(format!(
                "Failed to inspect audit directory {}: {error}",
                parent.display()
            ))
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(TempestError::Audit(format!(
                "Audit directory must be a non-symlink directory: {}",
                parent.display()
            )));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o022 != 0 {
                return Err(TempestError::Audit(format!(
                    "Audit directory is group/world writable: {}",
                    parent.display()
                )));
            }
        }
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    || !metadata.is_file()
                    || audit_file_is_writable_by_others(&metadata) =>
            {
                return Err(TempestError::Audit(format!(
                    "Audit file is unsafe: {}",
                    path.display()
                )));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(TempestError::Audit(format!(
                    "Failed to inspect audit file {}: {error}",
                    path.display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn audit_file_is_writable_by_others(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o022 != 0
}

#[cfg(not(unix))]
fn audit_file_is_writable_by_others(_metadata: &fs::Metadata) -> bool {
    false
}

fn ensure_appendable_audit_file(path: &Path) -> Result<(), TempestError> {
    let file = open_audit_append_file(path)?;
    file.sync_data()?;
    sync_parent_directory(path)
}

/// Open an existing audit file and validate the named and opened identities
/// before any bytes are consumed from the handle.
fn open_existing_audit_file(path: &Path) -> Result<fs::File, TempestError> {
    let before = fs::symlink_metadata(path).map_err(|error| {
        TempestError::Audit(format!(
            "Failed to inspect audit file {}: {error}",
            path.display()
        ))
    })?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || audit_file_is_writable_by_others(&before)
    {
        return Err(TempestError::Audit(format!(
            "Audit file is unsafe: {}",
            path.display()
        )));
    }
    let file = fs::File::open(path).map_err(|error| {
        TempestError::Audit(format!(
            "Failed to open audit file {}: {error}",
            path.display()
        ))
    })?;
    let opened = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if named.file_type().is_symlink()
        || !named.is_file()
        || !same_audit_file_identity(&before, &opened)
        || !same_audit_file_identity(&opened, &named)
    {
        return Err(TempestError::Audit(
            "Audit file changed while it was being opened".into(),
        ));
    }
    Ok(file)
}

/// Opens an existing audit-owned file for bounded recovery updates while
/// preserving the same named/opened identity checks used by readers.
fn open_audit_update_file(path: &Path) -> Result<fs::File, TempestError> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || audit_file_is_writable_by_others(&before)
    {
        return Err(TempestError::Audit(format!(
            "Audit file is unsafe: {}",
            path.display()
        )));
    }
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let opened = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if named.file_type().is_symlink()
        || !named.is_file()
        || !same_audit_file_identity(&before, &opened)
        || !same_audit_file_identity(&opened, &named)
    {
        return Err(TempestError::Audit(
            "Audit file changed while it was being opened".into(),
        ));
    }
    Ok(file)
}

/// Repairs only a crash-torn final JSON line. A syntactically complete entry
/// gets its missing delimiter restored; non-EOF parse failures remain a hard
/// verification error so corruption cannot be mistaken for recovery.
fn truncate_incomplete_audit_tail(path: &Path) -> Result<(), TempestError> {
    use std::io::{Read, Seek, SeekFrom};

    const MAX_RECOVERABLE_LINE_BYTES: u64 = 64 * 1024;

    let mut file = match fs::symlink_metadata(path) {
        Ok(_) => open_audit_update_file(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)?;
    if last[0] == b'\n' {
        return Ok(());
    }

    let tail_start = len.saturating_sub(MAX_RECOVERABLE_LINE_BYTES);
    file.seek(SeekFrom::Start(tail_start))?;
    let mut tail = vec![0u8; (len - tail_start) as usize];
    file.read_exact(&mut tail)?;
    let truncate_to = match tail.iter().rposition(|byte| *byte == b'\n') {
        Some(index) => tail_start + index as u64 + 1,
        None if tail_start == 0 => 0,
        None => {
            return Err(TempestError::Audit(
                "Unterminated audit entry exceeds the recovery limit".into(),
            ));
        }
    };
    let fragment_offset = (truncate_to - tail_start) as usize;
    let fragment = &tail[fragment_offset..];
    if fragment.len() as u64 > MAX_RECOVERABLE_LINE_BYTES {
        return Err(TempestError::Audit(
            "Unterminated audit entry exceeds the recovery limit".into(),
        ));
    }
    match serde_json::from_slice::<AuditEntry>(fragment) {
        Ok(_) => {
            file.seek(SeekFrom::End(0))?;
            file.write_all(b"\n")?;
            file.sync_data()?;
            return Ok(());
        }
        Err(error) if !error.is_eof() => {
            return Err(TempestError::Audit(format!(
                "Final audit entry is corrupt: {error}"
            )));
        }
        Err(_) => {}
    }
    file.set_len(truncate_to)?;
    file.sync_data()?;
    Ok(())
}

fn open_audit_append_file(path: &Path) -> Result<fs::File, TempestError> {
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path).map_err(|error| {
        TempestError::Audit(format!(
            "Failed to initialize audit log {}: {error}",
            path.display()
        ))
    })?;
    let opened = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if named.file_type().is_symlink()
        || !named.is_file()
        || !same_audit_file_identity(&opened, &named)
    {
        return Err(TempestError::Audit(
            "Audit log changed while it was being opened".into(),
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn same_audit_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_audit_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

fn sync_parent_directory(path: &Path) -> Result<(), TempestError> {
    #[cfg(unix)]
    {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                TempestError::Audit(format!(
                    "Failed to sync audit directory {}: {error}",
                    parent.display()
                ))
            })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
