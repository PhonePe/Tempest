// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_audit_dir() -> PathBuf {
    let id = TEST_COUNTER.fetch_add(1, AtomicOrdering::SeqCst);
    let dir = std::env::temp_dir().join(format!("tempest_audit_test_{}_{id}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn terminal_record(sequence: usize) -> AuditRecord {
    AuditRecord {
        client_ip: "192.0.2.10".to_string(),
        client_mac: None,
        client_serial: None,
        boot_profile: Some("default".to_string()),
        file_path: format!("artifact-{sequence}.bin"),
        file_sha256: format!("{sequence:064x}"),
        blocks_sent: 1,
        retransmissions: 0,
        outcome: TransferOutcome::Completed,
        timestamp: Timestamp::now(),
        trace_id: None,
        delivery: None,
    }
}

fn audit_line(sequence: u64, mac: Option<&str>) -> Vec<u8> {
    let entry = AuditEntry {
        sequence,
        client_mac: mac.map(str::to_owned),
        client_serial: None,
        boot_profile: None,
        client_ip: "192.0.2.1".into(),
        file_path: "kernel".into(),
        file_sha256: "ab".repeat(32),
        blocks_sent: 1,
        retransmissions: 0,
        outcome: TransferOutcome::Completed,
        timestamp: Timestamp::now(),
        trace_id: None,
        delivery: None,
    };
    let mut line = serde_json::to_vec(&entry).unwrap();
    line.push(b'\n');
    line
}

#[test]
fn recent_audit_stops_after_one_tail_chunk() {
    let mut bytes = vec![b'\n'; 16 * 1024 * 1024];
    bytes.extend(audit_line(7, None));
    let mut reader = std::io::Cursor::new(&bytes);
    let mut remaining = 16 * 1024 * 1024;
    let mut entries = Vec::new();
    read_recent_segment(
        &mut reader,
        bytes.len() as u64,
        &mut remaining,
        None,
        1,
        &mut entries,
    )
    .unwrap();
    assert_eq!(entries[0].sequence, 7);
    assert_eq!(remaining, 16 * 1024 * 1024 - 64 * 1024);
}

#[test]
fn recent_audit_handles_long_lines_and_missing_delimiters() {
    let mut entry: serde_json::Value = serde_json::from_slice(&audit_line(9, None)).unwrap();
    entry["trace_id"] = serde_json::Value::String("x".repeat(3 * 64 * 1024));
    let mut bytes = audit_line(8, None);
    bytes.extend(serde_json::to_vec(&entry).unwrap());
    bytes.push(b'\n');
    let mut remaining = bytes.len() as u64;
    let mut entries = Vec::new();
    read_recent_segment(
        &mut std::io::Cursor::new(&bytes),
        bytes.len() as u64,
        &mut remaining,
        None,
        2,
        &mut entries,
    )
    .unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>(),
        [9, 8]
    );
    assert_eq!(entries[0].trace_id.as_ref().unwrap().len(), 3 * 64 * 1024);
    let malformed = vec![b'x'; 16 * 1024 * 1024];
    let mut remaining = malformed.len() as u64;
    entries.clear();
    read_recent_segment(
        &mut std::io::Cursor::new(&malformed),
        malformed.len() as u64,
        &mut remaining,
        None,
        1,
        &mut entries,
    )
    .unwrap();
    assert!(entries.is_empty());
    assert_eq!(remaining, 0);
}

#[test]
fn recent_audit_preserves_boundary_lines_filtering_and_scan_limit() {
    let first = audit_line(1, Some("02:00:00:00:00:01"));
    let second = audit_line(2, Some("02:00:00:00:00:02"));
    let third = audit_line(3, Some("02:00:00:00:00:01"));
    // Place the second JSON record across a backward chunk boundary.
    let mut bytes = first.clone();
    bytes.extend(&second);
    bytes.extend(vec![b'\n'; 64 * 1024 - third.len() - second.len() / 2]);
    bytes.extend(&third);
    let mut reader = std::io::Cursor::new(&bytes);
    let mut entries = Vec::new();
    let mut remaining = bytes.len() as u64;
    read_recent_segment(
        &mut reader,
        bytes.len() as u64,
        &mut remaining,
        None,
        3,
        &mut entries,
    )
    .unwrap();
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>(),
        [3, 2, 1]
    );
    entries.clear();
    remaining = 64 * 1024;
    read_recent_segment(
        &mut reader,
        bytes.len() as u64,
        &mut remaining,
        Some("02:00:00:00:00:02"),
        1,
        &mut entries,
    )
    .unwrap();
    assert!(
        entries.is_empty(),
        "a partial record outside the byte budget must not be returned"
    );
    assert_eq!(remaining, 0);
    remaining = bytes.len() as u64;
    read_recent_segment(
        &mut reader,
        bytes.len() as u64,
        &mut remaining,
        Some("02:00:00:00:00:02"),
        1,
        &mut entries,
    )
    .unwrap();
    assert_eq!(entries[0].sequence, 2);
}

fn terminal_delivery_record(sequence: usize) -> AuditRecord {
    let mut record = terminal_record(sequence);
    record.delivery = Some(DeliveryIdentity {
        transfer_id: format!("transfer-{sequence}"),
        group_id: Some("release-a".to_string()),
        artifact_version_id: Some(sequence as u64),
        manifest_digest: Some("ab".repeat(32)),
        phase: "KERNEL".to_string(),
        transport: "TFTP".to_string(),
    });
    record
}

#[test]
fn transfer_failure_diagnostics_are_bounded_and_log_safe() {
    let mut record = terminal_record(0);
    record.outcome =
        TransferOutcome::from_error(&TempestError::Version(format!("\t{}\n", "é".repeat(512))));
    assert!(record.outcome.detail_len() <= 512);
    assert!(
        !record
            .outcome
            .failure_detail()
            .unwrap()
            .chars()
            .any(char::is_control)
    );
    assert!(encode_audit_record(&record).is_ok());
}

fn maximally_escaped_record() -> AuditRecord {
    let mut record = terminal_delivery_record(0);
    record.client_ip = "\"".repeat(256);
    record.client_mac = Some("\\".repeat(128));
    record.client_serial = Some("\"".repeat(128));
    record.boot_profile = Some("\\".repeat(64));
    record.file_path = "\"".repeat(1024);
    record.file_sha256 = "\\".repeat(128);
    record.outcome = TransferOutcome::Failed("\"".repeat(512));
    record.trace_id = Some("\\".repeat(128));
    let delivery = record.delivery.as_mut().unwrap();
    delivery.transfer_id = "\"".repeat(128);
    delivery.group_id = Some("\\".repeat(128));
    delivery.manifest_digest = Some("\"".repeat(128));
    delivery.phase = "\\".repeat(64);
    delivery.transport = "\"".repeat(16);
    record
}

#[test]
fn validated_entry_size_bound_covers_json_escaping() {
    let dir = temp_audit_dir();
    let log = AuditLog::new(dir.join("audit.jsonl")).unwrap();
    let record = maximally_escaped_record();
    let (_, estimated) = encode_audit_record(&record).unwrap();
    let mut entry = log
        .build_entry_at(
            record.client_ip.clone(),
            record.client_mac.clone(),
            record.client_serial.clone(),
            record.boot_profile.clone(),
            record.file_path.clone(),
            record.file_sha256.clone(),
            record.blocks_sent,
            record.retransmissions,
            record.outcome.clone(),
            record.trace_id.clone(),
            record.delivery.clone(),
            u64::MAX - 1,
        )
        .unwrap();
    entry.timestamp = record.timestamp;
    let actual = serde_json::to_vec(&entry).unwrap().len() + 1;
    assert!(actual <= estimated);
    assert!(estimated <= MAX_AUDIT_ENTRY_BYTES);

    let mut invalid = terminal_record(0);
    invalid.file_path.push('\n');
    assert!(encode_audit_record(&invalid).is_err());
}

#[test]
fn encoded_record_omits_absent_optional_identity() {
    let (encoded, _) = encode_audit_record(&terminal_record(0)).unwrap();
    let record: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    let object = record.as_object().unwrap();
    assert!(!object.contains_key("client_mac"));
    assert!(!object.contains_key("client_serial"));
    assert!(!object.contains_key("trace_id"));
    assert!(!object.contains_key("delivery"));

    let mut record = terminal_record(1);
    record.delivery = Some(DeliveryIdentity {
        transfer_id: "transfer-1".to_string(),
        group_id: None,
        artifact_version_id: None,
        manifest_digest: None,
        phase: "CONFIG".to_string(),
        transport: "TFTP".to_string(),
    });
    let (encoded, _) = encode_audit_record(&record).unwrap();
    let record: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    let delivery = record["delivery"].as_object().unwrap();
    assert!(!delivery.contains_key("group_id"));
    assert!(!delivery.contains_key("artifact_version_id"));
    assert!(!delivery.contains_key("manifest_digest"));
}

#[test]
fn audit_queue_capacity_is_derived_from_bytes_and_batch_bounds() {
    assert_eq!(
        AuditWriter::queue_capacity_for(2 * MAX_AUDIT_ENTRY_BYTES),
        2
    );
    assert_eq!(
        AuditWriter::queue_capacity_for(usize::MAX),
        AUDIT_WRITER_MAX_QUEUE_RECORDS
    );
    assert_eq!(AUDIT_WRITER_MAX_BATCH_RECORDS, 16_384);
    assert_eq!(AUDIT_WRITER_MAX_BATCH_BYTES, 16 * 1024 * 1024);
    assert_eq!(AUDIT_WRITER_BATCH_DELAY, Duration::from_millis(10));
}

#[test]
fn audit_byte_reservation_shrinks_to_encoded_upper_bound() {
    let budget = Arc::new(AuditByteBudget::new(MAX_AUDIT_ENTRY_BYTES));
    let mut permit = budget.try_reserve(MAX_AUDIT_ENTRY_BYTES).unwrap();
    let (_, encoded) = encode_audit_record(&terminal_record(0)).unwrap();
    permit.shrink_to(encoded).unwrap();
    assert_eq!(budget.used(), encoded);
    drop(permit);
    assert_eq!(budget.used(), 0);
}

#[test]
fn audit_admission_reports_byte_exhaustion_separately() {
    let dir = temp_audit_dir();
    let log = Arc::new(AuditLog::new(dir.join("audit.jsonl")).unwrap());
    let writer = AuditWriter::start_with_queue_capacity(
        log,
        MAX_AUDIT_ENTRY_BYTES,
        2,
        Arc::new(AtomicBool::new(true)),
    )
    .unwrap();

    let reservation = writer.try_reserve().unwrap();
    assert!(writer.try_reserve().is_err());
    let metrics = writer.metrics_snapshot();
    assert_eq!(metrics.byte_capacity_rejected_total, 1);
    assert_eq!(metrics.queue_capacity_rejected_total, 0);
    drop(reservation);
}

#[test]
fn audit_admission_reports_queue_exhaustion_separately() {
    let dir = temp_audit_dir();
    let log = Arc::new(AuditLog::new(dir.join("audit.jsonl")).unwrap());
    let writer = AuditWriter::start_with_queue_capacity(
        log,
        2 * MAX_AUDIT_ENTRY_BYTES,
        1,
        Arc::new(AtomicBool::new(true)),
    )
    .unwrap();

    let reservation = writer.try_reserve().unwrap();
    assert!(writer.try_reserve().is_err());
    let metrics = writer.metrics_snapshot();
    assert_eq!(metrics.byte_capacity_rejected_total, 0);
    assert_eq!(metrics.queue_capacity_rejected_total, 1);
    assert_eq!(metrics.reserved_bytes, MAX_AUDIT_ENTRY_BYTES);
    drop(reservation);
}

#[tokio::test]
async fn audit_writer_group_commits_before_releasing_reservations() {
    let dir = temp_audit_dir();
    let log_path = dir.join("audit.jsonl");
    let log = Arc::new(AuditLog::new(log_path.clone()).unwrap());
    let writer = AuditWriter::start(
        log.clone(),
        4 * 1024 * 1024,
        Arc::new(AtomicBool::new(true)),
    )
    .unwrap();

    for sequence in 0..128 {
        writer
            .try_reserve()
            .unwrap()
            .record(terminal_record(sequence))
            .unwrap();
    }
    writer.wait_idle().await.unwrap();

    let metrics = writer.metrics_snapshot();
    assert_eq!(metrics.jsonl_records_total, 128);
    assert!((1..=128).contains(&metrics.jsonl_batches_total));
    assert_eq!(
        metrics.jsonl_batches_total,
        log.durable_syncs.load(Ordering::Acquire)
    );
    assert_eq!(
        metrics.jsonl_bytes_total,
        std::fs::metadata(&log_path).unwrap().len()
    );
    assert_eq!(metrics.outstanding_records, 0);
    assert_eq!(metrics.reserved_bytes, 0);
    assert_eq!(log.recent_entries(None, 128).unwrap().len(), 128);
}

#[test]
fn audit_log_batch_preserves_order_and_has_no_cryptographic_envelope() {
    let dir = temp_audit_dir();
    let log = AuditLog::new(dir.join("audit.jsonl")).unwrap();
    let records: Vec<_> = (0..128).map(terminal_delivery_record).collect();
    let references: Vec<_> = records.iter().collect();
    let commit = log.append_record_batch(&references).unwrap();
    assert_eq!(commit.records, 128);
    assert_eq!(log.durable_syncs.load(Ordering::Acquire), 1);

    let entries = log.recent_entries(None, records.len()).unwrap();
    assert_eq!(entries[0].sequence, 127);
    assert_eq!(entries[127].sequence, 0);
    let line = std::fs::read_to_string(&log.log_path).unwrap();
    let value: serde_json::Value = serde_json::from_str(line.lines().next().unwrap()).unwrap();
    for removed in [
        "chain_version",
        "prev_entry_hash",
        "entry_hash",
        "attestation",
        "signature",
    ] {
        assert!(value.get(removed).is_none(), "unexpected field {removed}");
    }
}

#[test]
fn audit_log_restart_recovers_only_bounded_tail_state() {
    let dir = temp_audit_dir();
    let log_path = dir.join("audit.jsonl");
    let log = AuditLog::new(log_path.clone()).unwrap();
    for sequence in 0..3 {
        log.append_record_batch(&[&terminal_record(sequence)])
            .unwrap();
    }
    drop(log);

    let mut lines: Vec<_> = std::fs::read_to_string(&log_path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect();
    lines[0] = "{historical-record-not-verified}".to_string();
    std::fs::write(&log_path, format!("{}\n", lines.join("\n"))).unwrap();

    let recovered = AuditLog::new(log_path).unwrap();
    assert_eq!(recovered.next_sequence(), 3);
}

#[test]
fn audit_log_tail_recovery_ignores_a_partial_utf8_prefix() {
    let dir = temp_audit_dir();
    let log_path = dir.join("audit.jsonl");
    let final_entry = AuditLog::new(dir.join("seed.jsonl"))
        .unwrap()
        .build_entry_at(
            "192.0.2.10".into(),
            None,
            None,
            None,
            "artifact.bin".into(),
            "ab".repeat(32),
            1,
            0,
            TransferOutcome::Completed,
            None,
            None,
            7,
        )
        .unwrap();
    let final_line = format!("{}\n", serde_json::to_string(&final_entry).unwrap());
    let mut historical = format!("\"{}\"", "é".repeat(40_000));
    loop {
        let mut bytes = historical.as_bytes().to_vec();
        bytes.push(b'\n');
        bytes.extend_from_slice(final_line.as_bytes());
        let seek = bytes.len() - 64 * 1024;
        if bytes[seek] & 0b1100_0000 == 0b1000_0000 {
            std::fs::write(&log_path, bytes).unwrap();
            break;
        }
        historical.push('x');
    }

    let recovered = AuditLog::new(log_path).unwrap();
    assert_eq!(recovered.next_sequence(), 8);
}

#[test]
fn audit_log_restart_repairs_only_crash_torn_final_lines() {
    let dir = temp_audit_dir();
    let log_path = dir.join("audit.jsonl");
    let log = AuditLog::new(log_path.clone()).unwrap();
    log.append_record_batch(&[&terminal_record(0)]).unwrap();
    drop(log);

    let file = open_audit_update_file(&log_path).unwrap();
    let len = file.metadata().unwrap().len();
    file.set_len(len - 1).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let recovered = AuditLog::new(log_path.clone()).unwrap();
    assert!(std::fs::read(&log_path).unwrap().ends_with(b"\n"));
    drop(recovered);

    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .unwrap();
    file.write_all(b"{not-json").unwrap();
    file.sync_all().unwrap();
    drop(file);
    let error = AuditLog::new(log_path).err().unwrap();
    assert!(error.to_string().contains("Final audit entry is corrupt"));
}

#[test]
fn audit_log_torn_line_repair_is_bounded() {
    let dir = temp_audit_dir();
    let log_path = dir.join("audit.jsonl");
    let log = AuditLog::new(log_path.clone()).unwrap();
    log.append_record_batch(&[&terminal_record(0)]).unwrap();
    drop(log);

    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&log_path)
        .unwrap();
    file.write_all(&vec![b'x'; 64 * 1024 + 1]).unwrap();
    file.sync_all().unwrap();
    drop(file);

    let error = AuditLog::new(log_path).err().unwrap();
    assert!(error.to_string().contains("exceeds the recovery limit"));
}

#[test]
fn unrelated_legacy_spool_does_not_block_direct_jsonl_appends() {
    let dir = temp_audit_dir();
    let log_path = dir.join("audit.jsonl");
    let spool_path = dir.join("audit.jsonl.spool");
    std::fs::write(&spool_path, b"unrelated legacy bytes").unwrap();

    let log = AuditLog::new(log_path).unwrap();
    log.append_record_batch(&[&terminal_record(0)]).unwrap();

    assert_eq!(log.recent_entries(None, 1).unwrap().len(), 1);
    assert_eq!(
        std::fs::read(spool_path).unwrap(),
        b"unrelated legacy bytes"
    );
}

#[test]
fn audit_log_rotation_retention_is_simple_and_bounded() {
    let dir = temp_audit_dir();
    let log_path = dir.join("audit.jsonl");
    let log = AuditLog::new_with_rotation(log_path.clone(), Some(1024), 2).unwrap();
    for batch in 0..8 {
        let records: Vec<_> = (0..16)
            .map(|offset| terminal_delivery_record(batch * 16 + offset))
            .collect();
        let references: Vec<_> = records.iter().collect();
        log.append_record_batch(&references).unwrap();
    }
    assert!(AuditLog::rotated_log_paths(&log_path).len() <= 2);
    assert!(!dir.join("audit.anchor").exists());
    assert!(!dir.join("audit.checkpoint").exists());
    drop(log);
    assert!(AuditLog::new_with_rotation(log_path, Some(1024), 2).is_ok());
}

#[cfg(unix)]
#[tokio::test]
async fn audit_writer_failure_is_fail_closed_and_counted_separately() {
    use std::os::unix::fs::symlink;

    let dir = temp_audit_dir();
    let log_path = dir.join("audit.jsonl");
    let target_path = dir.join("target.jsonl");
    let log = Arc::new(AuditLog::new(log_path.clone()).unwrap());
    let healthy = Arc::new(AtomicBool::new(true));
    let writer = AuditWriter::start(log, 1024 * 1024, healthy.clone()).unwrap();
    std::fs::remove_file(&log_path).unwrap();
    std::fs::write(&target_path, b"").unwrap();
    symlink(&target_path, &log_path).unwrap();

    writer
        .try_reserve()
        .unwrap()
        .record(terminal_record(0))
        .unwrap();
    let error = writer.wait_idle().await.unwrap_err();
    assert!(error.to_string().contains("Audit JSONL writer stopped"));
    assert!(!healthy.load(Ordering::Acquire));
    assert!(writer.try_reserve().is_err());
    assert_eq!(writer.metrics_snapshot().writer_failed_rejected_total, 1);
    assert_eq!(std::fs::metadata(target_path).unwrap().len(), 0);
}
