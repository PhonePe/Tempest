// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn numeric_header_preserves_full_unsigned_domain_and_owned_lifetime() {
    for value in [0, 1, 9, 10, 1024, u32::MAX as u64, u64::MAX] {
        let header = numeric_header_value(value);
        assert_eq!(header.as_bytes(), value.to_string().as_bytes());
        assert!(!header.is_sensitive());
        let cloned = header.clone();
        drop(header);
        assert_eq!(cloned.to_str().unwrap(), value.to_string());
    }
}

#[test]
fn numeric_header_replaces_existing_field_without_duplicate_values() {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from_static("0"));
    headers.insert(header::CONTENT_LENGTH, numeric_header_value(u64::MAX));
    assert_eq!(headers.len(), 1);
    assert_eq!(headers[header::CONTENT_LENGTH], "18446744073709551615");
}

#[tokio::test]
async fn numeric_headers_preserve_native_audit_identity_and_cleanup() {
    use axum::body::to_bytes;
    use tower::ServiceExt;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    std::fs::write(root.join("boot.img"), [0x5a; 1024]).unwrap();
    let mut config = crate::config::TempestConfig::default();
    config.server.root = root.clone();
    config.api.enable_native_http_boot = true;
    config.api.native_http_boot_filename = "boot.img".into();
    config.audit.enabled = true;
    config.audit.log_path = Some(root.join("audit.jsonl"));
    let server = crate::server::TftpServer::new(config);
    let state = server.state();
    let group = state
        .version_store
        .atomic_switch_for_profile(
            "default".into(),
            "numeric-audit".into(),
            vec![("boot.img".into(), root.join("boot.img"))],
        )
        .unwrap();
    let ip = IpAddr::from([127, 0, 0, 1]);
    state.insert_boot_session(
        ip,
        BootSessionEntry {
            trace_id: Some("numeric-audit".into()),
            boot_profile: "default".into(),
            client_mac: None,
            serial: None,
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(300),
        },
    );
    let router = api_router(state.clone());
    for _ in 0..100 {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/boot/v1/boot.img")
                    .extension(ConnectInfo(SocketAddr::new(ip, 40100)))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_LENGTH], "1024");
        assert_eq!(
            response.headers()["x-tempest-version-id"],
            group.version_id.to_string()
        );
        assert_eq!(
            response.headers()["x-tempest-artifact-version-id"],
            group.version_id.to_string()
        );
        assert_eq!(
            response.headers()["x-tempest-manifest-digest"],
            group.manifest.manifest_digest
        );
        assert_eq!(
            to_bytes(response.into_body(), 1024).await.unwrap(),
            &[0x5a; 1024][..]
        );
    }
    let writer = state.audit_writer.as_ref().unwrap();
    tokio::time::timeout(Duration::from_secs(10), writer.wait_idle())
        .await
        .unwrap()
        .unwrap();
    let audit = state.audit_log.as_ref().unwrap();
    let entries = audit.recent_entries(None, 100).unwrap();
    assert_eq!(entries.len(), 100);
    let mut ids = std::collections::HashSet::new();
    for entry in entries {
        assert!(matches!(entry.outcome, TransferOutcome::Completed));
        assert_eq!(entry.client_ip, "127.0.0.1");
        assert_eq!(entry.file_path, "boot.img");
        assert_eq!(entry.file_sha256, group.files[0].content_hash);
        let delivery = entry.delivery.unwrap();
        assert_eq!(delivery.group_id.as_deref(), Some("numeric-audit"));
        assert_eq!(delivery.artifact_version_id, Some(group.version_id));
        assert_eq!(
            delivery.manifest_digest.as_deref(),
            Some(group.manifest.manifest_digest.as_str())
        );
        assert_eq!(delivery.transport, TRANSPORT_HTTP_NATIVE);
        assert!(uuid::Uuid::parse_str(&delivery.transfer_id).is_ok());
        assert!(ids.insert(delivery.transfer_id));
    }
    let metrics = writer.metrics_snapshot();
    assert_eq!(metrics.jsonl_records_total, 100);
    assert_eq!(metrics.outstanding_records, 0);
    assert_eq!(metrics.reserved_bytes, 0);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
    assert_eq!(
        state
            .version_store
            .pinned_count_for_profile("default", "boot.img", group.version_id),
        0
    );
}
