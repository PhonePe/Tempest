// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

#[tokio::test]
async fn additional_hotpath_preserves_closed_audit_sequence_and_identity() {
    use axum::body::to_bytes;
    use tower::ServiceExt;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    std::fs::write(root.join("boot.img"), [0x5a; 1024]).unwrap();
    let log = root.join("audit.jsonl");
    let mut config = crate::config::TempestConfig::default();
    config.server.root = root.clone();
    config.api.enable_native_http_boot = true;
    config.api.native_http_boot_filename = "boot.img".into();
    config.audit.enabled = true;
    config.audit.log_path = Some(log.clone());
    let server = crate::server::TftpServer::new(config);
    let state = server.state();
    let group = state
        .version_store
        .atomic_switch_for_profile(
            "default".into(),
            "additional-audit".into(),
            vec![("boot.img".into(), root.join("boot.img"))],
        )
        .unwrap();
    let ip = IpAddr::from([127, 0, 0, 1]);
    state.insert_boot_session(
        ip,
        BootSessionEntry {
            trace_id: Some("additional-audit".into()),
            boot_profile: "default".into(),
            client_mac: Some("02:00:00:00:00:01".into()),
            serial: Some("synthetic-serial".into()),
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
    let pipeline = writer.metrics_snapshot();
    assert_eq!(pipeline.jsonl_records_total, 100);
    assert_eq!(pipeline.outstanding_records, 0);
    assert_eq!(pipeline.reserved_bytes, 0);
    let text = std::fs::read_to_string(log).unwrap();
    let entries: Vec<crate::features::audit::AuditEntry> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(entries.len(), 100);
    let mut ids = std::collections::HashSet::new();
    for (sequence, entry) in entries.into_iter().enumerate() {
        assert_eq!(entry.sequence, sequence as u64);
        assert!(matches!(entry.outcome, TransferOutcome::Completed));
        assert_eq!(entry.client_ip, "127.0.0.1");
        assert_eq!(entry.client_mac.as_deref(), Some("02:00:00:00:00:01"));
        assert_eq!(entry.client_serial.as_deref(), Some("synthetic-serial"));
        assert_eq!(entry.trace_id.as_deref(), Some("additional-audit"));
        assert_eq!(entry.boot_profile.as_deref(), Some("default"));
        assert_eq!(entry.file_path, "boot.img");
        assert_eq!(entry.file_sha256, group.files[0].content_hash);
        let delivery = entry.delivery.unwrap();
        assert_eq!(delivery.group_id.as_deref(), Some("additional-audit"));
        assert_eq!(delivery.artifact_version_id, Some(group.version_id));
        assert_eq!(
            delivery.manifest_digest.as_deref(),
            Some(group.manifest.manifest_digest.as_str())
        );
        assert_eq!(delivery.phase, "OS_IMAGE");
        assert_eq!(delivery.transport, TRANSPORT_HTTP_NATIVE);
        assert!(uuid::Uuid::parse_str(&delivery.transfer_id).is_ok());
        assert!(ids.insert(delivery.transfer_id));
    }
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
    assert_eq!(
        state
            .version_store
            .pinned_count_for_profile("default", "boot.img", group.version_id),
        0
    );
}

use super::*;

#[tokio::test]
async fn static_security_headers_preserve_replacement_errors_and_owned_response() {
    use tower::ServiceExt;

    let router = Router::new()
        .route(
            "/",
            get(|| async {
                (
                    [
                        (header::CACHE_CONTROL, "public"),
                        (header::X_FRAME_OPTIONS, "SAMEORIGIN"),
                    ],
                    "body",
                )
            }),
        )
        .layer(middleware::from_fn(security_headers));
    for (method, path, expected_status) in [
        ("GET", "/", StatusCode::OK),
        ("GET", "/missing", StatusCode::NOT_FOUND),
        ("POST", "/", StatusCode::METHOD_NOT_ALLOWED),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected_status);
        let headers = response.headers().clone();
        drop(response);
        for (name, value) in [
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::X_FRAME_OPTIONS, "DENY"),
            (header::CACHE_CONTROL, "no-store"),
            (
                header::STRICT_TRANSPORT_SECURITY,
                "max-age=31536000; includeSubDomains",
            ),
            (header::REFERRER_POLICY, "no-referrer"),
        ] {
            assert_eq!(headers.get_all(&name).iter().count(), 1);
            assert_eq!(headers[&name], value);
            assert!(!headers[&name].is_sensitive());
        }
    }
}

#[tokio::test]
async fn static_native_labels_preserve_cached_get_head_range_and_drop_cleanup() {
    use axum::body::to_bytes;
    use tower::ServiceExt;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    std::fs::write(root.join("boot.img"), [0x5a; 1024]).unwrap();
    let mut config = crate::config::TempestConfig::default();
    config.server.root = root.clone();
    config.api.enable_native_http_boot = true;
    config.api.native_http_boot_filename = "boot.img".into();
    config.audit.enabled = false;
    let server = crate::server::TftpServer::new(config);
    let state = server.state();
    let group = state
        .version_store
        .atomic_switch_for_profile(
            "default".into(),
            "static-labels".into(),
            vec![("boot.img".into(), root.join("boot.img"))],
        )
        .unwrap();
    let ip = IpAddr::from([127, 0, 0, 1]);
    state.insert_boot_session(
        ip,
        BootSessionEntry {
            trace_id: None,
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
    for (method, range, status, length, drain) in [
        ("GET", None, StatusCode::OK, "1024", true),
        ("GET", None, StatusCode::OK, "1024", false),
        ("HEAD", None, StatusCode::OK, "1024", true),
        (
            "GET",
            Some("bytes=1-3"),
            StatusCode::PARTIAL_CONTENT,
            "3",
            true,
        ),
    ] {
        let mut request = Request::builder()
            .method(method)
            .uri("/boot/v1/boot.img")
            .extension(ConnectInfo(SocketAddr::new(ip, 40100)));
        if let Some(range) = range {
            request = request.header(header::RANGE, range);
        }
        let response = router
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(
            response.headers()["x-tempest-transport"],
            TRANSPORT_HTTP_NATIVE
        );
        assert_eq!(response.headers()["x-tempest-http-mode"], "native");
        assert_eq!(response.headers()["x-tempest-boot-phase"], "OS_IMAGE");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::CONTENT_LENGTH], length);
        assert_eq!(
            response.headers()["x-tempest-manifest-digest"],
            group.manifest.manifest_digest
        );
        if drain {
            let body = to_bytes(response.into_body(), 1024).await.unwrap();
            assert_eq!(
                body.len(),
                if method == "HEAD" {
                    0
                } else {
                    length.parse().unwrap()
                }
            );
            assert!(body.iter().all(|b| *b == 0x5a));
        } else {
            drop(response);
        }
        assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
        assert_eq!(
            state
                .version_store
                .pinned_count_for_profile("default", "boot.img", group.version_id),
            0
        );
    }
    // A warm verified cache must not hide new live quarantine or session expiry.
    state.quarantine_artifact("boot.img".into());
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
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    drop(response);
    state.quarantined_files.remove("boot.img");
    state.boot_sessions.get_mut(&ip).unwrap().expires_at = Instant::now() - Duration::from_secs(1);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/boot/v1/boot.img")
                .extension(ConnectInfo(SocketAddr::new(ip, 40100)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    drop(response);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
    assert_eq!(
        state
            .version_store
            .pinned_count_for_profile("default", "boot.img", group.version_id),
        0
    );
}
