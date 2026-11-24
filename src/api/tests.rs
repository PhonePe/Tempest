// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize};

use axum::body::to_bytes;
use axum::http::Method;
use tower::ServiceExt;

use super::versions::VerifyGroupRequest;

async fn deadline_test_server() -> (Arc<ServerState>, SocketAddr, tokio::task::JoinHandle<()>) {
    let mut config = crate::config::TempestConfig::default();
    config.api.allow_insecure_loopback = true;
    config.api.max_connections = 1;
    config.api.read_timeout_secs = 1;
    let state = crate::server::TftpServer::new(config).state();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server_state = state.clone();
    let task =
        tokio::spawn(async move { run_http_server_on(server_state, listener).await.unwrap() });
    (state, address, task)
}

async fn read_http_response(stream: &mut tokio::net::TcpStream) -> String {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(stream.read_u8().await.unwrap());
            assert!(headers.len() < 16 * 1024);
        }
        let headers = String::from_utf8(headers).unwrap();
        let len = headers
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .map(|value| value.parse::<usize>().unwrap())
            })
            .unwrap_or(0);
        let mut body = vec![0; len];
        stream.read_exact(&mut body).await.unwrap();
        headers
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn silent_and_partial_protocol_connections_expire_before_headers() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (_, address, server) = deadline_test_server().await;
    for prefix in [b"".as_slice(), b"P"] {
        let mut idle = tokio::net::TcpStream::connect(address).await.unwrap();
        idle.write_all(prefix).await.unwrap();
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(30), idle.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
    let mut next = tokio::net::TcpStream::connect(address).await.unwrap();
    next.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    assert!(
        read_http_response(&mut next)
            .await
            .starts_with("HTTP/1.1 200")
    );
    server.abort();
}

#[tokio::test]
async fn idle_http_connection_expires_and_releases_listener_capacity() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (_, address, server) = deadline_test_server().await;
    let mut idle = tokio::net::TcpStream::connect(address).await.unwrap();
    idle.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    assert!(
        read_http_response(&mut idle)
            .await
            .starts_with("HTTP/1.1 200")
    );
    let mut next = tokio::net::TcpStream::connect(address).await.unwrap();
    next.write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    assert!(
        read_http_response(&mut next)
            .await
            .starts_with("HTTP/1.1 200")
    );
    let mut byte = [0];
    assert_eq!(idle.read(&mut byte).await.unwrap(), 0);
    server.abort();
}

#[tokio::test]
async fn incomplete_http_headers_and_bodies_have_absolute_deadlines() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (state, address, server) = deadline_test_server().await;
    let mut headers = tokio::net::TcpStream::connect(address).await.unwrap();
    headers
        .write_all(b"GET /health HTTP/1.1\r\nHost:")
        .await
        .unwrap();
    let mut byte = [0];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(30), headers.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let mut body = tokio::net::TcpStream::connect(address).await.unwrap();
    body.write_all(b"POST /api/v1/sessions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{").await.unwrap();
    assert!(
        read_http_response(&mut body)
            .await
            .starts_with("HTTP/1.1 408")
    );
    assert!(state.boot_sessions.is_empty());
    server.abort();
}

#[tokio::test]
async fn http_read_deadline_does_not_limit_application_processing() {
    use tokio::io::AsyncWriteExt;
    let (state, address, server) = deadline_test_server().await;
    let control = state.control_plane_lock.lock().await;
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    let body = r#"{"client_ip":"192.0.2.1","trace_id":"deadline-test"}"#;
    stream.write_all(format!("POST /api/v1/sessions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    drop(control);
    assert!(
        read_http_response(&mut stream)
            .await
            .starts_with("HTTP/1.1 201")
    );
    server.abort();
}

fn test_state_with_root(root: PathBuf) -> Arc<ServerState> {
    test_state_with_root_and_api_bind(root, crate::config::ApiConfig::default().bind)
}

fn test_state_with_root_and_api_bind(root: PathBuf, api_bind: IpAddr) -> Arc<ServerState> {
    test_state_with_root_api_bind_and_key(root, api_bind, None)
}

fn test_state_with_root_api_bind_and_key(
    root: PathBuf,
    api_bind: IpAddr,
    api_key: Option<String>,
) -> Arc<ServerState> {
    test_state_with_root_api_bind_key_and_session_limit(
        root,
        api_bind,
        api_key,
        crate::config::ServerConfig::default().max_boot_sessions,
    )
}

fn test_state_with_root_api_bind_key_and_session_limit(
    root: PathBuf,
    api_bind: IpAddr,
    api_key: Option<String>,
    max_boot_sessions: usize,
) -> Arc<ServerState> {
    let mut config = crate::config::TempestConfig::default();
    config.server.root = root;
    config.server.max_boot_sessions = max_boot_sessions;
    config.api.bind = api_bind;
    config.api.api_key = api_key;
    let config = Arc::new(config);
    let active_transfers = Arc::new(AtomicUsize::new(0));
    let metrics = Arc::new(crate::server::ServerMetrics::new(active_transfers.clone()));
    Arc::new(crate::server::ServerState {
        config: config.clone(),
        version_store: crate::features::versioning::VersionStore::new(),
        phase_classifier: crate::features::boot_phase::PhaseClassifier::new(&config.boot_phases),
        shared_blocks: None,
        transfer_pacing: None,
        read_protocol: None,
        read_request_router: None,
        admission_policy: None,
        metrics,
        active_transfers,
        queued_transfers: Arc::new(AtomicUsize::new(0)),
        inflight_tftp_tids: Arc::new(dashmap::DashMap::new()),
        tftp_client_limits: Arc::new(crate::server::TftpClientLimits::new(
            config.server.max_tftp_transfers_per_ip,
        )),
        transfer_ids: crate::server::TransferIdGenerator::new(),
        drain_mode: AtomicBool::new(false),
        tftp_ready: AtomicBool::new(true),
        tftp_bound_port: std::sync::atomic::AtomicU16::new(config.server.port),
        critical_services_healthy: Arc::new(AtomicBool::new(true)),
        start_time: Instant::now(),
        tftp_rate_limiter: Arc::new(crate::rate_limit::PerIpRateLimiter::new(
            config.server.tftp_requests_per_ip_per_second,
            "TFTP",
        )),
        malformed_log_limiter: Arc::new(crate::rate_limit::PerIpRateLimiter::new(
            2,
            "TFTP malformed packet",
        )),
        unexpected_log_limiter: Arc::new(crate::rate_limit::PerIpRateLimiter::new(
            2,
            "TFTP unexpected opcode",
        )),
        http_rate_limiter: Arc::new(crate::rate_limit::PerIpRateLimiter::new(
            config.server.http_requests_per_ip_per_second,
            "API",
        )),
        http_observer: None,
        dscp_manager: Arc::new(crate::features::dscp::DscpManager::new(
            &std::collections::HashMap::new(),
            false,
        )),
        audit_log: None,
        audit_writer: None,
        audit_read_budget: Arc::new(tokio::sync::Semaphore::new(
            crate::server::MAX_CONCURRENT_AUDIT_READS,
        )),
        quarantined_files: Arc::new(dashmap::DashSet::new()),
        quarantine_admission: parking_lot::Mutex::new(()),
        scheduler: None,
        provisioning_priority: None,
        boot_sessions: Arc::new(dashmap::DashMap::new()),
        http_session_tokens: Arc::new(dashmap::DashMap::new()),
        persistence: None,
        persistence_revision: std::sync::atomic::AtomicI64::new(-1),
        persistence_snapshot_validated_at: parking_lot::Mutex::new(None),
        control_plane_lock: Arc::new(tokio::sync::Mutex::new(())),
        session_registration_queue: std::sync::OnceLock::new(),
        bandwidth_governor: None,
        artifact_hash_budget: Arc::new(tokio::sync::Semaphore::new(4)),
        artifact_root: std::sync::OnceLock::new(),
        artifact_io_budget: Arc::new(tokio::sync::Semaphore::new(32)),
        hot_artifact_cache: Arc::new(
            crate::artifact_cache::HotArtifactCache::with_default_limits(),
        ),
        http_artifact_cache: Arc::new(crate::artifact_cache::HotArtifactCache::with_limits(
            usize::try_from(config.api.artifact_cache_max_bytes).unwrap(),
            usize::try_from(config.api.artifact_cache_max_file_bytes).unwrap(),
        )),
    })
}

fn enable_native_http_boot(state: &mut Arc<ServerState>, filename: &str) {
    let mutable = Arc::get_mut(state).unwrap();
    let mut config = (*mutable.config).clone();
    config.api.enable_native_http_boot = true;
    config.api.native_http_boot_filename = filename.to_string();
    mutable.config = Arc::new(config);
}

fn insert_native_boot_session(state: &ServerState, client_ip: IpAddr, boot_profile: &str) {
    state.insert_boot_session(
        client_ip,
        BootSessionEntry {
            trace_id: Some("native-http-test".to_string()),
            boot_profile: boot_profile.to_string(),
            client_mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            serial: Some("NATIVE-HTTP-001".to_string()),
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(300),
        },
    );
}

#[test]
fn http_artifact_names_reject_audit_control_characters() {
    for control in ['\t', '\n', '\r', '\x7f', '\u{85}', '\u{9f}'] {
        assert!(validate_http_artifact_name(&format!("kernel{control}")).is_err());
    }
    assert!(validate_http_artifact_name("images/noyau-é").is_ok());
}

#[tokio::test]
async fn artifact_error_responses_distinguish_missing_files_from_server_failures() {
    for (error, status, message) in [
        (
            TempestError::Protocol(ProtocolError::FileNotFound("private-name".into())),
            StatusCode::NOT_FOUND,
            "Artifact not found",
        ),
        (
            TempestError::Persistence("private database failure".into()),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Artifact unavailable",
        ),
        (
            TempestError::PersistenceSnapshotStale,
            StatusCode::SERVICE_UNAVAILABLE,
            "Persistent state is stale",
        ),
        (
            TempestError::PersistenceBusy("private coordination timeout".into()),
            StatusCode::SERVICE_UNAVAILABLE,
            "Artifact temporarily unavailable",
        ),
        (
            TempestError::Conflict("private conflict".into()),
            StatusCode::INTERNAL_SERVER_ERROR,
            "Artifact unavailable",
        ),
        (
            TempestError::Version("private release conflict".into()),
            StatusCode::CONFLICT,
            "Pinned boot chain unavailable",
        ),
    ] {
        let response = artifact_error_response(error);
        assert_eq!(response.status(), status);
        assert_eq!(to_bytes(response.into_body(), 8192).await.unwrap(), message);
    }
}

#[tokio::test]
async fn cancelled_http_session_resolution_releases_transfer_capacity() {
    let root = tempfile::tempdir().unwrap();
    let mut config = crate::config::TempestConfig::default();
    config.server.root = root.path().to_path_buf();
    config.server.max_concurrent_transfers = 1;
    let server = crate::server::TftpServer::new(config);
    let state = server.state();
    let client_ip = IpAddr::from([127, 0, 0, 1]);
    insert_native_boot_session(&state, client_ip, "default");
    let session = active_boot_session(&state, client_ip).unwrap();
    let lock = state.control_plane_lock.lock().await;
    let request_state = state.clone();
    let request = tokio::spawn(async move {
        serve_session_artifact(
            request_state,
            client_ip,
            client_ip,
            session,
            &HeaderMap::new(),
            "kernel".into(),
            TRANSPORT_HTTP_NATIVE,
            "application/octet-stream",
            false,
            true,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(30), async {
        while state.active_transfers.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    request.abort();
    assert!(request.await.unwrap_err().is_cancelled());
    drop(lock);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
    server.drain();
    tokio::time::timeout(Duration::from_secs(30), server.wait_for_drain())
        .await
        .unwrap();
}

#[tokio::test]
async fn coherent_snapshot_and_core_owned_verification_support_physical_path_mapping() {
    let directory = tempfile::tempdir().unwrap();
    let releases = directory.path().join("releases/v2");
    std::fs::create_dir_all(&releases).unwrap();
    let artifact = releases.join("kernel.bin");
    std::fs::write(&artifact, b"trusted-kernel").unwrap();
    let state = test_state_with_root(directory.path().to_path_buf());
    state
        .version_store
        .atomic_switch_for_profile(
            "focal".into(),
            "release-2".into(),
            vec![("vmlinuz".into(), artifact.clone())],
        )
        .unwrap();
    let manifest_digest = state.version_store.list_groups()[0]
        .manifest
        .manifest_digest
        .clone();

    let snapshot = release_snapshot(State(state.clone())).await.into_response();
    assert_eq!(snapshot.status(), StatusCode::OK);
    let snapshot_body = to_bytes(snapshot.into_body(), usize::MAX).await.unwrap();
    let snapshot_json: serde_json::Value = serde_json::from_slice(&snapshot_body).unwrap();
    assert_eq!(snapshot_json["versions"][0]["name"], "vmlinuz");
    assert_eq!(snapshot_json["active_groups"][0]["boot_profile"], "focal");
    assert_eq!(snapshot_json["active_groups"][0]["group_id"], "release-2");
    assert_eq!(
        snapshot_json["active_groups"][0]["manifest_digest"],
        manifest_digest
    );
    assert_eq!(snapshot_json["groups"][0]["group_id"], "release-2");

    let request = || VerifyGroupRequest {
        boot_profile: "focal".into(),
        group_id: "release-2".into(),
        manifest_digest: manifest_digest.clone(),
        files: vec!["vmlinuz".into()],
    };
    let verified = verify_group(State(state.clone()), Json(request()))
        .await
        .into_response();
    assert_eq!(verified.status(), StatusCode::OK);
    let verified_body = to_bytes(verified.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&verified_body).unwrap()["verified"],
        true
    );

    let duplicate = verify_group(
        State(state.clone()),
        Json(VerifyGroupRequest {
            boot_profile: "focal".into(),
            group_id: "release-2".into(),
            manifest_digest: manifest_digest.clone(),
            files: vec!["vmlinuz".into(), "vmlinuz".into()],
        }),
    )
    .await
    .into_response();
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);

    let unknown_file = verify_group(
        State(state.clone()),
        Json(VerifyGroupRequest {
            boot_profile: "focal".into(),
            group_id: "release-2".into(),
            manifest_digest: manifest_digest.clone(),
            files: vec!["not-in-release".into()],
        }),
    )
    .await
    .into_response();
    assert_eq!(unknown_file.status(), StatusCode::BAD_REQUEST);

    let missing_group = verify_group(
        State(state.clone()),
        Json(VerifyGroupRequest {
            boot_profile: "focal".into(),
            group_id: "release-404".into(),
            manifest_digest: manifest_digest.clone(),
            files: vec!["vmlinuz".into()],
        }),
    )
    .await
    .into_response();
    assert_eq!(missing_group.status(), StatusCode::NOT_FOUND);

    let worker_permits = state
        .artifact_hash_budget
        .clone()
        .acquire_many_owned(4)
        .await
        .unwrap();
    let saturated = verify_group(State(state.clone()), Json(request()))
        .await
        .into_response();
    assert_eq!(saturated.status(), StatusCode::SERVICE_UNAVAILABLE);
    drop(worker_permits);

    std::fs::write(&artifact, b"hostile-kernel").unwrap();
    let wrong_manifest = verify_group(
        State(state.clone()),
        Json(VerifyGroupRequest {
            boot_profile: "focal".into(),
            group_id: "release-2".into(),
            manifest_digest: "0".repeat(64),
            files: vec!["vmlinuz".into()],
        }),
    )
    .await
    .into_response();
    assert_eq!(wrong_manifest.status(), StatusCode::NOT_FOUND);

    let corrupted = verify_group(State(state.clone()), Json(request()))
        .await
        .into_response();
    let corrupted_body = to_bytes(corrupted.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&corrupted_body).unwrap()["verified"],
        false
    );

    std::fs::remove_file(&artifact).unwrap();
    std::fs::create_dir(&artifact).unwrap();
    let replaced = verify_group(State(state), Json(request()))
        .await
        .into_response();
    assert_eq!(replaced.status(), StatusCode::OK);
    let replaced_body = to_bytes(replaced.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&replaced_body).unwrap()["verified"],
        false
    );
}

async fn artifact_body(response: Response) -> Bytes {
    to_bytes(response.into_body(), usize::MAX).await.unwrap()
}

const TEST_ARTIFACT_TOKEN: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn artifact_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        HeaderValue::from_static(
            "Bearer 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ),
    );
    headers
}

#[test]
fn managed_http_range_selection_is_bounded_and_validator_aware() {
    let etag = "\"sha256-test\"";
    let selected = |value: &'static str, if_range: Option<&'static str>| {
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, HeaderValue::from_static(value));
        if let Some(if_range) = if_range {
            headers.insert(header::IF_RANGE, HeaderValue::from_static(if_range));
        }
        select_http_range(&headers, 10, Some(etag))
    };

    assert_eq!(
        selected("bytes=2-5", None),
        HttpRangeSelection::Partial(HttpByteRange { start: 2, len: 4 })
    );
    assert_eq!(
        selected("bytes=6-", None),
        HttpRangeSelection::Partial(HttpByteRange { start: 6, len: 4 })
    );
    assert_eq!(
        selected("bytes=-3", None),
        HttpRangeSelection::Partial(HttpByteRange { start: 7, len: 3 })
    );
    assert_eq!(
        selected("bytes=0-99", Some(etag)),
        HttpRangeSelection::Partial(HttpByteRange { start: 0, len: 10 })
    );
    assert_eq!(
        selected("bytes=10-", None),
        HttpRangeSelection::Unsatisfiable
    );
    assert_eq!(
        selected("bytes=5-4", None),
        HttpRangeSelection::Unsatisfiable
    );
    assert_eq!(
        selected("bytes=-0", None),
        HttpRangeSelection::Unsatisfiable
    );
    assert_eq!(selected("bytes=0-1,4-5", None), HttpRangeSelection::Full);
    assert_eq!(selected("items=0-1", None), HttpRangeSelection::Full);
    assert_eq!(selected("bytes=+1-3", None), HttpRangeSelection::Full);
    assert_eq!(selected("bytes=1-+3", None), HttpRangeSelection::Full);
    assert_eq!(selected("bytes=-+3", None), HttpRangeSelection::Full);
    assert_eq!(
        selected("bytes=2-5", Some("\"sha256-other\"")),
        HttpRangeSelection::Full
    );
    assert_eq!(
        select_http_range(&HeaderMap::new(), 10, Some(etag)),
        HttpRangeSelection::Full
    );
    let mut headers = HeaderMap::new();
    headers.insert(header::RANGE, HeaderValue::from_static("bytes=2-5"));
    assert_eq!(
        select_http_range(&headers, 10, None),
        HttpRangeSelection::Full
    );
    headers.append(header::RANGE, HeaderValue::from_static("bytes=6-7"));
    assert_eq!(
        select_http_range(&headers, 10, Some(etag)),
        HttpRangeSelection::Full
    );
}

#[tokio::test]
async fn managed_http_ranges_stream_only_the_selected_verified_bytes() {
    let tempdir = tempfile::tempdir().unwrap();
    let root = tempdir.path().to_path_buf();
    std::fs::write(root.join("artifact-v1"), b"0123456789").unwrap();
    let state = test_state_with_root(root.clone());
    state
        .version_store
        .atomic_switch_for_profile(
            "default".into(),
            "range-release".into(),
            vec![("artifact".into(), root.join("artifact-v1"))],
        )
        .unwrap();
    let client_ip = IpAddr::from([192, 0, 2, 60]);
    state.insert_boot_session(
        client_ip,
        with_test_artifact_token(BootSessionEntry {
            trace_id: None,
            boot_profile: "default".into(),
            client_mac: None,
            serial: None,
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(300),
        }),
    );

    let mut headers = artifact_headers();
    headers.insert(header::RANGE, HeaderValue::from_static("bytes=2-5"));
    let partial = serve_artifact(
        State(state.clone()),
        ConnectInfo(SocketAddr::new(client_ip, 40200)),
        headers,
        AxumPath("artifact".into()),
    )
    .await;
    assert_eq!(partial.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(partial.headers()[header::ACCEPT_RANGES], "bytes");
    assert_eq!(partial.headers()[header::CONTENT_LENGTH], "4");
    assert_eq!(partial.headers()[header::CONTENT_RANGE], "bytes 2-5/10");
    let etag = partial.headers()[header::ETAG].clone();
    assert_eq!(
        etag,
        HeaderValue::from_str(&format!(
            "\"sha256-{}\"",
            hex::encode(Sha256::digest(b"0123456789"))
        ))
        .unwrap()
    );
    assert_eq!(&artifact_body(partial).await[..], b"2345");
    assert_eq!(state.http_artifact_cache.stats().entries, 0);

    let mut headers = artifact_headers();
    headers.insert(header::RANGE, HeaderValue::from_static("bytes=-3"));
    headers.insert(header::IF_RANGE, HeaderValue::from_static("\"stale\""));
    let stale = serve_artifact(
        State(state.clone()),
        ConnectInfo(SocketAddr::new(client_ip, 40201)),
        headers,
        AxumPath("artifact".into()),
    )
    .await;
    assert_eq!(stale.status(), StatusCode::OK);
    assert!(stale.headers().get(header::CONTENT_RANGE).is_none());
    assert_eq!(&artifact_body(stale).await[..], b"0123456789");

    let mut headers = artifact_headers();
    headers.insert(header::RANGE, HeaderValue::from_static("bytes=-3"));
    headers.insert(header::IF_RANGE, etag);
    let cached = serve_artifact(
        State(state.clone()),
        ConnectInfo(SocketAddr::new(client_ip, 40202)),
        headers,
        AxumPath("artifact".into()),
    )
    .await;
    assert_eq!(cached.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(&artifact_body(cached).await[..], b"789");
    // Non-Unix platforms lack stable file identity, so snapshots are never retained.
    assert_eq!(
        state.http_artifact_cache.stats().verified_hits,
        u64::from(cfg!(unix))
    );

    let mut headers = artifact_headers();
    headers.insert(header::RANGE, HeaderValue::from_static("bytes=99-"));
    let unsatisfiable = serve_artifact(
        State(state.clone()),
        ConnectInfo(SocketAddr::new(client_ip, 40203)),
        headers,
        AxumPath("artifact".into()),
    )
    .await;
    assert_eq!(unsatisfiable.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(unsatisfiable.headers()[header::CONTENT_RANGE], "bytes */10");
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);

    let mut headers = artifact_headers();
    headers.insert(header::RANGE, HeaderValue::from_static("bytes=0-1"));
    let abandoned = serve_artifact(
        State(state.clone()),
        ConnectInfo(SocketAddr::new(client_ip, 40204)),
        headers,
        AxumPath("artifact".into()),
    )
    .await;
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 1);
    drop(abandoned);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
}

#[test]
fn forwarded_client_ip_is_accepted_only_from_an_exact_trusted_peer() {
    let proxy = IpAddr::from([127, 0, 0, 1]);
    let client = IpAddr::from([192, 0, 2, 42]);
    let untrusted = IpAddr::from([127, 0, 0, 2]);
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("192.0.2.42"));

    assert_eq!(resolved_client_ip(proxy, &headers, &[proxy]), Ok(client));
    assert_eq!(
        resolved_client_ip(untrusted, &headers, &[proxy]),
        Ok(untrusted)
    );
}

#[test]
fn trusted_ipv6_proxy_accepts_one_numeric_ipv6_client() {
    let proxy: IpAddr = "fd00::10".parse().unwrap();
    let client: IpAddr = "fd00::42".parse().unwrap();
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("fd00::42"));

    assert_eq!(resolved_client_ip(proxy, &headers, &[proxy]), Ok(client));
}

#[test]
fn trusted_proxy_rejects_forwarded_chains_and_malformed_addresses() {
    let proxy = IpAddr::from([127, 0, 0, 1]);
    for value in ["192.0.2.42, 198.51.100.8", "not-an-ip", ""] {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_str(value).unwrap());
        assert_eq!(resolved_client_ip(proxy, &headers, &[proxy]), Err(()));
    }
}

fn with_test_artifact_token(mut entry: BootSessionEntry) -> BootSessionEntry {
    entry.artifact_token_hash = Some(Sha256::digest(TEST_ARTIFACT_TOKEN.as_bytes()).into());
    entry
}

#[tokio::test]
async fn test_api_key_authentication_requires_exact_match() {
    // Exercise the authentication call site, not subtle itself or execution timing.
    let dir = tempfile::tempdir().unwrap();
    let expected = "a".repeat(32);
    let state = test_state_with_root_api_bind_and_key(
        dir.path().to_path_buf(),
        IpAddr::from([0, 0, 0, 0]),
        Some(expected.clone()),
    );
    let app = api_router(state);
    let mut cases = vec![
        (None, StatusCode::UNAUTHORIZED),
        (Some(expected.clone()), StatusCode::OK),
        (Some(format!("{expected}a")), StatusCode::UNAUTHORIZED),
    ];
    for index in 0..expected.len() {
        let mut provided = expected.as_bytes().to_vec();
        provided[index] = b'b';
        cases.push((
            Some(String::from_utf8(provided).unwrap()),
            StatusCode::UNAUTHORIZED,
        ));
    }
    for len in 0..expected.len() {
        cases.push((Some(expected[..len].to_owned()), StatusCode::UNAUTHORIZED));
    }
    for (key, expected_status) in cases {
        let mut request = Request::builder()
            .uri("/api/v1/info")
            .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40110))));
        if let Some(key) = key {
            request = request.header("x-api-key", key);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected_status);
    }
}

#[test]
fn test_normalize_mac_address_accepts_common_forms() {
    assert_eq!(
        normalize_mac_address("AA:BB:CC:DD:EE:FF").as_deref(),
        Some("aa:bb:cc:dd:ee:ff")
    );
    assert_eq!(
        normalize_mac_address("aabbccddeeff").as_deref(),
        Some("aa:bb:cc:dd:ee:ff")
    );
    assert_eq!(
        normalize_mac_address("aa-bb-cc-dd-ee-ff").as_deref(),
        Some("aa:bb:cc:dd:ee:ff")
    );
}

#[test]
fn test_normalize_mac_address_rejects_invalid_values() {
    assert!(normalize_mac_address("aa:bb:cc").is_none());
    assert!(normalize_mac_address("aa:bb:cc:dd:ee:gg").is_none());
    assert!(normalize_mac_address("aa:bb:cc:dd:ee:ff:00").is_none());
}

#[test]
fn test_session_identity_validators() {
    assert!(is_valid_trace_id("trace-ABC123"));
    assert!(!is_valid_trace_id("trace_ABC123"));
    assert!(is_valid_serial("SN-ABC_123.9:rack7"));
    assert!(!is_valid_serial("SN 123"));
    assert!(is_valid_boot_profile("ubuntu-jammy.x86_64"));
    assert!(!is_valid_boot_profile("../jammy"));
}

#[tokio::test]
async fn test_session_capacity_rejects_only_new_client_ips() {
    let dir = tempfile::tempdir().unwrap();
    let state = test_state_with_root_api_bind_key_and_session_limit(
        dir.path().to_path_buf(),
        "127.0.0.1".parse().unwrap(),
        None,
        1,
    );
    let request = |client_ip, trace_id: &str| RegisterSessionRequest {
        client_ip,
        trace_id: Some(trace_id.into()),
        boot_profile: None,
        client_mac: None,
        serial: None,
        ttl_seconds: Some(60),
        new_epoch: false,
        require_managed: false,
    };

    let first = register_session(
        State(state.clone()),
        Json(request("192.0.2.1".parse().unwrap(), "first")),
    )
    .await
    .into_response();
    assert_eq!(first.status(), StatusCode::CREATED);

    let rejected = register_session(
        State(state.clone()),
        Json(request("192.0.2.2".parse().unwrap(), "second")),
    )
    .await
    .into_response();
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);

    let update = register_session(
        State(state),
        Json(request("192.0.2.1".parse().unwrap(), "updated")),
    )
    .await
    .into_response();
    assert_eq!(update.status(), StatusCode::CREATED);
}

#[test]
fn test_http_governor_cost_multiplier_prioritizes_boot_phases() {
    assert_eq!(http_governor_cost_multiplier(BootPhase::PxeRom), 1.0);
    assert!(http_governor_cost_multiplier(BootPhase::Config) < 1.3);
    assert!(http_governor_cost_multiplier(BootPhase::Kernel) > 1.6);
    assert!(http_governor_cost_multiplier(BootPhase::OsImage) > 3.0);
    assert_eq!(governed_http_charge_len(100, 10.0 / 6.0), 167);
}

#[test]
fn test_http_stream_chunks_reduce_file_reads_without_unbounded_peak_buffers() {
    assert_eq!(http_stream_chunk_bytes(1), 4 * 1024 * 1024);
    assert_eq!(http_stream_chunk_bytes(10), 4 * 1024 * 1024);
    assert_eq!(http_stream_chunk_bytes(31), 4 * 1024 * 1024);
    assert_eq!(http_stream_chunk_bytes(32), 256 * 1024);
    assert_eq!(http_stream_chunk_bytes(127), 256 * 1024);
    assert_eq!(http_stream_chunk_bytes(128), 64 * 1024);
    assert_eq!(http_stream_chunk_bytes(500), 64 * 1024);
}

#[test]
fn test_http_guard_drop_after_full_body_counts_completed() {
    let tempdir = tempfile::tempdir().unwrap();
    let state = test_state_with_root(tempdir.path().to_path_buf());
    state.active_transfers.fetch_add(1, Ordering::AcqRel);
    {
        let mut guard = HttpArtifactTransferGuard::new(
            state.clone(),
            None,
            BootPhase::Kernel,
            "focal".to_string(),
            IpAddr::from([10, 33, 128, 153]),
            "vmlinuz".to_string(),
            6,
            Some("hash".to_string()),
            None,
            None,
            None,
            TRANSPORT_HTTP,
        );
        guard.start();
        guard.record_chunk(6);
    }

    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
    let transport_metrics = state.metrics.transport_metrics_snapshot();
    assert_eq!(
        transport_metrics
            .iter()
            .find(|(transport, _)| *transport == TRANSPORT_HTTP)
            .map(|(_, (_, bytes, _))| *bytes),
        Some(6)
    );
    assert!(
        transport_metrics
            .iter()
            .all(|(_, (_, _, failures))| *failures == 0)
    );
}

#[tokio::test]
async fn test_http_guard_uses_reserved_durable_audit_capacity() {
    let tempdir = tempfile::tempdir().unwrap();
    let mut state = test_state_with_root(tempdir.path().to_path_buf());
    let audit = Arc::new(
        crate::features::audit::AuditLog::new(tempdir.path().join("audit.jsonl")).unwrap(),
    );
    let writer = crate::features::audit::AuditWriter::start(
        audit.clone(),
        1024 * 1024,
        state.critical_services_healthy.clone(),
    )
    .unwrap();
    let reservation = writer.try_reserve().unwrap();
    let mutable = Arc::get_mut(&mut state).unwrap();
    mutable.audit_log = Some(audit.clone());
    mutable.audit_writer = Some(writer.clone());
    metrics::initialize(&state, None);
    state.active_transfers.fetch_add(1, Ordering::AcqRel);

    {
        let mut guard = HttpArtifactTransferGuard::new(
            state.clone(),
            None,
            BootPhase::Kernel,
            "focal".to_string(),
            IpAddr::from([192, 0, 2, 8]),
            "vmlinuz".to_string(),
            6,
            Some("a".repeat(64)),
            None,
            None,
            Some(reservation),
            TRANSPORT_HTTP,
        );
        guard.start();
        guard.record_chunk(6);
    }

    writer.wait_idle().await.unwrap();
    let entries = audit.recent_entries(None, 2).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(matches!(entries[0].outcome, TransferOutcome::Completed));
    assert_eq!(
        entries[0].delivery.as_ref().unwrap().transport,
        TRANSPORT_HTTP
    );
    let pipeline = writer.metrics_snapshot();
    assert_eq!(pipeline.jsonl_records_total, 1);
    assert_eq!(pipeline.outstanding_records, 0);
    assert_eq!(pipeline.reserved_bytes, 0);
    let metrics_response = metrics_handler(State(state.clone())).await.into_response();
    let metrics_text = String::from_utf8(
        to_bytes(metrics_response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(metrics_text.contains("tempest_audit_queue_outstanding_records 0"));
    assert!(metrics_text.contains("tempest_audit_queue_reserved_bytes 0"));
    assert!(metrics_text.contains("tempest_audit_jsonl_records_total 1"));
    assert!(
        metrics_text.contains("tempest_audit_admission_rejected_total{reason=\"byte_capacity\"} 0")
    );
    assert!(
        metrics_text.contains("tempest_audit_admission_rejected_total{reason=\"writer_queue\"} 0")
    );
    assert!(
        metrics_text
            .contains("tempest_audit_admission_rejected_total{reason=\"writer_failure\"} 0")
    );
    assert!(state.critical_services_healthy.load(Ordering::Acquire));
}

#[tokio::test]
async fn test_http_artifacts_stay_on_session_pinned_version_group() {
    let tempdir = tempfile::tempdir().unwrap();
    let root = tempdir.path().to_path_buf();
    std::fs::write(root.join("v1-vmlinuz"), b"v1-kernel").unwrap();
    std::fs::write(root.join("v1-initrd"), b"v1-initrd").unwrap();
    std::fs::write(root.join("v2-vmlinuz"), b"v2-kernel").unwrap();
    std::fs::write(root.join("v2-initrd"), b"v2-initrd").unwrap();
    std::fs::write(root.join("unmanaged"), b"outside-manifest").unwrap();

    let audit_path = root.join("audit.jsonl");
    let mut state = test_state_with_root(root.clone());
    Arc::get_mut(&mut state).unwrap().audit_log = Some(Arc::new(
        crate::features::audit::AuditLog::new(audit_path.clone()).unwrap(),
    ));
    metrics::initialize(&state, None);
    let group_v1 = state
        .version_store
        .atomic_switch_for_profile(
            "focal".to_string(),
            "release-a".to_string(),
            vec![
                ("vmlinuz".to_string(), root.join("v1-vmlinuz")),
                ("initrd".to_string(), root.join("v1-initrd")),
            ],
        )
        .unwrap();

    let client_ip = IpAddr::from([10, 33, 128, 150]);
    state.insert_boot_session(
        client_ip,
        with_test_artifact_token(BootSessionEntry {
            trace_id: Some("trace-1".to_string()),
            boot_profile: "focal".to_string(),
            client_mac: None,
            serial: None,
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(300),
        }),
    );

    let first = serve_artifact(
        State(state.clone()),
        ConnectInfo(SocketAddr::new(client_ip, 40100)),
        artifact_headers(),
        AxumPath("vmlinuz".to_string()),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(
        first.headers().get("x-tempest-group-id").unwrap(),
        "release-a"
    );
    assert_eq!(
        first.headers().get("x-tempest-version-id").unwrap(),
        &HeaderValue::from_str(&group_v1.version_id.to_string()).unwrap()
    );
    assert_eq!(first.headers().get("x-tempest-transport").unwrap(), "HTTP");
    assert_eq!(
        first.headers().get("x-tempest-boot-phase").unwrap(),
        "KERNEL"
    );
    assert_eq!(first.headers().get("x-tempest-phase-weight").unwrap(), "6");
    assert_eq!(
        first
            .headers()
            .get("x-tempest-http-governor-cost-multiplier")
            .unwrap(),
        "1.667"
    );
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 1);
    assert_eq!(&artifact_body(first).await[..], b"v1-kernel");
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);

    assert_eq!(
        state
            .boot_sessions
            .get(&client_ip)
            .and_then(|entry| entry.pinned_boot_chain.clone())
            .unwrap()
            .group_id,
        "release-a"
    );

    state
        .version_store
        .atomic_switch_for_profile(
            "focal".to_string(),
            "release-b".to_string(),
            vec![
                ("vmlinuz".to_string(), root.join("v2-vmlinuz")),
                ("initrd".to_string(), root.join("v2-initrd")),
            ],
        )
        .unwrap();

    let mut second_headers = artifact_headers();
    second_headers.insert(header::RANGE, HeaderValue::from_static("bytes=3-"));
    let second = serve_artifact(
        State(state.clone()),
        ConnectInfo(SocketAddr::new(client_ip, 40100)),
        second_headers,
        AxumPath("initrd".to_string()),
    )
    .await;
    assert_eq!(second.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        second.headers().get("x-tempest-group-id").unwrap(),
        "release-a"
    );
    assert_eq!(second.headers()[header::CONTENT_RANGE], "bytes 3-8/9");
    assert_eq!(&artifact_body(second).await[..], b"initrd");
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);

    let unmanaged = serve_artifact(
        State(state.clone()),
        ConnectInfo(SocketAddr::new(client_ip, 40100)),
        artifact_headers(),
        AxumPath("unmanaged".to_string()),
    )
    .await;
    assert_eq!(unmanaged.status(), StatusCode::NOT_FOUND);
    assert!(
        unmanaged
            .headers()
            .get("x-tempest-manifest-digest")
            .is_none()
    );
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);

    let entries: Vec<crate::features::audit::AuditEntry> = std::fs::read_to_string(audit_path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(entries.len(), 2);
    assert!(
        entries.iter().all(|entry| {
            entry.delivery.as_ref().is_some_and(|delivery| {
                delivery.group_id.as_deref() == Some("release-a")
                    && delivery.manifest_digest == Some(group_v1.manifest.manifest_digest.clone())
                    && delivery.transport == TRANSPORT_HTTP
            })
        }),
        "unexpected audit entries: {entries:#?}"
    );

    state.metrics.release_event("cutover_attempt");
    state
        .metrics
        .extension_failed(crate::server::ExtensionFailure::SchedulerSendPacket);
    state
        .metrics
        .extension_failed(crate::server::ExtensionFailure::ReadProtocolEncodePacket);
    state
        .metrics
        .cutover_finished(Instant::now(), "cutover_success");
    let metrics_response = metrics_handler(State(state.clone())).await.into_response();
    let metrics_text = String::from_utf8(
        to_bytes(metrics_response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(metrics_text.contains("tempest_transfers_by_transport_total{transport=\"HTTP\"} 2"));
    assert!(metrics_text.contains(
        "tempest_transfers_by_transport_phase_total{transport=\"HTTP\",phase=\"KERNEL\"} 1"
    ));
    assert!(metrics_text.contains(
        "tempest_transfers_by_profile_transport_total{boot_profile=\"focal\",transport=\"HTTP\"} 2"
    ));
    assert!(
        metrics_text.contains("tempest_release_control_events_total{event=\"cutover_attempt\"} 1")
    );
    assert!(metrics_text.contains("tempest_release_cutover_duration_seconds_count 1"));
    assert!(metrics_text.contains("tempest_listener_shard_requests_total{shard=\"0\"} 0"));
    assert!(metrics_text.contains(
        "tempest_extension_failures_total{contract=\"scheduler\",operation=\"send_packet\"} 1"
    ));
    assert!(metrics_text.contains(
        "tempest_extension_failures_total{contract=\"read_protocol\",operation=\"encode_packet\"} 1"
    ));
    assert!(
        metrics_text.contains(
            "tempest_extension_failures_total{contract=\"router\",operation=\"handle\"} 0"
        )
    );
    #[cfg(target_pointer_width = "64")]
    assert!(metrics_text.contains("tempest_runtime_worker_busy_seconds_total{worker=\"0\"}"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_http_cache_reuses_verified_snapshot_without_touching_tftp_cache() {
    let tempdir = tempfile::tempdir().unwrap();
    let root = tempdir.path().to_path_buf();
    let artifact = root.join("kernel-v1");
    std::fs::write(&artifact, b"verified-kernel").unwrap();
    let state = test_state_with_root(root.clone());
    state
        .version_store
        .atomic_switch_for_profile(
            "focal".to_string(),
            "release-cache".to_string(),
            vec![("vmlinuz".to_string(), artifact.clone())],
        )
        .unwrap();
    let client_ip = IpAddr::from([10, 33, 128, 159]);
    state.insert_boot_session(
        client_ip,
        with_test_artifact_token(BootSessionEntry {
            trace_id: None,
            boot_profile: "focal".to_string(),
            client_mac: None,
            serial: None,
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(300),
        }),
    );

    let first = serve_artifact(
        State(state.clone()),
        ConnectInfo(SocketAddr::new(client_ip, 40109)),
        artifact_headers(),
        AxumPath("vmlinuz".to_string()),
    )
    .await;
    assert_eq!(&artifact_body(first).await[..], b"verified-kernel");

    let replacement = root.join("kernel-replacement");
    std::fs::write(&replacement, b"changed-content").unwrap();
    std::fs::rename(replacement, &artifact).unwrap();

    let second = serve_artifact(
        State(state.clone()),
        ConnectInfo(SocketAddr::new(client_ip, 40109)),
        artifact_headers(),
        AxumPath("vmlinuz".to_string()),
    )
    .await;
    assert_eq!(&artifact_body(second).await[..], b"verified-kernel");
    assert_eq!(state.http_artifact_cache.stats().verified_hits, 1);
    assert_eq!(state.hot_artifact_cache.stats().entries, 0);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn test_http_cache_reuses_recent_unmanaged_snapshot_without_touching_tftp_cache() {
    let tempdir = tempfile::tempdir().unwrap();
    let root = tempdir.path().to_path_buf();
    let artifact = root.join("unmanaged");
    std::fs::write(&artifact, b"cached-bytes").unwrap();
    let mut state = test_state_with_root(root.clone());
    let mutable = Arc::get_mut(&mut state).unwrap();
    let mut config = (*mutable.config).clone();
    // A real-clock window: an hour so a stalled runner cannot expire it
    // between the two requests this test expects to share one snapshot.
    config.server.unmanaged_cache_validation_interval_ms = 3_600_000;
    mutable.config = Arc::new(config);
    let client_ip = IpAddr::from([10, 33, 128, 160]);
    state.insert_boot_session(
        client_ip,
        with_test_artifact_token(BootSessionEntry {
            trace_id: None,
            boot_profile: "focal".to_string(),
            client_mac: None,
            serial: None,
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(300),
        }),
    );

    let mut unmanaged_headers = artifact_headers();
    unmanaged_headers.insert(header::RANGE, HeaderValue::from_static("bytes=2-5"));
    let first = serve_artifact(
        State(state.clone()),
        ConnectInfo(SocketAddr::new(client_ip, 40110)),
        unmanaged_headers,
        AxumPath("unmanaged".to_string()),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(first.headers()[header::ACCEPT_RANGES], "none");
    assert!(first.headers().get(header::ETAG).is_none());
    assert_eq!(&artifact_body(first).await[..], b"cached-bytes");

    std::fs::write(&artifact, b"replacement!").unwrap();
    let second = serve_artifact(
        State(state.clone()),
        ConnectInfo(SocketAddr::new(client_ip, 40110)),
        artifact_headers(),
        AxumPath("unmanaged".to_string()),
    )
    .await;
    assert_eq!(&artifact_body(second).await[..], b"cached-bytes");
    assert_eq!(state.http_artifact_cache.stats().freshness_hits, 1);
    assert_eq!(state.hot_artifact_cache.stats().entries, 0);
}

#[test]
fn test_http_memory_cache_hit_selects_one_frame_only_without_governance() {
    assert_eq!(http_source_chunk_bytes(10, true, false), usize::MAX);
    assert_eq!(
        http_source_chunk_bytes(10, true, true),
        HTTP_STREAM_CHUNK_BYTES
    );
    assert_eq!(
        http_source_chunk_bytes(HTTP_STREAM_SATURATED_TRANSFERS, true, true),
        HTTP_STREAM_SATURATED_CHUNK_BYTES
    );
    assert_eq!(
        http_source_chunk_bytes(10, false, false),
        HTTP_STREAM_CHUNK_BYTES
    );
}

#[tokio::test]
async fn test_http_artifact_rejects_path_traversal_and_releases_slot() {
    let tempdir = tempfile::tempdir().unwrap();
    let state = test_state_with_root(tempdir.path().to_path_buf());
    let client_ip = IpAddr::from([10, 33, 128, 151]);

    let response = serve_artifact(
        State(state.clone()),
        ConnectInfo(SocketAddr::new(client_ip, 40101)),
        HeaderMap::new(),
        AxumPath("../secret".to_string()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn test_http_artifact_requires_active_boot_session() {
    let tempdir = tempfile::tempdir().unwrap();
    let root = tempdir.path().to_path_buf();
    std::fs::write(root.join("vmlinuz"), b"kernel").unwrap();
    let state = test_state_with_root(root);
    let client_ip = IpAddr::from([10, 33, 128, 152]);

    let response = serve_artifact(
        State(state.clone()),
        ConnectInfo(SocketAddr::new(client_ip, 40102)),
        HeaderMap::new(),
        AxumPath("vmlinuz".to_string()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn test_http_artifact_route_allows_seeded_pxe_client_without_api_key() {
    let tempdir = tempfile::tempdir().unwrap();
    let root = tempdir.path().to_path_buf();
    std::fs::write(root.join("vmlinuz-v1"), b"kernel-over-http").unwrap();
    let state = test_state_with_root_api_bind_and_key(
        root.clone(),
        IpAddr::from([0, 0, 0, 0]),
        Some("strong-artifact-api-key".to_string()),
    );
    state
        .version_store
        .atomic_switch_for_profile(
            "focal".to_string(),
            "release-http".to_string(),
            vec![("vmlinuz".to_string(), root.join("vmlinuz-v1"))],
        )
        .unwrap();
    let client_ip = IpAddr::from([10, 33, 128, 155]);
    state.insert_boot_session(
        client_ip,
        with_test_artifact_token(BootSessionEntry {
            trace_id: Some("trace-http".to_string()),
            boot_profile: "focal".to_string(),
            client_mac: Some("aa:bb:cc:dd:ee:ff".to_string()),
            serial: Some("PXE-HTTP-001".to_string()),
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(300),
        }),
    );

    let app = api_router(state.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/artifacts/vmlinuz")
                .header(
                    axum::http::header::AUTHORIZATION,
                    format!("Bearer {TEST_ARTIFACT_TOKEN}"),
                )
                .extension(ConnectInfo(SocketAddr::new(client_ip, 40105)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("x-tempest-boot-profile").unwrap(),
        "focal"
    );
    assert_eq!(
        response.headers().get("x-tempest-group-id").unwrap(),
        "release-http"
    );
    assert_eq!(&artifact_body(response).await[..], b"kernel-over-http");
}

#[tokio::test]
async fn test_http_artifact_route_rejects_unseeded_pxe_client_without_api_key() {
    let tempdir = tempfile::tempdir().unwrap();
    let root = tempdir.path().to_path_buf();
    std::fs::write(root.join("vmlinuz"), b"kernel").unwrap();
    let state = test_state_with_root_api_bind_and_key(
        root,
        IpAddr::from([0, 0, 0, 0]),
        Some("strong-artifact-api-key".to_string()),
    );
    let client_ip = IpAddr::from([10, 33, 128, 156]);
    let app = api_router(state.clone());

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/artifacts/vmlinuz")
                .extension(ConnectInfo(SocketAddr::new(client_ip, 40106)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn test_native_http_boot_uses_source_ip_session_and_managed_profile() {
    let tempdir = tempfile::tempdir().unwrap();
    let root = tempdir.path().to_path_buf();
    std::fs::write(root.join("focal-boot.efi"), b"managed-native-boot").unwrap();
    let mut state = test_state_with_root(root.clone());
    enable_native_http_boot(&mut state, "boot.efi");
    metrics::initialize(&state, None);
    state
        .version_store
        .atomic_switch_for_profile(
            "focal".to_string(),
            "native-release".to_string(),
            vec![("boot.efi".to_string(), root.join("focal-boot.efi"))],
        )
        .unwrap();
    let client_ip = IpAddr::from([192, 0, 2, 42]);
    insert_native_boot_session(&state, client_ip, "focal");

    let response = api_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/boot/v1/boot.efi")
                .header(header::RANGE, "bytes=8-13")
                .extension(ConnectInfo(SocketAddr::new(client_ip, 40120)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/efi");
    assert_eq!(response.headers()[header::CONTENT_RANGE], "bytes 8-13/19");
    assert_eq!(
        response.headers()["x-tempest-transport"],
        TRANSPORT_HTTP_NATIVE
    );
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()["x-tempest-http-mode"], "native");
    assert_eq!(response.headers()["x-tempest-boot-profile"], "focal");
    assert_eq!(response.headers()["x-tempest-group-id"], "native-release");
    assert_eq!(&artifact_body(response).await[..], b"native");
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
    assert_eq!(
        state
            .metrics
            .transport_metrics_snapshot()
            .into_iter()
            .find(|(transport, _)| *transport == TRANSPORT_HTTP_NATIVE),
        Some((TRANSPORT_HTTP_NATIVE, (1, 6, 0)))
    );
    let metrics_response = metrics_handler(State(state.clone())).await.into_response();
    let metrics_text = String::from_utf8(
        to_bytes(metrics_response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(
        metrics_text.contains("tempest_transfers_by_transport_total{transport=\"HTTP_NATIVE\"} 1")
    );
    assert!(metrics_text.contains(
        "tempest_transfers_by_profile_transport_total{boot_profile=\"focal\",transport=\"HTTP_NATIVE\"} 1"
    ));
}

#[tokio::test]
async fn test_native_http_boot_uses_ipv6_source_ip_session() {
    let tempdir = tempfile::tempdir().unwrap();
    let root = tempdir.path().to_path_buf();
    std::fs::write(root.join("focal-boot.efi"), b"managed-ipv6-native-boot").unwrap();
    let mut state = test_state_with_root(root.clone());
    enable_native_http_boot(&mut state, "boot.efi");
    state
        .version_store
        .atomic_switch_for_profile(
            "focal".to_string(),
            "ipv6-native-release".to_string(),
            vec![("boot.efi".to_string(), root.join("focal-boot.efi"))],
        )
        .unwrap();
    let client_ip: IpAddr = "fd89:60::42".parse().unwrap();
    insert_native_boot_session(&state, client_ip, "focal");

    let response = api_router(state)
        .oneshot(
            Request::builder()
                .uri("/boot/v1/boot.efi")
                .extension(ConnectInfo(SocketAddr::new(client_ip, 40120)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["x-tempest-boot-profile"], "focal");
    assert_eq!(
        response.headers()["x-tempest-group-id"],
        "ipv6-native-release"
    );
    assert_eq!(
        &artifact_body(response).await[..],
        b"managed-ipv6-native-boot"
    );
}

#[tokio::test]
async fn test_native_http_boot_fails_closed_without_session_or_managed_release() {
    let tempdir = tempfile::tempdir().unwrap();
    let root = tempdir.path().to_path_buf();
    std::fs::write(root.join("boot.efi"), b"unmanaged-must-not-escape").unwrap();
    let mut state = test_state_with_root(root);
    enable_native_http_boot(&mut state, "boot.efi");
    let client_ip = IpAddr::from([192, 0, 2, 43]);
    let app = api_router(state.clone());

    let without_session = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/boot/v1/boot.efi")
                .header(
                    header::AUTHORIZATION,
                    format!("Bearer {TEST_ARTIFACT_TOKEN}"),
                )
                .extension(ConnectInfo(SocketAddr::new(client_ip, 40121)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(without_session.status(), StatusCode::FORBIDDEN);

    insert_native_boot_session(&state, client_ip, "default");
    let unmanaged = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/boot/v1/boot.efi")
                .extension(ConnectInfo(SocketAddr::new(client_ip, 40122)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unmanaged.status(), StatusCode::NOT_FOUND);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);

    let other_name = app
        .oneshot(
            Request::builder()
                .uri("/boot/v1/other.efi")
                .extension(ConnectInfo(SocketAddr::new(client_ip, 40123)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(other_name.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_native_http_boot_head_completes_audit_without_streaming_body() {
    let tempdir = tempfile::tempdir().unwrap();
    let root = tempdir.path().to_path_buf();
    std::fs::write(root.join("boot.efi"), b"native-head").unwrap();
    let audit = Arc::new(crate::features::audit::AuditLog::new(root.join("audit.jsonl")).unwrap());
    let mut state = test_state_with_root(root.clone());
    enable_native_http_boot(&mut state, "boot.efi");
    Arc::get_mut(&mut state).unwrap().audit_log = Some(audit.clone());
    state
        .version_store
        .atomic_switch_for_profile(
            "default".to_string(),
            "native-head-release".to_string(),
            vec![("boot.efi".to_string(), root.join("boot.efi"))],
        )
        .unwrap();
    let client_ip = IpAddr::from([192, 0, 2, 44]);
    insert_native_boot_session(&state, client_ip, "default");

    let response = api_router(state.clone())
        .oneshot(
            Request::builder()
                .method(Method::HEAD)
                .uri("/boot/v1/boot.efi")
                .extension(ConnectInfo(SocketAddr::new(client_ip, 40124)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_LENGTH], "11");
    assert_eq!(response.headers()[header::ACCEPT_RANGES], "bytes");
    assert!(response.headers().get(header::ETAG).is_some());
    assert!(artifact_body(response).await.is_empty());
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
    let entries = audit.recent_entries(None, 2).unwrap();
    assert_eq!(entries.len(), 1);
    assert!(matches!(entries[0].outcome, TransferOutcome::Completed));
    assert_eq!(entries[0].blocks_sent, 0);
    assert_eq!(
        entries[0].delivery.as_ref().unwrap().transport,
        TRANSPORT_HTTP_NATIVE
    );
}

#[tokio::test]
async fn test_native_http_boot_accepts_only_trusted_forwarded_client_identity() {
    let tempdir = tempfile::tempdir().unwrap();
    let root = tempdir.path().to_path_buf();
    std::fs::write(root.join("boot.efi"), b"native-proxy").unwrap();
    let mut state = test_state_with_root(root.clone());
    enable_native_http_boot(&mut state, "boot.efi");
    let proxy_ip = IpAddr::from([192, 0, 2, 10]);
    let mutable = Arc::get_mut(&mut state).unwrap();
    Arc::make_mut(&mut mutable.config).api.trusted_proxy_ips = vec![proxy_ip];
    state
        .version_store
        .atomic_switch_for_profile(
            "default".to_string(),
            "native-proxy-release".to_string(),
            vec![("boot.efi".to_string(), root.join("boot.efi"))],
        )
        .unwrap();
    let client_ip = IpAddr::from([192, 0, 2, 45]);
    insert_native_boot_session(&state, client_ip, "default");
    let app = api_router(state.clone());

    let trusted = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/boot/v1/boot.efi")
                .header("x-forwarded-for", client_ip.to_string())
                .extension(ConnectInfo(SocketAddr::new(proxy_ip, 40125)))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(trusted.status(), StatusCode::OK);
    assert_eq!(&artifact_body(trusted).await[..], b"native-proxy");

    let untrusted = app
        .oneshot(
            Request::builder()
                .uri("/boot/v1/boot.efi")
                .header("x-forwarded-for", client_ip.to_string())
                .extension(ConnectInfo(SocketAddr::from(([198, 51, 100, 10], 40126))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(untrusted.status(), StatusCode::FORBIDDEN);
}

#[cfg(unix)]
#[tokio::test]
async fn test_http_artifact_rejects_versioned_parent_symlink_escape() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("vmlinuz"), b"outside-kernel").unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("release-link")).unwrap();

    let state = test_state_with_root(root.path().to_path_buf());
    state
        .version_store
        .atomic_switch_for_profile(
            "focal".to_string(),
            "release-escape".to_string(),
            vec![(
                "vmlinuz".to_string(),
                root.path().join("release-link/vmlinuz"),
            )],
        )
        .unwrap();
    let client_ip = IpAddr::from([10, 33, 128, 154]);
    state.insert_boot_session(
        client_ip,
        with_test_artifact_token(BootSessionEntry {
            trace_id: Some("trace-escape".to_string()),
            boot_profile: "focal".to_string(),
            client_mac: None,
            serial: None,
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(300),
        }),
    );

    let response = serve_artifact(
        State(state.clone()),
        ConnectInfo(SocketAddr::new(client_ip, 40104)),
        artifact_headers(),
        AxumPath("vmlinuz".to_string()),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn test_mutation_routes_require_api_key_when_api_bind_is_not_loopback() {
    let tempdir = tempfile::tempdir().unwrap();
    let state =
        test_state_with_root_and_api_bind(tempdir.path().to_path_buf(), IpAddr::from([0, 0, 0, 0]));
    let app = api_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/v1/drain")
                .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40110))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_exposed_api_requires_key_for_operational_read_routes() {
    let tempdir = tempfile::tempdir().unwrap();
    let state =
        test_state_with_root_and_api_bind(tempdir.path().to_path_buf(), IpAddr::from([0, 0, 0, 0]));
    let app = api_router(state);

    let info_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/info")
                .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40111))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(info_response.status(), StatusCode::UNAUTHORIZED);

    let health_response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health_response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_metrics_require_api_key_by_default() {
    let tempdir = tempfile::tempdir().unwrap();
    let state = test_state_with_root_api_bind_and_key(
        tempdir.path().to_path_buf(),
        IpAddr::from([0, 0, 0, 0]),
        Some("strong-metrics-test-key".into()),
    );
    metrics::initialize(&state, None);
    let app = api_router(state);
    let request = || {
        Request::builder()
            .method(Method::GET)
            .uri("/metrics")
            .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40112))))
    };

    let unauthenticated = app
        .clone()
        .oneshot(request().body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let authenticated = app
        .oneshot(
            request()
                .header("x-api-key", "strong-metrics-test-key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authenticated.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_metrics_authentication_can_be_disabled_without_exposing_control_routes() {
    let tempdir = tempfile::tempdir().unwrap();
    let mut state = test_state_with_root_api_bind_and_key(
        tempdir.path().to_path_buf(),
        IpAddr::from([0, 0, 0, 0]),
        Some("strong-metrics-test-key".into()),
    );
    let mut config = (*state.config).clone();
    config.api.metrics_require_api_key = false;
    Arc::get_mut(&mut state).unwrap().config = Arc::new(config);
    metrics::initialize(&state, None);
    let app = api_router(state);

    let metrics_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/metrics")
                .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40113))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(metrics_response.status(), StatusCode::OK);

    let info_response = app
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/info")
                .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40113))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(info_response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_disabled_api_surfaces_are_not_registered() {
    let root = tempfile::tempdir().unwrap();
    let mut state = test_state_with_root(root.path().to_path_buf());
    let config = Arc::get_mut(&mut state).unwrap().config.clone();
    let mut config = (*config).clone();
    config.api.enable_metrics = false;
    config.api.enable_versions_api = false;
    config.api.enable_audit_api = false;
    Arc::get_mut(&mut state).unwrap().config = Arc::new(config);
    let app = api_router(state);

    for uri in [
        "/metrics",
        "/api/v1/versions",
        "/api/v1/versions/groups",
        "/api/v1/audit",
        "/boot/v1/boot.efi",
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{uri}");
    }
}

#[tokio::test]
async fn test_readiness_tracks_listener_drain_and_critical_health() {
    let state = test_state_with_root(tempfile::tempdir().unwrap().path().to_path_buf());
    assert_eq!(
        readiness_check(State(state.clone()))
            .await
            .into_response()
            .status(),
        StatusCode::OK
    );
    state.tftp_ready.store(false, Ordering::Release);
    assert_eq!(
        readiness_check(State(state.clone()))
            .await
            .into_response()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    state.tftp_ready.store(true, Ordering::Release);
    state.drain_mode.store(true, Ordering::Release);
    assert_eq!(
        readiness_check(State(state.clone()))
            .await
            .into_response()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    state
        .critical_services_healthy
        .store(false, Ordering::Release);
    assert_eq!(
        readiness_check(State(state)).await.into_response().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn test_audit_api_filters_and_limits_entries() {
    let root = tempfile::tempdir().unwrap();
    let mut state = test_state_with_root_api_bind_and_key(
        root.path().to_path_buf(),
        IpAddr::from([127, 0, 0, 1]),
        Some("strong-audit-test-key".to_string()),
    );
    let audit =
        Arc::new(crate::features::audit::AuditLog::new(root.path().join("audit.jsonl")).unwrap());
    for mac in [
        "aa:bb:cc:dd:ee:ff",
        "11:22:33:44:55:66",
        "aa:bb:cc:dd:ee:ff",
    ] {
        audit
            .append(
                "10.0.0.1".into(),
                Some(mac.into()),
                "vmlinuz".into(),
                "hash".into(),
                1,
                0,
                TransferOutcome::Completed,
                None,
            )
            .unwrap();
    }
    Arc::get_mut(&mut state).unwrap().audit_log = Some(audit);
    let response = api_router(state)
        .oneshot(
            Request::builder()
                .uri("/api/v1/audit?client_mac=AA-BB-CC-DD-EE-FF&limit=1")
                .header("x-api-key", "strong-audit-test-key")
                .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40112))))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let entries: Vec<crate::features::audit::AuditEntry> =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].sequence, 2);
}

#[tokio::test]
async fn test_audit_api_rejects_work_when_scan_capacity_is_exhausted() {
    let root = tempfile::tempdir().unwrap();
    let mut state = test_state_with_root(root.path().to_path_buf());
    let audit =
        Arc::new(crate::features::audit::AuditLog::new(root.path().join("audit.jsonl")).unwrap());
    Arc::get_mut(&mut state).unwrap().audit_log = Some(audit);

    let _all_permits = state
        .audit_read_budget
        .clone()
        .acquire_many_owned(crate::server::MAX_CONCURRENT_AUDIT_READS as u32)
        .await
        .unwrap();
    let response = list_audit(
        State(state),
        Query(AuditQuery {
            client_mac: None,
            limit: None,
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn audit_query_task_failure_does_not_disclose_runtime_details() {
    let error = tokio::spawn(async { panic!("private audit failure detail") })
        .await
        .unwrap_err();

    let response = audit_query_join_error_response(error);
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(
        to_bytes(response.into_body(), usize::MAX).await.unwrap(),
        "Audit query failed"
    );
}

#[test]
fn test_server_info_no_sensitive_fields() {
    let info = ServerInfo {
        name: "Tempest",
        version: "0.1.0",
        tftp_port: 69,
        active_transfers: 0,
        drain_mode: false,
        uptime_secs: 0,
    };
    let json = serde_json::to_string(&info).unwrap();
    assert!(!json.contains("root"));
    assert!(!json.contains("tftpboot"));
    assert!(!json.contains("max_concurrent"));
}

#[test]
fn test_server_info_serialization() {
    let info = ServerInfo {
        name: "Tempest",
        version: "0.1.0",
        tftp_port: 69,
        active_transfers: 5,
        drain_mode: true,
        uptime_secs: 100,
    };
    let json = serde_json::to_string(&info).unwrap();
    assert!(json.contains("\"drain_mode\":true"));
    assert!(json.contains("\"active_transfers\":5"));
    assert!(!json.contains("api_key"));
    assert!(!json.contains("bind"));
}

#[test]
fn test_server_info_has_uptime() {
    let info = ServerInfo {
        name: "Tempest",
        version: "0.1.0",
        tftp_port: 69,
        active_transfers: 0,
        drain_mode: false,
        uptime_secs: 42,
    };
    let json = serde_json::to_string(&info).unwrap();
    assert!(json.contains("\"uptime_secs\":42"));
}

#[test]
fn test_server_info_no_write_enabled_leak() {
    let info = ServerInfo {
        name: "Tempest",
        version: "0.1.0",
        tftp_port: 69,
        active_transfers: 0,
        drain_mode: false,
        uptime_secs: 0,
    };
    let json = serde_json::to_string(&info).unwrap();
    assert!(!json.contains("write_enabled"));
    assert!(!json.contains("max_write"));
    assert!(!json.contains("api_key"));
}

#[test]
fn test_drain_status_response_fields() {
    let resp = DrainStatusResponse {
        drain_mode: false,
        active_transfers: 5,
        queued_transfers: 2,
        drain_complete: false,
    };
    let json = serde_json::to_string(&resp).unwrap();
    assert!(json.contains("\"drain_mode\":false"));
    assert!(json.contains("\"active_transfers\":5"));
    assert!(json.contains("\"queued_transfers\":2"));
    assert!(json.contains("\"drain_complete\":false"));
}

#[test]
fn test_drain_complete_logic() {
    let resp = DrainStatusResponse {
        drain_mode: true,
        active_transfers: 0,
        queued_transfers: 0,
        drain_complete: true,
    };
    let json: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&resp).unwrap()).unwrap();
    assert_eq!(json["drain_complete"], true);

    let resp2 = DrainStatusResponse {
        drain_mode: true,
        active_transfers: 3,
        queued_transfers: 0,
        drain_complete: false, // still draining
    };
    let json2: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&resp2).unwrap()).unwrap();
    assert_eq!(json2["drain_complete"], false);

    let queued = DrainStatusResponse {
        drain_mode: true,
        active_transfers: 0,
        queued_transfers: 1,
        drain_complete: false,
    };
    assert!(!queued.drain_complete);
}

#[test]
fn test_api_router_has_undrain_route() {
    let config = crate::config::TempestConfig::default();
    let config = std::sync::Arc::new(config);
    let active_transfers = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let metrics = std::sync::Arc::new(crate::server::ServerMetrics::new(active_transfers.clone()));
    let state = std::sync::Arc::new(crate::server::ServerState {
        config: config.clone(),
        version_store: crate::features::versioning::VersionStore::new(),
        phase_classifier: crate::features::boot_phase::PhaseClassifier::new(&config.boot_phases),
        shared_blocks: None,
        transfer_pacing: None,
        read_protocol: None,
        read_request_router: None,
        admission_policy: None,
        metrics,
        active_transfers,
        queued_transfers: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        inflight_tftp_tids: std::sync::Arc::new(dashmap::DashMap::new()),
        tftp_client_limits: std::sync::Arc::new(crate::server::TftpClientLimits::new(
            config.server.max_tftp_transfers_per_ip,
        )),
        transfer_ids: crate::server::TransferIdGenerator::new(),
        drain_mode: std::sync::atomic::AtomicBool::new(false),
        tftp_ready: std::sync::atomic::AtomicBool::new(true),
        tftp_bound_port: std::sync::atomic::AtomicU16::new(config.server.port),
        critical_services_healthy: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
        start_time: std::time::Instant::now(),
        tftp_rate_limiter: std::sync::Arc::new(crate::rate_limit::PerIpRateLimiter::new(
            config.server.tftp_requests_per_ip_per_second,
            "TFTP",
        )),
        malformed_log_limiter: std::sync::Arc::new(crate::rate_limit::PerIpRateLimiter::new(
            2,
            "TFTP malformed packet",
        )),
        unexpected_log_limiter: std::sync::Arc::new(crate::rate_limit::PerIpRateLimiter::new(
            2,
            "TFTP unexpected opcode",
        )),
        http_rate_limiter: std::sync::Arc::new(crate::rate_limit::PerIpRateLimiter::new(
            config.server.http_requests_per_ip_per_second,
            "API",
        )),
        http_observer: None,
        dscp_manager: std::sync::Arc::new(crate::features::dscp::DscpManager::new(
            &std::collections::HashMap::new(),
            false,
        )),
        audit_log: None,
        audit_writer: None,
        audit_read_budget: Arc::new(tokio::sync::Semaphore::new(
            crate::server::MAX_CONCURRENT_AUDIT_READS,
        )),
        quarantined_files: std::sync::Arc::new(dashmap::DashSet::new()),
        quarantine_admission: parking_lot::Mutex::new(()),
        scheduler: None,
        provisioning_priority: None,
        boot_sessions: std::sync::Arc::new(dashmap::DashMap::new()),
        http_session_tokens: std::sync::Arc::new(dashmap::DashMap::new()),
        persistence: None,
        persistence_revision: std::sync::atomic::AtomicI64::new(-1),
        persistence_snapshot_validated_at: parking_lot::Mutex::new(None),
        control_plane_lock: Arc::new(tokio::sync::Mutex::new(())),
        session_registration_queue: std::sync::OnceLock::new(),
        bandwidth_governor: None,
        artifact_hash_budget: Arc::new(tokio::sync::Semaphore::new(4)),
        artifact_root: std::sync::OnceLock::new(),
        artifact_io_budget: Arc::new(tokio::sync::Semaphore::new(32)),
        hot_artifact_cache: Arc::new(
            crate::artifact_cache::HotArtifactCache::with_default_limits(),
        ),
        http_artifact_cache: Arc::new(crate::artifact_cache::HotArtifactCache::with_limits(
            usize::try_from(config.api.artifact_cache_max_bytes).unwrap(),
            usize::try_from(config.api.artifact_cache_max_file_bytes).unwrap(),
        )),
    });
    let _router = api_router(state);
}

#[test]
fn test_drain_undrain_symmetry() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let drain_mode = AtomicBool::new(false);

    drain_mode.store(true, Ordering::Release);
    assert!(drain_mode.load(Ordering::Acquire));

    drain_mode.store(false, Ordering::Release);
    assert!(!drain_mode.load(Ordering::Acquire));
}

#[tokio::test]
async fn http_observer_preserves_auth_and_reports_safe_metadata() {
    let observations = Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured = observations.clone();
    let mut config = crate::config::TempestConfig::default();
    config.api.api_key = Some("test-key".into());
    let state = crate::server::TftpServer::builder(config)
        .with_http_observer(move |observation| captured.lock().unwrap().push(observation))
        .build()
        .unwrap()
        .state();
    for (path, status) in [
        ("/api/v1/info?secret=hidden", StatusCode::UNAUTHORIZED),
        ("/health", StatusCode::OK),
        ("/unknown-secret", StatusCode::NOT_FOUND),
    ] {
        let response = api_router(state.clone())
            .oneshot(
                Request::get(path)
                    .extension(ConnectInfo(
                        "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
                    ))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
    }
    let observations = observations.lock().unwrap();
    assert_eq!(observations.len(), 3);
    assert_eq!(observations[0].route.as_deref(), Some("/api/v1/info"));
    assert_eq!(observations[0].status, Some(401));
    assert_eq!(observations[1].status, Some(200));
    assert_eq!(observations[2].route, None);
    assert!(observations.iter().all(|item| item.method == "GET"));
}

#[tokio::test]
async fn http_observer_reports_cancelled_processing() {
    let observations = Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured = observations.clone();
    let state = crate::server::TftpServer::builder(crate::config::TempestConfig::default())
        .with_http_observer(move |observation| captured.lock().unwrap().push(observation))
        .build()
        .unwrap()
        .state();
    let app = Router::new()
        .route(
            "/pending",
            get(|| async { std::future::pending::<StatusCode>().await }),
        )
        .layer(middleware::from_fn_with_state(state, observe_http));
    assert!(
        tokio::time::timeout(
            Duration::from_millis(10),
            app.oneshot(Request::get("/pending").body(Body::empty()).unwrap())
        )
        .await
        .is_err()
    );
    assert_eq!(observations.lock().unwrap().len(), 1);
    assert_eq!(observations.lock().unwrap()[0].status, None);
}

#[tokio::test]
async fn tftp_boot_preserves_registered_release_across_cutover() {
    let dir = tempfile::tempdir().unwrap();
    for (name, bytes) in [
        ("loader", "loader-v1"),
        ("kernel-v1", "kernel-v1"),
        ("kernel-v2", "kernel-v2"),
    ] {
        std::fs::write(dir.path().join(name), bytes).unwrap();
    }
    let state = test_state_with_root(dir.path().to_path_buf());
    state
        .version_store
        .atomic_switch_for_profile(
            "focal".into(),
            "release-v1".into(),
            vec![
                ("boot.efi".into(), dir.path().join("loader")),
                ("kernel".into(), dir.path().join("kernel-v1")),
            ],
        )
        .unwrap();
    let client_ip = IpAddr::from([192, 0, 2, 71]);
    insert_native_boot_session(&state, client_ip, "focal");
    let loader = state
        .resolve_file_for_boot_session(client_ip, "default", "boot.efi")
        .await
        .unwrap();
    let identity = loader.boot_chain.as_ref().unwrap().manifest_digest.clone();
    let pinned = loader.pinned_version.unwrap();
    state.version_store.unpin_version_for_profile(
        &pinned.boot_profile,
        &pinned.logical_name,
        pinned.version_id,
    );
    state
        .version_store
        .atomic_switch_for_profile(
            "focal".into(),
            "release-v2".into(),
            vec![("kernel".into(), dir.path().join("kernel-v2"))],
        )
        .unwrap();
    let kernel = state
        .resolve_file_for_boot_session(client_ip, "default", "kernel")
        .await
        .unwrap();
    assert_eq!(
        kernel.boot_chain.as_ref().unwrap().manifest_digest,
        identity
    );
    assert_eq!(std::fs::read(&kernel.path).unwrap(), b"kernel-v1");
    let pinned = kernel.pinned_version.unwrap();
    state.version_store.unpin_version_for_profile(
        &pinned.boot_profile,
        &pinned.logical_name,
        pinned.version_id,
    );
}

#[tokio::test]
async fn managed_session_registration_requires_an_active_release() {
    let dir = tempfile::tempdir().unwrap();
    let state = test_state_with_root(dir.path().to_path_buf());
    let request = || {
        serde_json::from_value(serde_json::json!({
        "client_ip":"192.0.2.72", "boot_profile":"focal", "new_epoch":true, "require_managed":true
    })).unwrap()
    };
    let response = register_session(State(state.clone()), Json(request()))
        .await
        .into_response();
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(state.boot_sessions.is_empty());
    std::fs::write(dir.path().join("kernel"), b"kernel").unwrap();
    state
        .version_store
        .atomic_switch_for_profile(
            "focal".into(),
            "release-v1".into(),
            vec![("kernel".into(), dir.path().join("kernel"))],
        )
        .unwrap();
    let response = register_session(State(state.clone()), Json(request()))
        .await
        .into_response();
    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(
        active_boot_session(&state, "192.0.2.72".parse().unwrap())
            .unwrap()
            .pinned_boot_chain
            .is_some()
    );
}

#[tokio::test]
async fn session_revocation_requires_the_current_artifact_token() {
    let dir = tempfile::tempdir().unwrap();
    let state = test_state_with_root(dir.path().to_path_buf());
    let client_ip = IpAddr::from([192, 0, 2, 73]);
    state.insert_boot_session(
        client_ip,
        with_test_artifact_token(BootSessionEntry {
            trace_id: None,
            boot_profile: "focal".into(),
            client_mac: None,
            serial: None,
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(300),
        }),
    );
    let replaced = revoke_session(
        State(state.clone()),
        AxumPath(client_ip),
        Json(RevokeSessionRequest {
            artifact_token: "f".repeat(64),
        }),
    )
    .await
    .into_response();
    assert_eq!(replaced.status(), StatusCode::CONFLICT);
    assert!(active_boot_session(&state, client_ip).is_some());

    let revoked = revoke_session(
        State(state.clone()),
        AxumPath(client_ip),
        Json(RevokeSessionRequest {
            artifact_token: TEST_ARTIFACT_TOKEN.into(),
        }),
    )
    .await
    .into_response();
    assert_eq!(revoked.status(), StatusCode::NO_CONTENT);
    assert!(active_boot_session(&state, client_ip).is_none());
}

#[tokio::test]
async fn disconnected_session_revocation_waiter_does_not_start_mutation() {
    let state = test_state_with_root(tempfile::tempdir().unwrap().path().to_path_buf());
    let client_ip = IpAddr::from([192, 0, 2, 74]);
    let token_hash: [u8; 32] = Sha256::digest(TEST_ARTIFACT_TOKEN.as_bytes()).into();
    state.insert_boot_session(
        client_ip,
        with_test_artifact_token(BootSessionEntry {
            trace_id: None,
            boot_profile: "focal".into(),
            client_mac: None,
            serial: None,
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(300),
        }),
    );
    let control_guard = state.control_plane_lock.lock().await;
    let mut caller = tokio::spawn(revoke_session(
        State(state.clone()),
        AxumPath(client_ip),
        Json(RevokeSessionRequest {
            artifact_token: TEST_ARTIFACT_TOKEN.into(),
        }),
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut caller)
            .await
            .is_err()
    );
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());

    drop(control_guard);
    tokio::task::yield_now().await;
    assert!(state.boot_session_for_artifact_token(&token_hash).is_some());
}

#[tokio::test]
async fn removed_public_boot_route_is_not_exposed() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("kernel"), b"kernel").unwrap();
    let mut state = test_state_with_root(dir.path().to_path_buf());
    Arc::get_mut(&mut Arc::get_mut(&mut state).unwrap().config)
        .unwrap()
        .api
        .enable_native_http_boot = true;
    state
        .version_store
        .atomic_switch_for_profile(
            "default".into(),
            "manual-v1".into(),
            vec![("kernel".into(), dir.path().join("kernel"))],
        )
        .unwrap();
    let client_ip = IpAddr::from([192, 0, 2, 75]);
    for registered in [false, true] {
        if registered {
            insert_native_boot_session(&state, client_ip, "default");
        }
        for method in [Method::GET, Method::HEAD] {
            let response = api_router(state.clone())
                .oneshot(
                    axum::http::Request::builder()
                        .method(method)
                        .uri("/public/v1/kernel")
                        .header(header::RANGE, "bytes=1-3")
                        .extension(ConnectInfo(SocketAddr::new(client_ip, 40000)))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            assert!(response.headers().get("x-tempest-http-mode").is_none());
            assert!(response.headers().get(header::CONTENT_RANGE).is_none());
            assert!(artifact_body(response).await.is_empty());
            assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
            assert_eq!(state.boot_sessions.len(), usize::from(registered));
        }
    }
}

#[tokio::test]
async fn artifact_token_cannot_be_replayed_from_another_client() {
    let tempdir = tempfile::tempdir().unwrap();
    std::fs::write(tempdir.path().join("artifact"), b"boot bytes").unwrap();
    let state = test_state_with_root(tempdir.path().to_path_buf());
    let client_ip = IpAddr::from([192, 0, 2, 60]);
    state.insert_boot_session(
        client_ip,
        with_test_artifact_token(BootSessionEntry {
            trace_id: None,
            boot_profile: "default".into(),
            client_mac: None,
            serial: None,
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: None,
            expires_at: Instant::now() + Duration::from_secs(300),
        }),
    );
    let mut spoofed = artifact_headers();
    spoofed.insert("x-forwarded-for", HeaderValue::from_static("192.0.2.60"));
    let response = serve_artifact(
        State(state.clone()),
        ConnectInfo(SocketAddr::new(IpAddr::from([192, 0, 2, 61]), 40200)),
        spoofed,
        AxumPath("artifact".into()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
    let response = serve_artifact(
        State(state.clone()),
        ConnectInfo(SocketAddr::new(client_ip, 40200)),
        artifact_headers(),
        AxumPath("artifact".into()),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(&artifact_body(response).await[..], b"boot bytes");
}

#[test]
fn trusted_proxy_rejects_duplicate_forwarded_headers() {
    let proxy = IpAddr::from([127, 0, 0, 1]);
    let mut headers = HeaderMap::new();
    headers.append("x-forwarded-for", HeaderValue::from_static("192.0.2.42"));
    headers.append("x-forwarded-for", HeaderValue::from_static("192.0.2.43"));
    assert_eq!(resolved_client_ip(proxy, &headers, &[proxy]), Err(()));
}
