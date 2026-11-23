// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::config::TempestConfig;
use crate::server::TftpServer;

fn request(ip: IpAddr, new_epoch: bool) -> Registration {
    Registration {
        client_ip: ip,
        boot_profile: "default".into(),
        trace_id: Some("batch-test".into()),
        client_mac: None,
        serial: None,
        ttl_seconds: None,
        new_epoch,
        require_managed: false,
    }
}

fn command(ip: IpAddr, new_epoch: bool) -> (Command, oneshot::Receiver<Response>) {
    let (reply, response) = oneshot::channel();
    (
        Command {
            request: request(ip, new_epoch),
            reply,
        },
        response,
    )
}

#[tokio::test]
async fn registration_without_required_sql_store_preserves_sessions_and_tokens() {
    use axum::{body::Body, extract::ConnectInfo, http::Request};
    use tower::ServiceExt;

    for (enabled, coordinated_deletion) in [(true, false), (false, true), (true, true)] {
        let mut config = TempestConfig::default();
        config.api.api_key = Some("test-key-at-least-sixteen".into());
        let state = TftpServer::new(config).state();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let (entry, _) = prepare(&state, request(ip, false), &HashMap::new()).unwrap();
        let original_hash = entry.artifact_token_hash.unwrap();
        state.insert_boot_session(ip, entry.clone());
        let mut state = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("live state owner"));
        let config = Arc::make_mut(&mut state.config);
        config.persistence.enabled = enabled;
        config.persistence.coordinated_deletion = coordinated_deletion;
        let state = Arc::new(state);
        let router = crate::api::api_router(state.clone());

        for client_ip in ["192.0.2.1", "192.0.2.2"] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/api/v1/sessions")
                        .header("x-api-key", "test-key-at-least-sixteen")
                        .header("content-type", "application/json")
                        .extension(ConnectInfo(
                            "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                        ))
                        .body(Body::from(
                            serde_json::json!({
                                "client_ip": client_ip,
                                "trace_id": "missing-store",
                                "new_epoch": true
                            })
                            .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(state.boot_sessions.len(), 1);
            let current = state.boot_sessions.get(&ip).unwrap();
            assert_eq!(current.boot_epoch, entry.boot_epoch);
            assert_eq!(current.expires_at, entry.expires_at);
            assert_eq!(current.artifact_token_hash, Some(original_hash));
            assert!(
                state
                    .boot_session_for_artifact_token(&original_hash)
                    .is_some()
            );
        }
    }
}

#[tokio::test]
async fn batch_rejects_superseded_duplicate_and_preserves_exact_capacity() {
    let mut config = TempestConfig::default();
    config.server.max_boot_sessions = 1;
    let state = TftpServer::new(config).state();
    let ip = "192.0.2.1".parse().unwrap();
    let (first, first_response) = command(ip, false);
    let (second, second_response) = command(ip, true);
    let (third, third_response) = command("192.0.2.2".parse().unwrap(), false);
    commit_batch(&state, vec![first, second, third]).await;
    let first = first_response.await.unwrap();
    let second = second_response.await.unwrap();
    assert_eq!(first.status(), StatusCode::CONFLICT);
    assert_eq!(second.status(), StatusCode::CREATED);
    assert_eq!(
        third_response.await.unwrap().status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let second: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(second.into_body(), 4096)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(second["boot_epoch"], 2);
    let new_hash: [u8; 32] =
        Sha256::digest(second["artifact_token"].as_str().unwrap().as_bytes()).into();
    assert!(state.boot_session_for_artifact_token(&new_hash).is_some());
    assert_eq!(state.boot_sessions.len(), 1);
}

#[tokio::test]
async fn cancelled_queued_registration_does_not_change_state() {
    let state = TftpServer::new(TempestConfig::default()).state();
    let (cancelled, response) = command("192.0.2.1".parse().unwrap(), false);
    drop(response);
    commit_batch(&state, vec![cancelled]).await;
    assert!(state.boot_sessions.is_empty());
}

#[tokio::test]
async fn disconnected_later_duplicate_does_not_supersede_live_registration() {
    let state = TftpServer::new(TempestConfig::default()).state();
    let ip = "192.0.2.1".parse().unwrap();
    let (first, first_response) = command(ip, false);
    let (second, second_response) = command(ip, true);
    drop(second_response);

    commit_batch(&state, vec![first, second]).await;

    let first = first_response.await.unwrap();
    assert_eq!(first.status(), StatusCode::CREATED);
    let first: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(first.into_body(), 4096).await.unwrap())
            .unwrap();
    assert_eq!(first["boot_epoch"], 1);
    let token_hash: [u8; 32] =
        Sha256::digest(first["artifact_token"].as_str().unwrap().as_bytes()).into();
    assert!(state.boot_session_for_artifact_token(&token_hash).is_some());
}

#[tokio::test]
async fn expired_pending_session_can_be_replaced_at_capacity() {
    let mut config = TempestConfig::default();
    config.server.max_boot_sessions = 1;
    let state = TftpServer::new(config).state();
    let ip = "192.0.2.1".parse().unwrap();
    let (mut expired, first) = command(ip, false);
    expired.request.ttl_seconds = Some(0);
    let (replacement, second) = command(ip, false);
    commit_batch(&state, vec![expired, replacement]).await;
    assert_eq!(first.await.unwrap().status(), StatusCode::CONFLICT);
    assert_eq!(second.await.unwrap().status(), StatusCode::CREATED);
    assert!(active_boot_session(&state, ip).is_some());
}

#[cfg(feature = "sql-persistence")]
#[tokio::test]
async fn sql_batch_failure_does_not_publish_any_session() {
    let Some(url) = crate::persistence::test_database_url() else {
        return;
    };
    let _database_slot = crate::persistence::test_database_slot().await;
    let store = Arc::new(
        crate::persistence::PersistenceStore::connect(&url)
            .await
            .unwrap(),
    );
    let state = TftpServer::builder(TempestConfig::default())
        .with_persistence(store.clone())
        .build()
        .unwrap()
        .state();
    let ip = IpAddr::V6(uuid::Uuid::new_v4().as_u128().into());
    let other_ip = IpAddr::V6(uuid::Uuid::new_v4().as_u128().into());
    let (entry, _) = prepare(&state, request(ip, false), &HashMap::new()).unwrap();
    state.insert_boot_session(
        ip,
        BootSessionEntry {
            boot_epoch: u64::MAX,
            ..entry
        },
    );
    let (invalid, failed) = command(ip, true);
    let (valid, also_failed) = command(other_ip, false);
    commit_batch(&state, vec![valid, invalid]).await;
    assert_eq!(
        failed.await.unwrap().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        also_failed.await.unwrap().status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(!state.boot_sessions.contains_key(&other_ip));
    assert!(
        !store
            .load_boot_sessions(100_000)
            .await
            .unwrap()
            .iter()
            .any(|(candidate, _)| *candidate == other_ip)
    );
}

#[cfg(feature = "sql-persistence")]
#[tokio::test]
async fn sql_registration_queue_is_bounded_and_groups_commits() {
    with_isolated_database(assert_registration_queue_is_bounded_and_groups_commits).await;
}

#[cfg(feature = "sql-persistence")]
async fn assert_registration_queue_is_bounded_and_groups_commits(url: String) {
    let store = Arc::new(
        crate::persistence::PersistenceStore::connect(&url)
            .await
            .unwrap(),
    );
    let state = TftpServer::builder(TempestConfig::default())
        .with_persistence(store.clone())
        .build()
        .unwrap()
        .state();
    let before = store.state_revision().await.unwrap();
    let guard = state.control_plane_lock.lock().await;
    let mut tasks = Vec::new();
    for _ in 0..32 {
        let state = state.clone();
        let ip = IpAddr::V6(uuid::Uuid::new_v4().as_u128().into());
        tasks.push(tokio::spawn(register(state, request(ip, false))));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if state
                .session_registration_queue
                .get()
                .is_some_and(|sender| sender.capacity() <= QUEUE_CAPACITY - 31)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // Fill remaining queue slots without creating more waiting HTTP tasks.
    let sender = state.session_registration_queue.get().unwrap();
    let available = sender.capacity();
    let reserved = sender.reserve_many(available).await.unwrap();
    assert_eq!(
        register(
            state.clone(),
            request("192.0.2.250".parse().unwrap(), false)
        )
        .await
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop(reserved);
    drop(guard);
    for task in tasks {
        assert_eq!(task.await.unwrap().status(), StatusCode::CREATED);
    }
    assert_eq!(store.state_revision().await.unwrap(), before + 1);
    let persisted = store.load_boot_sessions(100_000).await.unwrap();
    for entry in state.boot_sessions.iter() {
        assert!(
            persisted.iter().any(|(ip, row)| ip == entry.key()
                && row.artifact_token_hash == entry.artifact_token_hash)
        );
    }
}

#[cfg(feature = "sql-persistence")]
#[tokio::test]
async fn disconnected_sql_registration_finishes_durable_publication() {
    with_isolated_database(assert_disconnected_registration_finishes_durable_publication).await;
}

#[cfg(feature = "sql-persistence")]
async fn assert_disconnected_registration_finishes_durable_publication(url: String) {
    let store = Arc::new(
        crate::persistence::PersistenceStore::connect(&url)
            .await
            .unwrap(),
    );
    let state = TftpServer::builder(TempestConfig::default())
        .with_persistence(store.clone())
        .build()
        .unwrap()
        .state();
    let database = sqlx::AnyPool::connect(&url).await.unwrap();
    let mut transaction = database.begin().await.unwrap();
    sqlx::query("SELECT revision FROM tempest_state_revision WHERE singleton_id = 1 FOR UPDATE")
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
    let ip = IpAddr::V6(uuid::Uuid::new_v4().as_u128().into());
    let mut caller = tokio::spawn(register(state.clone(), request(ip, false)));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut caller)
            .await
            .is_err()
    );
    assert!(state.control_plane_lock.try_lock().is_err());
    assert_eq!(
        state.session_registration_queue.get().unwrap().capacity(),
        QUEUE_CAPACITY
    );
    assert!(!state.boot_sessions.contains_key(&ip));
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    transaction.rollback().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !state.boot_sessions.contains_key(&ip) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        store
            .load_boot_sessions(100_000)
            .await
            .unwrap()
            .iter()
            .any(|(candidate, row)| *candidate == ip
                && row.artifact_token_hash
                    == state.boot_sessions.get(&ip).unwrap().artifact_token_hash)
    );
}

#[cfg(feature = "sql-persistence")]
#[tokio::test]
async fn disconnected_sql_revocation_finishes_durable_and_local_deletion() {
    // Isolated like the registration case: a concurrent test holding the shared
    // serving namespace would fail admission before the revision lock is reached.
    with_isolated_database(assert_disconnected_revocation_finishes_durable_and_local_deletion)
        .await;
}

#[cfg(feature = "sql-persistence")]
async fn assert_disconnected_revocation_finishes_durable_and_local_deletion(url: String) {
    use axum::extract::{Path, State};

    let store = Arc::new(
        crate::persistence::PersistenceStore::connect(&url)
            .await
            .unwrap(),
    );
    let state = TftpServer::builder(TempestConfig::default())
        .with_persistence(store.clone())
        .build()
        .unwrap()
        .state();
    let ip = IpAddr::V6(uuid::Uuid::new_v4().as_u128().into());
    let (entry, response) = prepare(&state, request(ip, false), &HashMap::new()).unwrap();
    let token = response.artifact_token;
    let token_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    store.persist_boot_session(ip, &entry).await.unwrap();
    state.insert_boot_session(ip, entry);

    let database = sqlx::AnyPool::connect(&url).await.unwrap();
    let mut transaction = database.begin().await.unwrap();
    sqlx::query("SELECT revision FROM tempest_state_revision WHERE singleton_id = 1 FOR UPDATE")
        .fetch_one(&mut *transaction)
        .await
        .unwrap();
    let mut caller = tokio::spawn(super::super::revoke_session(
        State(state.clone()),
        Path(ip),
        Json(super::super::RevokeSessionRequest {
            artifact_token: token,
        }),
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut caller)
            .await
            .is_err()
    );
    assert!(state.control_plane_lock.try_lock().is_err());
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());

    transaction.rollback().await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        while state.boot_session_for_artifact_token(&token_hash).is_some() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        !store
            .load_boot_sessions(100_000)
            .await
            .unwrap()
            .iter()
            .any(|(candidate, _)| *candidate == ip)
    );
}

#[cfg(feature = "sql-persistence")]
#[tokio::test]
async fn sql_peer_observes_registration_and_token_rotation() {
    with_isolated_database(assert_peer_registration_and_rotation).await;
}

#[cfg(feature = "sql-persistence")]
async fn with_isolated_database<F, Fut>(test: F)
where
    F: FnOnce(String) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some(url) = crate::persistence::test_database_url() else {
        return;
    };
    let _database_slot = crate::persistence::test_database_slot().await;
    // Global revisions and snapshot limits are shared across clients/profiles.
    // Sibling databases also reclaim committed sessions after cancellation.
    sqlx::any::install_default_drivers();
    let admin = sqlx::AnyPool::connect(&url).await.unwrap();
    let database = format!("tempest_peer_{}", uuid::Uuid::new_v4().simple());
    // The identifier is generated locally from a fixed prefix and UUID hex.
    sqlx::query(&format!("CREATE DATABASE {database}"))
        .execute(&admin).await
        .expect("cross-node regression requires CREATE DATABASE permission on the disposable test server");
    let mut options: sqlx::any::AnyConnectOptions = url.parse().unwrap();
    options.database_url.set_path(&format!("/{database}"));
    let isolated_url = options.database_url.to_string();
    // Joining a child task lets cleanup run even when an assertion panics.
    let result = tokio::spawn(test(isolated_url)).await;
    if !url.starts_with("mysql:") {
        sqlx::query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()")
            .bind(&database).execute(&admin).await.unwrap();
    }
    sqlx::query(&format!("DROP DATABASE {database}"))
        .execute(&admin)
        .await
        .unwrap();
    admin.close().await;
    if let Err(error) = result {
        if error.is_panic() {
            std::panic::resume_unwind(error.into_panic());
        }
        panic!("cross-node test task was cancelled: {error}");
    }
}

#[cfg(feature = "sql-persistence")]
async fn assert_peer_registration_and_rotation(url: String) {
    use axum::body::{Body, to_bytes};
    use axum::extract::ConnectInfo;
    use axum::http::Request;
    use tower::ServiceExt;
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("boot.bin"), b"boot artifact").unwrap();
    let mut config = TempestConfig::default();
    config.server.root = root.path().to_owned();
    config.api.api_key = Some("test-key".into());
    let store = Arc::new(
        crate::persistence::PersistenceStore::connect(&url)
            .await
            .unwrap(),
    );
    let writer = TftpServer::builder(config.clone())
        .with_persistence(store.clone())
        .build()
        .unwrap()
        .state();
    let peer_store = Arc::new(
        crate::persistence::PersistenceStore::connect(&url)
            .await
            .unwrap(),
    );
    let peer = TftpServer::builder(config)
        .with_persistence(peer_store)
        .build()
        .unwrap()
        .state();
    peer.sync_persistent_state().await.unwrap();
    let ip = IpAddr::V6(uuid::Uuid::new_v4().as_u128().into());
    let address = std::net::SocketAddr::new(ip, 12345);
    let mut tokens = Vec::new();
    for new_epoch in [false, true] {
        let response = super::super::api_router(writer.clone()).oneshot(
            Request::post("/api/v1/sessions")
                .header("x-api-key", "test-key").header("content-type", "application/json")
                .extension(ConnectInfo(address))
                .body(Body::from(serde_json::json!({"client_ip": ip, "boot_profile": "default", "trace_id": "peer-test", "new_epoch": new_epoch}).to_string())).unwrap()
        ).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        let json: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        tokens.push(json["artifact_token"].as_str().unwrap().to_owned());
        peer.sync_persistent_state().await.unwrap();
        for (index, token) in tokens.iter().enumerate() {
            let response = super::super::api_router(peer.clone())
                .oneshot(
                    Request::get("/api/v1/artifacts/boot.bin")
                        .header("authorization", format!("Bearer {token}"))
                        .extension(ConnectInfo(address))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            if index + 1 == tokens.len() {
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(
                    to_bytes(response.into_body(), 4096).await.unwrap().as_ref(),
                    b"boot artifact"
                );
            } else {
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            }
        }
    }
    store.delete_boot_session(ip).await.unwrap();
}

#[cfg(feature = "sql-persistence")]
#[tokio::test]
async fn sql_registration_rejects_stale_issuers_and_releases() {
    with_isolated_database(|url| async move {
        let root = tempfile::tempdir().unwrap();
        let artifact = root.path().join("boot.bin");
        std::fs::write(&artifact, b"boot artifact").unwrap();
        let mut config = TempestConfig::default();
        config.server.root = root.path().to_owned();
        let store = Arc::new(
            crate::persistence::PersistenceStore::connect(&url)
                .await
                .unwrap(),
        );
        let writer = TftpServer::builder(config.clone())
            .with_persistence(store.clone())
            .build()
            .unwrap()
            .state();
        let peer = TftpServer::builder(config)
            .with_persistence(store.clone())
            .build()
            .unwrap()
            .state();
        let ip = "192.0.2.20".parse().unwrap();

        // Two empty caches race to issue one IP. The loser must not overwrite
        // the winner or publish an uncommitted token in its hot state.
        let (first, second) = tokio::join!(
            register(writer.clone(), request(ip, true)),
            register(peer.clone(), request(ip, true)),
        );
        let mut statuses = [first.status().as_u16(), second.status().as_u16()];
        statuses.sort_unstable();
        assert_eq!(statuses, [201, 409]);
        writer.sync_persistent_state().await.unwrap();
        peer.sync_persistent_state().await.unwrap();
        assert_eq!(active_boot_session(&writer, ip).unwrap().boot_epoch, 1);

        // The same race from an existing epoch can advance it exactly once.
        let (first, second) = tokio::join!(
            register(writer.clone(), request(ip, true)),
            register(peer.clone(), request(ip, true)),
        );
        let mut statuses = [first.status().as_u16(), second.status().as_u16()];
        statuses.sort_unstable();
        assert_eq!(statuses, [201, 409]);
        writer.sync_persistent_state().await.unwrap();
        peer.sync_persistent_state().await.unwrap();
        assert_eq!(active_boot_session(&writer, ip).unwrap().boot_epoch, 2);

        // A stale request in a mixed batch rejects all writes atomically.
        assert_eq!(
            register(writer.clone(), request(ip, true)).await.status(),
            StatusCode::CREATED
        );
        let other_ip = "192.0.2.21".parse().unwrap();
        let (stale, stale_response) = command(ip, true);
        let (other, other_response) = command(other_ip, true);
        commit_batch(&peer, vec![stale, other]).await;
        assert_eq!(stale_response.await.unwrap().status(), StatusCode::CONFLICT);
        assert_eq!(other_response.await.unwrap().status(), StatusCode::CONFLICT);
        assert!(active_boot_session(&peer, other_ip).is_none());
        assert!(
            !store
                .load_boot_sessions(100)
                .await
                .unwrap()
                .iter()
                .any(|(candidate, _)| *candidate == other_ip)
        );

        // A durable cutover unseen by an issuer cannot issue an unmanaged or
        // obsolete release. Refreshing its snapshot makes issuance safe.
        let group = writer
            .version_store
            .atomic_switch_for_profile(
                "default".into(),
                "first".into(),
                vec![("boot.bin".into(), artifact.clone())],
            )
            .unwrap();
        store.persist_version_group(&group, 0).await.unwrap();
        assert_eq!(
            register(peer.clone(), request(other_ip, true))
                .await
                .status(),
            StatusCode::CONFLICT
        );
        peer.sync_persistent_state().await.unwrap();
        assert_eq!(
            register(peer.clone(), request(other_ip, true))
                .await
                .status(),
            StatusCode::CREATED
        );
        let old_pin = active_boot_session(&peer, other_ip)
            .unwrap()
            .pinned_boot_chain;
        let group = writer
            .version_store
            .atomic_switch_for_profile(
                "default".into(),
                "second".into(),
                vec![("boot.bin".into(), artifact)],
            )
            .unwrap();
        store.persist_version_group(&group, 1).await.unwrap();
        assert_eq!(
            register(peer.clone(), request(other_ip, false))
                .await
                .status(),
            StatusCode::CREATED
        );
        assert_eq!(
            active_boot_session(&peer, other_ip)
                .unwrap()
                .pinned_boot_chain,
            old_pin
        );
        assert_eq!(
            register(peer.clone(), request(other_ip, true))
                .await
                .status(),
            StatusCode::CONFLICT
        );
        peer.sync_persistent_state().await.unwrap();
        assert_eq!(
            register(peer.clone(), request(other_ip, true))
                .await
                .status(),
            StatusCode::CREATED
        );
        assert_ne!(
            active_boot_session(&peer, other_ip)
                .unwrap()
                .pinned_boot_chain,
            old_pin
        );
    })
    .await;
}

#[cfg(feature = "sql-persistence")]
#[tokio::test]
async fn sql_first_pin_rejects_stale_release_and_deletion_cannot_see_remote_transfer() {
    with_isolated_database(|url| async move {
        use axum::body::{Body, to_bytes};
        use axum::http::Request;
        use tower::ServiceExt;

        let root = tempfile::tempdir().unwrap();
        let artifact = root.path().join("boot.bin");
        std::fs::write(&artifact, b"boot artifact").unwrap();
        let mut config = TempestConfig::default();
        config.server.root = root.path().to_owned();
        config.api.api_key = Some("test-key".into());
        let store = Arc::new(crate::persistence::PersistenceStore::connect(&url).await.unwrap());
        let writer = TftpServer::builder(config.clone())
            .with_persistence(store.clone()).build().unwrap().state();
        let peer_store = Arc::new(crate::persistence::PersistenceStore::connect(&url).await.unwrap());
        let peer = TftpServer::builder(config)
            .with_persistence(peer_store).build().unwrap().state();
        let ip = "192.0.2.40".parse().unwrap();
        // Register before any release, so first resolution must claim a pin.
        assert_eq!(register(writer.clone(), request(ip, true)).await.status(), StatusCode::CREATED);
        let first = writer.version_store.atomic_switch(
            "first".into(), vec![("boot.bin".into(), artifact.clone())],
        ).unwrap();
        store.persist_version_group(&first, 0).await.unwrap();
        peer.sync_persistent_state().await.unwrap();
        let second = writer.version_store.atomic_switch(
            "second".into(), vec![("boot.bin".into(), artifact.clone())],
        ).unwrap();
        store.persist_version_group(&second, 1).await.unwrap();

        assert!(matches!(
            peer.resolve_file_for_boot_session(ip, "default", "boot.bin").await,
            Err(crate::error::TempestError::Conflict(_))
        ));
        assert_eq!(peer.version_store.pinned_count("boot.bin", first.version_id), 0);
        assert!(active_boot_session(&peer, ip).unwrap().pinned_boot_chain.is_none());
        assert!(store.load_boot_sessions(100).await.unwrap()[0].1.pinned_boot_chain.is_none());
        peer.sync_persistent_state().await.unwrap();
        let resolved = peer.resolve_file_for_boot_session(ip, "default", "boot.bin").await.unwrap();
        assert_eq!(resolved.boot_chain.as_ref().unwrap().manifest_digest, second.manifest.manifest_digest);
        assert_eq!(peer.version_store.pinned_count("boot.bin", second.version_id), 1);

        // Revocation and withdrawal do not end a remote transfer. Even a fresh
        // durable snapshot with no session references cannot prove zero readers.
        store.delete_boot_session(ip).await.unwrap();
        store.withdraw_version_group("default", "second", Some(&second.manifest.manifest_digest), 2).await.unwrap();
        writer.sync_persistent_state().await.unwrap();
        assert_eq!(writer.version_store.pinned_count("boot.bin", second.version_id), 0);
        let router = crate::api::api_router(writer.clone());
        let target = serde_json::json!({"kind":"retained_group","boot_profile":"default","group_id":"second"});
        let call = |route: &str, body: serde_json::Value| Request::builder()
            .method("POST").uri(route).header("x-api-key", "test-key")
            .extension(axum::extract::ConnectInfo("127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap()))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string())).unwrap();
        let response = router.clone().oneshot(call("/api/v2/delete/preview", serde_json::json!({"target": target}))).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let preview: serde_json::Value = serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(preview["can_delete"], false);
        assert_eq!(preview["blockers"], serde_json::json!(["persistence_coordination_unavailable"]));
        let response = router.oneshot(call("/api/v2/delete/confirm", serde_json::json!({
            "target": target, "expected_identity": second.manifest.manifest_digest,
        }))).await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(peer.version_store.pinned_count("boot.bin", second.version_id), 1);
        assert!(store.load_version_groups().await.unwrap().iter().any(|(group, _)| group == &second));
        assert_eq!(writer.version_store.group_count(), 2);
        assert_eq!(std::fs::read(artifact).unwrap(), b"boot artifact");
        peer.version_store.unpin_version("boot.bin", second.version_id);
    }).await;
}

#[cfg(feature = "sql-persistence")]
#[tokio::test]
async fn sql_revocation_uses_durable_identity_despite_stale_local_cache() {
    with_isolated_database(|url| async move {
        use axum::extract::{Path, State};
        let store = Arc::new(
            crate::persistence::PersistenceStore::connect(&url)
                .await
                .unwrap(),
        );
        let state = TftpServer::builder(TempestConfig::default())
            .with_persistence(store.clone())
            .build()
            .unwrap()
            .state();
        let ip = "192.0.2.30".parse().unwrap();
        let (mut entry, _) = prepare(&state, request(ip, true), &HashMap::new()).unwrap();
        let token = "a".repeat(64);
        let token_hash = Sha256::digest(token.as_bytes()).into();
        entry.artifact_token_hash = Some(token_hash);
        let revoke = |token: String| {
            super::super::revoke_session(
                State(state.clone()),
                Path(ip),
                Json(super::super::RevokeSessionRequest {
                    artifact_token: token,
                }),
            )
        };
        store.persist_boot_session(ip, &entry).await.unwrap();
        assert!(active_boot_session(&state, ip).is_none());
        assert_eq!(
            revoke(token.clone()).await.into_response().status(),
            StatusCode::NO_CONTENT
        );
        assert!(store.load_boot_sessions(100).await.unwrap().is_empty());
        assert_eq!(
            revoke(token.clone()).await.into_response().status(),
            StatusCode::NO_CONTENT
        );

        // A stale local token must neither prevent deletion of the current
        // durable token nor authorize deletion of a durable replacement.
        let mut stale = entry.clone();
        stale.artifact_token_hash = Some([42; 32]);
        state.insert_boot_session(ip, stale.clone());
        store.persist_boot_session(ip, &entry).await.unwrap();
        assert_eq!(
            revoke(token.clone()).await.into_response().status(),
            StatusCode::NO_CONTENT
        );
        assert!(active_boot_session(&state, ip).is_none());
        state.insert_boot_session(ip, entry.clone());
        store.persist_boot_session(ip, &stale).await.unwrap();
        assert_eq!(
            revoke(token.clone()).await.into_response().status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            store.load_boot_sessions(100).await.unwrap()[0]
                .1
                .artifact_token_hash,
            stale.artifact_token_hash
        );
    })
    .await;
}

#[tokio::test]
async fn batch_rejects_managed_requests_without_a_release_before_mutation() {
    let state = TftpServer::new(TempestConfig::default()).state();
    let (allowed, allowed_response) = command("192.0.2.1".parse().unwrap(), false);
    let (mut rejected, rejected_response) = command("192.0.2.2".parse().unwrap(), true);
    rejected.request.require_managed = true;
    commit_batch(&state, vec![allowed, rejected]).await;
    assert_eq!(
        allowed_response.await.unwrap().status(),
        StatusCode::CREATED
    );
    assert_eq!(
        rejected_response.await.unwrap().status(),
        StatusCode::CONFLICT
    );
    assert_eq!(state.boot_sessions.len(), 1);
    assert!(
        !state
            .boot_sessions
            .contains_key(&"192.0.2.2".parse::<IpAddr>().unwrap())
    );
}
