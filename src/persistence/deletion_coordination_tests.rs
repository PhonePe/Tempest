// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::features::versioning::deletion::{DeleteBlocker, DeleteError};
use crate::server::BootSessionEntry;
use sqlx::Executor;
use std::net::IpAddr;
use std::time::{Duration, Instant};

fn id() -> CoordinationId {
    CoordinationId::new(&uuid::Uuid::new_v4().simple().to_string()).unwrap()
}

async fn recorded_queries<F: std::future::Future>(operation: F) -> (F::Output, Vec<String>) {
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::layer::SubscriberExt;

    struct Queries(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Queries {
        fn on_new_span(
            &self,
            attributes: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _context: tracing_subscriber::layer::Context<'_, S>,
        ) {
            struct Visitor<'a>(&'a mut Vec<String>);
            impl tracing::field::Visit for Visitor<'_> {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    if field.name() == "db.query.text" {
                        self.0.push(value.into());
                    }
                }
                fn record_debug(
                    &mut self,
                    _field: &tracing::field::Field,
                    _value: &dyn std::fmt::Debug,
                ) {
                }
            }
            attributes.record(&mut Visitor(&mut self.0.lock().unwrap()));
        }
    }

    let queries = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let result = operation
        .with_subscriber(tracing_subscriber::registry().with(Queries(queries.clone())))
        .await;
    let statements = queries.lock().unwrap().clone();
    (result, statements)
}

async fn assert_reader_count(store: &PersistenceStore, expected: i64) {
    let recorded: i64 =
        sqlx::query_scalar("SELECT registered_count FROM tempest_reader_capacity WHERE id = 1")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    let actual: i64 = sqlx::query_scalar(store.coordination_sql(
        "SELECT CAST(COUNT(*) AS BIGINT) FROM tempest_group_readers",
        "SELECT CAST(COUNT(*) AS SIGNED) FROM tempest_group_readers",
    ))
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!((recorded, actual), (expected, expected));
}

#[tokio::test]
async fn session_batches_check_each_distinct_group_with_two_bounded_queries() {
    with_fixture(|store, _, identity| async move {
        store.ensure_serving_admission(false).await.unwrap();
        let entry = BootSessionEntry {
            trace_id: None,
            boot_profile: identity.profile.clone(),
            client_mac: None,
            serial: None,
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: Some(pin(&identity)),
            expires_at: Instant::now() + Duration::from_secs(300),
        };
        let mut entries: Vec<_> = (1..=32)
            .map(|host| (IpAddr::from([192, 0, 2, host]), entry.clone()))
            .collect();
        let (result, statements) = recorded_queries(store.persist_boot_sessions(&entries)).await;
        result.unwrap();
        let fences: Vec<_> = statements
            .iter()
            .filter(|query| query.starts_with("SELECT group_id FROM tempest_group_"))
            .collect();
        assert_eq!(fences.len(), 2);
        assert!(fences.iter().all(|query| query.matches("boot_profile =").count() == 1));

        let names: Vec<_> = (0..33).map(|index| format!("release-{index}")).collect();
        let pairs: Vec<_> = names.iter().map(|name| ("coordination", name.as_str())).collect();
        let mut tx = store.begin_coordination().await.unwrap();
        let (result, statements) = recorded_queries(store.reject_reserved_groups(&mut tx, &pairs[..32])).await;
        result.unwrap();
        assert_eq!(statements.len(), 2);
        assert!(statements.iter().all(|query| query.matches("boot_profile =").count() == 32));
        assert!(store.reject_reserved_groups(&mut tx, &pairs).await.is_err());
        drop(tx);

        sqlx::query("INSERT INTO tempest_group_tombstones (boot_profile, group_id, names_json) VALUES ('other-profile', 'release', '[]')")
            .execute(&store.pool).await.unwrap();
        store.persist_boot_sessions(&entries).await.unwrap();
        let last = &mut entries.last_mut().unwrap().1;
        last.boot_profile = "other-profile".into();
        last.pinned_boot_chain.as_mut().unwrap().boot_profile = "other-profile".into();
        let revision = store.state_revision().await.unwrap();
        assert!(matches!(store.persist_boot_sessions(&entries).await, Err(TempestError::Conflict(_))));
        assert_eq!(store.state_revision().await.unwrap(), revision);
        sqlx::query("DELETE FROM tempest_group_tombstones").execute(&store.pool).await.unwrap();
        sqlx::query(store.coordination_sql(
            "INSERT INTO tempest_group_deletion_reservations (operation_id, boot_profile, group_id, version_id, manifest_digest) VALUES ($1, 'other-profile', 'release', 1, $2)",
            "INSERT INTO tempest_group_deletion_reservations (operation_id, boot_profile, group_id, version_id, manifest_digest) VALUES (?, 'other-profile', 'release', 1, ?)",
        )).bind(id().0).bind(&identity.digest).execute(&store.pool).await.unwrap();
        assert!(matches!(store.persist_boot_sessions(&entries).await, Err(TempestError::Conflict(_))));
        assert_eq!(store.state_revision().await.unwrap(), revision);
    }).await;
}

#[tokio::test]
async fn reader_capacity_is_transactional_idempotent_and_backfilled_once() {
    with_fixture(|store, _, identity| async move {
        let reader = id();
        let (result, statements) =
            recorded_queries(store.acquire_group_reader(&identity, &reader)).await;
        result.unwrap();
        assert!(!statements.is_empty());
        assert!(statements.iter().all(|query| !query.contains("COUNT(")));
        assert_reader_count(&store, 1).await;
        store
            .acquire_group_reader(&identity, &reader)
            .await
            .unwrap();
        assert_reader_count(&store, 1).await;
        let wrong = GroupIdentity {
            group: "other".into(),
            ..identity.clone()
        };
        assert!(store.release_group_reader(&wrong, &reader).await.is_err());
        assert_reader_count(&store, 1).await;
        store
            .release_group_reader(&identity, &reader)
            .await
            .unwrap();
        store
            .release_group_reader(&identity, &reader)
            .await
            .unwrap();
        assert_reader_count(&store, 0).await;
        let mut tx = store.begin_coordination().await.unwrap();
        store
            .acquire_reader_in_tx(&mut tx, &identity, &id())
            .await
            .unwrap();
        drop(tx);
        assert_reader_count(&store, 0).await;
        store
            .acquire_group_reader(&identity, &reader)
            .await
            .unwrap();
        sqlx::query("DELETE FROM tempest_reader_capacity")
            .execute(&store.pool)
            .await
            .unwrap();
        store.migrate().await.unwrap();
        assert_reader_count(&store, 1).await;
        let (result, statements) = recorded_queries(store.migrate()).await;
        result.unwrap();
        assert!(
            statements
                .iter()
                .all(|query| !query.contains("FROM tempest_group_readers LIMIT 4097"))
        );
        assert_reader_count(&store, 1).await;
        store.ensure_serving_admission(true).await.unwrap();
        assert_eq!(store.recover_reader_bookkeeping().await.unwrap(), 1);
        assert_reader_count(&store, 0).await;
    })
    .await;
}

#[tokio::test]
async fn serving_probe_deadline_bounds_mutex_wait_without_poisoning_the_owner() {
    with_fixture(|store, _, _| async move {
        store.ensure_serving_admission(true).await.unwrap();
        let held = store.serving_transaction_for_test().await;
        assert!(tokio::time::timeout(
            Duration::from_millis(20),
            store.ensure_serving_admission(true),
        ).await.is_err());
        let results = tokio::time::timeout(COORDINATION_TIMEOUT + Duration::from_secs(25), async {
            tokio::join!(
                store.ensure_serving_admission(true),
                store.ensure_serving_admission(true),
                store.ensure_serving_admission(true),
            )
        }).await.expect("lease mutex wait exceeded the admission deadline");
        for result in [results.0, results.1, results.2] {
            assert!(matches!(result, Err(TempestError::PersistenceBusy(message)) if message.contains("deadline")));
        }
        assert!(held.is_some(), "waiting or cancelled requests must not poison the owner");
        drop(held);
        store.ensure_serving_admission(true).await.unwrap();
    }).await;
}

#[tokio::test]
async fn late_lease_mutex_waiter_gets_a_full_probe_budget_without_poisoning() {
    with_fixture(|store, _, _| async move {
        store.ensure_serving_admission(true).await.unwrap();
        // Probe latency exceeds what remains of the admission deadline after a
        // long mutex wait; a healthy database must not poison the lease.
        // Release with 2.5s of the admission deadline left for the mutex wake-up;
        // the 2.6s probe still overruns that remainder but fits a fresh budget
        // with 2.4s to spare.
        store.set_serving_probe_delay_for_test(Duration::from_millis(2600));
        let held = store.serving_transaction_for_test().await;
        let release = async {
            tokio::time::sleep(COORDINATION_TIMEOUT - Duration::from_millis(2500)).await;
            drop(held);
        };
        let (result, ()) = tokio::join!(store.ensure_serving_admission(true), release);
        result.expect("a late waiter's healthy probe must succeed");
        store.set_serving_probe_delay_for_test(Duration::ZERO);
        assert!(
            store.serving_transaction_for_test().await.is_some(),
            "a healthy lease must not be poisoned"
        );
        store.ensure_serving_admission(true).await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn cancelled_lease_probe_neither_poisons_nor_releases_the_namespace() {
    with_fixture(|store, peer, _| async move {
        store.ensure_serving_admission(true).await.unwrap();
        // The outer request deadline interrupts the probe while SQL is in flight.
        store.set_serving_probe_delay_for_test(Duration::from_secs(1));
        assert!(
            tokio::time::timeout(
                Duration::from_millis(200),
                store.ensure_serving_admission(true),
            )
            .await
            .is_err()
        );
        store.set_serving_probe_delay_for_test(Duration::ZERO);
        assert!(!store.serving_lease_lost());
        store.ensure_serving_admission(true).await.unwrap();
        assert!(!store.serving_lease_lost());
        assert!(peer.ensure_serving_admission(true).await.is_err());
    })
    .await;
}

#[tokio::test]
async fn deletion_mode_writes_probe_the_lease_once() {
    with_fixture(|store, _, _| async move {
        store.ensure_serving_admission(true).await.unwrap();
        let before = store.serving_probe_count_for_test();
        let group = super::super::tests::version_group("single-probe", "release", 2);
        store.persist_version_group(&group, 0).await.unwrap();
        assert_eq!(store.serving_probe_count_for_test() - before, 1);
        let before = store.serving_probe_count_for_test();
        store.prune_expired_boot_sessions().await.unwrap();
        assert_eq!(store.serving_probe_count_for_test() - before, 1);
    })
    .await;
}

#[tokio::test]
async fn lost_serving_lease_reports_degraded_readiness() {
    with_fixture(|store, peer, _| async move {
        use axum::{
            body::{Body, to_bytes},
            http::{Request, StatusCode},
        };
        use tower::ServiceExt;
        let store = std::sync::Arc::new(store);
        let (_root, state, _, _) = runtime_fixture(store.clone(), "boot/kernel", true).await;
        state
            .tftp_ready
            .store(true, std::sync::atomic::Ordering::Release);
        let router = crate::api::api_router(state.clone());
        let ready = || async {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/ready")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = response.status();
            (status, to_bytes(response.into_body(), 64).await.unwrap())
        };
        assert_eq!(ready().await.0, StatusCode::OK);
        kill_serving_connection(&store, &peer).await;
        assert!(store.ensure_serving_admission(true).await.is_err());
        assert!(store.serving_lease_lost());
        let (status, body) = ready().await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(&body[..], b"DEGRADED");
    })
    .await;
}

#[tokio::test]
async fn artifact_resolution_probes_only_inside_authoritative_transactions() {
    with_fixture(|store, _, _| async move {
        let store = std::sync::Arc::new(store);
        let (root, state, _, entry) = runtime_fixture(store.clone(), "boot/kernel", true).await;
        for expected_probes in [2, 1] {
            let before = store.serving_probe_count_for_test();
            let resolved = state
                .resolve_file_for_required_boot_session("127.0.0.1".parse().unwrap(), "boot/kernel")
                .await
                .unwrap();
            assert!(resolved.durable_reader.is_some());
            assert_eq!(std::fs::read(&resolved.path).unwrap(), b"managed bytes");
            assert_eq!(
                store.serving_probe_count_for_test() - before,
                expected_probes
            );
            let pin = resolved.pinned_version.as_ref().unwrap();
            state.version_store.unpin_version_for_profile(
                &pin.boot_profile,
                &pin.logical_name,
                pin.version_id,
            );
            drop(resolved);
            let drained = tokio::time::timeout(
                Duration::from_secs(10),
                store.reader_budget.clone().acquire_many_owned(4096),
            )
            .await
            .unwrap()
            .unwrap();
            drop(drained);
        }
        std::fs::write(root.path().join("unmanaged"), b"unmanaged bytes").unwrap();
        let ip = "127.0.0.2".parse().unwrap();
        store.persist_boot_session(ip, &entry).await.unwrap();
        let token_hash = entry.artifact_token_hash.unwrap();
        state.insert_boot_session(ip, entry);
        let before = store.serving_probe_count_for_test();
        let resolved = state
            .resolve_file_for_authorized_boot_session(ip, &token_hash, "unmanaged")
            .await
            .unwrap();
        assert!(resolved.durable_reader.is_none());
        assert_eq!(std::fs::read(&resolved.path).unwrap(), b"unmanaged bytes");
        assert_eq!(store.serving_probe_count_for_test() - before, 1);
        assert!(store.ensure_serving_mode(false).await.is_err());
    })
    .await;
}

#[tokio::test]
async fn ordinary_snapshot_age_bounds_http_tftp_and_readiness_and_recovers() {
    with_fixture(|store, peer, _| async move {
        use axum::{
            body::{Body, to_bytes},
            extract::ConnectInfo,
            http::{Request, StatusCode},
        };
        use tower::ServiceExt;
        let store = std::sync::Arc::new(store);
        let (_root, state, _, _) = runtime_fixture(store, "boot/kernel", false).await;
        state
            .tftp_ready
            .store(true, std::sync::atomic::Ordering::Release);
        let router = crate::api::api_router(state.clone());
        let artifact_request = || {
            Request::builder()
                .uri("/api/v1/artifacts/boot/kernel")
                .header("authorization", format!("Bearer {}", "ab".repeat(32)))
                .extension(ConnectInfo(
                    "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                ))
                .body(Body::empty())
                .unwrap()
        };
        let in_flight = router.clone().oneshot(artifact_request()).await.unwrap();
        assert_eq!(in_flight.status(), StatusCode::OK);
        let stale_at =
            Instant::now() - Duration::from_secs(state.config.persistence.max_snapshot_age_secs);
        *state.persistence_snapshot_validated_at.lock() = Some(stale_at);
        assert!(matches!(
            state
                .resolve_file_for_boot_session(
                    "127.0.0.3".parse().unwrap(),
                    "default",
                    "boot/kernel"
                )
                .await,
            Err(TempestError::PersistenceSnapshotStale)
        ));
        let response = router.clone().oneshot(artifact_request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            &to_bytes(response.into_body(), 8192).await.unwrap()[..],
            b"Persistent state is stale"
        );
        let ready = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            &to_bytes(in_flight.into_body(), 8192).await.unwrap()[..],
            b"managed bytes"
        );
        state.sync_persistent_state().await.unwrap();
        state.ensure_persistence_snapshot_fresh().unwrap();
        let ready = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::OK);
        *state.persistence_snapshot_validated_at.lock() = Some(stale_at);
        let revision = peer.version_revision("default").await.unwrap();
        peer.withdraw_version_group("default", "first", None, revision)
            .await
            .unwrap();
        state.sync_persistent_state().await.unwrap();
        state.ensure_persistence_snapshot_fresh().unwrap();
        assert!(matches!(
            state
                .resolve_file_for_boot_session(
                    "127.0.0.3".parse().unwrap(),
                    "default",
                    "boot/kernel"
                )
                .await,
            Err(TempestError::Protocol(
                crate::error::ProtocolError::FileNotFound(_)
            ))
        ));
    })
    .await;
}

async fn fill_managed_name_index(store: &PersistenceStore, count: usize) {
    for start in (0..count).step_by(500) {
        let rows: Vec<_> = (start..(start + 500).min(count))
            .map(|index| format!("('{index:064x}')"))
            .collect();
        sqlx::query(&format!(
            "INSERT INTO tempest_managed_names (name_hash) VALUES {}",
            rows.join(",")
        ))
        .execute(&store.pool)
        .await
        .unwrap();
    }
}

async fn managed_name_count(store: &PersistenceStore) -> i64 {
    sqlx::query_scalar(store.coordination_sql(
        "SELECT CAST(COUNT(*) AS BIGINT) FROM tempest_managed_names",
        "SELECT CAST(COUNT(*) AS SIGNED) FROM tempest_managed_names",
    ))
    .fetch_one(&store.pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn ordinary_sql_releases_ignore_a_full_permanent_managed_name_index() {
    with_fixture(|store, _, _| async move {
        store.ensure_serving_admission(false).await.unwrap();
        sqlx::query("DELETE FROM tempest_managed_names")
            .execute(&store.pool)
            .await
            .unwrap();
        fill_managed_name_index(&store, 20_000).await;
        sqlx::query("UPDATE tempest_deletion_safety SET ownership_ready = 1 WHERE id = 1")
            .execute(&store.pool)
            .await
            .unwrap();
        let group = super::super::tests::version_group("coordination", "ordinary", 2);
        store.persist_version_group(&group, 2).await.unwrap();
        store.migrate().await.unwrap();
        assert_eq!(managed_name_count(&store).await, 20_000);
        let ready: i32 =
            sqlx::query_scalar("SELECT ownership_ready FROM tempest_deletion_safety WHERE id = 1")
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(ready, 0);
    })
    .await;
}

#[tokio::test]
async fn deletion_mode_backfills_managed_names_after_ordinary_publication() {
    with_fixture(|store, peer, _| async move {
        store.ensure_serving_admission(false).await.unwrap();
        sqlx::query("UPDATE tempest_deletion_safety SET ownership_ready = 1 WHERE id = 1")
            .execute(&store.pool)
            .await
            .unwrap();
        use sha2::{Digest, Sha256};
        sqlx::query(store.coordination_sql(
            "INSERT INTO tempest_managed_names (name_hash) VALUES ($1)",
            "INSERT INTO tempest_managed_names (name_hash) VALUES (?)",
        ))
        .bind(hex::encode(Sha256::digest(b"retired-kernel")))
        .execute(&store.pool)
        .await
        .unwrap();
        let mut group = super::super::tests::version_group("coordination", "ordinary", 2);
        group.files[0].logical_name = "vmlinuz-6.8.0-45".into();
        group.manifest.artifacts[0].logical_name = group.files[0].logical_name.clone();
        store.persist_version_group(&group, 2).await.unwrap();
        assert_eq!(managed_name_count(&store).await, 1);
        drop(store);
        sqlx::query(
            "UPDATE tempest_serving_namespace SET protocol = 3 WHERE id = 1 AND protocol = 2",
        )
        .execute(&peer.pool)
        .await
        .unwrap();
        peer.ensure_serving_admission(true).await.unwrap();
        for name in ["artifact.bin", "vmlinuz-6.8.0-45", "retired-kernel"] {
            assert!(
                peer.check_unmanaged_admission("default", name)
                    .await
                    .is_err()
            );
        }
        peer.check_unmanaged_admission("default", "unmanaged")
            .await
            .unwrap();
    })
    .await;
}

#[tokio::test]
async fn deletion_mode_managed_name_capacity_is_atomic_and_allows_existing_names() {
    with_fixture(|store, peer, _| async move {
        store.ensure_serving_admission(true).await.unwrap();
        fill_managed_name_index(&store, 19_999).await;
        let group = super::super::tests::version_group("coordination", "same-name", 2);
        peer.persist_version_group(&group, 2).await.unwrap();
        let mut extra = super::super::tests::version_group("coordination", "new-name", 3);
        extra.files[0].logical_name = "vmlinuz-6.8.0-45".into();
        extra.manifest.artifacts[0].logical_name = extra.files[0].logical_name.clone();
        let revision = peer.state_revision().await.unwrap();
        assert!(matches!(
            peer.persist_version_group(&extra, 3).await,
            Err(TempestError::Conflict(message)) if message.contains("managed-name capacity")
        ));
        assert_eq!(peer.state_revision().await.unwrap(), revision);
        assert!(
            peer.load_version_groups()
                .await
                .unwrap()
                .iter()
                .all(|(group, _)| group.group_id != "new-name")
        );
        assert_eq!(managed_name_count(&peer).await, 20_000);
    })
    .await;
}

async fn runtime_fixture(
    store: std::sync::Arc<PersistenceStore>,
    name: &str,
    coordinated_deletion: bool,
) -> (
    tempfile::TempDir,
    std::sync::Arc<crate::server::ServerState>,
    crate::features::versioning::VersionGroup,
    BootSessionEntry,
) {
    use sha2::{Digest, Sha256};
    sqlx::query("DELETE FROM tempest_version_groups")
        .execute(&store.pool)
        .await
        .unwrap();
    let root = tempfile::tempdir().unwrap();
    let artifact = root.path().join(name);
    std::fs::create_dir_all(artifact.parent().unwrap()).unwrap();
    std::fs::write(&artifact, b"managed bytes").unwrap();
    let mut config = crate::config::TempestConfig::default();
    config.server.root = root.path().to_owned();
    config.persistence.enabled = true;
    config.persistence.coordinated_deletion = coordinated_deletion;
    config.api.api_key = Some("test-key".into());
    let state = crate::server::TftpServer::builder(config)
        .with_persistence(store.clone())
        .build()
        .unwrap()
        .state();
    let group = state
        .version_store
        .atomic_switch("first".into(), vec![(name.into(), artifact)])
        .unwrap();
    store.persist_version_group(&group, 0).await.unwrap();
    state.sync_persistent_state().await.unwrap();
    let entry = BootSessionEntry {
        trace_id: None,
        boot_profile: "default".into(),
        client_mac: None,
        serial: None,
        boot_epoch: 1,
        artifact_token_hash: Some(Sha256::digest("ab".repeat(32).as_bytes()).into()),
        pinned_boot_chain: None,
        expires_at: Instant::now() + Duration::from_secs(300),
    };
    store
        .persist_boot_session("127.0.0.1".parse().unwrap(), &entry)
        .await
        .unwrap();
    state.insert_boot_session("127.0.0.1".parse().unwrap(), entry.clone());
    (root, state, group, entry)
}

async fn kill_serving_connection(store: &PersistenceStore, peer: &PersistenceStore) {
    let connection = store.serving_connection_id().await;
    match store.dialect {
        DatabaseDialect::Postgres => {
            sqlx::query("SELECT pg_terminate_backend($1)")
                .bind(connection as i32)
                .execute(&peer.pool)
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    let remaining: i64 =
                        sqlx::query_scalar("SELECT COUNT(*) FROM pg_stat_activity WHERE pid = $1")
                            .bind(connection as i32)
                            .fetch_one(&peer.pool)
                            .await
                            .unwrap();
                    if remaining == 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("terminated PostgreSQL serving backend did not exit within 30 seconds");
        }
        DatabaseDialect::MySql => {
            sqlx::query(&format!("KILL CONNECTION {connection}"))
                .execute(&peer.pool)
                .await
                .unwrap();
            // KILL CONNECTION returns once the kill request is acknowledged, not
            // once the backend has exited and released its row locks. Wait for
            // the connection to actually disappear so the lock is gone before a
            // peer's NOWAIT admission races it; mirrors the PostgreSQL path.
            tokio::time::timeout(Duration::from_secs(30), async {
                loop {
                    let remaining: i64 = sqlx::query_scalar(&format!(
                        "SELECT COUNT(*) FROM information_schema.processlist WHERE id = {connection}"
                    ))
                    .fetch_one(&peer.pool)
                    .await
                    .unwrap();
                    if remaining == 0 {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("killed MySQL serving backend did not exit within 30 seconds");
        }
    }
}

#[tokio::test]
async fn deleted_names_cannot_escape_sql_bearer_fences_through_path_aliases() {
    with_fixture(|store, _, _| async move {
        use axum::{
            body::{Body, to_bytes},
            extract::ConnectInfo,
            http::{Request, StatusCode},
        };
        use std::sync::Arc;
        use tower::ServiceExt;
        let store = Arc::new(store);
        let (root, state, group, entry) = runtime_fixture(store.clone(), "boot/kernel", true).await;
        std::fs::write(root.path().join("unmanaged"), b"compatible bytes").unwrap();
        store
            .withdraw_version_group("default", "first", None, 1)
            .await
            .unwrap();
        state.version_store.withdraw_profile("default").unwrap();
        store.delete_sql_group(&group, 2).await.unwrap();
        // Empty local metadata represents a post-commit/pre-publication restart:
        // only SQL tombstones can retain ownership of the bytes still on disk.
        let fresh = crate::server::TftpServer::builder((*state.config).clone())
            .with_persistence(store.clone())
            .build()
            .unwrap()
            .state();
        fresh.insert_boot_session("127.0.0.1".parse().unwrap(), entry);
        let router = crate::api::api_router(fresh.clone());
        for (path, expected) in [
            ("boot/kernel", StatusCode::NOT_FOUND),
            ("missing", StatusCode::NOT_FOUND),
            ("boot//kernel", StatusCode::FORBIDDEN),
            ("boot/./kernel", StatusCode::FORBIDDEN),
            ("boot/%2e/kernel", StatusCode::FORBIDDEN),
            ("boot/kernel/", StatusCode::FORBIDDEN),
            ("unmanaged", StatusCode::OK),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/v1/artifacts/{path}"))
                        .header("authorization", format!("Bearer {}", "ab".repeat(32)))
                        .extension(ConnectInfo(
                            "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                        ))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected, "{path}");
            if expected == StatusCode::OK {
                assert_eq!(
                    &to_bytes(response.into_body(), 8192).await.unwrap()[..],
                    b"compatible bytes"
                );
            } else if expected == StatusCode::NOT_FOUND {
                assert_eq!(
                    &to_bytes(response.into_body(), 8192).await.unwrap()[..],
                    b"Artifact not found"
                );
            }
        }
        for alias in ["boot//kernel", "boot/./kernel", "boot/kernel/"] {
            assert!(
                fresh
                    .resolve_file_for_required_boot_session("127.0.0.1".parse().unwrap(), alias)
                    .await
                    .is_err()
            );
            assert!(
                store
                    .check_unmanaged_admission("default", alias)
                    .await
                    .is_err()
            );
        }
    })
    .await;
}

#[tokio::test]
async fn unicode_tombstones_survive_ascii_schema_upgrade_and_fence_exact_names() {
    with_fixture(|store, _, _| async move {
        if store.dialect == DatabaseDialect::MySql {
            sqlx::query("ALTER TABLE tempest_group_tombstones MODIFY COLUMN names_json TEXT CHARACTER SET ascii COLLATE ascii_bin NOT NULL")
                .execute(&store.pool).await.unwrap();
            sqlx::query("INSERT INTO tempest_group_tombstones (boot_profile, group_id, names_json) VALUES ('legacy', 'legacy', '[\"legacy/kernel\"]')")
                .execute(&store.pool).await.unwrap();
            store.migrate().await.unwrap();
            store.migrate().await.unwrap(); // idempotent and preserves legacy data
            let row = sqlx::query("SELECT names_json FROM tempest_group_tombstones WHERE group_id = 'legacy'").fetch_one(&store.pool).await.unwrap();
            assert_eq!(row_text(&row, "names_json").unwrap(), "[\"legacy/kernel\"]");
        }
        let store = std::sync::Arc::new(store);
        let name = "boot/noyau-é-🌀";
        let (_root, state, group, _) = runtime_fixture(store.clone(), name, true).await;
        store.withdraw_version_group("default", "first", None, 1).await.unwrap();
        state.version_store.withdraw_profile("default").unwrap();
        store.delete_sql_group(&group, 2).await.unwrap();
        let row = sqlx::query("SELECT names_json FROM tempest_group_tombstones WHERE group_id = 'first'").fetch_one(&store.pool).await.unwrap();
        let names: Vec<String> = serde_json::from_str(&row_text(&row, "names_json").unwrap()).unwrap();
        assert_eq!(names, [name]);
        assert!(store.check_unmanaged_admission("default", name).await.is_err());
        store.check_unmanaged_admission("default", "boot/noyau-e-🌀").await.unwrap();
        store.check_unmanaged_admission("default", "boot/noyau-é-🌊").await.unwrap();
    }).await;
}

#[tokio::test]
async fn queued_resolver_and_old_router_mutations_refuse_replacement_serving_generation() {
    with_fixture(|store, peer, _| async move {
        use axum::{body::Body, extract::ConnectInfo, http::{Request, StatusCode}};
        use std::sync::Arc;
        use tower::ServiceExt;
        let store = Arc::new(store);
        let (_root, state, group, entry) = runtime_fixture(store.clone(), "boot/kernel", true).await;
        let pin = BootChainPin { boot_profile: "default".into(), group_id: group.group_id.clone(), version_id: group.version_id, manifest_digest: group.manifest.manifest_digest.clone() };
        let reader = store.register_reader(&pin).await.unwrap();
        let guard = state.control_plane_lock.lock().await;
        let probes_before = store.serving_probe_count_for_test();
        let mut resolver = Box::pin(state.resolve_file_for_required_boot_session(
            "127.0.0.1".parse().unwrap(), "boot/kernel",
        ));
        let waiting = tokio::time::timeout(Duration::from_millis(50), &mut resolver).await;
        assert!(waiting.is_err());
        assert_eq!(store.serving_probe_count_for_test(), probes_before,
            "queued resolution must not run a preliminary SQL probe");
        // The resolver is queued on the control lock. Replace the serving owner
        // before it reaches its authoritative transaction admission.
        kill_serving_connection(&store, &peer).await;
        assert!(state.ensure_persistence_admission().await.is_err());
        peer.ensure_serving_admission(true).await.unwrap();
        let revision = peer.state_revision().await.unwrap();
        let profile_revision = peer.version_revision("default").await.unwrap();
        drop(guard);
        assert!(tokio::time::timeout(Duration::from_secs(10), resolver).await.unwrap().is_err());
        assert!(store.register_reader(&pin).await.is_err());
        assert!(store.check_unmanaged_admission("default", "unmanaged").await.is_err());
        let router = crate::api::api_router(state.clone());
        let response = router.oneshot(Request::builder().method("POST").uri("/api/v2/versions/withdraw")
            .header("x-api-key", "test-key").header("content-type", "application/json")
            .extension(ConnectInfo("127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap()))
            .body(Body::from(serde_json::json!({"boot_profile":"default", "group_id":"first", "manifest_digest":group.manifest.manifest_digest}).to_string())).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(state.version_store.active_boot_chain_for_profile("default").unwrap().unwrap().group_id, "first");
        assert!(store.persist_version_group(&group, profile_revision).await.is_err());
        assert!(store.rollback_version_group("default", "first", None, profile_revision, None, None).await.is_err());
        assert!(store.persist_boot_session("192.0.2.99".parse().unwrap(), &entry).await.is_err());
        assert!(store.pin_boot_session("127.0.0.1".parse().unwrap(), 1, &pin).await.is_err());
        assert!(store.delete_boot_session("127.0.0.1".parse().unwrap()).await.is_err());
        assert!(store.delete_boot_session_with_token("127.0.0.1".parse().unwrap(), &entry.artifact_token_hash.unwrap()).await.is_err());
        assert!(store.prune_expired_boot_sessions().await.is_err());
        assert_eq!(peer.state_revision().await.unwrap(), revision);
        assert_eq!(peer.version_revision("default").await.unwrap(), profile_revision);
        // Exact cleanup is deliberately exempt from lease/generation admission.
        drop(reader);
        let drained = tokio::time::timeout(Duration::from_secs(10), store.reader_budget.clone().acquire_many_owned(4096)).await.unwrap().unwrap();
        drop(drained);
        assert!(sqlx::query("SELECT operation_id FROM tempest_group_readers").fetch_optional(&peer.pool).await.unwrap().is_none());
        peer.persist_boot_session("192.0.2.99".parse().unwrap(), &entry).await.unwrap();
    }).await;
}

#[tokio::test]
async fn reader_generation_is_checked_inside_the_revision_transaction() {
    with_fixture(|store, peer, identity| async move {
        store.ensure_serving_admission(true).await.unwrap();
        // Simulate a durable generation change independently of local poisoning:
        // the original namespace connection still probes successfully.
        let mut tx = peer.pool.begin().await.unwrap();
        peer.lock_state_revision_unchecked(&mut tx).await.unwrap();
        sqlx::query(
            "UPDATE tempest_serving_generation SET generation = generation + 1 WHERE id = 1",
        )
        .execute(tx.executor())
        .await
        .unwrap();
        let reader_pin = pin(&identity);
        let mut registration = Box::pin(store.register_reader(&reader_pin));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut registration)
                .await
                .is_err()
        );
        tx.commit().await.unwrap();
        assert!(registration.await.is_err());
        assert!(store.ensure_serving_admission(true).await.is_err());
        assert!(
            sqlx::query("SELECT operation_id FROM tempest_group_readers")
                .fetch_optional(&peer.pool)
                .await
                .unwrap()
                .is_none()
        );
    })
    .await;
}

#[tokio::test]
async fn ordinary_downloads_need_no_sql_but_new_session_pins_remain_durable() {
    with_fixture(|store, peer, _| async move {
        use axum::{
            body::{Body, to_bytes},
            extract::ConnectInfo,
            http::{Request, StatusCode},
        };
        use std::sync::Arc;
        use tower::ServiceExt;

        let store = Arc::new(store);
        let (_root, state, group, mut entry) =
            runtime_fixture(store.clone(), "boot/kernel", false).await;
        let pinned_ip = "127.0.0.1".parse().unwrap();
        let unpinned_ip = "127.0.0.2".parse().unwrap();
        entry.artifact_token_hash = None;
        store
            .persist_boot_session(unpinned_ip, &entry)
            .await
            .unwrap();
        state.insert_boot_session(unpinned_ip, entry);
        let release = |resolved: crate::features::versioning::ResolvedFile| {
            assert!(resolved.durable_reader.is_none());
            assert_eq!(std::fs::read(&resolved.path).unwrap(), b"managed bytes");
            let pin = resolved.pinned_version.unwrap();
            state.version_store.unpin_version_for_profile(
                &pin.boot_profile,
                &pin.logical_name,
                pin.version_id,
            );
        };
        release(
            state
                .resolve_file_for_boot_session(pinned_ip, "default", "boot/kernel")
                .await
                .unwrap(),
        );
        assert!(
            state
                .boot_sessions
                .get(&pinned_ip)
                .unwrap()
                .pinned_boot_chain
                .is_some()
        );
        store.pool.close().await;
        let validated_at = *state.persistence_snapshot_validated_at.lock();
        assert!(state.sync_persistent_state().await.is_err());
        assert_eq!(
            *state.persistence_snapshot_validated_at.lock(),
            validated_at
        );
        let router = crate::api::api_router(state.clone());
        for _ in 0..3 {
            for ip in [pinned_ip, "127.0.0.3".parse().unwrap()] {
                release(
                    state
                        .resolve_file_for_boot_session(ip, "default", "boot/kernel")
                        .await
                        .unwrap(),
                );
            }
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/artifacts/boot/kernel")
                        .header("authorization", format!("Bearer {}", "ab".repeat(32)))
                        .extension(ConnectInfo(
                            "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                        ))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                &to_bytes(response.into_body(), 8192).await.unwrap()[..],
                b"managed bytes",
            );
        }
        let pins = state
            .version_store
            .pinned_count("boot/kernel", group.version_id);
        assert!(
            state
                .resolve_file_for_boot_session(unpinned_ip, "default", "boot/kernel")
                .await
                .is_err()
        );
        assert!(
            state
                .boot_sessions
                .get(&unpinned_ip)
                .unwrap()
                .pinned_boot_chain
                .is_none()
        );
        assert_eq!(
            state
                .version_store
                .pinned_count("boot/kernel", group.version_id),
            pins
        );
        assert!(
            sqlx::query("SELECT operation_id FROM tempest_group_readers")
                .fetch_all(&peer.pool)
                .await
                .unwrap()
                .is_empty()
        );
        *state.persistence_snapshot_validated_at.lock() = Some(
            Instant::now() - Duration::from_secs(state.config.persistence.max_snapshot_age_secs),
        );
        assert!(state.sync_persistent_state().await.is_err());
        assert!(matches!(
            state.ensure_persistence_snapshot_fresh(),
            Err(TempestError::PersistenceSnapshotStale)
        ));
    })
    .await;
}

#[tokio::test]
async fn standalone_servers_enforce_attached_store_admission_without_cli_configuration() {
    with_fixture(|store, peer, _| async move {
        use std::sync::Arc;
        let root = tempfile::tempdir().unwrap();
        let mut config = crate::config::TempestConfig::default();
        config.server.root = root.path().to_owned();
        config.api.api_key = Some("test-key-at-least-sixteen".into());
        config.server.bind = "127.0.0.1".parse().unwrap();
        config.server.port = 0;
        assert!(!config.persistence.enabled);
        let owner = Arc::new(store);
        let peer = Arc::new(peer);
        owner.ensure_serving_admission(true).await.unwrap();
        // A composition-attached store participates even if the CLI/config
        // persistence switch is false. Both standalone listeners must refuse.
        let competing = crate::server::TftpServer::builder(config.clone())
            .with_persistence(peer.clone())
            .build()
            .unwrap();
        let assert_namespace_refusal = |error| match error {
            TempestError::Persistence(reason) => assert!(
                reason.starts_with("acquire serving namespace (another server may own it): "),
                "unexpected persistence refusal: {reason}",
            ),
            TempestError::PersistenceBusy(reason) => {
                assert_eq!(reason, "serving namespace deadline exceeded")
            }
            other => panic!("expected SQL serving namespace refusal, got {other:?}"),
        };
        assert_namespace_refusal(competing.run().await.unwrap_err());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert_namespace_refusal(
            crate::api::run_http_server_on(competing.state(), listener)
                .await
                .unwrap_err(),
        );
        assert!(
            !competing
                .state()
                .tftp_ready
                .load(std::sync::atomic::Ordering::Acquire)
        );
        config.persistence.coordinated_deletion = true;
        let owner_state = crate::server::TftpServer::builder(config)
            .with_persistence(owner.clone())
            .build()
            .unwrap()
            .state();
        owner_state.ensure_persistence_admission().await.unwrap();
        // Loss poisons the same store for every public state sharing it, rather
        // than reconnecting on behalf of a new listener or resolver.
        kill_serving_connection(&owner, &peer).await;
        assert!(owner_state.ensure_persistence_admission().await.is_err());
        assert!(
            owner_state
                .resolve_file_for_boot_session("127.0.0.1".parse().unwrap(), "default", "kernel")
                .await
                .is_err()
        );
        assert!(owner_state.ensure_persistence_admission().await.is_err());
        assert!(peer.ensure_serving_admission(false).await.is_err());
        peer.ensure_serving_admission(true).await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn retention_cannot_remove_durable_readers_or_reserved_groups() {
    with_fixture(|store, peer, identity| async move {
        let original = sqlx::query("SELECT files_json FROM tempest_version_groups")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        let original = row_text(&original, "files_json").unwrap();
        let oversized = "x".repeat(super::super::MAX_PERSISTED_JSON_BYTES + 1);
        let update = store.coordination_sql(
            "UPDATE tempest_version_groups SET files_json = $1",
            "UPDATE tempest_version_groups SET files_json = ?",
        );
        for reservation in [false, true] {
            let operation = id();
            if reservation {
                store
                    .reserve_group_deletion(&identity, &operation)
                    .await
                    .unwrap();
            } else {
                store
                    .acquire_group_reader(&identity, &operation)
                    .await
                    .unwrap();
            }
            sqlx::query(update)
                .bind(&oversized)
                .execute(&store.pool)
                .await
                .unwrap();
            assert!(peer.enforce_version_group_retention().await.is_err());
            let count: i64 = sqlx::query_scalar(store.coordination_sql(
                "SELECT CAST(COUNT(*) AS BIGINT) FROM tempest_version_groups",
                "SELECT CAST(COUNT(*) AS SIGNED) FROM tempest_version_groups",
            ))
            .fetch_one(&peer.pool)
            .await
            .unwrap();
            assert_eq!(count, 1);
            sqlx::query(update)
                .bind(&original)
                .execute(&store.pool)
                .await
                .unwrap();
            if reservation {
                store
                    .release_group_deletion(&identity, &operation)
                    .await
                    .unwrap();
            } else {
                store
                    .release_group_reader(&identity, &operation)
                    .await
                    .unwrap();
            }
        }
        sqlx::query(update)
            .bind(oversized)
            .execute(&store.pool)
            .await
            .unwrap();
        peer.enforce_version_group_retention().await.unwrap();
        assert!(peer.load_version_groups().await.unwrap().is_empty());
    })
    .await;
}

#[tokio::test]
async fn exhausted_reader_tracking_blocks_retention_until_offline_recovery() {
    with_fixture(|store, peer, identity| async move {
        for index in 0..super::super::MAX_PERSISTED_GROUPS - 2 {
            let group =
                super::super::tests::version_group(&format!("retained-{index}"), "release", 1);
            store.persist_version_group(&group, 0).await.unwrap();
        }
        sqlx::query(
            "UPDATE tempest_deletion_safety SET reader_tracking_exhausted = 1 WHERE id = 1",
        )
        .execute(&store.pool)
        .await
        .unwrap();
        let within_budget = super::super::tests::version_group("within-budget", "release", 1);
        peer.persist_version_group(&within_budget, 0).await.unwrap();
        let revision = store.state_revision().await.unwrap();
        let replacement = super::super::tests::version_group("replacement", "release", 1);
        assert!(
            matches!(
                peer.persist_version_group(&replacement, 0).await,
                Err(TempestError::Conflict(reason)) if reason.contains("reader tracking exhausted")
            ),
            "retention must not evict an inactive release while reader tracking is exhausted",
        );
        assert_eq!(store.state_revision().await.unwrap(), revision);
        assert_eq!(store.version_revision("replacement").await.unwrap(), 0);
        assert_eq!(
            store.load_version_groups().await.unwrap().len(),
            super::super::MAX_PERSISTED_GROUPS,
        );
        let reader = id();
        peer.acquire_group_reader(&identity, &reader).await.unwrap();
        peer.check_unmanaged_admission("default", "unmanaged")
            .await
            .unwrap();
        assert_eq!(peer.recover_reader_bookkeeping().await.unwrap(), 1);
        peer.persist_version_group(&replacement, 0).await.unwrap();
        assert_eq!(
            peer.load_version_groups().await.unwrap().len(),
            super::super::MAX_PERSISTED_GROUPS,
        );
        assert!(
            peer.coordination_group(&mut peer.begin_coordination().await.unwrap(), &identity)
                .await
                .is_err()
        );
    })
    .await;
}

#[tokio::test]
async fn permanent_deletion_capacity_preserves_http_serving_and_ownership_fences() {
    with_fixture(|store, _, _| async move {
        use axum::{
            body::{Body, to_bytes},
            extract::ConnectInfo,
            http::{Request, StatusCode},
        };
        use std::sync::Arc;
        use tower::ServiceExt;

        let store = Arc::new(store);
        let (root, state, _, _) = runtime_fixture(store.clone(), "boot/kernel", true).await;
        std::fs::write(root.path().join("unmanaged"), b"compatible bytes").unwrap();
        for index in 0..MAX_RESERVATIONS {
            let group = super::super::tests::version_group(
                "retired",
                &format!("release-{index}"),
                index as u64 + 1,
            );
            store
                .persist_version_group(&group, index * 3)
                .await
                .unwrap();
            store
                .withdraw_version_group("retired", &group.group_id, None, index * 3 + 1)
                .await
                .unwrap();
            store.delete_sql_group(&group, index * 3 + 2).await.unwrap();
        }
        let group = super::super::tests::version_group("retired", "one-too-many", 101);
        store
            .persist_version_group(&group, MAX_RESERVATIONS * 3)
            .await
            .unwrap();
        store
            .withdraw_version_group("retired", &group.group_id, None, MAX_RESERVATIONS * 3 + 1)
            .await
            .unwrap();
        let revision = store.state_revision().await.unwrap();
        assert!(
            store
                .delete_sql_group(&group, MAX_RESERVATIONS * 3 + 2)
                .await
                .is_err()
        );
        assert_eq!(store.state_revision().await.unwrap(), revision);
        assert_eq!(store.recover_reader_bookkeeping().await.unwrap(), 0);
        assert!(
            store
                .delete_sql_group(&group, MAX_RESERVATIONS * 3 + 2)
                .await
                .is_err()
        );
        assert!(
            store
                .check_unmanaged_admission("default", "artifact.bin")
                .await
                .is_err()
        );
        let tombstones: i64 = sqlx::query_scalar(store.coordination_sql(
            "SELECT CAST(COUNT(*) AS BIGINT) FROM tempest_group_tombstones",
            "SELECT CAST(COUNT(*) AS SIGNED) FROM tempest_group_tombstones",
        ))
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(tombstones, MAX_RESERVATIONS);

        let router = crate::api::api_router(state);
        for (path, expected) in [
            ("unmanaged", b"compatible bytes".as_slice()),
            ("boot/kernel", b"managed bytes".as_slice()),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/v1/artifacts/{path}"))
                        .header("authorization", format!("Bearer {}", "ab".repeat(32)))
                        .extension(ConnectInfo(
                            "127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap(),
                        ))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(
                &to_bytes(response.into_body(), 8192).await.unwrap()[..],
                expected
            );
        }
        // Finish asynchronous reader cleanup before fixture teardown drops the
        // database; MySQL would otherwise block DROP behind in-flight cleanup.
        let drained = tokio::time::timeout(
            Duration::from_secs(10),
            store.reader_budget.clone().acquire_many_owned(4096),
        )
        .await
        .unwrap()
        .unwrap();
        drop(drained);
    })
    .await;
}

#[tokio::test]
async fn sql_delete_error_rolls_back_reservation_tombstone_and_revisions() {
    with_fixture(|store, peer, identity| async move {
        store.ensure_serving_admission(true).await.unwrap();
        let group = store.load_version_groups().await.unwrap().remove(0).0;
        let revision = store.version_revision(&identity.profile).await.unwrap();
        let shared = store.state_revision().await.unwrap();
        match store.dialect {
            DatabaseDialect::Postgres => {
                sqlx::query("CREATE FUNCTION refuse_group_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected delete failure'; END $$")
                    .execute(&peer.pool).await.unwrap();
                sqlx::query("CREATE TRIGGER refuse_group_delete BEFORE DELETE ON tempest_version_groups FOR EACH ROW EXECUTE FUNCTION refuse_group_delete()")
                    .execute(&peer.pool).await.unwrap();
            }
            DatabaseDialect::MySql => {
                (&peer.pool).execute("CREATE TRIGGER refuse_group_delete BEFORE DELETE ON tempest_version_groups FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'injected delete failure'")
                    .await.unwrap();
            }
        }
        // Failure occurs after reservation and tombstone inserts, not before
        // the transaction begins. None may survive a rejected durable delete.
        assert!(store.delete_sql_group(&group, revision).await.is_err());
        assert_eq!(peer.state_revision().await.unwrap(), shared);
        assert_eq!(peer.version_revision(&identity.profile).await.unwrap(), revision);
        assert_eq!(peer.load_version_groups().await.unwrap().len(), 1);
        assert!(sqlx::query("SELECT group_id FROM tempest_group_tombstones").fetch_optional(&peer.pool).await.unwrap().is_none());
        assert!(sqlx::query("SELECT operation_id FROM tempest_group_deletion_reservations").fetch_optional(&peer.pool).await.unwrap().is_none());
        peer.preview_sql_group_deletion(&group).await.unwrap();
        let drop_trigger = store.coordination_sql(
            "DROP TRIGGER refuse_group_delete ON tempest_version_groups",
            "DROP TRIGGER refuse_group_delete",
        );
        (&peer.pool).execute(drop_trigger).await.unwrap();
        store.delete_sql_group(&group, revision).await.unwrap();
        assert!(peer.load_version_groups().await.unwrap().is_empty());
    }).await;
}

#[tokio::test]
async fn offline_reader_recovery_requires_exclusion_and_preserves_deletion_fences() {
    with_fixture(|store, peer, identity| async move {
        store.ensure_serving_admission(true).await.unwrap();
        let reader = id();
        store.acquire_group_reader(&identity, &reader).await.unwrap();
        sqlx::query("UPDATE tempest_deletion_safety SET reader_tracking_exhausted = 1 WHERE id = 1")
            .execute(&store.pool).await.unwrap();
        sqlx::query(store.coordination_sql(
            "INSERT INTO tempest_group_tombstones (boot_profile, group_id, names_json) VALUES ($1, 'retired', '[]')",
            "INSERT INTO tempest_group_tombstones (boot_profile, group_id, names_json) VALUES (?, 'retired', '[]')",
        )).bind(&identity.profile).execute(&store.pool).await.unwrap();
        assert!(peer.recover_reader_bookkeeping().await.is_err());
        kill_serving_connection(&store, &peer).await;
        assert_eq!(peer.recover_reader_bookkeeping().await.unwrap(), 1);
        assert_eq!(peer.recover_reader_bookkeeping().await.unwrap(), 0);
        let readers = sqlx::query("SELECT operation_id FROM tempest_group_readers")
            .fetch_all(&peer.pool).await.unwrap();
        assert!(readers.is_empty());
        let exhausted: i32 = sqlx::query_scalar(
            "SELECT reader_tracking_exhausted FROM tempest_deletion_safety WHERE id = 1",
        ).fetch_one(&peer.pool).await.unwrap();
        assert_eq!(exhausted, 0);
        assert_reader_count(&peer, 0).await;
        let mut tx = peer.begin_coordination().await.unwrap();
        assert!(peer.reject_deleted_group(&mut tx, &identity.profile, "retired").await.is_err());
        drop(tx);
        assert!(store.acquire_group_reader(&identity, &id()).await.is_err());
        let reservation = id();
        peer.reserve_group_deletion(&identity, &reservation).await.unwrap();
    }).await;
}

#[tokio::test]
async fn offline_reader_recovery_refuses_ordinary_namespaces_and_missing_confirmation() {
    assert!(
        PersistenceStore::recover_abandoned_readers("invalid://unused", false)
            .await
            .is_err()
    );
    with_fixture(|store, peer, _| async move {
        store.ensure_serving_admission(false).await.unwrap();
        assert!(peer.recover_reader_bookkeeping().await.is_err());
    })
    .await;
}

#[tokio::test]
async fn offline_reader_recovery_preserves_releases_and_skips_startup_migrations() {
    for (exclusive, stop_owner) in [(false, false), (true, false), (true, true)] {
        with_fixture(move |store, peer, identity| async move {
            let url = fixture_database_url(&peer).await;
            store.ensure_serving_admission(exclusive).await.unwrap();
            if stop_owner {
                store.acquire_group_reader(&identity, &id()).await.unwrap();
                kill_serving_connection(&store, &peer).await;
            }
            let oversized = "x".repeat(super::super::MAX_PERSISTED_JSON_BYTES + 1);
            sqlx::query(store.coordination_sql(
                "UPDATE tempest_version_groups SET files_json = $1",
                "UPDATE tempest_version_groups SET files_json = ?",
            ))
            .bind(&oversized)
            .execute(&peer.pool)
            .await
            .unwrap();
            sqlx::query("ALTER TABLE tempest_boot_sessions DROP COLUMN boot_epoch")
                .execute(&peer.pool)
                .await
                .unwrap();
            let revision = peer.state_revision().await.unwrap();

            let recovered = PersistenceStore::recover_abandoned_readers(&url, true).await;
            if stop_owner {
                assert_eq!(recovered.unwrap(), 1);
            } else {
                assert!(recovered.is_err());
            }
            let rows = sqlx::query("SELECT files_json FROM tempest_version_groups")
                .fetch_all(&peer.pool)
                .await
                .unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(row_text(&rows[0], "files_json").unwrap(), oversized);
            assert_eq!(peer.state_revision().await.unwrap(), revision);
            assert!(!peer.boot_session_column_exists("boot_epoch").await.unwrap());

            if !exclusive {
                let restarted = PersistenceStore::connect(&url).await.unwrap();
                assert!(restarted.load_version_groups().await.unwrap().is_empty());
                assert!(
                    restarted
                        .boot_session_column_exists("boot_epoch")
                        .await
                        .unwrap()
                );
            }
        })
        .await;
    }
}

#[tokio::test]
async fn serving_probes_preserve_namespace_lock_and_fail_closed_in_both_modes() {
    for exclusive in [false, true] {
        with_fixture(move |store, peer, _| async move {
            store.ensure_serving_admission(exclusive).await.unwrap();
            if !exclusive {
                peer.ensure_serving_admission(false).await.unwrap();
                assert!(peer.ensure_serving_admission(true).await.is_err());
                store.pool.close().await;
                store.ensure_serving_admission(false).await.unwrap();
                return;
            }
            let connection = store.serving_connection_id().await;
            for _ in 0..3 {
                store.ensure_serving_admission(exclusive).await.unwrap();
                assert_eq!(store.serving_connection_id().await, connection);
                let mut contender = peer.pool.begin().await.unwrap();
                assert!(
                    sqlx::query(
                        "SELECT protocol FROM tempest_serving_namespace WHERE id = 1 FOR UPDATE NOWAIT",
                    )
                    .fetch_one(contender.executor())
                    .await
                    .is_err(),
                    "probes must not release the lifetime namespace lock",
                );
                drop(contender);
                // Normal nodes retain a shared lock, not an upgraded exclusive
                // lock; deletion-enabled nodes must exclude shared owners too.
                let mut shared = peer.pool.begin().await.unwrap();
                let admitted = sqlx::query(
                    "SELECT protocol FROM tempest_serving_namespace WHERE id = 1 FOR SHARE NOWAIT",
                )
                .fetch_one(shared.executor())
                .await
                .is_ok();
                assert_eq!(admitted, !exclusive);
            }
            kill_serving_connection(&store, &peer).await;
            assert!(store.ensure_serving_admission(exclusive).await.is_err());
            peer.ensure_serving_admission(true).await.unwrap();
            assert!(store.ensure_serving_admission(exclusive).await.is_err());
        })
        .await;
    }
}

#[tokio::test]
async fn mysql_serving_probes_do_not_establish_a_repeatable_read_snapshot() {
    for exclusive in [false, true] {
        with_fixture(move |store, peer, _| async move {
            if store.dialect != DatabaseDialect::MySql || !exclusive {
                return;
            }
            store.ensure_serving_admission(exclusive).await.unwrap();
            let connection = store.serving_connection_id().await;
            // Generation is intentionally separate from the lifetime-locked
            // namespace. Its committed change is a snapshot witness, not a
            // purge/undo-history measurement or a production generation check.
            sqlx::query(
                "UPDATE tempest_serving_generation SET generation = generation + 1 WHERE id = 1",
            )
            .execute(&peer.pool)
            .await
            .unwrap();
            let committed: i64 = sqlx::query_scalar(
                "SELECT generation FROM tempest_serving_generation WHERE id = 1",
            )
            .fetch_one(&peer.pool)
            .await
            .unwrap();
            for _ in 0..3 {
                store.ensure_serving_admission(exclusive).await.unwrap();
            }
            assert_eq!(store.serving_connection_id().await, connection);
            let (isolation, observed) = store.serving_snapshot_for_test().await;
            assert_eq!(isolation, "REPEATABLE-READ");
            assert_eq!(
                observed, committed,
                "a probe must not pin an older consistent-read snapshot",
            );
        })
        .await;
    }
}

#[tokio::test]
async fn serving_namespace_excludes_other_nodes_and_recovers_only_after_owner_stops() {
    with_fixture(|store, peer, _| async move {
        store.ensure_serving_admission(true).await.unwrap();
        // A newly connecting process must reach an explicit admission refusal,
        // not hang in idempotent migrations behind the lifetime namespace lock.
        // A lock wait would last at least InnoDB's 50-second row-lock timeout
        // (metadata-lock waits are unbounded), so this bound still detects a
        // hang while tolerating full migrations under coverage instrumentation.
        let url = fixture_database_url(&peer).await;
        let newcomer =
            tokio::time::timeout(Duration::from_secs(30), PersistenceStore::connect(&url))
                .await
                .unwrap()
                .unwrap();
        let group = super::super::tests::version_group("control-writer", "release", 2);
        newcomer.persist_version_group(&group, 0).await.unwrap();
        assert!(newcomer.ensure_serving_admission(true).await.is_err());
        assert!(peer.ensure_serving_admission(true).await.is_err());
        assert!(peer.ensure_serving_admission(false).await.is_err());
        store.stop_serving_for_test().await;
        assert!(peer.ensure_serving_admission(false).await.is_err());
        peer.ensure_serving_admission(true).await.unwrap();
        assert!(newcomer.ensure_serving_admission(false).await.is_err());
        assert!(newcomer.ensure_serving_admission(true).await.is_err());
    })
    .await;
}

#[tokio::test]
async fn sql_deletion_cas_readers_and_tombstones_are_durable() {
    with_fixture(|store, peer, identity| async move {
        let group = store.load_version_groups().await.unwrap().remove(0).0;
        let revision = store.version_revision(&identity.profile).await.unwrap();
        store.ensure_serving_admission(true).await.unwrap();
        store.preview_sql_group_deletion(&group).await.unwrap();
        let reader = store.register_reader(&pin(&identity)).await.unwrap();
        let last_owner = reader.clone();
        drop(reader);
        for refusal in [
            store.delete_sql_group(&group, revision).await,
            store.preview_sql_group_deletion(&group).await,
        ] {
            assert!(
                matches!(&refusal, Err(DeleteError::Blocked(blockers)) if blockers == &[DeleteBlocker::TransferPinned]),
                "live readers must be reported as transfer pins: {refusal:?}"
            );
        }
        drop(last_owner);
        // All permits are available only after bounded asynchronous release
        // has completed; no sleeps or schedule-dependent polling.
        let drained = tokio::time::timeout(
            Duration::from_secs(10),
            store.reader_budget.clone().acquire_many_owned(4096),
        )
        .await
        .unwrap()
        .unwrap();
        drop(drained);
        assert!(matches!(
            store.delete_sql_group(&group, revision - 1).await,
            Err(DeleteError::Stale)
        ));
        assert_eq!(
            store.version_revision(&identity.profile).await.unwrap(),
            revision
        );
        let stale = crate::features::versioning::VersionGroup {
            manifest: crate::features::versioning::BootChainManifest {
                manifest_digest: "ff".repeat(32),
                ..group.manifest.clone()
            },
            ..group.clone()
        };
        assert!(matches!(
            store.delete_sql_group(&stale, revision).await,
            Err(DeleteError::Stale)
        ));
        store.delete_sql_group(&group, revision).await.unwrap();
        assert!(peer.load_version_groups().await.unwrap().is_empty());
        let next = peer.version_revision(&identity.profile).await.unwrap();
        assert_eq!(next, revision + 1);
        assert!(peer.persist_version_group(&group, next).await.is_err());
        assert!(
            peer.rollback_version_group(&identity.profile, &identity.group, None, next, None, None)
                .await
                .is_err()
        );
        assert!(
            peer.withdraw_version_group(&identity.profile, &identity.group, None, next)
                .await
                .is_err()
        );
        assert!(peer.register_reader(&pin(&identity)).await.is_err());
        assert!(
            peer.check_unmanaged_admission(&identity.profile, "artifact.bin")
                .await
                .is_err()
        );
        assert!(
            peer.check_unmanaged_admission("other-profile", "artifact.bin")
                .await
                .is_err()
        );
        let row = sqlx::query("SELECT operation_id FROM tempest_group_deletion_reservations")
            .fetch_one(&peer.pool)
            .await
            .unwrap();
        let reservation = CoordinationId::new(&row_text(&row, "operation_id").unwrap()).unwrap();
        assert!(
            peer.release_group_deletion(&identity, &reservation)
                .await
                .is_err()
        );
        let entry = BootSessionEntry {
            trace_id: None,
            boot_profile: identity.profile.clone(),
            client_mac: None,
            serial: None,
            boot_epoch: 1,
            artifact_token_hash: None,
            pinned_boot_chain: Some(pin(&identity)),
            expires_at: Instant::now() + Duration::from_secs(300),
        };
        let ip = "192.0.2.55".parse().unwrap();
        assert!(peer.persist_boot_session(ip, &entry).await.is_err());
        assert!(peer.pin_boot_session(ip, 1, &pin(&identity)).await.is_err());
        assert_eq!(
            peer.version_revision(&identity.profile).await.unwrap(),
            next
        );
        store.stop_serving_for_test().await;
        peer.ensure_serving_admission(true).await.unwrap();
        assert!(peer.load_version_groups().await.unwrap().is_empty());
        assert!(
            peer.check_unmanaged_admission(&identity.profile, "artifact.bin")
                .await
                .is_err()
        );
    })
    .await;
}

#[tokio::test]
async fn lost_namespace_connection_never_expires_or_forgets_a_live_reader() {
    with_fixture(|store, peer, identity| async move {
        store.ensure_serving_admission(true).await.unwrap();
        let reader = store.register_reader(&pin(&identity)).await.unwrap();
        kill_serving_connection(&store, &peer).await;
        assert!(store.ensure_serving_admission(true).await.is_err());
        peer.ensure_serving_admission(true).await.unwrap();
        // A new exclusive owner is NOT authority to erase the old reader.
        let group = peer.load_version_groups().await.unwrap().remove(0).0;
        let revision = peer.version_revision(&identity.profile).await.unwrap();
        assert!(peer.delete_sql_group(&group, revision).await.is_err());
        assert!(store.ensure_serving_admission(true).await.is_err());
        let unavailable = PersistenceStore::unavailable_for_deletion_test().await;
        assert!(
            unavailable
                .release_group_reader(&identity, &reader.id_for_test())
                .await
                .is_err()
        );
        assert!(peer.preview_sql_group_deletion(&group).await.is_err());
        drop(reader);
        let drained = tokio::time::timeout(
            Duration::from_secs(10),
            store.reader_budget.clone().acquire_many_owned(4096),
        )
        .await
        .unwrap()
        .unwrap();
        drop(drained);
        peer.delete_sql_group(&group, revision).await.unwrap();
        assert!(store.ensure_serving_admission(true).await.is_err());
    })
    .await;
}

#[tokio::test]
async fn sql_http_body_and_tftp_cancellation_hold_admission_until_actual_finish() {
    with_fixture(|store, peer, _| async move {
        use axum::body::{Body, to_bytes};
        use axum::extract::ConnectInfo;
        use axum::http::{Request, StatusCode};
        use sha2::{Digest, Sha256};
        use std::sync::Arc;
        use std::sync::atomic::Ordering;
        use tower::ServiceExt;
        // Replace the primitive-only invalid-path fixture with real artifacts.
        sqlx::query("DELETE FROM tempest_version_groups").execute(&store.pool).await.unwrap();
        let root = tempfile::tempdir().unwrap();
        let artifact = root.path().join("kernel");
        std::fs::write(&artifact, b"real SQL coordinated transfer").unwrap();
        let mut config = crate::config::TempestConfig::default();
        config.server.root = root.path().to_owned();
        config.persistence.enabled = true;
        config.persistence.coordinated_deletion = true;
        config.api.api_key = Some("test-key".into());
        let store = Arc::new(store);
        let state = crate::server::TftpServer::builder(config.clone()).with_persistence(store.clone()).build().unwrap().state();
        let first = state.version_store.atomic_switch("first".into(), vec![("kernel".into(), artifact.clone())]).unwrap();
        store.persist_version_group(&first, 0).await.unwrap();
        state.sync_persistent_state().await.unwrap();
        let token = "ab".repeat(32);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let entry = BootSessionEntry {
            trace_id: None, boot_profile: "default".into(), client_mac: None, serial: None,
            boot_epoch: 1, artifact_token_hash: Some(Sha256::digest(token.as_bytes()).into()),
            pinned_boot_chain: Some(BootChainPin { boot_profile: "default".into(), group_id: first.group_id.clone(), version_id: first.version_id, manifest_digest: first.manifest.manifest_digest.clone() }),
            expires_at: Instant::now() + Duration::from_secs(300),
        };
        store.persist_boot_session(ip, &entry).await.unwrap();
        state.insert_boot_session(ip, entry.clone());
        let router = crate::api::api_router(state.clone());
        let call = |path: &str, body: serde_json::Value| Request::builder().method("POST").uri(path)
            .header("x-api-key", "test-key").header("content-type", "application/json")
            .extension(ConnectInfo("127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap()))
            .body(Body::from(body.to_string())).unwrap();
        let artifact_request = |method: &str, range: Option<&str>| {
            let mut request = Request::builder().method(method).uri("/api/v1/artifacts/kernel")
                .header("authorization", format!("Bearer {token}"))
                .extension(ConnectInfo("127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap()));
            if let Some(range) = range { request = request.header("range", range); }
            request.body(Body::empty()).unwrap()
        };
        // Full consumption, metadata-only responses and post-resolution errors
        // must all finish the durable registration, not just dropped bodies.
        let complete = router.clone().oneshot(artifact_request("GET", None)).await.unwrap();
        assert_eq!(complete.status(), StatusCode::OK);
        assert_eq!(&to_bytes(complete.into_body(), 8192).await.unwrap()[..], b"real SQL coordinated transfer");
        let head = router.clone().oneshot(artifact_request("HEAD", None)).await.unwrap();
        assert_eq!(head.status(), StatusCode::OK);
        drop(head);
        let invalid = router.clone().oneshot(artifact_request("GET", Some("bytes=999999-"))).await.unwrap();
        assert_eq!(invalid.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        drop(invalid);
        state.quarantined_files.insert("kernel".into());
        let denied = router.clone().oneshot(artifact_request("GET", None)).await.unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        drop(denied);
        state.quarantined_files.remove("kernel");
        let drained = tokio::time::timeout(Duration::from_secs(10), store.reader_budget.clone().acquire_many_owned(4096)).await.unwrap().unwrap();
        drop(drained);
        assert_eq!(state.version_store.pinned_count("kernel", first.version_id), 0);
        // A normally ACKed SQL-backed TFTP transfer releases its row as well.
        let completed_client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let completed_socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        state.active_transfers.fetch_add(1, Ordering::Relaxed);
        let completed_transfer = tokio::spawn(crate::protocol::transfer::run_read_transfer(
            completed_socket, completed_client.local_addr().unwrap(), "kernel".into(), "default".into(), None,
            crate::protocol::options::NegotiatedOptions::default(), vec![], state.clone(), uuid::Uuid::new_v4(),
        ));
        let mut completed_packet = [0; 1024];
        let (size, tid) = tokio::time::timeout(Duration::from_secs(10), completed_client.recv_from(&mut completed_packet)).await.unwrap().unwrap();
        assert_eq!(&completed_packet[..4], &[0, 3, 0, 1]);
        assert_eq!(&completed_packet[4..size], b"real SQL coordinated transfer");
        assert!(sqlx::query("SELECT operation_id FROM tempest_group_readers").fetch_optional(&peer.pool).await.unwrap().is_some());
        completed_client.send_to(&[0, 4, 0, 1], tid).await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), completed_transfer).await.unwrap().unwrap().unwrap();
        let drained = tokio::time::timeout(Duration::from_secs(10), store.reader_budget.clone().acquire_many_owned(4096)).await.unwrap().unwrap();
        drop(drained);
        let response = router.clone().oneshot(Request::builder().uri("/api/v1/artifacts/kernel")
            .header("authorization", format!("Bearer {token}"))
            .extension(ConnectInfo("127.0.0.1:12345".parse::<std::net::SocketAddr>().unwrap()))
            .body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // The API itself must reject active targets, independently of SQL tests.
        let target = serde_json::json!({"kind":"retained_group","boot_profile":"default","group_id":"first"});
        let confirmation = serde_json::json!({"target":target,"expected_identity":first.manifest.manifest_digest});
        assert_eq!(router.clone().oneshot(call("/api/v2/delete/confirm", confirmation.clone())).await.unwrap().status(), StatusCode::CONFLICT);
        // A real UDP transfer receives DATA but deliberately withholds its ACK.
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        state.active_transfers.fetch_add(1, Ordering::Relaxed);
        let transfer = tokio::spawn(crate::protocol::transfer::run_read_transfer(
            socket, client.local_addr().unwrap(), "kernel".into(), "default".into(), None,
            crate::protocol::options::NegotiatedOptions::default(), vec![], state.clone(), uuid::Uuid::new_v4(),
        ));
        let mut packet = [0; 1024];
        let (size, _) = tokio::time::timeout(Duration::from_secs(10), client.recv_from(&mut packet)).await.unwrap().unwrap();
        assert!(size > 4);
        assert_eq!(&packet[..2], &[0, 3]);
        let second = state.version_store.atomic_switch("second".into(), vec![("kernel".into(), artifact.clone())]).unwrap();
        store.persist_version_group(&second, 1).await.unwrap();
        // A remote durable pin that is absent from hot state must veto the API.
        let remote_ip: IpAddr = "192.0.2.77".parse().unwrap();
        peer.persist_boot_session(remote_ip, &entry).await.unwrap();
        // Revocation does NOT make the two actual in-flight readers disappear.
        store.delete_boot_session(ip).await.unwrap();
        let removed = state.boot_sessions.remove(&ip).unwrap().1;
        state.version_store.unpin_boot_chain(removed.pinned_boot_chain.as_ref().unwrap());
        assert!(store.preview_sql_group_deletion(&first).await.is_err());
        assert_eq!(router.clone().oneshot(call("/api/v2/delete/confirm", confirmation.clone())).await.unwrap().status(), StatusCode::CONFLICT);
        transfer.abort();
        assert!(transfer.await.unwrap_err().is_cancelled());
        assert!(store.preview_sql_group_deletion(&first).await.is_err()); // body still owns reader
        drop(response); // dropped/unpolled HTTP body must clean up too
        let drained = tokio::time::timeout(Duration::from_secs(10), store.reader_budget.clone().acquire_many_owned(4096)).await.unwrap().unwrap();
        drop(drained);
        assert_eq!(router.clone().oneshot(call("/api/v2/delete/confirm", confirmation.clone())).await.unwrap().status(), StatusCode::CONFLICT);
        peer.delete_boot_session(remote_ip).await.unwrap();
        // A durable reader registered through a different pool is also observed.
        let remote = peer.register_reader(entry.pinned_boot_chain.as_ref().unwrap()).await.unwrap();
        assert_eq!(router.clone().oneshot(call("/api/v2/delete/confirm", confirmation.clone())).await.unwrap().status(), StatusCode::CONFLICT);
        drop(remote);
        let drained = tokio::time::timeout(Duration::from_secs(10), peer.reader_budget.clone().acquire_many_owned(4096)).await.unwrap().unwrap();
        drop(drained);
        let stale_confirmation = serde_json::json!({"target":target,"expected_identity":"ff".repeat(32)});
        assert_eq!(router.clone().oneshot(call("/api/v2/delete/confirm", stale_confirmation)).await.unwrap().status(), StatusCode::CONFLICT);
        // Cancelling the real confirmation while its revision read is blocked
        // must not reserve/delete anything or advance either revision.
        let revision = store.state_revision().await.unwrap();
        let tx = peer.begin_coordination().await.unwrap();
        let request = router.clone().oneshot(call("/api/v2/delete/confirm", confirmation.clone()));
        assert!(tokio::time::timeout(Duration::from_millis(50), request).await.is_err());
        drop(tx);
        assert_eq!(store.state_revision().await.unwrap(), revision);
        assert_eq!(store.load_version_groups().await.unwrap().len(), 2);
        let preview = router.clone().oneshot(call("/api/v2/delete/preview", serde_json::json!({"target":target}))).await.unwrap();
        assert_eq!(preview.status(), StatusCode::OK);
        let value: serde_json::Value = serde_json::from_slice(&to_bytes(preview.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(value["can_delete"], true, "{value}");
        let response = router.clone().oneshot(call("/api/v2/delete/confirm", confirmation)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: serde_json::Value = serde_json::from_slice(&to_bytes(response.into_body(), 8192).await.unwrap()).unwrap();
        assert_eq!(value["bytes_deleted"], false);
        assert_eq!(store.load_version_groups().await.unwrap().len(), 1);
        assert_eq!(state.version_store.group_count(), 1);
        assert_eq!(std::fs::read(&artifact).unwrap(), b"real SQL coordinated transfer");
        assert!(peer.ensure_serving_admission(false).await.is_err());
        // Simulate post-commit/pre-publication cancellation: a second state with
        // stale metadata cannot serve it, even with an expired/revoked session.
        let stale = crate::server::TftpServer::builder(config).with_persistence(store.clone()).build().unwrap().state();
        stale.version_store.atomic_switch("first".into(), vec![("kernel".into(), artifact)]).unwrap();
        assert!(stale.resolve_file_for_boot_session(ip, "default", "kernel").await.is_err());
        assert_eq!(stale.version_store.pinned_count("kernel", first.version_id), 0);
        // Full artifact-validated reconciliation recovers stale in-memory state.
        stale.sync_persistent_state().await.unwrap();
        assert_eq!(stale.version_store.group_count(), 1);
        assert_eq!(stale.version_store.list_groups()[0].group_id, "second");
    }).await;
}

fn pin(identity: &GroupIdentity) -> BootChainPin {
    BootChainPin {
        boot_profile: identity.profile.clone(),
        group_id: identity.group.clone(),
        version_id: identity.version as u64,
        manifest_digest: identity.digest.clone(),
    }
}

async fn fixture_database_url(store: &PersistenceStore) -> String {
    let row = sqlx::query(store.coordination_sql(
        "SELECT CAST(current_database() AS TEXT) AS name",
        "SELECT DATABASE() AS name",
    ))
    .fetch_one(&store.pool)
    .await
    .unwrap();
    let mut options: sqlx::any::AnyConnectOptions = std::env::var("TEMPEST_TEST_DATABASE_URL")
        .unwrap()
        .parse()
        .unwrap();
    options
        .database_url
        .set_path(&format!("/{}", row_text(&row, "name").unwrap()));
    options.database_url.to_string()
}

/// Each test has a disposable sibling DB and TWO independent connection pools.
/// Cleanup also runs after a panic; no production/shared database may be supplied.
async fn with_fixture<F, Fut>(test: F)
where
    F: FnOnce(PersistenceStore, PersistenceStore, GroupIdentity) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some(url) = crate::persistence::test_database_url() else {
        return;
    };
    let _database_slot = crate::persistence::test_database_slot().await;
    sqlx::any::install_default_drivers();
    let admin = sqlx::AnyPool::connect(&url).await.unwrap();
    let database = format!("tempest_coord_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {database}"))
        .execute(&admin)
        .await
        .unwrap();
    let mut options: sqlx::any::AnyConnectOptions = url.parse().unwrap();
    options.database_url.set_path(&format!("/{database}"));
    let result = tokio::spawn(async move {
        let store = PersistenceStore::connect(options.database_url.as_str())
            .await
            .unwrap();
        let peer = PersistenceStore::connect(options.database_url.as_str())
            .await
            .unwrap();
        let group = super::super::tests::version_group("coordination", "release", 1);
        store.persist_version_group(&group, 0).await.unwrap();
        store
            .withdraw_version_group("coordination", "release", None, 1)
            .await
            .unwrap();
        let identity = GroupIdentity::new(&BootChainPin {
            boot_profile: group.boot_profile,
            group_id: group.group_id,
            version_id: group.version_id,
            manifest_digest: group.manifest.manifest_digest,
        })
        .unwrap();
        test(store, peer, identity).await;
    })
    .await;
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
        panic!("coordination test cancelled: {error}");
    }
}

#[test]
fn coordination_inputs_are_bounded_and_canonical() {
    for bad in [
        "",
        "reader",
        "../reader",
        &"a".repeat(33),
        &"A".repeat(32),
        &"é".repeat(16),
    ] {
        assert!(matches!(
            CoordinationId::new(bad),
            Err(CoordinationError::InvalidInput)
        ));
    }
    let valid = BootChainPin {
        boot_profile: "default".into(),
        group_id: "release-1".into(),
        version_id: 1,
        manifest_digest: "ab".repeat(32),
    };
    assert!(GroupIdentity::new(&valid).is_ok());
    for invalid in [
        BootChainPin {
            boot_profile: "../default".into(),
            ..valid.clone()
        },
        BootChainPin {
            group_id: "".into(),
            ..valid.clone()
        },
        BootChainPin {
            group_id: "g".repeat(129),
            ..valid.clone()
        },
        BootChainPin {
            group_id: "group/name".into(),
            ..valid.clone()
        },
        BootChainPin {
            manifest_digest: "AB".repeat(32),
            ..valid.clone()
        },
        BootChainPin {
            manifest_digest: "ab".repeat(31),
            ..valid.clone()
        },
        BootChainPin {
            version_id: u64::MAX,
            ..valid.clone()
        },
    ] {
        assert!(matches!(
            GroupIdentity::new(&invalid),
            Err(CoordinationError::InvalidInput)
        ));
    }
}

#[tokio::test]
async fn reader_and_reservation_retries_are_exact_and_do_not_advance_revisions() {
    with_fixture(|store, peer, identity| async move {
        let revision = store.state_revision().await.unwrap();
        let profile_revision = store.version_revision(&identity.profile).await.unwrap();
        let reader = id();
        store
            .acquire_group_reader(&identity, &reader)
            .await
            .unwrap();
        peer.acquire_group_reader(&identity, &reader).await.unwrap();
        let changed = GroupIdentity {
            digest: "ff".repeat(32),
            ..identity.clone()
        };
        assert!(matches!(
            peer.release_group_reader(&changed, &reader).await,
            Err(CoordinationError::IdConflict)
        ));
        assert!(matches!(
            peer.reserve_group_deletion(&identity, &id()).await,
            Err(CoordinationError::ReadersPresent)
        ));
        peer.release_group_reader(&identity, &reader).await.unwrap();
        store
            .release_group_reader(&identity, &reader)
            .await
            .unwrap();
        let reservation = id();
        store
            .reserve_group_deletion(&identity, &reservation)
            .await
            .unwrap();
        peer.reserve_group_deletion(&identity, &reservation)
            .await
            .unwrap();
        assert!(matches!(
            peer.reserve_group_deletion(&identity, &id()).await,
            Err(CoordinationError::Reserved)
        ));
        assert!(matches!(
            peer.acquire_group_reader(&identity, &id()).await,
            Err(CoordinationError::Reserved)
        ));
        assert!(matches!(
            peer.release_group_deletion(&changed, &reservation).await,
            Err(CoordinationError::IdConflict)
        ));
        peer.release_group_deletion(&identity, &reservation)
            .await
            .unwrap();
        store
            .release_group_deletion(&identity, &reservation)
            .await
            .unwrap();
        assert_eq!(store.state_revision().await.unwrap(), revision);
        assert_eq!(
            store.version_revision(&identity.profile).await.unwrap(),
            profile_revision
        );
        assert_eq!(store.load_version_groups().await.unwrap().len(), 1);
        let store = PersistenceStore::unavailable_for_deletion_test().await;
        assert!(matches!(
            store.acquire_group_reader(&identity, &id()).await,
            Err(CoordinationError::Persistence(_))
        ));
    })
    .await;
}

#[tokio::test]
async fn stale_and_reused_group_identities_never_admit_readers_or_reservations() {
    with_fixture(|store, peer, identity| async move {
        for changed in [
            GroupIdentity {
                profile: "missing".into(),
                ..identity.clone()
            },
            GroupIdentity {
                group: "missing".into(),
                ..identity.clone()
            },
            GroupIdentity {
                group: "RELEASE".into(),
                ..identity.clone()
            },
            GroupIdentity {
                version: 2,
                ..identity.clone()
            },
            GroupIdentity {
                digest: "ff".repeat(32),
                ..identity.clone()
            },
        ] {
            assert!(matches!(
                store.acquire_group_reader(&changed, &id()).await,
                Err(CoordinationError::IdentityChanged)
            ));
            assert!(matches!(
                peer.reserve_group_deletion(&changed, &id()).await,
                Err(CoordinationError::IdentityChanged)
            ));
        }
        // Simulate a legacy writer replacing the exact durable identity while a
        // reader waits. The current locking read must see the committed version.
        let mut tx = store.begin_coordination().await.unwrap();
        store.bump_state_revision(&mut tx).await.unwrap();
        sqlx::query("UPDATE tempest_version_groups SET version_id = 2")
            .execute(tx.executor())
            .await
            .unwrap();
        let operation = id();
        let acquire = peer.acquire_group_reader(&identity, &operation);
        tokio::pin!(acquire);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut acquire)
                .await
                .is_err()
        );
        tx.commit().await.unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(30), acquire)
                .await
                .unwrap(),
            Err(CoordinationError::IdentityChanged)
        ));
    })
    .await;
}

#[tokio::test]
async fn reader_first_serialization_blocks_reservation_after_commit() {
    with_fixture(|store, peer, identity| async move {
        let reader = id();
        let reservation = id();
        let mut tx = store.begin_coordination().await.unwrap();
        store
            .acquire_reader_in_tx(&mut tx, &identity, &reader)
            .await
            .unwrap();
        let reserve = peer.reserve_group_deletion(&identity, &reservation);
        tokio::pin!(reserve);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut reserve)
                .await
                .is_err()
        );
        tx.commit().await.unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(30), reserve)
                .await
                .unwrap(),
            Err(CoordinationError::ReadersPresent)
        ));
        peer.release_group_reader(&identity, &reader).await.unwrap();
        peer.reserve_group_deletion(&identity, &reservation)
            .await
            .unwrap();
    })
    .await;
}

#[tokio::test]
async fn reservation_first_serialization_blocks_reader_after_commit() {
    with_fixture(|store, peer, identity| async move {
        let reservation = id();
        let reader = id();
        let mut tx = store.begin_coordination().await.unwrap();
        store
            .reserve_deletion_in_tx(&mut tx, &identity, &reservation)
            .await
            .unwrap();
        let acquire = peer.acquire_group_reader(&identity, &reader);
        tokio::pin!(acquire);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), &mut acquire)
                .await
                .is_err()
        );
        tx.commit().await.unwrap();
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(30), acquire)
                .await
                .unwrap(),
            Err(CoordinationError::Reserved)
        ));
    })
    .await;
}

#[tokio::test]
async fn cancellation_rolls_back_staged_rows_and_waiting_operations() {
    with_fixture(|store, peer, identity| async move {
        let revision = store.state_revision().await.unwrap();
        for reservation in [false, true] {
            let operation = id();
            let mut tx = store.begin_coordination().await.unwrap();
            if reservation {
                store
                    .reserve_deletion_in_tx(&mut tx, &identity, &operation)
                    .await
                    .unwrap();
            } else {
                store
                    .acquire_reader_in_tx(&mut tx, &identity, &operation)
                    .await
                    .unwrap();
            }
            // Drop the future while it is awaiting the common revision lock.
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(30),
                    peer.acquire_group_reader(&identity, &id())
                )
                .await
                .is_err()
            );
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(30),
                    peer.reserve_group_deletion(&identity, &id())
                )
                .await
                .is_err()
            );
            drop(tx); // SQLx rolls back staged inserts, including on task cancellation.
            let check = id();
            peer.reserve_group_deletion(&identity, &check)
                .await
                .unwrap();
            peer.release_group_deletion(&identity, &check)
                .await
                .unwrap();
            peer.acquire_group_reader(&identity, &check).await.unwrap();
            peer.release_group_reader(&identity, &check).await.unwrap();
        }
        assert_eq!(store.state_revision().await.unwrap(), revision);
    })
    .await;
}

#[tokio::test]
async fn lock_wait_deadline_is_typed_and_does_not_leave_a_reader_or_reservation() {
    with_fixture(|store, peer, identity| async move {
        let revision = store.state_revision().await.unwrap();
        let tx = store.begin_coordination().await.unwrap();
        let reader = id();
        let reservation = id();
        // Both actual protocol deadlines expire while a durable writer holds
        // the singleton; an outer bound guards against a broken timeout wrapper.
        let (acquire, reserve) =
            tokio::time::timeout(COORDINATION_TIMEOUT + Duration::from_secs(25), async {
                tokio::join!(
                    peer.acquire_group_reader(&identity, &reader),
                    peer.reserve_group_deletion(&identity, &reservation),
                )
            })
            .await
            .unwrap();
        assert!(matches!(acquire, Err(CoordinationError::DeadlineExceeded)));
        assert!(matches!(reserve, Err(CoordinationError::DeadlineExceeded)));
        drop(tx);
        // Retry the SAME opaque IDs, not newly generated operations.
        peer.reserve_group_deletion(&identity, &reservation)
            .await
            .unwrap();
        peer.release_group_deletion(&identity, &reservation)
            .await
            .unwrap();
        peer.acquire_group_reader(&identity, &reader).await.unwrap();
        peer.release_group_reader(&identity, &reader).await.unwrap();
        assert_eq!(store.state_revision().await.unwrap(), revision);
    })
    .await;
}

#[tokio::test]
async fn active_and_live_session_checks_use_durable_state_but_readers_never_expire() {
    with_fixture(|store, peer, identity| async move {
        store
            .rollback_version_group(
                &identity.profile,
                &identity.group,
                Some(&identity.digest),
                2,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(matches!(
            peer.reserve_group_deletion(&identity, &id()).await,
            Err(CoordinationError::Active)
        ));
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        store
            .persist_boot_session(
                ip,
                &BootSessionEntry {
                    trace_id: None,
                    boot_profile: identity.profile.clone(),
                    client_mac: None,
                    serial: None,
                    boot_epoch: 1,
                    artifact_token_hash: None,
                    pinned_boot_chain: Some(pin(&identity)),
                    expires_at: Instant::now() + Duration::from_secs(300),
                },
            )
            .await
            .unwrap();
        store
            .withdraw_version_group(&identity.profile, &identity.group, None, 3)
            .await
            .unwrap();
        assert!(matches!(
            peer.reserve_group_deletion(&identity, &id()).await,
            Err(CoordinationError::LiveSession)
        ));
        let reader = id();
        store
            .acquire_group_reader(&identity, &reader)
            .await
            .unwrap();
        // Expiry/revocation is not reader completion. Even an unknown, ancient
        // reader survives; the schema deliberately has no expiry/heartbeat field.
        sqlx::query("UPDATE tempest_boot_sessions SET expires_at = '2000-01-01T00:00:00+00:00'")
            .execute(&store.pool)
            .await
            .unwrap();
        store.delete_boot_session(ip).await.unwrap();
        assert!(matches!(
            peer.reserve_group_deletion(&identity, &id()).await,
            Err(CoordinationError::ReadersPresent)
        ));
        store.migrate().await.unwrap(); // restart/migration must not reap readers
        assert!(matches!(
            peer.reserve_group_deletion(&identity, &id()).await,
            Err(CoordinationError::ReadersPresent)
        ));
        store
            .release_group_reader(&identity, &reader)
            .await
            .unwrap();
        let reservation = id();
        peer.reserve_group_deletion(&identity, &reservation)
            .await
            .unwrap();
        store.migrate().await.unwrap();
        assert!(matches!(
            store.acquire_group_reader(&identity, &id()).await,
            Err(CoordinationError::Reserved)
        ));
    })
    .await;
}

#[tokio::test]
async fn durable_caps_refuse_without_eviction_and_allow_exact_retries_and_release() {
    with_fixture(|store, peer, identity| async move {
        let reader = id();
        store.acquire_group_reader(&identity, &reader).await.unwrap();
        // Seed the durable bound efficiently; production admission is checked
        // under the same singleton lock. Unknown identities MUST count too.
        let mut tx = store.begin_coordination().await.unwrap();
        for batch in 0..16 {
            let start = batch * 256;
            // Only generated numeric hex and fixed fixture literals enter this
            // statement. Any's QueryBuilder placeholders are not portable to PG.
            let values = (start..(start + 256).min(MAX_READERS - 1))
                .map(|value| format!("('{value:032x}', 'unknown', 'unknown', 1, '{}')", "00".repeat(32)))
                .collect::<Vec<_>>().join(",");
            sqlx::query(&format!("INSERT INTO tempest_group_readers (operation_id, boot_profile, group_id, version_id, manifest_digest) VALUES {values}"))
                .execute(tx.executor()).await.unwrap();
        }
        sqlx::query("UPDATE tempest_reader_capacity SET registered_count = 4096 WHERE id = 1")
            .execute(tx.executor()).await.unwrap();
        tx.commit().await.unwrap();
        peer.acquire_group_reader(&identity, &id()).await.unwrap();
        assert!(matches!(peer.reserve_group_deletion(&identity, &id()).await, Err(CoordinationError::Capacity)));
        peer.check_unmanaged_admission("default", "unmanaged-file").await.unwrap();
        peer.acquire_group_reader(&identity, &reader).await.unwrap();
        peer.release_group_reader(&identity, &reader).await.unwrap();
        let replacement = id();
        peer.acquire_group_reader(&identity, &replacement).await.unwrap();
        peer.release_group_reader(&identity, &replacement).await.unwrap();
    }).await;
    with_fixture(|store, peer, identity| async move {
        let reservation = id();
        store
            .reserve_group_deletion(&identity, &reservation)
            .await
            .unwrap();
        let mut tx = store.begin_coordination().await.unwrap();
        for value in 0..MAX_RESERVATIONS - 1 {
            let unknown = GroupIdentity {
                group: format!("unknown-{value}"),
                ..identity.clone()
            };
            store
                .insert_coordination(&mut tx, &unknown, &id(), true)
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();
        peer.reserve_group_deletion(&identity, &reservation)
            .await
            .unwrap();
        // A second real inactive group must be refused at the durable bound.
        let other = super::super::tests::version_group("other", "release", 1);
        store.persist_version_group(&other, 0).await.unwrap();
        store
            .withdraw_version_group("other", "release", None, 1)
            .await
            .unwrap();
        let other_identity = GroupIdentity {
            profile: "other".into(),
            ..identity.clone()
        };
        assert!(matches!(
            peer.reserve_group_deletion(&other_identity, &reservation)
                .await,
            Err(CoordinationError::IdConflict)
        ));
        assert!(matches!(
            peer.reserve_group_deletion(&other_identity, &id()).await,
            Err(CoordinationError::Capacity)
        ));
        peer.release_group_deletion(&identity, &reservation)
            .await
            .unwrap();
        peer.reserve_group_deletion(&other_identity, &id())
            .await
            .unwrap();
    })
    .await;
}
