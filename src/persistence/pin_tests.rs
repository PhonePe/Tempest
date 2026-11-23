// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Durable first-pin prerequisites for any future coordinated SQL deletion.

use super::*;

async fn with_fixture<F, Fut>(test: F)
where
    F: FnOnce(PersistenceStore, IpAddr, BootChainPin) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let Some(url) = crate::persistence::test_database_url() else {
        return;
    };
    let _database_slot = crate::persistence::test_database_slot().await;
    sqlx::any::install_default_drivers();
    let admin = sqlx::AnyPool::connect(&url).await.unwrap();
    let database = format!("tempest_pin_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {database}"))
        .execute(&admin)
        .await
        .unwrap();
    let mut options: sqlx::any::AnyConnectOptions = url.parse().unwrap();
    options.database_url.set_path(&format!("/{database}"));
    let result = tokio::spawn(async move {
        let (store, ip, pin) = fixture(options.database_url.as_str()).await;
        test(store, ip, pin).await;
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
        panic!("pin test task cancelled: {error}");
    }
}

async fn fixture(url: &str) -> (PersistenceStore, IpAddr, BootChainPin) {
    let store = PersistenceStore::connect(url).await.unwrap();
    let profile = format!("pin-{}", uuid::Uuid::new_v4());
    let group = super::tests::version_group(&profile, "release", 1);
    store.persist_version_group(&group, 0).await.unwrap();
    let ip = IpAddr::V6(std::net::Ipv6Addr::from(uuid::Uuid::new_v4().as_u128()));
    store
        .persist_boot_session(
            ip,
            &BootSessionEntry {
                trace_id: None,
                boot_profile: profile.clone(),
                client_mac: None,
                serial: None,
                boot_epoch: 2,
                artifact_token_hash: None,
                pinned_boot_chain: None,
                expires_at: Instant::now() + Duration::from_secs(300),
            },
        )
        .await
        .unwrap();
    (
        store,
        ip,
        BootChainPin {
            boot_profile: profile,
            group_id: group.group_id,
            version_id: group.version_id,
            manifest_digest: group.manifest.manifest_digest,
        },
    )
}

#[tokio::test]
async fn first_pin_requires_exact_active_release_and_rolls_back_rejections() {
    with_fixture(|store, ip, pin| async move {
        let revision = store.state_revision().await.unwrap();
        for candidate in [
            BootChainPin {
                group_id: "missing".into(),
                ..pin.clone()
            },
            BootChainPin {
                manifest_digest: "ff".repeat(32),
                ..pin.clone()
            },
            BootChainPin {
                version_id: 2,
                ..pin.clone()
            },
            BootChainPin {
                boot_profile: "missing-profile".into(),
                ..pin.clone()
            },
        ] {
            assert!(!store.pin_boot_session(ip, 2, &candidate).await.unwrap());
            assert_eq!(store.state_revision().await.unwrap(), revision);
        }
        assert!(!store.pin_boot_session(ip, 1, &pin).await.unwrap());
        assert!(store.pin_boot_session(ip, 2, &pin).await.unwrap());
        assert_eq!(store.state_revision().await.unwrap(), revision + 1);
        assert!(!store.pin_boot_session(ip, 2, &pin).await.unwrap());
        assert_eq!(store.state_revision().await.unwrap(), revision + 1);
        store.delete_boot_session(ip).await.unwrap();
        assert!(!store.pin_boot_session(ip, 2, &pin).await.unwrap());
    })
    .await;
}

#[tokio::test]
async fn first_pin_rejects_expired_session_and_out_of_range_version() {
    with_fixture(|store, ip, pin| async move {
        let invalid = BootChainPin {
            version_id: u64::MAX,
            ..pin.clone()
        };
        assert!(matches!(
            store.pin_boot_session(ip, 2, &invalid).await,
            Err(TempestError::Persistence(_))
        ));
        let sql = match store.dialect {
            DatabaseDialect::Postgres => {
                "UPDATE tempest_boot_sessions SET expires_at = $1 WHERE client_ip = $2"
            }
            DatabaseDialect::MySql => {
                "UPDATE tempest_boot_sessions SET expires_at = ? WHERE client_ip = ?"
            }
        };
        sqlx::query(sql)
            .bind(crate::timestamp::to_rfc3339(
                jiff::Timestamp::now() - Duration::from_secs(1),
            ))
            .bind(ip.to_string())
            .execute(&store.pool)
            .await
            .unwrap();
        let revision = store.state_revision().await.unwrap();
        assert!(!store.pin_boot_session(ip, 2, &pin).await.unwrap());
        assert_eq!(store.state_revision().await.unwrap(), revision);
        store.delete_boot_session(ip).await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn first_pin_waits_for_durable_writer_and_rejects_withdrawn_snapshot() {
    with_fixture(|store, ip, pin| async move {
        let revision = store.state_revision().await.unwrap();
        let mut tx = store.pool.begin().await.unwrap();
        store.bump_state_revision(&mut tx).await.unwrap();
        store
            .deactivate_groups_in_tx(&mut tx, &pin.boot_profile)
            .await
            .unwrap();
        let claim = store.pin_boot_session(ip, 2, &pin);
        tokio::pin!(claim);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut claim)
                .await
                .is_err()
        );
        tx.commit().await.unwrap();
        assert!(
            !tokio::time::timeout(Duration::from_secs(5), claim)
                .await
                .unwrap()
                .unwrap()
        );
        assert_eq!(store.state_revision().await.unwrap(), revision + 1);
        store.delete_boot_session(ip).await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn cancelling_waiting_first_pin_does_not_publish_or_advance_revision() {
    with_fixture(|store, ip, pin| async move {
        let revision = store.state_revision().await.unwrap();
        let mut tx = store.pool.begin().await.unwrap();
        store.lock_state_revision(&mut tx).await.unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                store.pin_boot_session(ip, 2, &pin)
            )
            .await
            .is_err()
        );
        drop(tx);
        assert_eq!(store.state_revision().await.unwrap(), revision);
        assert!(store.pin_boot_session(ip, 2, &pin).await.unwrap());
        store.delete_boot_session(ip).await.unwrap();
    })
    .await;
}
