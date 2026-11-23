// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use axum::body::to_bytes;
use serde_json::{Value, json};

fn fixture() -> (tempfile::TempDir, Arc<ServerState>, VersionGroup) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kernel");
    std::fs::write(&path, b"kernel").unwrap();
    let mut config = crate::config::TempestConfig::default();
    config.server.root = dir.path().to_path_buf();
    let state = crate::server::TftpServer::new(config).state();
    let group = state
        .version_store
        .atomic_switch("release".into(), vec![("kernel".into(), path)])
        .unwrap();
    state
        .version_store
        .atomic_switch(
            "keeper".into(),
            vec![("kernel".into(), dir.path().join("kernel"))],
        )
        .unwrap();
    state.version_store.rollback("release").unwrap();
    (dir, state, group)
}

fn target() -> DeleteTarget {
    DeleteTarget::RetainedGroup {
        boot_profile: "default".into(),
        group_id: "release".into(),
    }
}

async fn json_body(response: Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap()).unwrap()
}

async fn confirm(state: Arc<ServerState>, identity: &str) -> Response {
    confirm_delete(
        State(state),
        Json(ConfirmDeleteRequest {
            target: target(),
            expected_identity: identity.into(),
        }),
    )
    .await
}

#[tokio::test]
async fn deletion_flag_without_attached_sql_fails_closed_for_custom_state() {
    let (_dir, state, group) = fixture();
    state.version_store.withdraw_profile("default").unwrap();
    let mut state = Arc::try_unwrap(state).unwrap_or_else(|_| panic!("fixture has a live owner"));
    Arc::make_mut(&mut state.config)
        .persistence
        .coordinated_deletion = true;
    Arc::make_mut(&mut state.config).api.api_key = Some("test-key-at-least-sixteen".into());
    let state = Arc::new(state);
    let preview = build_preview(state.clone(), target()).await.unwrap();
    assert!(!preview.can_delete);
    assert!(
        preview
            .blockers
            .contains(&DeleteBlocker::PersistenceCoordinationUnavailable)
    );
    assert_eq!(
        confirm(state.clone(), &group.manifest.manifest_digest)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert!(state.sync_persistent_state().await.is_err());
    assert!(
        state
            .resolve_file_for_boot_session("127.0.0.1".parse().unwrap(), "default", "kernel")
            .await
            .is_err()
    );
    assert_eq!(state.version_store.group_count(), 2);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let error = crate::api::run_http_server_on(state, listener)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("attached SQL store"), "{error}");
}

#[tokio::test]
async fn deletion_revalidates_active_pins_stale_and_missing_without_deleting_bytes() {
    let (dir, state, group) = fixture();
    let digest = &group.manifest.manifest_digest;
    let preview = build_preview(state.clone(), target()).await.unwrap();
    assert!(!preview.can_delete);
    assert!(preview.blockers.contains(&DeleteBlocker::ActiveRelease));
    assert_eq!(
        confirm(state.clone(), digest).await.status(),
        StatusCode::CONFLICT
    );
    let resolved = state
        .version_store
        .resolve_file_for_transfer("kernel", dir.path())
        .unwrap();
    let pin = resolved.boot_chain.unwrap();
    state.version_store.withdraw_profile("default").unwrap();
    assert_eq!(
        confirm(state.clone(), digest).await.status(),
        StatusCode::CONFLICT
    );
    state
        .version_store
        .unpin_version("kernel", group.version_id);
    let preview = build_preview(state.clone(), target()).await.unwrap();
    assert!(preview.can_delete);
    // A new session pin after preview must veto confirmation.
    state.version_store.pin_boot_chain(&pin);
    let response = json_body(confirm(state.clone(), digest).await).await;
    assert_eq!(response["blockers"], json!(["boot_session_pinned"]));
    state.version_store.unpin_boot_chain(&pin);
    assert_eq!(
        confirm(state.clone(), &"0".repeat(64)).await.status(),
        StatusCode::CONFLICT
    );
    state.version_store.rollback("release").unwrap();
    assert_eq!(
        confirm(state.clone(), digest).await.status(),
        StatusCode::CONFLICT
    );
    state.version_store.withdraw_profile("default").unwrap();
    let response = confirm(state.clone(), digest).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json_body(response).await["bytes_deleted"], false);
    assert_eq!(state.version_store.list_groups().len(), 1);
    assert_eq!(std::fs::read(dir.path().join("kernel")).unwrap(), b"kernel");
    assert_eq!(confirm(state, digest).await.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn deletion_file_preview_is_bounded_confined_and_never_unlinks() {
    let (dir, state, _) = fixture();
    let file = DeleteTarget::File {
        path: "kernel".into(),
    };
    let preview = build_preview(state.clone(), file.clone()).await.unwrap();
    assert!(!preview.can_delete);
    assert_eq!(preview.referring_groups.len(), 2);
    assert!(preview.blockers.contains(&DeleteBlocker::RetainedReference));
    let response = confirm_delete(
        State(state.clone()),
        Json(ConfirmDeleteRequest {
            target: file.clone(),
            expected_identity: preview.expected_identity.clone(),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    std::fs::write(dir.path().join("kernel"), b"changed").unwrap();
    let response = confirm_delete(
        State(state.clone()),
        Json(ConfirmDeleteRequest {
            target: file.clone(),
            expected_identity: preview.expected_identity,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let permits = state
        .artifact_hash_budget
        .clone()
        .acquire_many_owned(4)
        .await
        .unwrap();
    assert_eq!(
        build_preview(state.clone(), file)
            .await
            .err()
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop(permits);
    for path in ["../kernel", "/etc/passwd", "", "a\\b"] {
        let response = preview_delete(
            State(state.clone()),
            Json(PreviewDeleteRequest {
                target: DeleteTarget::File { path: path.into() },
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    assert_eq!(
        build_preview(
            state.clone(),
            DeleteTarget::File {
                path: "missing".into()
            }
        )
        .await
        .err()
        .unwrap()
        .status(),
        StatusCode::NOT_FOUND
    );
    #[cfg(unix)]
    {
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();
        assert!(
            build_preview(
                state,
                DeleteTarget::File {
                    path: "escape".into()
                }
            )
            .await
            .is_err()
        );
        assert!(outside.path().exists());
    }
}

#[tokio::test]
async fn deletion_busy_control_lock_fails_closed() {
    let (_dir, state, group) = fixture();
    state.version_store.withdraw_profile("default").unwrap();
    let guard = state.control_plane_lock.lock().await;
    assert_eq!(
        confirm(state.clone(), &group.manifest.manifest_digest)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    drop(guard);
    assert_eq!(state.version_store.group_count(), 2);
}

#[tokio::test]
async fn deletion_rechecks_historical_transfer_and_prepared_rollback() {
    let (dir, state, group) = fixture();
    let pin = state
        .version_store
        .active_boot_chain_for_profile("default")
        .unwrap()
        .unwrap();
    state.version_store.withdraw_profile("default").unwrap();
    let preview = build_preview(state.clone(), target()).await.unwrap();
    assert!(preview.can_delete);
    let root = state.artifact_root().unwrap();
    let rollback = state
        .version_store
        .prepare_rollback_for_profile(
            &root,
            "default",
            "release",
            Some(&preview.expected_identity),
        )
        .unwrap();
    let resolved = state
        .version_store
        .resolve_file_for_transfer_in_boot_chain(&pin, "kernel", dir.path())
        .unwrap();
    let response = json_body(confirm(state.clone(), &preview.expected_identity).await).await;
    assert_eq!(response["blockers"], json!(["transfer_pinned"]));
    state
        .version_store
        .unpin_version("kernel", group.version_id);
    assert_eq!(
        confirm(state.clone(), &preview.expected_identity)
            .await
            .status(),
        StatusCode::OK
    );
    assert!(
        state
            .version_store
            .reserve_verified_rollback(rollback)
            .is_err()
    );
    assert!(!state.version_store.cutover_in_progress("default"));
    assert!(
        state
            .version_store
            .resolve_file_for_transfer_in_boot_chain(&pin, "kernel", dir.path())
            .is_err()
    );
    assert!(resolved.path.is_file());
}

#[tokio::test]
async fn deletion_preserves_other_profiles_and_history_ownership() {
    let (dir, state, group) = fixture();
    let other = state
        .version_store
        .atomic_switch_for_profile(
            "other".into(),
            "release".into(),
            vec![("kernel".into(), dir.path().join("kernel"))],
        )
        .unwrap();
    state.version_store.withdraw_profile("default").unwrap();
    // The old identity must not authorize deleting the same group ID in another profile.
    let response = confirm_delete(
        State(state.clone()),
        Json(ConfirmDeleteRequest {
            target: DeleteTarget::RetainedGroup {
                boot_profile: "other".into(),
                group_id: "release".into(),
            },
            expected_identity: group.manifest.manifest_digest.clone(),
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert!(
        state
            .version_store
            .resolve_file_for_transfer("kernel", dir.path())
            .is_err()
    );
    assert_eq!(
        confirm(state.clone(), &group.manifest.manifest_digest)
            .await
            .status(),
        StatusCode::OK
    );
    let snapshot = state.version_store.release_snapshot().unwrap();
    assert_eq!(snapshot.groups.len(), 2);
    assert!(
        snapshot
            .groups
            .iter()
            .any(|g| g.manifest.manifest_digest == other.manifest.manifest_digest)
    );
    // Deletion must not restore even authenticated unmanaged HTTP fallback.
    assert!(
        state
            .version_store
            .resolve_file_for_transfer("kernel", dir.path())
            .is_err()
    );
    assert!(
        state
            .version_store
            .resolve_managed_file_for_transfer_in_profile("default", "kernel", dir.path())
            .is_err()
    );
}

#[tokio::test]
async fn deletion_rechecks_last_managed_owner_after_preview() {
    let (dir, state, group) = fixture();
    state.version_store.withdraw_profile("default").unwrap();
    let preview = build_preview(state.clone(), target()).await.unwrap();
    assert!(preview.can_delete);
    let keeper = state
        .version_store
        .list_groups()
        .into_iter()
        .find(|g| g.group_id == "keeper")
        .unwrap();
    let response = confirm_delete(
        State(state.clone()),
        Json(ConfirmDeleteRequest {
            target: DeleteTarget::RetainedGroup {
                boot_profile: "default".into(),
                group_id: "keeper".into(),
            },
            expected_identity: keeper.manifest.manifest_digest,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    let response = json_body(confirm(state.clone(), &group.manifest.manifest_digest).await).await;
    assert_eq!(response["blockers"], json!(["ownership_fence_required"]));
    assert!(
        !build_preview(state.clone(), target())
            .await
            .unwrap()
            .can_delete
    );
    assert!(
        state
            .version_store
            .resolve_file_for_transfer("kernel", dir.path())
            .is_err()
    );
    assert_eq!(state.version_store.group_count(), 1);
}

#[tokio::test]
async fn deletion_missing_reference_never_becomes_permission_to_delete() {
    let (dir, state, _) = fixture();
    std::fs::write(dir.path().join("unmanaged"), b"raw").unwrap();
    std::fs::remove_file(dir.path().join("kernel")).unwrap();
    let preview = build_preview(
        state.clone(),
        DeleteTarget::File {
            path: "unmanaged".into(),
        },
    )
    .await
    .unwrap();
    assert!(!preview.can_delete);
    assert!(preview.referring_groups.is_empty());
    assert!(
        preview
            .blockers
            .contains(&DeleteBlocker::ReferenceCheckIncomplete)
    );
    let response = confirm_delete(
        State(state),
        Json(ConfirmDeleteRequest {
            target: preview.target,
            expected_identity: preview.expected_identity,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(std::fs::read(dir.path().join("unmanaged")).unwrap(), b"raw");
}

#[cfg(feature = "sql-persistence")]
#[tokio::test]
async fn deletion_unavailable_persistence_never_falls_back_to_memory() {
    let (dir, _, _) = fixture();
    let mut config = crate::config::TempestConfig::default();
    config.server.root = dir.path().to_path_buf();
    let persistence =
        Arc::new(crate::persistence::PersistenceStore::unavailable_for_deletion_test().await);
    let state = crate::server::TftpServer::builder(config)
        .with_persistence(persistence)
        .build()
        .unwrap()
        .state();
    let group = state
        .version_store
        .atomic_switch(
            "release".into(),
            vec![("kernel".into(), dir.path().join("kernel"))],
        )
        .unwrap();
    state.version_store.withdraw_profile("default").unwrap();
    let preview = build_preview(state.clone(), target()).await.unwrap();
    assert!(
        preview
            .blockers
            .contains(&DeleteBlocker::PersistenceCoordinationUnavailable)
    );
    let response = confirm(state.clone(), &group.manifest.manifest_digest).await;
    assert_eq!(response.status(), StatusCode::CONFLICT);
    assert_eq!(state.version_store.group_count(), 1);
    assert!(dir.path().join("kernel").exists());
}

#[tokio::test]
async fn deletion_changed_group_identity_and_cutover_are_rejected() {
    let (dir, state, original) = fixture();
    state.version_store.withdraw_profile("default").unwrap();
    let preview = build_preview(state.clone(), target()).await.unwrap();
    let reserved = state
        .version_store
        .prepare_drain_gated_group_for_profile(
            "default".into(),
            "next".into(),
            vec![("kernel".into(), dir.path().join("kernel"))],
            std::time::Duration::from_millis(10),
            false,
        )
        .await
        .unwrap();
    let response = json_body(confirm(state.clone(), &preview.expected_identity).await).await;
    assert_eq!(response["blockers"], json!(["cutover_in_progress"]));
    state
        .version_store
        .abort_prepared_group("default", &reserved.group_id);
    assert_eq!(
        confirm(state.clone(), &preview.expected_identity)
            .await
            .status(),
        StatusCode::OK
    );
    state
        .version_store
        .atomic_switch(
            "release".into(),
            vec![("kernel".into(), dir.path().join("kernel"))],
        )
        .unwrap();
    state.version_store.withdraw_profile("default").unwrap();
    assert_eq!(
        confirm(state.clone(), &original.manifest.manifest_digest)
            .await
            .status(),
        StatusCode::CONFLICT
    );
    assert_eq!(state.version_store.group_count(), 2);
}

#[tokio::test]
async fn deletion_file_aliases_unmanaged_limits_and_special_files_fail_closed() {
    let (dir, state, _) = fixture();
    std::fs::hard_link(dir.path().join("kernel"), dir.path().join("alias")).unwrap();
    let preview = build_preview(
        state.clone(),
        DeleteTarget::File {
            path: "alias".into(),
        },
    )
    .await
    .unwrap();
    assert_eq!(preview.referring_groups.len(), 2);
    std::fs::write(dir.path().join("unmanaged"), b"raw").unwrap();
    let file = DeleteTarget::File {
        path: "unmanaged".into(),
    };
    let preview = build_preview(state.clone(), file.clone()).await.unwrap();
    assert!(!preview.can_delete);
    assert!(preview.referring_groups.is_empty());
    assert_eq!(
        confirm_delete(
            State(state.clone()),
            Json(ConfirmDeleteRequest {
                target: file,
                expected_identity: preview.expected_identity,
            })
        )
        .await
        .status(),
        StatusCode::CONFLICT
    );
    let huge = std::fs::File::create(dir.path().join("huge")).unwrap();
    huge.set_len(4 * 1024 * 1024 * 1024 + 1).unwrap();
    assert_eq!(
        build_preview(
            state.clone(),
            DeleteTarget::File {
                path: "huge".into()
            }
        )
        .await
        .err()
        .unwrap()
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    #[cfg(unix)]
    {
        assert!(
            std::process::Command::new("mkfifo")
                .arg(dir.path().join("fifo"))
                .status()
                .unwrap()
                .success()
        );
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            build_preview(
                state,
                DeleteTarget::File {
                    path: "fifo".into(),
                },
            ),
        )
        .await
        .unwrap();
        assert_eq!(result.err().unwrap().status(), StatusCode::BAD_REQUEST);
    }
}
