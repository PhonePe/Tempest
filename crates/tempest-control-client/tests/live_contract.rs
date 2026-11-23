// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;

use tempest_control_client::{
    ConfirmDeleteRequest, ControlClient, ControlError, CutoverPolicy, DeleteBlocker, DeleteTarget,
    DeployFile, DeployRequest, PreviewDeleteRequest, RegisterSessionRequest, RevokeSessionRequest,
    RollbackRequest, VerifyGroupRequest, WithdrawRequest,
};

const SESSION_TTL_SECONDS: u64 = 60;

#[tokio::test]
#[ignore = "requires the local server and fixtures started by make test-live"]
async fn live_tempest_contract() {
    let base_url = std::env::var("TEMPEST_TEST_BASE_URL")
        .expect("TEMPEST_TEST_BASE_URL must identify the live server");
    let artifact_path = std::env::var("TEMPEST_TEST_ARTIFACT_PATH")
        .expect("TEMPEST_TEST_ARTIFACT_PATH must identify the first fixture");
    let replacement_path = std::env::var("TEMPEST_TEST_REPLACEMENT_PATH")
        .expect("TEMPEST_TEST_REPLACEMENT_PATH must identify the replacement fixture");
    let api_key = std::env::var("TEMPEST_TEST_API_KEY").ok();
    let client = ControlClient::new(&base_url, api_key).expect("live Tempest URL must be valid");
    let unauthenticated =
        ControlClient::new(&base_url, None).expect("live Tempest URL must be valid");
    assert!(matches!(
        unauthenticated.list_versions().await,
        Err(ControlError::Api { status, .. }) if status.as_u16() == 401
    ));

    let deployed = client
        .deploy(&DeployRequest {
            boot_profile: Some("live-contract".into()),
            group_id: "contract-release-1".into(),
            files: vec![DeployFile {
                name: "contract.bin".into(),
                path: artifact_path.clone(),
            }],
            drain_timeout_ms: Some(1_000),
            cutover_policy: CutoverPolicy::PreserveSessions,
        })
        .await
        .expect("deploy request and response must match the live Tempest contract");
    assert_eq!(deployed.boot_profile, "live-contract");
    assert_eq!(deployed.group_id, "contract-release-1");
    assert_eq!(deployed.files.len(), 1);
    assert_eq!(deployed.files[0].name, "contract.bin");

    let delete_request = PreviewDeleteRequest {
        target: DeleteTarget::RetainedGroup {
            boot_profile: "live-contract".into(),
            group_id: deployed.group_id.clone(),
        },
    };
    let unauthorized_delete = unauthenticated.preview_delete(&delete_request).await;
    assert!(
        matches!(&unauthorized_delete,
            Err(ControlError::Api { status, .. }) if status.as_u16() == 401),
        "unexpected unauthenticated deletion result: {unauthorized_delete:?}"
    );
    let preview = client.preview_delete(&delete_request).await.unwrap();
    assert!(!preview.can_delete);
    assert!(preview.blockers.contains(&DeleteBlocker::ActiveRelease));
    assert_eq!(preview.expected_identity, deployed.manifest_digest);
    assert!(matches!(client.confirm_delete(&ConfirmDeleteRequest {
        target: preview.target,
        expected_identity: preview.expected_identity,
    }).await, Err(ControlError::Api { status, .. }) if status.as_u16() == 409));

    let file_preview = client
        .preview_delete(&PreviewDeleteRequest {
            target: DeleteTarget::File {
                path: "contract-v1.bin".into(),
            },
        })
        .await
        .unwrap();
    assert!(!file_preview.can_delete);
    assert!(
        file_preview
            .blockers
            .contains(&DeleteBlocker::ByteDeletionUnavailable)
    );
    assert!(
        file_preview
            .blockers
            .contains(&DeleteBlocker::RetainedReference)
    );
    assert_eq!(file_preview.referring_groups.len(), 1);
    assert_eq!(
        file_preview.referring_groups[0].manifest_digest,
        deployed.manifest_digest
    );
    assert!(matches!(client.confirm_delete(&ConfirmDeleteRequest {
        target: file_preview.target,
        expected_identity: file_preview.expected_identity,
    }).await, Err(ControlError::Api { status, message })
        if status.as_u16() == 409 && message.contains("byte_deletion_unavailable")));

    let versions = client
        .list_versions()
        .await
        .expect("active versions must match the typed client contract");
    let groups = client
        .list_groups()
        .await
        .expect("version groups must match the typed client contract");
    assert!(versions.items.iter().any(|version| {
        version.boot_profile == "live-contract" && version.name == "contract.bin"
    }));
    assert!(groups.items.iter().any(|group| {
        group.boot_profile == "live-contract"
            && group.group_id == "contract-release-1"
            && group.files.len() == 1
    }));
    let snapshot = client
        .release_snapshot()
        .await
        .expect("coherent release snapshot must match the live Tempest contract");
    assert!(snapshot.versions.iter().any(|version| {
        version.boot_profile == "live-contract" && version.version_id == deployed.version_id
    }));
    assert!(snapshot.active_groups.iter().any(|group| {
        group.boot_profile == "live-contract"
            && group.group_id == deployed.group_id
            && group.manifest_digest == deployed.manifest_digest
    }));
    assert!(
        client
            .verify_group(&VerifyGroupRequest {
                boot_profile: "live-contract".into(),
                group_id: "contract-release-1".into(),
                manifest_digest: deployed.manifest_digest.clone(),
                files: vec!["contract.bin".into()],
            })
            .await
            .expect("server-side release verification must match the live Tempest contract")
            .verified
    );

    let session = client
        .register_session(&RegisterSessionRequest {
            client_ip: "192.0.2.42".parse::<IpAddr>().unwrap(),
            trace_id: Some("live-contract-test".into()),
            boot_profile: Some("live-contract".into()),
            client_mac: None,
            serial: None,
            ttl_seconds: Some(SESSION_TTL_SECONDS),
            new_epoch: true,
            require_managed: true,
        })
        .await
        .expect("session request must match the live Tempest contract");
    assert_eq!(session.artifact_token.len(), 64);
    assert!(!session.expires_at.is_empty());
    assert!(session.boot_epoch > 0);
    assert_eq!(session.boot_profile, "live-contract");
    assert_eq!(
        session.manifest_digest.as_deref(),
        Some(deployed.manifest_digest.as_str())
    );

    let profile_conflict = client
        .register_session(&RegisterSessionRequest {
            client_ip: "192.0.2.42".parse::<IpAddr>().unwrap(),
            trace_id: Some("live-contract-conflict".into()),
            boot_profile: Some("default".into()),
            client_mac: None,
            serial: None,
            ttl_seconds: Some(SESSION_TTL_SECONDS),
            new_epoch: false,
            require_managed: true,
        })
        .await;
    assert!(matches!(
        profile_conflict,
        Err(ControlError::Api { status, .. }) if status.as_u16() == 409
    ));

    let capacity_response = client
        .register_session(&RegisterSessionRequest {
            client_ip: "192.0.2.43".parse::<IpAddr>().unwrap(),
            trace_id: Some("live-contract-capacity".into()),
            boot_profile: Some("live-contract".into()),
            client_mac: None,
            serial: None,
            ttl_seconds: Some(SESSION_TTL_SECONDS),
            new_epoch: true,
            require_managed: true,
        })
        .await;
    assert!(matches!(
        capacity_response,
        Err(ControlError::Api { status, .. }) if status.as_u16() == 429
    ));

    let replacement = client
        .deploy(&DeployRequest {
            boot_profile: Some("live-contract".into()),
            group_id: "contract-release-2".into(),
            files: vec![DeployFile {
                name: "contract.bin".into(),
                path: replacement_path,
            }],
            drain_timeout_ms: Some(1_000),
            cutover_policy: CutoverPolicy::PreserveSessions,
        })
        .await
        .expect("second release must activate while preserving the pinned session");
    assert!(replacement.version_id > deployed.version_id);
    assert!(
        client
            .list_versions()
            .await
            .unwrap()
            .items
            .iter()
            .any(|version| version.version_id == replacement.version_id)
    );

    let first_group_page = client
        .list_groups_page(None, 1)
        .await
        .expect("first group page must match the live Tempest contract");
    assert_eq!(first_group_page.items.len(), 1);
    let cursor = first_group_page
        .next_cursor
        .as_deref()
        .expect("two deployed groups must produce a continuation cursor");
    let second_group_page = client
        .list_groups_page(Some(cursor), 1)
        .await
        .expect("continuation cursor must match the live Tempest contract");
    assert_eq!(second_group_page.items.len(), 1);
    assert_ne!(
        first_group_page.items[0].version_id,
        second_group_page.items[0].version_id
    );

    let original = std::fs::read(&artifact_path).expect("contract artifact must remain readable");
    std::fs::write(&artifact_path, b"corrupt rollback fixture")
        .expect("contract artifact must be writable for rollback validation");
    let corrupt_rollback = client
        .rollback(&RollbackRequest {
            boot_profile: Some("live-contract".into()),
            group_id: "contract-release-1".into(),
            manifest_digest: Some(deployed.manifest_digest.clone()),
            expected_active_group: Some("contract-release-2".into()),
            expected_active_manifest_digest: Some(replacement.manifest_digest.clone()),
        })
        .await;
    std::fs::write(&artifact_path, original).expect("contract artifact must be restored");
    assert!(
        matches!(
            &corrupt_rollback,
            Err(ControlError::Api { status, .. }) if status.as_u16() == 500
        ),
        "unexpected corrupt rollback result: {corrupt_rollback:?}"
    );
    assert!(
        client
            .list_versions()
            .await
            .unwrap()
            .items
            .iter()
            .any(|version| version.version_id == replacement.version_id),
        "failed verification must not change the active release"
    );

    client
        .rollback(&RollbackRequest {
            boot_profile: Some("live-contract".into()),
            group_id: "contract-release-1".into(),
            manifest_digest: Some(deployed.manifest_digest.clone()),
            expected_active_group: Some("contract-release-2".into()),
            expected_active_manifest_digest: Some(replacement.manifest_digest.clone()),
        })
        .await
        .expect("rollback request must match the live Tempest contract");
    assert!(
        client
            .list_versions()
            .await
            .unwrap()
            .items
            .iter()
            .any(|version| version.version_id == deployed.version_id)
    );

    let ip = "192.0.2.42".parse::<IpAddr>().unwrap();
    let stale = client
        .revoke_session(
            ip,
            &RevokeSessionRequest {
                artifact_token: "f".repeat(64),
            },
        )
        .await;
    assert!(matches!(stale, Err(ControlError::Api { status, .. }) if status.as_u16() == 409));
    let proof = RevokeSessionRequest {
        artifact_token: session.artifact_token,
    };
    client
        .revoke_session(ip, &proof)
        .await
        .expect("matching session must be revoked");
    client
        .revoke_session(ip, &proof)
        .await
        .expect("revocation must be idempotent");

    client
        .withdraw(&WithdrawRequest {
            boot_profile: Some("live-contract".into()),
            group_id: "contract-release-1".into(),
            manifest_digest: Some(deployed.manifest_digest.clone()),
        })
        .await
        .expect("withdraw request must match the live Tempest contract");
    let preview = client.preview_delete(&delete_request).await.unwrap();
    assert!(preview.can_delete);
    assert!(matches!(client.confirm_delete(&ConfirmDeleteRequest {
        target: preview.target.clone(),
        expected_identity: "0".repeat(64),
    }).await, Err(ControlError::Api { status, message })
        if status.as_u16() == 409 && message.contains("identity changed")));
    let deleted = client
        .confirm_delete(&ConfirmDeleteRequest {
            target: preview.target,
            expected_identity: preview.expected_identity,
        })
        .await
        .unwrap();
    assert!(!deleted.bytes_deleted);
    assert_eq!(deleted.expected_identity, deployed.manifest_digest);
    assert!(matches!(client.confirm_delete(&ConfirmDeleteRequest {
        target: deleted.deleted,
        expected_identity: deleted.expected_identity,
    }).await, Err(ControlError::Api { status, .. }) if status.as_u16() == 404));
    assert!(std::path::Path::new(&artifact_path).is_file());
    let last_owner = client
        .preview_delete(&PreviewDeleteRequest {
            target: DeleteTarget::RetainedGroup {
                boot_profile: "live-contract".into(),
                group_id: "contract-release-2".into(),
            },
        })
        .await
        .unwrap();
    assert!(!last_owner.can_delete);
    assert!(
        last_owner
            .blockers
            .contains(&DeleteBlocker::OwnershipFenceRequired)
    );
    assert!(matches!(client.confirm_delete(&ConfirmDeleteRequest {
        target: last_owner.target,
        expected_identity: last_owner.expected_identity,
    }).await, Err(ControlError::Api { status, message })
        if status.as_u16() == 409 && message.contains("ownership_fence_required")));
    assert!(
        client
            .release_snapshot()
            .await
            .unwrap()
            .groups
            .iter()
            .all(|group| { group.group_id != deployed.group_id })
    );
    assert!(
        client
            .list_versions()
            .await
            .unwrap()
            .items
            .iter()
            .all(|version| version.boot_profile != "live-contract")
    );
}
