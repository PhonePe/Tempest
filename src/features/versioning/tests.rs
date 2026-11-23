// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn legacy_manifest_timestamp_keeps_digest_and_signature_valid() {
    let payload = br#"{"boot_profile":"default","group_id":"legacy","version_id":7,"created_at":"2026-11-17T12:34:56.123450+00:00","artifacts":[]}"#;
    let key = SigningKey::from_bytes(&[7; 32]);
    let manifest = BootChainManifest {
        boot_profile: "default".into(),
        group_id: "legacy".into(),
        version_id: 7,
        created_at: "2026-11-17T12:34:56.123450Z".parse().unwrap(),
        artifacts: Vec::new(),
        manifest_digest: hex::encode(Sha256::digest(payload)),
        signature: Some(hex::encode(key.sign(payload).to_bytes())),
    };
    assert_eq!(manifest.signed_bytes().unwrap(), payload);
    assert!(manifest.verify_digest().unwrap());
    assert!(manifest.verify(&key.verifying_key()).unwrap());
}

#[test]
fn unchanged_persistent_groups_reuse_metadata_and_release_maps_but_recheck_files() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("kernel");
    std::fs::write(&path, b"good").unwrap();
    let store = VersionStore::new();
    let group = store
        .prepare_group(
            "default",
            "release".into(),
            vec![("kernel".into(), path.clone())],
        )
        .unwrap();
    let root = ArtifactRoot::open(directory.path()).unwrap();
    let first = store
        .validate_persistent_groups(&root, vec![(group.clone(), true)])
        .unwrap();
    store.commit_persistent_groups(first.clone());
    let snapshot = store.active_releases.load_full();
    let second = store
        .validate_persistent_groups(&root, vec![(group.clone(), true)])
        .unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    store.commit_persistent_groups(second);
    assert!(Arc::ptr_eq(&snapshot, &store.active_releases.load_full()));

    let mut corrupt_metadata = group.clone();
    corrupt_metadata.files[0].content_hash = "ff".repeat(32);
    assert!(
        store
            .validate_persistent_groups(&root, vec![(corrupt_metadata, true)])
            .is_err()
    );
    let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
    std::fs::write(&path, b"evil").unwrap();
    // Same-size writes can share timestamps on coarse filesystem clocks. Make
    // the identity change explicit so this exercises changed-file verification.
    let file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_modified(modified + Duration::from_secs(2))
        .unwrap();
    assert_ne!(file.metadata().unwrap().modified().unwrap(), modified);
    assert!(
        store
            .validate_persistent_groups(&root, vec![(group, true)])
            .is_err()
    );
}
use std::io::Write;

#[test]
fn verification_cache_turns_over_without_evicting_live_verifiers() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let metadata = file.as_file().metadata().unwrap();
    let store = VersionStore::new();
    let live = store.artifact_verification(file.path(), &metadata, "live");
    for index in 1..MAX_VERIFIED_ARTIFACTS {
        store.cache_verified_artifact(file.path(), &metadata, &format!("hash-{index}"));
    }
    for index in 0..128 {
        let hash = format!("replacement-{index}");
        store.cache_verified_artifact(file.path(), &metadata, &hash);
        assert_eq!(
            store
                .artifact_verification(file.path(), &metadata, &hash)
                .get(),
            Some(&hash)
        );
    }
    assert!(Arc::ptr_eq(
        &live,
        &store.artifact_verification(file.path(), &metadata, "live")
    ));
    assert_eq!(store.verified_artifacts.len(), MAX_VERIFIED_ARTIFACTS);
    assert_eq!(
        store.verification_order.lock().len(),
        MAX_VERIFIED_ARTIFACTS
    );
}

#[test]
fn concurrent_verification_admission_stays_bounded() {
    let file = tempfile::NamedTempFile::new().unwrap();
    let metadata = file.as_file().metadata().unwrap();
    let store = VersionStore::new();
    for index in 0..MAX_VERIFIED_ARTIFACTS - 1 {
        store.cache_verified_artifact(file.path(), &metadata, &format!("hash-{index}"));
    }
    let barrier = std::sync::Barrier::new(16);
    std::thread::scope(|scope| {
        for index in 0..16 {
            let (store, file, metadata, barrier) = (&store, &file, &metadata, &barrier);
            scope.spawn(move || {
                barrier.wait();
                store.cache_verified_artifact(file.path(), metadata, &format!("new-{index}"));
            });
        }
    });
    assert_eq!(store.verified_artifacts.len(), MAX_VERIFIED_ARTIFACTS);
    assert_eq!(
        store.verification_order.lock().len(),
        MAX_VERIFIED_ARTIFACTS
    );
}
#[test]
fn test_version_store_new() {
    let store = VersionStore::new();
    assert_eq!(store.list_versions().len(), 0);
    assert_eq!(store.list_groups().len(), 0);
}

#[test]
fn managed_artifact_names_reject_control_characters() {
    for alias in [
        "boot//kernel",
        "boot/./kernel",
        "boot/kernel/",
        "./kernel",
        "/kernel",
        "boot/../kernel",
    ] {
        assert!(!is_valid_logical_name(alias), "{alias}");
        let store = VersionStore::new();
        assert!(
            store.resolve_file(alias, Path::new(".")).is_err(),
            "{alias}"
        );
    }
    for control in ['\t', '\n', '\x7f', '\u{85}', '\u{9f}'] {
        assert!(!is_valid_logical_name(&format!("kernel{control}")));
    }
    assert!(is_valid_logical_name("images/noyau-é"));
}

#[test]
fn release_preparation_rejects_more_than_one_hundred_artifacts_before_hashing() {
    let files = (0..=MAX_GROUP_ARTIFACTS)
        .map(|index| {
            (
                format!("artifact-{index}"),
                PathBuf::from(format!("does-not-need-to-exist-{index}")),
            )
        })
        .collect();
    let error = VersionStore::new()
        .prepare_group(DEFAULT_BOOT_PROFILE, "release".into(), files)
        .unwrap_err();

    assert!(error.to_string().contains("at most 100 files"));
}

#[test]
fn unmanaged_resolution_defers_lookup_to_the_capability_open() {
    let directory = tempfile::tempdir().unwrap();
    let resolved = VersionStore::new()
        .resolve_file_for_transfer("not-created-yet", directory.path())
        .unwrap();

    assert_eq!(resolved.path, directory.path().join("not-created-yet"));
    assert!(resolved.pinned_version.is_none());
}

#[test]
fn managed_resolution_keeps_generic_raw_compatibility_separate() {
    let directory = tempfile::tempdir().unwrap();
    let artifact = directory.path().join("kernel");
    std::fs::write(&artifact, b"kernel").unwrap();
    let store = VersionStore::new();
    assert!(
        store
            .resolve_file_for_transfer("kernel", directory.path())
            .unwrap()
            .pinned_version
            .is_none()
    );
    assert!(
        store
            .resolve_managed_file_for_transfer_in_profile("default", "kernel", directory.path())
            .is_err()
    );
    store
        .atomic_switch("release".into(), vec![("managed".into(), artifact)])
        .unwrap();
    // Exercise the unknown-name fallback independently of the empty-store path.
    assert!(
        store
            .resolve_file_for_transfer("kernel", directory.path())
            .unwrap()
            .pinned_version
            .is_none()
    );
    assert!(
        store
            .resolve_managed_file_for_transfer_in_profile("default", "kernel", directory.path())
            .is_err()
    );
}

#[test]
fn managed_resolution_missing_chain_does_not_leak_a_transfer_pin() {
    let directory = tempfile::tempdir().unwrap();
    let artifact = directory.path().join("kernel");
    std::fs::write(&artifact, b"kernel").unwrap();
    let store = VersionStore::new();
    let group = store
        .atomic_switch("release".into(), vec![("kernel".into(), artifact)])
        .unwrap();
    let mut broken = (*store.active_releases.load_full()).clone();
    broken.chains.clear();
    store.active_releases.store(Arc::new(broken));
    assert!(
        store
            .resolve_managed_file_for_transfer_in_profile("default", "kernel", directory.path())
            .is_err()
    );
    assert_eq!(store.pinned_count("kernel", group.version_id), 0);
}

#[test]
fn active_release_snapshot_indexes_chain_and_historical_ownership() {
    let directory = tempfile::tempdir().unwrap();
    let artifact = directory.path().join("kernel");
    std::fs::write(&artifact, b"kernel").unwrap();
    let store = VersionStore::new();
    let group = store
        .atomic_switch(
            "release-1".into(),
            vec![("kernel".into(), artifact.clone())],
        )
        .unwrap();

    let active = store.active_releases.load();
    assert_eq!(
        active
            .chains
            .get(DEFAULT_BOOT_PROFILE)
            .map(|pin| pin.group_id.as_str()),
        Some("release-1")
    );
    assert!(
        active
            .owned_names
            .contains(&VersionKey::new(DEFAULT_BOOT_PROFILE, "kernel"))
    );
    drop(active);

    store.withdraw_profile(DEFAULT_BOOT_PROFILE).unwrap();
    assert!(matches!(
        store.resolve_file_for_transfer("kernel", directory.path()),
        Err(TempestError::Protocol(
            crate::error::ProtocolError::FileNotFound(_)
        ))
    ));
    assert_eq!(group.version_id, 1);
}

#[test]
fn test_compute_sha256_streaming() {
    let dir = std::env::temp_dir().join("tempest_test_sha256");
    std::fs::create_dir_all(&dir).unwrap();
    let file_path = dir.join("test.bin");
    {
        let mut f = std::fs::File::create(&file_path).unwrap();
        f.write_all(&[0xAB; 100_000]).unwrap(); // 100KB test file
    }
    let hash = compute_sha256(&file_path).unwrap();
    assert_eq!(hash.len(), 64); // SHA-256 hex = 64 chars
    let hash2 = compute_sha256(&file_path).unwrap();
    assert_eq!(hash, hash2);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn confined_release_never_hashes_a_replacement_for_an_opened_path() {
    let directory = tempfile::tempdir().unwrap();
    let candidate = directory.path().join("kernel");
    let displaced = directory.path().join("kernel.original");
    std::fs::write(&candidate, b"approved kernel").unwrap();
    let artifact_root = ArtifactRoot::open(directory.path()).unwrap();
    let opened = artifact_root.open_read_with_metadata(&candidate).unwrap();

    std::fs::rename(&candidate, &displaced).unwrap();
    std::fs::write(&candidate, b"replacement kernel").unwrap();

    let result = hash_stable_open_file(
        opened.file,
        &opened.path,
        opened.metadata,
        Some(4 * 1024 * 1024 * 1024),
    );
    match result {
        Ok((hash, metadata)) => {
            assert_eq!(hash, hex::encode(Sha256::digest(b"approved kernel")));
            assert_ne!(hash, hex::encode(Sha256::digest(b"replacement kernel")));
            assert_eq!(metadata.len(), b"approved kernel".len() as u64);
        }
        Err(error) => assert!(error.to_string().contains("File changed while hashing")),
    }
}

#[test]
fn test_hash_cache_stores_timestamp() {
    let store = VersionStore::new();
    let dir = std::env::temp_dir().join("tempest_test_cache");
    std::fs::create_dir_all(&dir).unwrap();
    let file_path = dir.join("cached.bin");
    std::fs::write(&file_path, b"hello").unwrap();

    let hash1 = store.content_hash(&file_path).unwrap();
    let hash2 = store.content_hash(&file_path).unwrap();
    assert_eq!(hash1, hash2);

    store.invalidate_hash(&file_path);
    let hash3 = store.content_hash(&file_path).unwrap();
    assert_eq!(hash1, hash3);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_group_history_is_bounded() {
    let store = VersionStore::new();
    let dir = std::env::temp_dir().join("tempest_test_groups");
    std::fs::create_dir_all(&dir).unwrap();

    let file_path = dir.join("kernel");
    std::fs::write(&file_path, b"test kernel data").unwrap();

    for i in 0..(MAX_GROUP_HISTORY + 20) {
        let _ = store.atomic_switch(
            format!("group_{i}"),
            vec![("kernel".to_string(), file_path.clone())],
        );
    }

    let groups = store.list_groups();
    assert!(groups.len() <= MAX_GROUP_HISTORY);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_pin_unpin_version() {
    let store = VersionStore::new();
    store.pin_version(DEFAULT_BOOT_PROFILE, "file.bin", 1);
    assert_eq!(store.pinned_count("file.bin", 1), 1);
    store.pin_version(DEFAULT_BOOT_PROFILE, "file.bin", 1);
    assert_eq!(store.pinned_count("file.bin", 1), 2);
    store.unpin_version("file.bin", 1);
    assert_eq!(store.pinned_count("file.bin", 1), 1);
    store.unpin_version("file.bin", 1);
    assert_eq!(store.pinned_count("file.bin", 1), 0);
}

#[test]
fn test_resolve_file_for_transfer_returns_pinned_identity() {
    let store = VersionStore::new();
    let dir = std::env::temp_dir().join("tempest_test_resolve_pin_identity");
    std::fs::create_dir_all(&dir).unwrap();
    let file_path = dir.join("kernel-v1.bin");
    std::fs::write(&file_path, b"kernel-v1").unwrap();

    let group = store
        .atomic_switch(
            "release_pin".into(),
            vec![("kernel".into(), file_path.clone())],
        )
        .unwrap();
    let resolved = store
        .resolve_file_for_transfer("kernel", Path::new("."))
        .unwrap();
    let pinned = resolved.pinned_version.unwrap();

    assert_eq!(resolved.path, file_path);
    assert_eq!(pinned.logical_name, "kernel");
    assert_eq!(pinned.version_id, group.version_id);
    assert_eq!(
        resolved.content_hash.as_deref(),
        Some(pinned.content_hash.as_str())
    );
    assert_eq!(store.pinned_count("kernel", group.version_id), 1);

    store.unpin_version("kernel", group.version_id);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_resolve_file_for_transfer_in_pinned_boot_chain_keeps_old_group() {
    let store = VersionStore::new();
    let dir = tempfile::tempdir().unwrap();
    let kernel_v1 = dir.path().join("kernel-v1");
    let initrd_v1 = dir.path().join("initrd-v1");
    let kernel_v2 = dir.path().join("kernel-v2");
    let initrd_v2 = dir.path().join("initrd-v2");
    std::fs::write(&kernel_v1, b"kernel-v1").unwrap();
    std::fs::write(&initrd_v1, b"initrd-v1").unwrap();
    std::fs::write(&kernel_v2, b"kernel-v2").unwrap();
    std::fs::write(&initrd_v2, b"initrd-v2").unwrap();

    let group_v1 = store
        .atomic_switch_for_profile(
            "ubuntu-focal".into(),
            "focal-v1".into(),
            vec![
                ("vmlinuz".into(), kernel_v1.clone()),
                ("initrd.img".into(), initrd_v1.clone()),
            ],
        )
        .unwrap();
    let boot_chain = BootChainPin {
        boot_profile: group_v1.boot_profile.clone(),
        group_id: group_v1.group_id.clone(),
        version_id: group_v1.version_id,
        manifest_digest: group_v1.manifest.manifest_digest.clone(),
    };
    store.pin_boot_chain(&boot_chain);

    for release in 2..(MAX_GROUP_HISTORY + 20) {
        store
            .atomic_switch_for_profile(
                "ubuntu-focal".into(),
                format!("focal-v{release}"),
                vec![
                    ("vmlinuz".into(), kernel_v2.clone()),
                    ("initrd.img".into(), initrd_v2.clone()),
                ],
            )
            .unwrap();
    }

    let resolved = store
        .resolve_file_for_transfer_in_boot_chain(&boot_chain, "initrd.img", dir.path())
        .unwrap();
    assert_eq!(resolved.path, initrd_v1);
    assert_eq!(resolved.boot_chain.as_ref(), Some(&boot_chain));
    assert_eq!(
        resolved.pinned_version.as_ref().map(|pin| pin.version_id),
        Some(group_v1.version_id)
    );
    assert_eq!(
        store.pinned_count_for_profile("ubuntu-focal", "initrd.img", group_v1.version_id),
        1
    );
    assert_eq!(store.pinned_boot_chain_count(&boot_chain), 1);
    assert!(store.group_count() <= MAX_GROUP_HISTORY);

    store.unpin_version_for_profile("ubuntu-focal", "initrd.img", group_v1.version_id);
    store.unpin_boot_chain(&boot_chain);
    store.prune_group_history();
}

#[test]
fn test_pinned_boot_chain_rejects_artifact_outside_manifest() {
    let store = VersionStore::new();
    let dir = tempfile::tempdir().unwrap();
    let kernel = dir.path().join("kernel");
    std::fs::write(&kernel, b"kernel").unwrap();
    std::fs::write(dir.path().join("unmanaged"), b"outside").unwrap();
    store
        .atomic_switch("release-a".into(), vec![("kernel".into(), kernel)])
        .unwrap();
    let pin = store
        .active_boot_chain_for_profile(DEFAULT_BOOT_PROFILE)
        .unwrap()
        .unwrap();

    assert!(matches!(
        store.resolve_file_for_transfer_in_boot_chain(&pin, "unmanaged", dir.path()),
        Err(TempestError::Protocol(
            crate::error::ProtocolError::FileNotFound(_)
        ))
    ));
}

#[tokio::test]
async fn drain_gated_switch_waits_for_removed_artifact_pins() {
    let store = std::sync::Arc::new(VersionStore::new());
    let dir = std::env::temp_dir().join(format!(
        "tempest_test_drain_cutover_{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let v1_path = dir.join("kernel-v1.bin");
    let initrd_path = dir.join("initrd-v1.bin");
    let v2_path = dir.join("kernel-v2.bin");
    std::fs::write(&v1_path, b"kernel-v1").unwrap();
    std::fs::write(&initrd_path, b"initrd-v1").unwrap();
    std::fs::write(&v2_path, b"kernel-v2").unwrap();

    let group1 = store
        .atomic_switch(
            "release_drain_v1".into(),
            vec![("kernel".into(), v1_path), ("initrd".into(), initrd_path)],
        )
        .unwrap();
    let resolved = store
        .resolve_file_for_transfer("initrd", Path::new("."))
        .unwrap();
    let pinned = resolved.pinned_version.unwrap();
    assert_eq!(pinned.version_id, group1.version_id);
    let boot_chain = store
        .active_boot_chain_for_profile(DEFAULT_BOOT_PROFILE)
        .unwrap()
        .unwrap();

    let task_store = store.clone();
    let handle = tokio::spawn(async move {
        task_store
            .drain_gated_switch_for_profile(
                DEFAULT_BOOT_PROFILE.into(),
                "release_drain_v2".into(),
                vec![("kernel".into(), v2_path)],
                Duration::from_secs(2),
                false,
            )
            .await
    });

    for _ in 0..100 {
        if !store.cutover_gates.read().is_empty() {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(!store.cutover_gates.read().is_empty());
    assert!(
        store
            .active_boot_chain_for_profile(DEFAULT_BOOT_PROFILE)
            .is_err()
    );

    let existing_session = store
        .resolve_file_for_transfer_in_boot_chain(&boot_chain, "kernel", Path::new("."))
        .unwrap();
    let existing_pin = existing_session.pinned_version.unwrap();
    store.unpin_version(&existing_pin.logical_name, existing_pin.version_id);

    let blocked = store.resolve_file_for_transfer("kernel", Path::new("."));
    assert!(matches!(
        blocked,
        Err(TempestError::Protocol(
            crate::error::ProtocolError::AccessViolation(_)
        ))
    ));

    store.unpin_version(&pinned.logical_name, pinned.version_id);
    let group2 = tokio::time::timeout(Duration::from_secs(1), handle)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(group2.group_id, "release_drain_v2");
    assert!(store.cutover_gates.read().is_empty());

    let resolved_new = store
        .resolve_file_for_transfer("kernel", Path::new("."))
        .unwrap();
    let new_pin = resolved_new.pinned_version.unwrap();
    assert_eq!(new_pin.version_id, group2.version_id);
    store.unpin_version(&new_pin.logical_name, new_pin.version_id);

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn drain_all_waits_for_a_disjoint_outgoing_boot_chain() {
    let store = std::sync::Arc::new(VersionStore::new());
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("kernel");
    let new = dir.path().join("shim");
    std::fs::write(&old, b"kernel").unwrap();
    std::fs::write(&new, b"shim").unwrap();
    store
        .atomic_switch("release-a".into(), vec![("kernel".into(), old)])
        .unwrap();
    let pin = store
        .active_boot_chain_for_profile(DEFAULT_BOOT_PROFILE)
        .unwrap()
        .unwrap();
    store.pin_boot_chain(&pin);

    let task_store = store.clone();
    let switch = tokio::spawn(async move {
        task_store
            .drain_gated_switch(
                "release-b".into(),
                vec![("shim".into(), new)],
                Duration::from_secs(2),
            )
            .await
    });
    for _ in 0..100 {
        if store.cutover_in_progress(DEFAULT_BOOT_PROFILE) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(store.cutover_in_progress(DEFAULT_BOOT_PROFILE));
    assert!(!switch.is_finished());

    store.unpin_boot_chain(&pin);
    let active = tokio::time::timeout(Duration::from_secs(1), switch)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(active.group_id, "release-b");
}

#[tokio::test]
async fn test_drain_gated_switch_timeout_clears_gate() {
    let store = VersionStore::new();
    let dir = std::env::temp_dir().join(format!(
        "tempest_test_drain_cutover_timeout_{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&dir).unwrap();

    let v1_path = dir.join("kernel-v1.bin");
    let v2_path = dir.join("kernel-v2.bin");
    std::fs::write(&v1_path, b"kernel-v1").unwrap();
    std::fs::write(&v2_path, b"kernel-v2").unwrap();

    let group1 = store
        .atomic_switch(
            "release_timeout_v1".into(),
            vec![("kernel".into(), v1_path)],
        )
        .unwrap();
    let resolved = store
        .resolve_file_for_transfer("kernel", Path::new("."))
        .unwrap();
    let pinned = resolved.pinned_version.unwrap();

    let result = store
        .drain_gated_switch(
            "release_timeout_v2".into(),
            vec![("kernel".into(), v2_path)],
            Duration::from_millis(1),
        )
        .await;

    assert!(matches!(result, Err(TempestError::Version(_))));
    assert!(store.cutover_gates.read().is_empty());

    let resolved_again = store
        .resolve_file_for_transfer("kernel", Path::new("."))
        .unwrap();
    let repinned = resolved_again.pinned_version.unwrap();
    assert_eq!(repinned.version_id, group1.version_id);

    store.unpin_version(&repinned.logical_name, repinned.version_id);
    store.unpin_version(&pinned.logical_name, pinned.version_id);

    std::fs::remove_dir_all(&dir).ok();
}

#[tokio::test]
async fn cancelling_drain_gated_switch_clears_gate() {
    let store = std::sync::Arc::new(VersionStore::new());
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("kernel-v1");
    let new = dir.path().join("kernel-v2");
    std::fs::write(&old, b"kernel-v1").unwrap();
    std::fs::write(&new, b"kernel-v2").unwrap();
    store
        .atomic_switch("release-1".into(), vec![("kernel".into(), old)])
        .unwrap();
    let pin = store
        .resolve_file_for_transfer("kernel", Path::new("."))
        .unwrap()
        .pinned_version
        .unwrap();

    let task_store = store.clone();
    let task = tokio::spawn(async move {
        task_store
            .drain_gated_switch(
                "release-2".into(),
                vec![("kernel".into(), new)],
                Duration::from_secs(60),
            )
            .await
    });
    for _ in 0..100 {
        if store.cutover_in_progress(DEFAULT_BOOT_PROFILE) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(store.cutover_in_progress(DEFAULT_BOOT_PROFILE));

    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(!store.cutover_in_progress(DEFAULT_BOOT_PROFILE));
    store.unpin_version(&pin.logical_name, pin.version_id);
    assert!(
        store
            .resolve_file_for_transfer("kernel", Path::new("."))
            .is_ok()
    );
}

#[tokio::test]
async fn test_session_preserving_cutover_serves_new_release_and_keeps_old_session() {
    let store = std::sync::Arc::new(VersionStore::new());
    let dir = tempfile::tempdir().unwrap();
    let old_kernel = dir.path().join("old-kernel");
    let old_initrd = dir.path().join("old-initrd");
    let new_kernel = dir.path().join("new-kernel");
    let new_initrd = dir.path().join("new-initrd");
    for (path, bytes) in [
        (&old_kernel, b"old-kernel".as_slice()),
        (&old_initrd, b"old-initrd".as_slice()),
        (&new_kernel, b"new-kernel".as_slice()),
        (&new_initrd, b"new-initrd".as_slice()),
    ] {
        std::fs::write(path, bytes).unwrap();
    }
    let old = store
        .atomic_switch(
            "release-a".into(),
            vec![
                ("kernel".into(), old_kernel),
                ("initrd".into(), old_initrd.clone()),
            ],
        )
        .unwrap();
    let pin = store
        .active_boot_chain_for_profile(DEFAULT_BOOT_PROFILE)
        .unwrap()
        .unwrap();
    store.pin_boot_chain(&pin);

    let switched = store
        .drain_gated_switch_for_profile(
            DEFAULT_BOOT_PROFILE.into(),
            "release-b".into(),
            vec![("kernel".into(), new_kernel), ("initrd".into(), new_initrd)],
            Duration::from_secs(1),
            false,
        )
        .await
        .unwrap();

    assert_eq!(switched.group_id, "release-b");
    assert_eq!(
        store
            .resolve_file_for_transfer("initrd", dir.path())
            .unwrap()
            .pinned_version
            .unwrap()
            .version_id,
        switched.version_id
    );
    assert_eq!(
        store
            .resolve_file_for_transfer_in_boot_chain(&pin, "initrd", dir.path())
            .unwrap()
            .path,
        old_initrd
    );
    assert_ne!(old.version_id, switched.version_id);
}

#[test]
fn test_rollback_fails_with_missing_files() {
    let store = VersionStore::new();
    let dir = std::env::temp_dir().join("tempest_test_rollback_missing");
    std::fs::create_dir_all(&dir).unwrap();

    let file_path = dir.join("kernel.bin");
    std::fs::write(&file_path, b"kernel data").unwrap();
    let _ = store.atomic_switch(
        "group_1".into(),
        vec![("kernel.bin".to_string(), file_path.clone())],
    );

    std::fs::remove_file(&file_path).unwrap();

    let result = store.rollback("group_1");
    assert!(result.is_err());

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_rollback_succeeds_with_existing_files() {
    let store = VersionStore::new();
    let dir = std::env::temp_dir().join("tempest_test_rollback_success");
    std::fs::create_dir_all(&dir).unwrap();

    let file_path = dir.join("initrd.img");
    std::fs::write(&file_path, b"initrd data").unwrap();
    let _ = store.atomic_switch(
        "group_ok".into(),
        vec![("initrd.img".to_string(), file_path.clone())],
    );

    let result = store.rollback("group_ok");
    assert!(result.is_ok());

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_sha256_consistency_large_file() {
    let dir = std::env::temp_dir().join("tempest_test_sha256_large");
    std::fs::create_dir_all(&dir).unwrap();
    let file_path = dir.join("large.bin");
    let data: Vec<u8> = (0..500_000).map(|i| (i % 256) as u8).collect();
    std::fs::write(&file_path, &data).unwrap();

    let hash = compute_sha256(&file_path).unwrap();
    assert_eq!(hash.len(), 64);
    let hash2 = compute_sha256(&file_path).unwrap();
    assert_eq!(hash, hash2);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_group_count_tracks_switches() {
    let store = VersionStore::new();
    assert_eq!(store.group_count(), 0);

    let dir = std::env::temp_dir().join("tempest_test_group_count");
    std::fs::create_dir_all(&dir).unwrap();
    let file_path = dir.join("test.bin");
    std::fs::write(&file_path, b"test").unwrap();

    let _ = store.atomic_switch("g1".into(), vec![("test.bin".into(), file_path.clone())]);
    assert_eq!(store.group_count(), 1);

    let _ = store.atomic_switch("g2".into(), vec![("test.bin".into(), file_path)]);
    assert_eq!(store.group_count(), 2);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn test_list_versions_is_empty_for_new_store() {
    let store = VersionStore::new();
    let versions = store.list_versions();
    assert!(versions.is_empty());
}

#[test]
fn test_hash_cache_accepts_entries_below_its_limit() {
    let store = VersionStore::new();
    let dir = std::env::temp_dir().join("tempest_test_hash_cache_bound");
    std::fs::create_dir_all(&dir).unwrap();

    for i in 0..5 {
        let path = dir.join(format!("file_{i}.bin"));
        std::fs::write(&path, format!("content_{i}")).unwrap();
        let _ = store.content_hash(&path);
    }
    assert_eq!(store.hash_cache.len(), 5);

    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn release_activation_keeps_hash_cache_at_its_declared_limit() {
    let store = VersionStore::new();
    let inserted_at = Instant::now();
    for index in 0..MAX_HASH_CACHE_ENTRIES {
        store.hash_cache.insert(
            PathBuf::from(format!("cached-artifact-{index}")),
            ("0".repeat(64), inserted_at),
        );
    }

    let directory = tempfile::tempdir().unwrap();
    let artifact = directory.path().join("kernel");
    std::fs::write(&artifact, b"kernel").unwrap();
    store
        .atomic_switch("release".into(), vec![("kernel".into(), artifact)])
        .unwrap();

    assert!(store.hash_cache.len() <= MAX_HASH_CACHE_ENTRIES);
}

#[test]
fn test_resolve_file_rejects_long_filename() {
    let store = VersionStore::new();
    let long_name = "a".repeat(2000);
    let dir = std::env::temp_dir().join("tempest_test_longname");
    std::fs::create_dir_all(&dir).unwrap();
    let result = store.resolve_file(&long_name, &dir);
    assert!(result.is_err());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn filename_errors_distinguish_aliases_from_length_for_active_and_pinned_reads() {
    let store = VersionStore::new();
    let root = Path::new(".");
    let pin = BootChainPin {
        boot_profile: "default".into(),
        group_id: "release".into(),
        version_id: 1,
        manifest_digest: "00".repeat(32),
    };
    let long_name = "a".repeat(1025);
    for (name, expected) in [
        ("boot//kernel", "noncanonical filename"),
        ("./kernel", "noncanonical filename"),
        ("boot/./kernel", "noncanonical filename"),
        (long_name.as_str(), "filename too long"),
    ] {
        for result in [
            store.resolve_file(name, root).map(|_| ()),
            store
                .resolve_file_for_transfer_in_boot_chain(&pin, name, root)
                .map(|_| ()),
        ] {
            assert!(matches!(
                result,
                Err(TempestError::Protocol(
                    crate::error::ProtocolError::AccessViolation(reason)
                )) if reason == expected
            ));
        }
    }
}

#[test]
fn test_duplicate_group_id_rejected() {
    let store = VersionStore::new();
    let dir = std::env::temp_dir().join("tempest_test_dup_group");
    std::fs::create_dir_all(&dir).unwrap();
    let file_path = dir.join("test.bin");
    std::fs::write(&file_path, b"test").unwrap();

    let result1 = store.atomic_switch(
        "group_1".into(),
        vec![("test.bin".into(), file_path.clone())],
    );
    assert!(result1.is_ok());

    let result2 = store.atomic_switch("group_1".into(), vec![("test.bin".into(), file_path)]);
    assert!(result2.is_err()); // Duplicate group_id

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_release_group_requires_unique_members() {
    let store = VersionStore::new();
    let file_path = std::env::temp_dir().join("tempest_test_unique_member");
    std::fs::write(&file_path, b"test").unwrap();

    assert!(store.atomic_switch("empty".into(), vec![]).is_err());
    assert!(
        store
            .atomic_switch(
                "duplicate".into(),
                vec![
                    ("kernel".into(), file_path.clone()),
                    ("kernel".into(), file_path.clone()),
                ],
            )
            .is_err()
    );

    std::fs::remove_file(file_path).ok();
}

#[test]
fn test_activation_replaces_profile_release() {
    let store = VersionStore::new();
    let dir = std::env::temp_dir().join("tempest_test_profile_replace");
    std::fs::create_dir_all(&dir).unwrap();
    let kernel = dir.join("kernel");
    let initrd = dir.join("initrd");
    std::fs::write(&kernel, b"kernel").unwrap();
    std::fs::write(&initrd, b"initrd").unwrap();

    store
        .atomic_switch(
            "release-1".into(),
            vec![("kernel".into(), kernel.clone()), ("initrd".into(), initrd)],
        )
        .unwrap();
    store
        .atomic_switch("release-2".into(), vec![("kernel".into(), kernel)])
        .unwrap();

    let active = store.list_versions();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].logical_name, "kernel");

    std::fs::remove_dir_all(dir).ok();
}

#[test]
fn test_affected_release_lookup_does_not_withdraw_profile() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kernel");
    std::fs::write(&path, b"kernel").unwrap();
    let store = VersionStore::new();
    store
        .atomic_switch("release".into(), vec![("kernel".into(), path.clone())])
        .unwrap();

    assert_eq!(store.active_groups_for_path(&path).len(), 1);
    assert!(
        store
            .active_boot_chain_for_profile(DEFAULT_BOOT_PROFILE)
            .unwrap()
            .is_some()
    );
    store.withdraw_profile(DEFAULT_BOOT_PROFILE).unwrap();
    assert!(
        store
            .active_boot_chain_for_profile(DEFAULT_BOOT_PROFILE)
            .unwrap()
            .is_none()
    );
}

#[test]
fn test_same_logical_name_is_isolated_by_boot_profile() {
    let store = VersionStore::new();
    let dir = std::env::temp_dir().join("tempest_test_profile_isolation");
    std::fs::create_dir_all(&dir).unwrap();

    let focal_path = dir.join("focal-vmlinuz");
    let rhel_path = dir.join("rhel-vmlinuz");
    std::fs::write(&focal_path, b"focal kernel").unwrap();
    std::fs::write(&rhel_path, b"rhel kernel").unwrap();

    let focal = store
        .atomic_switch_for_profile(
            "ubuntu-focal".into(),
            "release-1".into(),
            vec![("vmlinuz".into(), focal_path.clone())],
        )
        .unwrap();
    let rhel = store
        .atomic_switch_for_profile(
            "rhel9".into(),
            "release-1".into(),
            vec![("vmlinuz".into(), rhel_path.clone())],
        )
        .unwrap();

    assert_ne!(focal.version_id, rhel.version_id);
    assert_eq!(focal.manifest.boot_profile, "ubuntu-focal");
    assert_eq!(rhel.manifest.boot_profile, "rhel9");

    let focal_resolved = store
        .resolve_file_for_transfer_in_profile("ubuntu-focal", "vmlinuz", Path::new("."))
        .unwrap();
    let rhel_resolved = store
        .resolve_file_for_transfer_in_profile("rhel9", "vmlinuz", Path::new("."))
        .unwrap();

    assert_eq!(focal_resolved.path, focal_path);
    assert_eq!(rhel_resolved.path, rhel_path);
    assert_eq!(
        store.pinned_count_for_profile("ubuntu-focal", "vmlinuz", focal.version_id),
        1
    );
    assert_eq!(
        store.pinned_count_for_profile("rhel9", "vmlinuz", rhel.version_id),
        1
    );

    let focal_pin = focal_resolved.pinned_version.unwrap();
    let rhel_pin = rhel_resolved.pinned_version.unwrap();
    store.unpin_version_for_profile(
        &focal_pin.boot_profile,
        &focal_pin.logical_name,
        focal_pin.version_id,
    );
    store.unpin_version_for_profile(
        &rhel_pin.boot_profile,
        &rhel_pin.logical_name,
        rhel_pin.version_id,
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_rollback_is_scoped_to_boot_profile() {
    let store = VersionStore::new();
    let dir = std::env::temp_dir().join("tempest_test_profile_rollback");
    std::fs::create_dir_all(&dir).unwrap();

    let focal_v1 = dir.join("focal-v1");
    let focal_v2 = dir.join("focal-v2");
    let focal_initrd = dir.join("focal-initrd");
    let jammy_v1 = dir.join("jammy-v1");
    std::fs::write(&focal_v1, b"focal v1").unwrap();
    std::fs::write(&focal_v2, b"focal v2").unwrap();
    std::fs::write(&focal_initrd, b"focal initrd").unwrap();
    std::fs::write(&jammy_v1, b"jammy v1").unwrap();

    store
        .atomic_switch_for_profile(
            "ubuntu-focal".into(),
            "release-1".into(),
            vec![("vmlinuz".into(), focal_v1.clone())],
        )
        .unwrap();
    store
        .atomic_switch_for_profile(
            "ubuntu-focal".into(),
            "release-2".into(),
            vec![
                ("vmlinuz".into(), focal_v2.clone()),
                ("initrd".into(), focal_initrd),
            ],
        )
        .unwrap();
    store
        .atomic_switch_for_profile(
            "ubuntu-jammy".into(),
            "release-1".into(),
            vec![("vmlinuz".into(), jammy_v1.clone())],
        )
        .unwrap();

    let artifact_root = ArtifactRoot::open(&dir).unwrap();
    store
        .rollback_for_profile(&artifact_root, "ubuntu-focal", "release-1")
        .unwrap();

    let focal = store
        .resolve_file_in_profile("ubuntu-focal", "vmlinuz", Path::new("."))
        .unwrap();
    let jammy = store
        .resolve_file_in_profile("ubuntu-jammy", "vmlinuz", Path::new("."))
        .unwrap();

    assert_eq!(focal, focal_v1);
    assert_eq!(jammy, jammy_v1);
    assert!(
        store
            .list_versions()
            .iter()
            .all(|version| version.boot_profile != "ubuntu-focal"
                || version.logical_name == "vmlinuz")
    );

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_signed_manifest_verifies() {
    let signing_key_bytes = [7u8; 32];
    let store = VersionStore::new_with_manifest_signing_key(&signing_key_bytes);
    let dir = std::env::temp_dir().join("tempest_test_signed_manifest");
    std::fs::create_dir_all(&dir).unwrap();

    let kernel_path = dir.join("kernel-v1.bin");
    let initrd_path = dir.join("initrd-v1.img");
    std::fs::write(&kernel_path, b"kernel-v1").unwrap();
    std::fs::write(&initrd_path, b"initrd-v1").unwrap();

    let group = store
        .atomic_switch(
            "release_1".into(),
            vec![
                ("kernel".into(), kernel_path),
                ("initrd".into(), initrd_path),
            ],
        )
        .unwrap();

    assert_eq!(group.manifest.artifacts.len(), 2);
    assert_eq!(group.manifest.artifacts[0].logical_name, "kernel");
    assert!(group.manifest.signature.is_some());
    assert_eq!(group.files[0].logical_name, "kernel");

    let verifying_key = store.manifest_verifying_key().unwrap();
    assert!(group.manifest.verify(&verifying_key).unwrap());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_manifest_verification_fails_when_tampered() {
    let signing_key_bytes = [9u8; 32];
    let store = VersionStore::new_with_manifest_signing_key(&signing_key_bytes);
    let dir = std::env::temp_dir().join("tempest_test_manifest_tamper");
    std::fs::create_dir_all(&dir).unwrap();

    let file_path = dir.join("kernel.bin");
    std::fs::write(&file_path, b"kernel").unwrap();

    let group = store
        .atomic_switch("release_2".into(), vec![("kernel".into(), file_path)])
        .unwrap();
    let verifying_key = store.manifest_verifying_key().unwrap();

    let mut tampered = group.manifest.clone();
    tampered.artifacts[0].content_hash = "00".repeat(32);

    assert!(!tampered.verify(&verifying_key).unwrap());

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn test_persistent_hydration_rejects_tampered_manifest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kernel");
    std::fs::write(&path, b"kernel").unwrap();
    let source = VersionStore::new();
    let group = source
        .atomic_switch("release".into(), vec![("kernel".into(), path)])
        .unwrap();

    let target = VersionStore::new();
    let mut tampered = group.clone();
    tampered.manifest.manifest_digest = "00".repeat(32);
    assert!(
        target
            .replace_from_persistent(vec![(tampered, true)])
            .is_err()
    );
    let mut inconsistent = group;
    inconsistent.files[0].version_id += 1;
    assert!(
        target
            .replace_from_persistent(vec![(inconsistent, true)])
            .is_err()
    );
    assert_eq!(target.group_count(), 0);
    assert!(target.list_versions().is_empty());
}

#[test]
fn test_required_manifest_verifier_rejects_unsigned_hydration() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kernel");
    std::fs::write(&path, b"kernel").unwrap();
    let unsigned = VersionStore::new()
        .atomic_switch("release".into(), vec![("kernel".into(), path)])
        .unwrap();
    let key = SigningKey::from_bytes(&[31; 32]).verifying_key();
    let verifier = VersionStore::new_with_manifest_keys(None, Some(key), true);

    assert!(
        verifier
            .replace_from_persistent(vec![(unsigned.clone(), true)])
            .is_err()
    );
    let mut fake_signed = unsigned;
    fake_signed.manifest.signature = Some("00".repeat(64));
    assert!(
        VersionStore::new()
            .replace_from_persistent(vec![(fake_signed.clone(), true)])
            .is_err()
    );
    assert!(
        VersionStore::new_with_manifest_keys(None, None, true)
            .replace_from_persistent(vec![(fake_signed, true)])
            .is_err()
    );
}

#[test]
fn test_active_persisted_release_rejects_changed_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("kernel");
    std::fs::write(&path, b"kernel-a").unwrap();
    let group = VersionStore::new()
        .atomic_switch("release".into(), vec![("kernel".into(), path.clone())])
        .unwrap();
    std::fs::write(path, b"kernel-b").unwrap();

    assert!(
        VersionStore::new()
            .replace_from_persistent(vec![(group, true)])
            .is_err()
    );
}

#[test]
fn test_rollback_preserves_logical_name_binding() {
    let store = VersionStore::new();
    let dir = std::env::temp_dir().join("tempest_test_logical_name_rollback");
    std::fs::create_dir_all(&dir).unwrap();

    let v1_path = dir.join("kernel-v1.bin");
    let v2_path = dir.join("kernel-v2.bin");
    std::fs::write(&v1_path, b"kernel-v1").unwrap();
    std::fs::write(&v2_path, b"kernel-v2").unwrap();

    let logical_name = "images/kernel.bin";
    store
        .atomic_switch(
            "release_v1".into(),
            vec![(logical_name.into(), v1_path.clone())],
        )
        .unwrap();
    store
        .atomic_switch("release_v2".into(), vec![(logical_name.into(), v2_path)])
        .unwrap();

    store.rollback("release_v1").unwrap();
    let resolved = store
        .resolve_file(logical_name, Path::new("."))
        .expect("rollback should preserve logical artifact name");
    assert_eq!(resolved, v1_path);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn dropping_verified_rollback_reservation_clears_the_cutover_gate() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("kernel-v1");
    let second = directory.path().join("kernel-v2");
    std::fs::write(&first, b"kernel-v1").unwrap();
    std::fs::write(&second, b"kernel-v2").unwrap();
    let store = VersionStore::new();
    store
        .atomic_switch("release-1".into(), vec![("kernel".into(), first)])
        .unwrap();
    store
        .atomic_switch("release-2".into(), vec![("kernel".into(), second)])
        .unwrap();
    let artifact_root = ArtifactRoot::open(directory.path()).unwrap();
    let rollback = store
        .prepare_rollback_for_profile(&artifact_root, DEFAULT_BOOT_PROFILE, "release-1", None)
        .unwrap();

    let reservation = store.reserve_verified_rollback(rollback).unwrap();
    assert!(store.cutover_in_progress(DEFAULT_BOOT_PROFILE));
    drop(reservation);

    assert!(!store.cutover_in_progress(DEFAULT_BOOT_PROFILE));
    assert_eq!(
        store
            .active_boot_chain_for_profile(DEFAULT_BOOT_PROFILE)
            .unwrap()
            .unwrap()
            .group_id,
        "release-2"
    );
}

#[test]
fn coherent_release_snapshot_never_mixes_active_and_historical_state() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let directory = tempfile::tempdir().unwrap();
    let artifact = directory.path().join("kernel");
    std::fs::write(&artifact, b"stable-kernel").unwrap();
    let store = std::sync::Arc::new(VersionStore::new());
    store
        .atomic_switch(
            "release-0".into(),
            vec![("kernel".into(), artifact.clone())],
        )
        .unwrap();

    let finished = std::sync::Arc::new(AtomicBool::new(false));
    let writer_store = store.clone();
    let writer_finished = finished.clone();
    let writer = std::thread::spawn(move || {
        for sequence in 1..50 {
            writer_store
                .atomic_switch(
                    format!("release-{sequence}"),
                    vec![("kernel".into(), artifact.clone())],
                )
                .unwrap();
        }
        writer_finished.store(true, Ordering::Release);
    });

    while !finished.load(Ordering::Acquire) {
        let snapshot = store.release_snapshot().unwrap();
        for active in &snapshot.active_versions {
            assert!(snapshot.groups.iter().any(|group| {
                group.boot_profile == active.boot_profile
                    && group.version_id == active.version_id
                    && group.files.iter().any(|file| {
                        file.logical_name == active.logical_name
                            && file.content_hash == active.content_hash
                    })
            }));
        }
        for active in &snapshot.active_groups {
            assert!(snapshot.groups.iter().any(|group| {
                group.boot_profile == active.boot_profile
                    && group.group_id == active.group_id
                    && group.version_id == active.version_id
                    && group.manifest.manifest_digest == active.manifest_digest
            }));
        }
    }
    writer.join().unwrap();
}

#[test]
fn active_history_capacity_rejects_growth_but_allows_unpinned_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let artifact = directory.path().join("kernel");
    std::fs::write(&artifact, b"stable-kernel").unwrap();
    let store = VersionStore::new();
    for sequence in 0..MAX_RELEASE_SNAPSHOT_GROUPS {
        store
            .atomic_switch_for_profile(
                format!("profile-{sequence}"),
                format!("release-{sequence}"),
                vec![("kernel".into(), artifact.clone())],
            )
            .unwrap();
    }

    assert!(matches!(
        store.atomic_switch_for_profile(
            "overflow".into(),
            "overflow".into(),
            vec![("kernel".into(), artifact.clone())],
        ),
        Err(TempestError::Conflict(_))
    ));
    assert_eq!(
        store.release_snapshot().unwrap().groups.len(),
        MAX_GROUP_HISTORY
    );
    assert!(
        store
            .active_boot_chain_for_profile("overflow")
            .unwrap()
            .is_none()
    );

    let pin = store
        .active_boot_chain_for_profile("profile-0")
        .unwrap()
        .unwrap();
    store.pin_boot_chain(&pin);
    assert!(matches!(
        store.atomic_switch_for_profile(
            "profile-0".into(),
            "replacement".into(),
            vec![("kernel".into(), artifact.clone())],
        ),
        Err(TempestError::Conflict(_))
    ));
    assert_eq!(
        store
            .active_boot_chain_for_profile("profile-0")
            .unwrap()
            .unwrap()
            .manifest_digest,
        pin.manifest_digest
    );
    store.unpin_boot_chain(&pin);
    store
        .atomic_switch_for_profile(
            "profile-0".into(),
            "replacement".into(),
            vec![("kernel".into(), artifact)],
        )
        .unwrap();
    assert_eq!(
        store.release_snapshot().unwrap().groups.len(),
        MAX_GROUP_HISTORY
    );
    assert_eq!(
        store
            .active_boot_chain_for_profile("profile-0")
            .unwrap()
            .unwrap()
            .group_id,
        "replacement"
    );
}

#[test]
fn compute_sha256_accepts_file_below_default_limit() {
    let dir = std::env::temp_dir().join("tempest_test_sha_default_limit");
    std::fs::create_dir_all(&dir).unwrap();
    let file_path = dir.join("test.bin");
    std::fs::write(&file_path, b"test").unwrap();
    let result = compute_sha256(&file_path);
    assert!(result.is_ok());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn hashing_enforces_the_limit_against_bytes_actually_read() {
    let mut reader = std::io::Cursor::new(vec![0x5a; 9]);
    let error = hash_reader_with_limit(&mut reader, Some(8)).unwrap_err();

    assert!(error.to_string().contains("exceeded hashing limit"));
}

#[test]
fn test_hash_cache_invalidate_recompute() {
    let store = VersionStore::new();
    let dir = std::env::temp_dir().join("tempest_test_inval_recompute");
    std::fs::create_dir_all(&dir).unwrap();
    let file_path = dir.join("file.bin");
    std::fs::write(&file_path, b"original").unwrap();

    let hash1 = store.content_hash(&file_path).unwrap();
    store.invalidate_hash(&file_path);

    std::fs::write(&file_path, b"modified").unwrap();
    let hash2 = store.content_hash(&file_path).unwrap();

    assert_ne!(hash1, hash2);
    std::fs::remove_dir_all(&dir).ok();
}
