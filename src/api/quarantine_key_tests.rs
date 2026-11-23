// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use axum::body::to_bytes;
use tower::ServiceExt;

#[test]
fn quarantine_key_borrows_ordinary_relative_utf8() {
    let path = Path::new("/fixture/images/noyau-é.img");
    let relative = path.strip_prefix("/fixture").unwrap().to_str().unwrap();
    let key = quarantine_key_for_http_path(path, Path::new("/fixture")).unwrap();
    assert_eq!(&*key, "images/noyau-é.img");
    assert_eq!(key.as_ptr(), relative.as_ptr(), "ordinary key must borrow");
    assert!(
        quarantine_key_for_http_path(Path::new("/other/missing"), Path::new("/fixture")).is_none()
    );
}

#[test]
fn quarantine_key_preserves_normalization_and_canonical_fallback() {
    assert_eq!(
        &*quarantine_key_for_http_path(
            Path::new("/fixture/back\\slash.img"),
            Path::new("/fixture")
        )
        .unwrap(),
        "back/slash.img"
    );
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    std::fs::write(root.join("file.img"), b"fixture").unwrap();
    // Windows verbatim (canonical) paths resolve `..` on join, so use the lexical root.
    let lexical_root = directory.path();
    let aliased = lexical_root.join("missing/../file.img");
    // Lexical prefix behavior is intentionally unchanged, not new authority.
    assert_eq!(
        &*quarantine_key_for_http_path(&aliased, lexical_root).unwrap(),
        "missing/../file.img"
    );
    #[cfg(unix)]
    {
        let link = root.join("alias");
        std::os::unix::fs::symlink(&root, &link).unwrap();
        assert_eq!(
            &*quarantine_key_for_http_path(&link.join("file.img"), &root.join(".")).unwrap(),
            "alias/file.img"
        );
        let outside = tempfile::tempdir().unwrap();
        let outside_link = outside.path().join("alias");
        std::os::unix::fs::symlink(&root, &outside_link).unwrap();
        assert_eq!(
            &*quarantine_key_for_http_path(&outside_link.join("file.img"), &root).unwrap(),
            "file.img"
        );
    }
}

#[cfg(unix)]
#[test]
fn quarantine_key_preserves_lossy_non_utf8() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let path = Path::new(OsStr::from_bytes(b"/fixture/bad\xff\\name.img"));
    let key = quarantine_key_for_http_path(path, Path::new("/fixture")).unwrap();
    assert_eq!(&*key, "bad\u{fffd}/name.img");
}

#[tokio::test]
async fn quarantine_key_warm_cache_still_denies_and_releases_pins() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    std::fs::write(root.join("boot.img"), b"verified fixture").unwrap();
    let mut config = crate::config::TempestConfig::default();
    config.server.root = root.clone();
    config.api.enable_native_http_boot = true;
    config.api.native_http_boot_filename = "boot.img".into();
    config.audit.enabled = false;
    let server = crate::server::TftpServer::new(config);
    let state = server.state();
    state
        .version_store
        .atomic_switch_for_profile(
            "default".into(),
            "quarantine-fixture".into(),
            vec![("boot.img".into(), root.join("boot.img"))],
        )
        .unwrap();
    let ip = IpAddr::from([127, 0, 0, 1]);
    state.insert_boot_session(
        ip,
        BootSessionEntry {
            trace_id: Some("quarantine-regression".into()),
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
    let request = || {
        Request::builder()
            .uri("/boot/v1/boot.img")
            .extension(ConnectInfo(SocketAddr::new(ip, 40100)))
            .body(Body::empty())
            .unwrap()
    };
    let first = router.clone().oneshot(request()).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(first.into_body(), 1024).await.unwrap(),
        "verified fixture"
    );
    let pin = state
        .boot_sessions
        .get(&ip)
        .unwrap()
        .pinned_boot_chain
        .clone()
        .unwrap();
    state.quarantine_artifact("boot.img".into());
    let denied = router.oneshot(request()).await.unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    drop(denied);
    assert_eq!(state.active_transfers.load(Ordering::Acquire), 0);
    assert_eq!(
        state
            .version_store
            .pinned_count_for_profile("default", "boot.img", pin.version_id),
        0
    );
}
