// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::net::IpAddr;
use std::path::{Path, PathBuf};
#[cfg(all(feature = "sql-persistence", target_os = "linux"))]
use std::process::Command;

use tempest::config::TempestConfig;

fn repository_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn parse_example(relative: &str) -> TempestConfig {
    let content = std::fs::read_to_string(repository_path(relative)).unwrap();
    toml::from_str(&content).unwrap()
}

#[test]
fn dual_plane_examples_keep_service_addresses_and_state_explicit() {
    let l2 = parse_example("deploy/container/tempest-l2.toml.example");
    let l3 = parse_example("deploy/container/tempest-l3.toml.example");

    assert_ne!(l2.server.bind, IpAddr::from([0, 0, 0, 0]));
    assert_ne!(l3.server.bind, IpAddr::from([0, 0, 0, 0]));
    assert_ne!(l2.server.bind, l3.server.bind);
    assert_eq!(l2.api.bind, l2.server.bind);
    assert_eq!(l3.api.bind, l3.server.bind);
    assert_eq!(l2.server.listener_shards, 1);
    assert_eq!(l3.server.listener_shards, 5);

    for config in [&l2, &l3] {
        assert!(!config.server.write_enabled);
        assert!(config.api.metrics_require_api_key);
        assert_eq!(config.api.api_key.as_deref(), Some("env:TEMPEST_API_KEY"));
        assert!(config.persistence.enabled);
        assert_eq!(
            config.persistence.database_url.as_deref(),
            Some("env:TEMPEST_DATABASE_URL")
        );
        assert!(config.audit.enabled);
    }
}

#[test]
fn compose_profile_preserves_tftp_and_privilege_boundaries() {
    let compose =
        std::fs::read_to_string(repository_path("deploy/container/compose.dual-plane.yml"))
            .unwrap();

    assert_eq!(compose.matches("network_mode: host").count(), 1);
    assert!(compose.contains("cap_drop:\n    - ALL"));
    assert!(compose.contains("- NET_BIND_SERVICE"));
    assert!(compose.contains("no-new-privileges:true"));
    assert!(compose.contains("read_only: true"));
    assert!(!compose.contains("privileged: true"));
    assert!(!compose.contains("ports:"));
}

#[test]
fn https_profile_includes_required_environment_template() {
    let compose =
        std::fs::read_to_string(repository_path("deploy/container/https/compose.yml")).unwrap();
    let environment =
        std::fs::read_to_string(repository_path("deploy/container/https/.env.example")).unwrap();

    for variable in ["TEMPEST_TLS_IMAGE", "TEMPEST_TLS_CONFIG", "TEMPEST_TLS_DIR"] {
        assert!(compose.contains(&format!("${{{variable}:?")));
        assert!(environment.lines().any(|line| {
            line.strip_prefix(variable)
                .and_then(|value| value.strip_prefix('='))
                .is_some_and(|value| !value.trim().is_empty())
        }));
    }
}

#[test]
fn https_profile_uses_unprivileged_port_without_relaxing_host_security() {
    let compose =
        std::fs::read_to_string(repository_path("deploy/container/https/compose.yml")).unwrap();
    let nginx =
        std::fs::read_to_string(repository_path("deploy/container/https/nginx.conf.example"))
            .unwrap();

    let listeners: Vec<_> = nginx
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("listen "))
        .collect();
    assert_eq!(listeners, ["listen 8443 ssl;"]);
    for setting in [
        "network_mode: host",
        "user: \"101:101\"",
        "read_only: true",
        "cap_drop:\n      - ALL",
        "no-new-privileges:true",
    ] {
        assert!(compose.contains(setting), "missing {setting}");
    }
    for setting in [
        "cap_add:",
        "NET_BIND_SERVICE",
        "privileged:",
        "sysctls:",
        "ports:",
    ] {
        assert!(!compose.contains(setting), "unexpected {setting}");
    }
}

#[test]
fn https_profile_exposes_only_bearer_artifacts_and_preserves_client_identity() {
    let nginx =
        std::fs::read_to_string(repository_path("deploy/container/https/nginx.conf.example"))
            .unwrap();
    let locations: Vec<_> = nginx
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("location "))
        .collect();
    assert_eq!(locations, ["location /api/v1/artifacts/ {", "location / {"]);
    assert_eq!(nginx.matches("proxy_pass ").count(), 1);
    assert!(nginx.contains("location / {\n            return 404;\n        }"));
    // Nginx permits HEAD whenever GET is allowed by limit_except.
    assert!(nginx.contains("limit_except GET { deny all; }"));
    for directive in [
        "proxy_set_header Authorization $http_authorization;",
        "proxy_set_header X-Forwarded-For $remote_addr;",
        "proxy_set_header X-Real-IP $remote_addr;",
        "proxy_set_header Forwarded \"\";",
        "proxy_buffering off;",
        "proxy_cache off;",
    ] {
        assert!(nginx.contains(directive), "missing {directive}");
    }
}

#[cfg(all(feature = "sql-persistence", target_os = "linux"))]
#[test]
fn packaged_binary_accepts_both_dual_plane_configs() {
    for relative in [
        "deploy/container/tempest-l2.toml.example",
        "deploy/container/tempest-l3.toml.example",
    ] {
        // CI checkouts may be group- or world-writable (some runners use umask
        // 0000), which Tempest correctly rejects, so check a private copy.
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("tempest.toml");
        std::fs::copy(repository_path(relative), &config).unwrap();
        std::fs::set_permissions(&config, std::os::unix::fs::PermissionsExt::from_mode(0o644))
            .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_tempest"))
            .args(["--config", config.to_str().unwrap(), "--check-config"])
            .env("TEMPEST_API_KEY", "container-test-api-key-2026")
            .env(
                "TEMPEST_DATABASE_URL",
                "postgres://tempest:example@127.0.0.1/tempest",
            )
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "{relative}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.stdout, b"configuration valid\n");
    }
}
