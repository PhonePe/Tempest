// SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
// SPDX-License-Identifier: Apache-2.0

use std::process::Command;

fn tempest_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_tempest"))
}

#[test]
fn check_config_validates_without_starting_or_creating_the_artifact_root() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("must-not-be-created");
    let config_path = directory.path().join("tempest.toml");
    let root_value = toml::Value::String(root.to_string_lossy().into_owned()).to_string();
    std::fs::write(
        &config_path,
        format!(
            "[server]\nroot = {root_value}\n\
             [api]\nallow_insecure_loopback = true\n"
        ),
    )
    .unwrap();

    let output = tempest_command()
        .args(["--config", config_path.to_str().unwrap(), "--check-config"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "configuration valid\n"
    );
    assert!(!root.exists());
}

#[test]
fn print_effective_config_redacts_secrets_and_does_not_start_services() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("must-not-be-created");
    let config_path = directory.path().join("tempest.toml");
    let root_value = toml::Value::String(root.to_string_lossy().into_owned()).to_string();
    std::fs::write(
        &config_path,
        format!(
            "[server]\nroot = {root_value}\n\
             [api]\napi_key = 'literal-api-secret'\n\
             [persistence]\ndatabase_url = 'postgres://user:password@db/tempest'\n\
             [extensions.example]\ntoken = 'extension-secret'\n"
        ),
    )
    .unwrap();

    let output = tempest_command()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--print-effective-config",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains("literal-api-secret"));
    assert!(!stdout.contains("postgres://user:password@db/tempest"));
    assert!(!stdout.contains("extension-secret"));
    assert!(stdout.contains("api_key = \"<redacted>\""));
    assert!(stdout.contains("database_url = \"<redacted>\""));
    assert!(stdout.contains("example = \"<redacted>\""));
    assert!(stdout.contains("listener_shards = "));
    assert!(!stdout.contains("listener_shards = 0"));
    assert!(!root.exists());
}

#[test]
fn inspection_rejects_a_missing_configuration_file() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("missing.toml");

    let output = tempest_command()
        .args(["--config", config_path.to_str().unwrap(), "--check-config"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("configuration file does not exist"));
}

#[test]
fn check_config_validates_security_after_cli_overrides() {
    let directory = tempfile::tempdir().unwrap();
    let config_path = directory.path().join("tempest.toml");
    std::fs::write(
        &config_path,
        "[api]\nbind = '127.0.0.1'\nallow_insecure_loopback = true\n",
    )
    .unwrap();

    let output = tempest_command()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "--api-bind",
            "0.0.0.0",
            "--check-config",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("api.api_key is required"));
}
