# SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0

# Example pillar for the Tempest Salt formula.
#
# Keep environment-specific values here. The state files render these values into
# /etc/tempest/tempest.toml, the systemd unit, and optional observability config.

tempest:
  user: tempest
  group: tempest
  home: /var/lib/tempest

  install:
    # Supported values: release, binary, package, none.
    # `release` downloads an archive you built with `make rc-linux-*` and host
    # on your own artifact server, and verifies it against the sha256 written
    # beside it. Those archives include SQL persistence. `binary` copies a file
    # you place in the Salt file roots.
    method: release
    release:
      version: ""            # for example 0.1.0
      platform: linux-amd64  # linux-amd64, linux-arm64, or linux-amd64-gnu
      sha256: ""             # SHA-256 of tempest-<version>-<platform>.tar.gz
      base_url: https://artifacts.example.invalid/tempest  # serves v<version>/<archive>
      extract_dir: /opt/tempest
    binary_path: /usr/local/bin/tempest
    binary_source: salt://artifacts/tempest/tempest
    package_name: tempest
    setcap: true
    capability_package: libcap2-bin

  paths:
    config_dir: /etc/tempest
    config_file: /etc/tempest/tempest.toml
    env_file: /etc/tempest/tempest.env
    tftp_root: /tftpboot
    # Keep artifacts writable by the artifact publisher, but readable by Tempest.
    # For a dedicated publisher user, set tftp_root_user to that user and keep
    # tftp_root_group as tempest or another group the Tempest service belongs to.
    tftp_root_user: root
    tftp_root_group: tempest
    tftp_root_mode: '0750'
    log_dir: /var/log/tempest
    run_dir: /run/tempest
    audit_log: /var/log/tempest/audit.jsonl
    manifest_path: /tftpboot/manifest.json

  environment:
    manage: true
    mode: '0600'
    variables:
      # Prefer secret-backed pillar data in production.
      # TEMPEST_API_KEY: replace-with-at-least-16-characters
      # TEMPEST_DATABASE_URL: mysql://tempest:<secret>@db.example.net:3306/tempest
      RUST_LOG: info

  service:
    name: tempest
    enabled: true
    limit_nofile: 65536
    restart_sec: 5
    timeout_stop_sec: 30
    ambient_capabilities:
      - CAP_NET_BIND_SERVICE
    read_only_paths:
      - /tftpboot
    read_write_paths:
      - /var/log/tempest
      - /run/tempest

  server:
    bind: 0.0.0.0
    port: 69
    listener_shards: 0
    root: /tftpboot
    unmanaged_cache_validation_interval_ms: 0
    hot_artifact_cache_max_bytes: 67108864
    hot_artifact_cache_max_file_bytes: 2097152
    max_concurrent_transfers: 500
    tftp_requests_per_ip_per_second: 50
    http_requests_per_ip_per_second: 100
    default_block_size: 512
    max_window_size: 64
    accept_client_timeout: true
    retransmit_interval_ms: 1000
    min_retransmit_interval_ms: 250
    max_retransmit_interval_ms: 4000
    max_retries: 5
    listener_receive_buffer_bytes: 4194304
    transfer_socket_buffer_bytes: 0
    log_level: info
    json_logging: true
    write_enabled: false
    max_write_file_size: 536870912
    bandwidth_governor_enabled: true
    total_bandwidth_bytes_per_second: 125000000

  api:
    # Bind beyond loopback only when api_key is set to a strong value or env var.
    bind: 127.0.0.1
    port: 8080
    enable_metrics: true
    # Set false only when network policy limits /metrics to trusted Prometheus scrapers.
    metrics_require_api_key: true
    enable_versions_api: true
    enable_audit_api: true
    # Enable only for native UEFI firmware on a source-IP-preserving provisioning network.
    enable_native_http_boot: false
    native_http_boot_filename: boot.efi
    # Set this to env:TEMPEST_API_KEY when environment.variables.TEMPEST_API_KEY is populated.
    api_key: null
    # For the local HTTPS profile, set [127.0.0.1] and keep api.bind on loopback.
    # Trust only proxies that overwrite X-Forwarded-For with one source address.
    trusted_proxy_ips: []
    max_request_body_bytes: 1048576
    artifact_cache_max_bytes: 67108864
    artifact_cache_max_file_bytes: 16777216

  boot_phases:
    - name: PXE_ROM
      pattern: '(?i)(pxelinux\.0|undionly\.kpxe|ipxe\.\w+)$'
      block_size: 512
      max_window_size: 1
      retransmit_interval_ms: 200
      min_retransmit_interval_ms: 100
      max_retransmit_interval_ms: 1000
      max_retries: 10
    - name: IPXE
      pattern: '(?i)\.ipxe$'
      block_size: 1468
      max_window_size: 4
      retransmit_interval_ms: 300
      min_retransmit_interval_ms: 100
      max_retransmit_interval_ms: 1500
      max_retries: 5
    - name: KERNEL
      pattern: '(?i)(vmlinuz|bzImage|kernel)'
      block_size: 8192
      max_window_size: 32
      retransmit_interval_ms: 1000
      min_retransmit_interval_ms: 250
      max_retransmit_interval_ms: 4000
      max_retries: 5
    - name: INITRD
      pattern: '(?i)(initrd|initramfs)'
      block_size: 8192
      max_window_size: 32
      retransmit_interval_ms: 1000
      min_retransmit_interval_ms: 250
      max_retransmit_interval_ms: 4000
      max_retries: 5
    - name: OS_IMAGE
      pattern: '(?i)\.(img|iso|squashfs)$'
      block_size: 65464
      max_window_size: 64
      retransmit_interval_ms: 1000
      min_retransmit_interval_ms: 250
      max_retransmit_interval_ms: 4000
      max_retries: 3
    - name: CONFIG
      pattern: '(?i)(pxelinux\.cfg/|grub\.cfg|boot\.conf)'
      block_size: 512
      max_window_size: 1
      retransmit_interval_ms: 200
      min_retransmit_interval_ms: 100
      max_retransmit_interval_ms: 1000
      max_retries: 10

  dscp:
    ecn_enabled: false
    phase_dscp:
      PXE_ROM: 46
      KERNEL: 34
      INITRD: 26
      OS_IMAGE: 18
      CONFIG: 8

  audit:
    enabled: true
    # Bytes reserved by terminal records awaiting durable JSONL group commit.
    queue_max_bytes: 268435456
    # Tempest-owned audit rotation. 0 keeps every rotated segment.
    rotate_max_bytes: 1073741824
    rotate_keep_segments: 0
    log_path: /var/log/tempest/audit.jsonl
    manifest_signing_key_path: null
    manifest_verifying_key: null
    require_signed_manifests: false

  persistence:
    enabled: false
    # Enable in production HA or restart-survivable deployments, and populate
    # TEMPEST_DATABASE_URL through secret-backed pillar or an external secret file.
    database_url: env:TEMPEST_DATABASE_URL
    sync_interval_secs: 5

  observability:
    enabled: true
    prometheus:
      enabled: true
      install_package: false
      package_name: prometheus
      service_name: prometheus
      manage_service: false
      config_path: /etc/prometheus/conf.d/tempest.yml
      job_name: tempest
      scrape_interval: 15s
      metrics_path: /metrics
      targets:
        - 127.0.0.1:8080
    grafana:
      enabled: true
      install_package: false
      package_name: grafana
      service_name: grafana-server
      manage_service: false
      user: root
      group: root
      provisioning_dir: /etc/grafana/provisioning
      dashboard_dir: /var/lib/grafana/dashboards/tempest
      dashboard_source: salt://tempest/files/grafana/dashboards/tempest-dashboard.json
      datasource:
        name: Tempest Prometheus
        url: http://localhost:9090
        is_default: true
      dashboard_provider:
        name: Tempest
        folder: Tempest
