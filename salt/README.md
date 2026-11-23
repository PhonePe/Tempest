<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tempest Salt Formula

This directory contains a Salt formula for deploying Tempest with its runtime
configuration sourced from pillar data.

## Layout

- `top.sls` - example state top file targeting minions with the `roles: tempest` grain.
- `pillar/top.sls` - example pillar top file using the same target.
- `pillar/tempest.sls` - production-oriented example pillar with the important Tempest configuration fields.
- `tempest/` - state modules and Jinja templates.

## Basic Use

Copy or sync this directory into your Salt file roots, copy `pillar/tempest.sls`
into your pillar roots, then adjust the pillar values for each environment.

The example pillar installs a Linux archive built on a release tag with
`make rc-linux-* RC_TAG=` (`tempest:install:method: release`). Host the archive on your own artifact
server under `<base_url>/v<version>/`, then set `tempest:install:release:base_url`,
`version`, the platform (`linux-amd64`, `linux-arm64`, or `linux-amd64-gnu`),
and the archive's SHA-256 from the `.sha256` file written beside it. The state
refuses to run without all three pins, downloads
`tempest-<version>-<platform>.tar.gz`, verifies it, extracts it under
`/opt/tempest/<version>`, and installs the binary at `tempest:install:binary_path`.
These archives include SQL persistence.

To deploy a locally built binary instead, set `method: binary` and place it at
`salt://artifacts/tempest/tempest`. Build it with
`cargo build --release --features sql-persistence` when the deployment uses a
SQL control store; the default build has no SQL support.

The example pillar is secure by default: the HTTP API binds to `127.0.0.1` unless
you explicitly expose it and configure `tempest:api:api_key`, preferably as
`env:TEMPEST_API_KEY` with the value supplied from secret-backed pillar. The
formula renders the current `[persistence]` config section; enable it with a
PostgreSQL or MySQL/MariaDB URL when boot profiles, version groups, and sessions
must survive restarts or be shared by multiple Tempest nodes.

When deploying behind an HTTPS proxy, keep
`tempest:api:bind` on loopback and set `tempest:api:trusted_proxy_ips` to the exact
local proxy peer, normally `[127.0.0.1]`. The formula renders that list into the
core TOML. Deploy the separate proxy configuration and leaf certificates using
the host's existing proxy/certificate management; this formula does not issue
certificates or manage a CA private key.

Placing files in `/tftpboot` does not publish them. TFTP serves only members of
the active `default` release, or of a session's pinned release, so activate a
release through the versions API after deployment.

By default the systemd sandbox treats `/tftpboot` as read-only and allows writes
only to the log and run directories. If WRQ uploads or external integrity healing are
enabled, add the artifact root to `tempest:service:read_write_paths` and ensure
the root ownership/mode in `tempest:paths` still restricts writes to the intended
publisher or Tempest service account.

The formula exposes Tempest-owned audit rotation through `tempest:audit:rotate_max_bytes`
and `tempest:audit:rotate_keep_segments`. Prefer this over external `copytruncate`
for `/var/log/tempest/audit.jsonl` because Tempest owns durable group commits
and segment ordering. Audit output is unsigned. The same pillar section exposes
release-manifest signing and verification keys; set `require_signed_manifests:
true` only with at least one usable manifest key.

The formula manages `tempest.service` under systemd. By default the service is enabled, receives `SIGTERM` on stop, and has `TimeoutStopSec` set from `tempest:service:timeout_stop_sec` so graceful drain has a bounded stop window.
