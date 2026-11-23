<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tempest Local Test Runbook

This document explains how to run Tempest locally, exercise the simulated L2 demo, test coordinated boot-image upgrades, assign clients to boot profiles, verify retained releases, and inspect Prometheus/Grafana telemetry.

## What This Covers

- Native local Tempest on an unprivileged TFTP port.
- Podman-based simulated dual-stack L2 environment with real IPv4 and IPv6 Tempest listeners and a disposable reference client.
- Version-group upgrade testing through `/api/v1/versions/switch`, including the backward-compatible `default` boot profile.
- Multi-flavour boot selection through `/api/v1/sessions` for client-IP, MAC, serial, trace metadata, and boot-epoch pinning, including a dnsmasq-style Option 67 wiring proof and a fixed-URI native HTTP Boot proof in the Podman demo.
- Durable control-plane recovery through Postgres in the local demo; the same persistence layer supports `postgres://` and `mysql://` URLs for PostgreSQL, MariaDB, or Percona.
- Capability-confined release verification through `/api/v1/versions/verify`.
- Prometheus and Grafana for local observability.
- Debugging commands for logs, API state, audit records, and common failures.

## Prerequisites

Native local run:

```bash
cargo --version
python3 --version
curl --version
```

Simulated L2 demo:

```bash
podman --version
python3 --version
podman machine start
podman info --format '{{.Host.NetworkBackend}}'
```

The Podman network backend should be `netavark`. The demo runner accepts either `podman-compose` or the `podman compose` plugin.

Optional but useful:

```bash
jq --version
```

If `jq` is not installed, replace `| jq` with `| python3 -m json.tool` in the curl examples.

## Run Mode Port And Path Map

Use the native and Podman flows independently. They intentionally use different host API ports and different file paths:

| Mode | API variable | HTTP API | TFTP endpoint | Artifact paths in API requests |
| --- | --- | --- | --- | --- |
| Native local binary | `NATIVE_API` | `http://127.0.0.1:18081` | `127.0.0.1:6969` | Host paths under `$TEMPEST_ROOT`, for example `$TEMPEST_ROOT/releases/v3/vmlinuz` |
| Podman L2 demo | `DEMO_API` | IPv4 host `http://127.0.0.1:18080`; IPv6 container `[fd89:60::11]:8080` | IPv4 host `127.0.0.1:16969`, IPv4 container `tempest:6969`, IPv6 container `[fd89:60::11]:6969` | Container paths under `/tftpboot`, for example `/tftpboot/releases/v3/vmlinuz` |

Do not use `/tftpboot/...` paths with the native local binary. That path exists inside the Podman Tempest container, not on the host process started by `cargo run`.

## Quick Automated Demo

From the repository root:

```bash
python3 demo/l2-flat/demo.py check
python3 demo/l2-flat/demo.py run
```

The automated demo does the following:

1. Builds the current Tempest binary.
2. Seeds `demo/l2-flat/tftpboot/releases/v1`, `demo/l2-flat/tftpboot/releases/v2`, `demo/l2-flat/tftpboot/releases/ubuntu-focal`, `demo/l2-flat/tftpboot/releases/rhel9`, and typical Option 67 paths such as `ipxe/undionly.kpxe`, `rhel9-efi/x86_64-efi/core.efi`, `jammy-efi/syslinux.efi`, `bookworm-efi/ipxe.efi`, and `installer.ipxe`.
3. Writes a standalone checksum inventory for inspecting the seeded demo files.
4. Starts Postgres plus Tempest in a Podman L2 bridge network, publishing host UDP `16969` and host HTTP `18080` while using UDP `6969` and HTTP `8080` inside the container network.
5. Deploys `release-v1` to the `default` boot profile through the versions API.
6. Downloads PXE, kernel, initrd, and OS-image artifacts using the demo TFTP client.
7. Keeps a `release-v1` OS-image transfer pinned while trying to activate `release-v2`.
8. Verifies the drain-gated cutover returns HTTP `409` while the old release is pinned.
9. Activates `release-v2` in the `default` boot profile after the pin drains.
10. Deploys independent `ubuntu-focal` and `rhel9` profile releases with the same logical TFTP names.
11. Registers boot sessions from a compact dnsmasq-style wiring table: for example, `focal + bios + !ipxe` selects `ipxe/undionly.kpxe` while binding the client to boot profile `ubuntu-focal`, and `efi64 + rhel9` selects `rhel9-efi/x86_64-efi/core.efi` while binding the client to boot profile `rhel9`.
12. Downloads the advertised first-stage Option 67 file, then downloads ordinary logical names such as `vmlinuz` and verifies they resolve through the session-pinned boot profile.
13. Fetches the same `/boot/v1/boot.efi` URI without a bearer header and verifies the source-IP session selects the profile-specific managed artifact.
14. Verifies a pinned Focal wiring decision rejects a direct RHEL profile change until the demo registers `new_epoch=true` for a new PXE attempt.
15. Restarts Tempest and verifies the default, Focal, and RHEL version groups plus the unexpired boot-session pin recover from Postgres before bearer and native profile downloads.
16. Starts the IPv6-only listener, then validates managed TFTP, bearer HTTP, source-IP native HTTP Boot, and native session recovery from the fixed IPv6 client address.
17. Prints Prometheus metric lines for aggregate and boot-profile-labeled versions, transfers, sessions, and admission, including the `HTTP_NATIVE` transport.

On macOS, the demo builds the Tempest binary inside a Linux Rust builder container before packaging the runtime image. The first run can take a few minutes while Rust dependencies are downloaded and compiled; later runs reuse `demo/l2-flat/build/cargo-target`.

Run only the IPv6 lane when validating address-family changes:

```bash
python3 demo/l2-flat/demo.py ipv6
```

The lane uses ULA addresses on the Podman bridge and a software reference
client. It does not exercise Router Advertisements, DHCPv6 boot options, or
physical firmware. Treat it as Tempest transport, session, persistence, and
artifact-path evidence—not firmware interoperability evidence.

If the default published ports are occupied, select alternatives before
running the demo:

```bash
TEMPEST_DEMO_API_PORT=18081 \
TEMPEST_DEMO_TFTP_PORT=16970 \
  python3 demo/l2-flat/demo.py ipv6
```

Tear down the demo:

```bash
python3 demo/l2-flat/demo.py down
```

Clean generated files and containers:

```bash
python3 demo/l2-flat/demo.py clean
```

## Simulated L2 Environment With Observability

Use this when you want Tempest, Prometheus, and Grafana running together while you manually test API calls and TFTP downloads.

```bash
python3 demo/l2-flat/demo.py observe
```

This starts:

- Postgres persistence DB: `127.0.0.1:15432`
- Tempest TFTP: `127.0.0.1:16969/udp` on the host, `tempest:6969/udp` inside the demo network
- Tempest HTTP/API/metrics: `http://127.0.0.1:18080`
- Prometheus: `http://127.0.0.1:9090`
- Grafana: `http://127.0.0.1:3000` by default, or the fallback port printed by the runner if `3000` is already in use

If another local Grafana or web app is already listening on host port `3000`, the observe command automatically publishes the demo Grafana container on the first free port in the `13000`-`13099` range and prints the exact URL. To choose the host port yourself, set `TEMPEST_DEMO_GRAFANA_PORT`:

```bash
TEMPEST_DEMO_GRAFANA_PORT=13000 python3 demo/l2-flat/demo.py observe
```

Grafana credentials:

```text
admin / tempest
```

Grafana is provisioned with the Prometheus datasource and the `Tempest TFTP Server` dashboard under the `Tempest` folder.

Useful checks:

```bash
export DEMO_API="http://127.0.0.1:18080"
export API_KEY="tempest-demo-key-2026"

curl -sS "$DEMO_API/health"
curl -sS "$DEMO_API/ready"
curl -sS -H "x-api-key: $API_KEY" "$DEMO_API/api/v1/info" | jq
curl -sS -H "x-api-key: $API_KEY" "$DEMO_API/metrics" | grep '^tempest_'
```

Prometheus targets page:

```text
http://127.0.0.1:9090/targets
```

Prometheus queries to try:

```text
tempest_active_transfers
tempest_transfers_total
tempest_transfers_by_profile_total
tempest_transfer_bytes_total
tempest_transfer_bytes_by_profile_total
tempest_version_groups_total
tempest_version_groups_by_profile
tempest_active_versions
tempest_active_versions_by_profile
tempest_active_boot_sessions
tempest_hot_artifact_cache_hits_total
tempest_hot_artifact_cache_verified_hits_total
tempest_hot_artifact_cache_freshness_hits_total
tempest_hot_artifact_cache_misses_total
tempest_hot_artifact_cache_resident_bytes
tempest_listener_shard_requests_total
tempest_runtime_worker_busy_seconds_total
rate(tempest_transfer_bytes_total[1m])
rate(tempest_transfer_bytes_by_profile_total[1m])
histogram_quantile(0.95, rate(tempest_transfer_duration_seconds_bucket[5m]))
histogram_quantile(0.95, rate(tempest_transfer_duration_by_profile_seconds_bucket[5m]))
```

## Durable Control-Plane State

Tempest treats boot profiles, version groups, active versions, and boot sessions as control-plane state. When persistence is enabled, that state is stored in a SQL database and the in-process maps are only hot-path caches. On restart, Tempest hydrates the version store and active boot sessions from the database before accepting traffic, including each session's boot epoch and pinned group/version/manifest identity. During a multi-node deployment, multiple Tempest servers can point at the same database and periodically refresh their local caches so a version switch or session registration made through one node becomes visible to the others.

The local Podman demo enables this path with Postgres:

```toml
[persistence]
enabled = true
database_url = "env:TEMPEST_DATABASE_URL"
sync_interval_secs = 2
```

The compose file sets `TEMPEST_DATABASE_URL` to:

```text
postgres://tempest:tempest-demo-password@postgres:5432/tempest
```

For MariaDB or Percona, use a MySQL-compatible URL instead:

```text
mysql://tempest:password@mariadb-host:3306/tempest
```

Manual DB checks for the local demo:

```bash
cd demo/l2-flat
podman compose -f compose.yml exec postgres \
  psql -U tempest -d tempest \
  -c 'select boot_profile, group_id, active from tempest_version_groups order by boot_profile, version_id;'

podman compose -f compose.yml exec postgres \
  psql -U tempest -d tempest \
  -c 'select client_ip, boot_profile, boot_epoch, pinned_group_id, pinned_manifest_digest, trace_id, expires_at from tempest_boot_sessions order by client_ip;'
cd ../..
```

Manual restart recovery check:

```bash
cd demo/l2-flat
podman compose -f compose.yml restart tempest
cd ../..

export DEMO_API="http://127.0.0.1:18080"
export API_KEY="tempest-demo-key-2026"

curl -sS -H "x-api-key: $API_KEY" \
  "$DEMO_API/api/v1/versions/groups" | jq '.items | map({boot_profile, group_id})'
curl -sS -H "x-api-key: $API_KEY" \
  "$DEMO_API/metrics" | grep -E 'tempest_(version_groups_by_profile|active_versions_by_profile|transfers_by_profile_total)'
```

## Native Local Run

Use this when you want to run the Rust binary directly on your host without containers. This is the fastest loop for code changes, unit tests, logging, and simple TFTP RRQ checks.

### Controlled LAN performance profile

For a repeatable comparison on a trusted, immutable artifact root, these
settings remove unmanaged HTTP cache revalidation from the per-request path and
decline the client's RFC 2349 timeout option:

```toml
[server]
listener_shards = 0
tftp_requests_per_ip_per_second = 0
http_requests_per_ip_per_second = 0
unmanaged_cache_validation_interval_ms = 250
hot_artifact_cache_max_bytes = 536870912
hot_artifact_cache_max_file_bytes = 134217728
accept_client_timeout = false
retransmit_interval_ms = 1000
min_retransmit_interval_ms = 250
max_retransmit_interval_ms = 4000
bandwidth_governor_enabled = false
log_level = "warn"
json_logging = false
```

Declining the option is different from acknowledging it and retransmitting
early. Tempest omits `timeout` from OACK, as permitted by RFC 2347, and uses the
bounded adaptive policy above. A standards-compliant client ignores the omitted
option. Verify client behavior before using this profile with firmware, and
leave `accept_client_timeout = true` when the peer requires an exact negotiated
interval.

The cache interval applies only to unmanaged HTTP compatibility reads and can
delay visibility of a replacement by up to 250 ms. TFTP serves only managed
release members, so this setting does not affect TFTP benchmarks; managed
releases continue using their digest-verified snapshots. Use the default value
of zero when immediate unmanaged-file replacement visibility is required.

The cache limits above retain one 100 MiB comparison image on hosts with a
reviewed memory budget. Large cold entries populate on a bounded background
lane while requesters stream from their capability-opened handles; they do not
wait behind the memory copy. Keep the conservative 64 MiB/2 MiB defaults when
large-image retention does not improve a repeated run. Automatic listener
sharding uses the DUT's available CPU count; fix the value explicitly when the
benchmark harness changes CPU affinity. Disabling the per-source limiter and
bandwidth governor is appropriate only on the isolated comparison network.

Seed a small local TFTP root:

```bash
export TEMPEST_ROOT="$PWD/.tmp/tftpboot"
export TEMPEST_DOWNLOADS="$PWD/.tmp/downloads"
rm -rf "$TEMPEST_ROOT" "$TEMPEST_DOWNLOADS"
mkdir -p "$TEMPEST_ROOT/releases/v1" "$TEMPEST_ROOT/releases/v2" "$TEMPEST_DOWNLOADS"

printf 'release-v1:pxe\n' > "$TEMPEST_ROOT/releases/v1/pxelinux.0"
printf 'release-v1:kernel\n' > "$TEMPEST_ROOT/releases/v1/vmlinuz"
printf 'release-v1:initrd\n' > "$TEMPEST_ROOT/releases/v1/initrd.img"
printf 'release-v1:osimage\n' > "$TEMPEST_ROOT/releases/v1/rootfs.img"

printf 'release-v2:pxe\n' > "$TEMPEST_ROOT/releases/v2/pxelinux.0"
printf 'release-v2:kernel\n' > "$TEMPEST_ROOT/releases/v2/vmlinuz"
printf 'release-v2:initrd\n' > "$TEMPEST_ROOT/releases/v2/initrd.img"
printf 'release-v2:osimage\n' > "$TEMPEST_ROOT/releases/v2/rootfs.img"
```

Run Tempest on unprivileged UDP port `6969` and HTTP API port `18081`. Without
`--config`, Tempest loads `config/tempest.toml`, which reads the control API key
from `TEMPEST_API_KEY` (`api_key = "env:TEMPEST_API_KEY"`, at least 16
characters); startup fails if the variable is missing or empty. Generate a
local key and export it in both terminals:

```bash
export TEMPEST_API_KEY="$(openssl rand -hex 32)"
cargo run -- --port 6969 --api-port 18081 --root "$TEMPEST_ROOT" --log-level debug
```

Keep that process running in one terminal. In another terminal, export the same `TEMPEST_API_KEY` value and activate `release-v1`. The version, audit, and metrics routes all require the `x-api-key` header under the shipped configuration.

If you repeat this flow against the same running Tempest process, either restart the native Tempest process first or use fresh `group_id` values such as `release-v1-rerun-1`. Group IDs are intentionally immutable within each boot profile.

```bash
export NATIVE_API="http://127.0.0.1:18081"
export API_KEY="$TEMPEST_API_KEY"
export TEMPEST_ROOT="$PWD/.tmp/tftpboot"

curl -sS -X POST "$NATIVE_API/api/v1/versions/switch" \
  -H "x-api-key: $API_KEY" \
  -H 'content-type: application/json' \
  -d "{
    \"boot_profile\": \"default\",
    \"group_id\": \"release-v1\",
    \"drain_timeout_ms\": 30000,
    \"files\": [
      {\"name\": \"pxelinux.0\", \"path\": \"$TEMPEST_ROOT/releases/v1/pxelinux.0\"},
      {\"name\": \"vmlinuz\", \"path\": \"$TEMPEST_ROOT/releases/v1/vmlinuz\"},
      {\"name\": \"initrd.img\", \"path\": \"$TEMPEST_ROOT/releases/v1/initrd.img\"},
      {\"name\": \"rootfs.img\", \"path\": \"$TEMPEST_ROOT/releases/v1/rootfs.img\"}
    ]
  }" | jq
```

Download the active logical kernel through TFTP:

```bash
python3 demo/l2-flat/client/tftp_client.py \
  --server 127.0.0.1 \
  --port 6969 \
  --file vmlinuz \
  --output "$TEMPEST_DOWNLOADS/vmlinuz-v1.bin" \
  --blksize 512 \
  --trace-id native-v1-kernel \
  --expect-marker release-v1:kernel
```

Activate `release-v2`:

```bash
curl -sS -X POST "$NATIVE_API/api/v1/versions/switch" \
  -H "x-api-key: $API_KEY" \
  -H 'content-type: application/json' \
  -d "{
    \"boot_profile\": \"default\",
    \"group_id\": \"release-v2\",
    \"drain_timeout_ms\": 30000,
    \"files\": [
      {\"name\": \"pxelinux.0\", \"path\": \"$TEMPEST_ROOT/releases/v2/pxelinux.0\"},
      {\"name\": \"vmlinuz\", \"path\": \"$TEMPEST_ROOT/releases/v2/vmlinuz\"},
      {\"name\": \"initrd.img\", \"path\": \"$TEMPEST_ROOT/releases/v2/initrd.img\"},
      {\"name\": \"rootfs.img\", \"path\": \"$TEMPEST_ROOT/releases/v2/rootfs.img\"}
    ]
  }" | jq
```

Download again and verify the marker changed:

```bash
python3 demo/l2-flat/client/tftp_client.py \
  --server 127.0.0.1 \
  --port 6969 \
  --file vmlinuz \
  --output "$TEMPEST_DOWNLOADS/vmlinuz-v2.bin" \
  --blksize 512 \
  --trace-id native-v2-kernel \
  --expect-marker release-v2:kernel
```

Inspect active versions and version groups:

```bash
curl -sS -H "x-api-key: $API_KEY" "$NATIVE_API/api/v1/versions" | jq
curl -sS -H "x-api-key: $API_KEY" "$NATIVE_API/api/v1/versions/groups" | jq
curl -sS -H "x-api-key: $API_KEY" "$NATIVE_API/metrics" | grep -E 'tempest_(version_groups_total|active_versions|transfers_total|transfer_bytes_total)'
```

Optional native-local `release-v3` upgrade:

```bash
mkdir -p "$TEMPEST_ROOT/releases/v3"
printf 'release-v3:pxe\n' > "$TEMPEST_ROOT/releases/v3/pxelinux.0"
printf 'release-v3:kernel\n' > "$TEMPEST_ROOT/releases/v3/vmlinuz"
printf 'release-v3:initrd\n' > "$TEMPEST_ROOT/releases/v3/initrd.img"
printf 'release-v3:osimage\n' > "$TEMPEST_ROOT/releases/v3/rootfs.img"

curl -sS -X POST "$NATIVE_API/api/v1/versions/switch" \
  -H "x-api-key: $API_KEY" \
  -H 'content-type: application/json' \
  -d "{
    \"boot_profile\": \"default\",
    \"group_id\": \"release-v3\",
    \"drain_timeout_ms\": 30000,
    \"files\": [
      {\"name\": \"pxelinux.0\", \"path\": \"$TEMPEST_ROOT/releases/v3/pxelinux.0\"},
      {\"name\": \"vmlinuz\", \"path\": \"$TEMPEST_ROOT/releases/v3/vmlinuz\"},
      {\"name\": \"initrd.img\", \"path\": \"$TEMPEST_ROOT/releases/v3/initrd.img\"},
      {\"name\": \"rootfs.img\", \"path\": \"$TEMPEST_ROOT/releases/v3/rootfs.img\"}
    ]
  }" | jq
```

The native local flow is complete at this point. The following manual sections use the Podman demo port/path model unless a command explicitly says native-local: `DEMO_API=http://127.0.0.1:18080` and artifact paths under `/tftpboot`.

## Version-Group Upgrade As A Manifest Unit

The main upgrade primitive is `POST /api/v1/versions/switch`. The request supplies a `group_id`, an optional `boot_profile`, and the boot artifacts that should switch together. Tempest computes each artifact hash and size, builds a boot-chain manifest internally, exposes `manifest_digest` in the API response, and atomically publishes the new logical names inside that profile.

Important behavior:

- `group_id` is immutable and cannot be reused.
- `boot_profile` is the release namespace clients should resolve against. If omitted, Tempest uses `default` for backward compatibility.
- `files[].name` is the logical TFTP name clients request, such as `vmlinuz` or `pxelinux.cfg/default`. Safe relative paths are allowed; traversal, absolute paths, backslashes, and control characters are rejected.
- `files[].path` is the absolute path as seen by the Tempest process.
- In-flight transfers stay pinned to the version and boot profile they started with.
- A drain-gated switch waits for old pins in the same boot profile to drain up to `drain_timeout_ms`.
- If old pins do not drain in time, the API returns HTTP `409`.

In the Podman demo, paths must be container paths under `/tftpboot`, not host paths. Do not use this snippet for the native local run above. Example manual Podman `release-v3` upgrade:

If you already deployed `release-v3` in the same running demo, use a fresh `group_id` such as `release-v3-rerun-1` or restart/recreate the demo.

```bash
mkdir -p demo/l2-flat/tftpboot/releases/v3
printf 'release-v3:pxe\n' > demo/l2-flat/tftpboot/releases/v3/pxelinux.0
printf 'release-v3:kernel\n' > demo/l2-flat/tftpboot/releases/v3/vmlinuz
printf 'release-v3:initrd\n' > demo/l2-flat/tftpboot/releases/v3/initrd.img
printf 'release-v3:osimage\n' > demo/l2-flat/tftpboot/releases/v3/rootfs.img

python3 demo/l2-flat/demo.py manifest
```

Activate it through the demo API:

```bash
export DEMO_API="http://127.0.0.1:18080"
export API_KEY="tempest-demo-key-2026"

curl -sS -X POST "$DEMO_API/api/v1/versions/switch" \
  -H "x-api-key: $API_KEY" \
  -H 'content-type: application/json' \
  -d '{
    "boot_profile": "default",
    "group_id": "release-v3",
    "drain_timeout_ms": 30000,
    "files": [
      {"name": "pxelinux.0", "path": "/tftpboot/releases/v3/pxelinux.0"},
      {"name": "vmlinuz", "path": "/tftpboot/releases/v3/vmlinuz"},
      {"name": "initrd.img", "path": "/tftpboot/releases/v3/initrd.img"},
      {"name": "rootfs.img", "path": "/tftpboot/releases/v3/rootfs.img"}
    ]
  }' | jq
```

Verify the new logical kernel is served:

```bash
cd demo/l2-flat
podman compose -f compose.yml run --rm --no-deps client \
  --server tempest \
  --port 6969 \
  --file vmlinuz \
  --output /downloads/vmlinuz-v3.bin \
  --blksize 512 \
  --trace-id demo-v3-kernel \
  --expect-marker release-v3:kernel
cd ../..
```

Rollback to a previous registered group:

```bash
curl -sS -X POST "$DEMO_API/api/v1/versions/rollback" \
  -H "x-api-key: $API_KEY" \
  -H 'content-type: application/json' \
  -d '{"boot_profile":"default","group_id":"release-v2"}'
```

## Multi-Flavour Boot Profiles

Use `boot_profile` when one Tempest server must host several operating-system or hardware flavours with the same logical TFTP names. For example, `ubuntu-jammy`, `ubuntu-focal`, `rhel9`, `rocky9`, and `debian12` can each have an independent active `vmlinuz`, `initrd.img`, `rootfs.img`, and `pxelinux.cfg/default`.

Activate a Focal release in its own profile. The `observe` and `run` commands seed `demo/l2-flat/tftpboot/releases/ubuntu-focal` automatically; if you are preparing the files without starting the stack, run `python3 demo/l2-flat/demo.py seed` first. Inside the Tempest container, that seeded directory is visible as `/tftpboot/releases/ubuntu-focal`. Do not use `/tftpboot/releases/focal` or `pxelinux.cfg/default` with the seeded demo files; those paths are not created by the demo runner.

```bash
export DEMO_API="http://127.0.0.1:18080"
export API_KEY="tempest-demo-key-2026"

curl -sS -X POST "$DEMO_API/api/v1/versions/switch" \
  -H "x-api-key: $API_KEY" \
  -H 'content-type: application/json' \
  -d '{
    "boot_profile": "ubuntu-focal",
    "group_id": "ubuntu-focal-manual-1",
    "drain_timeout_ms": 30000,
    "files": [
      {"name": "pxelinux.0", "path": "/tftpboot/releases/ubuntu-focal/pxelinux.0"},
      {"name": "vmlinuz", "path": "/tftpboot/releases/ubuntu-focal/vmlinuz"},
      {"name": "initrd.img", "path": "/tftpboot/releases/ubuntu-focal/initrd.img"},
      {"name": "rootfs.img", "path": "/tftpboot/releases/ubuntu-focal/rootfs.img"}
    ]
  }' | jq
```

If you repeat this command against the same running demo, use a fresh `group_id`; group IDs are immutable within each boot profile.

Before triggering PXE for a host, have the orchestrator register the selected profile and any identity metadata it knows:

```bash
curl -sS -X POST "$DEMO_API/api/v1/sessions" \
  -H "x-api-key: $API_KEY" \
  -H 'content-type: application/json' \
  -d '{
    "client_ip": "10.0.1.42",
    "client_mac": "aa:bb:cc:dd:ee:ff",
    "serial": "SN-ABC-123",
    "boot_profile": "ubuntu-focal",
    "trace_id": "prov-abc123",
    "ttl_seconds": 900
  }'
```

The TFTP request still asks for ordinary logical names like `vmlinuz`. Tempest resolves those names against the registered `ubuntu-focal` profile for the session TTL and pins the boot-chain manifest for that boot epoch. Later RRQs from the same client IP continue using that pinned release even if the active Focal release changes while the host is booting. Tempest also writes `boot_profile`, `client_mac`, `client_serial`, and `trace_id` into audit records when available. The same logical names can simultaneously be active in `ubuntu-jammy`, `rhel9`, or any other valid profile without interfering with the Focal release.

If the same client IP must intentionally move to a different profile before the old session expires, the orchestrator must register a new PXE attempt explicitly:

```bash
curl -sS -X POST "$DEMO_API/api/v1/sessions" \
  -H "x-api-key: $API_KEY" \
  -H 'content-type: application/json' \
  -d '{
    "client_ip": "10.0.1.42",
    "client_mac": "aa:bb:cc:dd:ee:ff",
    "serial": "SN-ABC-123",
    "boot_profile": "rhel9",
    "trace_id": "prov-abc123-rhel9",
    "ttl_seconds": 900,
    "new_epoch": true
  }'
```

Without `new_epoch=true`, a profile change on a pinned session returns HTTP `409` with `Active boot session is pinned; use new_epoch=true for a new PXE boot attempt`.

When persistence is enabled, the profile release set and the boot session are stored in the SQL database. A Tempest restart reloads the active `ubuntu-focal` release and any unexpired sessions from that database; a second Tempest node pointed at the same database can refresh the same state through its sync loop.

TFTP packets themselves are not treated as a trusted source of MAC or serial identity. Those fields should come from the authenticated provisioning control plane, inventory system, DHCP lease data, or BMC workflow that calls `/api/v1/sessions`.

## Release Integrity Verification

Tempest core owns filesystem verification so it uses the same retained
logical-to-physical mapping and capability-confined root as the transfer path.
Fetch one coherent control-plane snapshot, then ask core to rehash a bounded
artifact batch from a retained group:

```bash
export DEMO_API="http://127.0.0.1:18080"
export API_KEY="tempest-demo-key-2026"

curl -sS -H "x-api-key: $API_KEY" \
  "$DEMO_API/api/v1/versions/snapshot" | jq

curl -sS -X POST "$DEMO_API/api/v1/versions/verify" \
  -H "x-api-key: $API_KEY" \
  -H 'content-type: application/json' \
  -d '{
    "boot_profile": "default",
    "group_id": "release-v2",
    "manifest_digest": "<manifest_digest from the snapshot>",
    "files": ["pxelinux.0", "vmlinuz", "initrd.img", "rootfs.img"]
  }' | jq
```

A clean release returns `{"verified":true}`. Missing, replaced, resized, or
digest-mismatched bytes return `{"verified":false}`; transient internal I/O
failures return an error instead of being classified as corruption.

An external integrity controller can consume these two authenticated endpoints.
For example, it can verify active releases within configured byte budgets and
roll back to the newest verified historical group, or withdraw the active group
when no verified fallback exists. Core does not contain a manifest-file watcher,
quarantine scanner, artifact downloader, or automatic repair service.

## Prometheus And Grafana

Start the observability stack:

```bash
python3 demo/l2-flat/demo.py observe
```

Prometheus scrape config is in:

```text
demo/l2-flat/prometheus.yml
```

Prometheus scrapes:

```text
tempest:8080/metrics
```

The demo sets `metrics_require_api_key = false` only on its isolated container
network so Prometheus can scrape without receiving the control-plane API key.
Production deployments should keep the secure default or enforce equivalent
network/reverse-proxy access control around `/metrics`.

Check scrape health:

```text
http://127.0.0.1:9090/targets
```

Open Grafana:

```text
http://127.0.0.1:3000
```

If `python3 demo/l2-flat/demo.py observe` reports a fallback Grafana port because `3000` is busy, open the printed URL instead, for example `http://127.0.0.1:13000`. You can also pin the host port explicitly with `TEMPEST_DEMO_GRAFANA_PORT=13000`.

Open `Dashboards -> Tempest -> Tempest TFTP Server`.

Panels to watch during tests:

- `Active Transfers`
- `Version Groups`
- `Active Versions`
- `Transfer Rate by Phase`
- `Bytes Throughput by Phase`

Metrics endpoint without Prometheus:

```bash
export DEMO_API="http://127.0.0.1:18080"
export API_KEY="tempest-demo-key-2026"

curl -sS -H "x-api-key: $API_KEY" \
  "$DEMO_API/metrics" | grep -E 'tempest_(active_transfers|transfers_total|transfer_bytes_total|version_groups_total|active_versions)'
```

## Debugging

Run Rust with verbose logs:

```bash
RUST_LOG=tempest=debug,tower_http=info cargo run -- --port 6969 --api-port 18081 --root "$TEMPEST_ROOT" --log-level debug
```

Follow demo logs:

```bash
cd demo/l2-flat
podman compose -f compose.yml logs -f tempest
```

Inspect Prometheus and Grafana logs:

```bash
cd demo/l2-flat
podman compose -f compose.yml logs -f prometheus
podman compose -f compose.yml logs -f grafana
```

Inspect Podman demo control-plane state:

```bash
export DEMO_API="http://127.0.0.1:18080"
export API_KEY="tempest-demo-key-2026"

curl -sS "$DEMO_API/health"
curl -sS "$DEMO_API/ready"
curl -sS -H "x-api-key: $API_KEY" "$DEMO_API/api/v1/info" | jq
curl -sS -H "x-api-key: $API_KEY" "$DEMO_API/api/v1/transfers/active" | jq
curl -sS -H "x-api-key: $API_KEY" "$DEMO_API/api/v1/drain/status" | jq
curl -sS -H "x-api-key: $API_KEY" "$DEMO_API/api/v1/versions/groups" | jq
```

Enable and disable drain mode in the demo:

```bash
export DEMO_API="http://127.0.0.1:18080"
export API_KEY="tempest-demo-key-2026"

curl -sS -X POST "$DEMO_API/api/v1/drain" -H "x-api-key: $API_KEY"
curl -sS "$DEMO_API/ready"
curl -sS -X POST "$DEMO_API/api/v1/undrain" -H "x-api-key: $API_KEY"
curl -sS "$DEMO_API/ready"
```

When running the native binary in a terminal, the first `Ctrl-C` or `SIGTERM` enters drain mode, stops the TFTP listener, and exits once active transfers reach zero. A second `Ctrl-C` or `SIGTERM` forces shutdown if a transfer is stuck during local testing.

Inspect audit records in the demo:

```bash
podman exec tempest-demo tail -f /var/log/tempest/audit.jsonl
```

Run a single client download with a trace ID:

```bash
cd demo/l2-flat
podman compose -f compose.yml run --rm --no-deps client \
  --server tempest \
  --port 6969 \
  --file vmlinuz \
  --output /downloads/vmlinuz-debug.bin \
  --blksize 512 \
  --trace-id debug-vmlinuz
```

Packet capture can be useful for low-level UDP issues. On Linux:

```bash
sudo tcpdump -ni any udp port 6969
```

On macOS with Podman Machine, capture inside the VM:

```bash
podman machine ssh sudo tcpdump -ni any udp port 6969
```

### Capacity-test interpretation

`blksize` and `windowsize` in a load-generator command are requests, not the
negotiated result. The matching `[[boot_phases]]` entry is a safety ceiling. For
example, an `.img` request matches `OS_IMAGE`; `max_window_size = 1` there forces
stop-and-wait even when the client asks for `windowsize=8`. Compare servers only
when successful transfer records show the same negotiated values. A recorded
value of zero means negotiation never completed and is an error outcome, not a
different protocol setting.

Record whether the RRQ actually contains RFC 2349 `timeout`. A load-generator
CLI timeout may instead be only its local receive deadline. If the option is
present, Tempest honors the whole-second value it acknowledges. Without that
option, Tempest uses the bounded adaptive policy selected by the matching boot
phase.

Treat the configured cell duration as the request-launch interval. The cell's
wall time can be longer while in-flight transfers drain, so report completed
bytes over wall time together with success rate and tail latency. For a 1 Gbit/s
link, throughput near the line-rate ceiling cannot be doubled in software;
windowing should instead be used to recover cells that fall below that ceiling.

## Automated Verification Commands

Format and build:

```bash
cargo fmt --check
cargo build
```

Run the whole Rust test suite:

```bash
cargo test
```

Run focused tests for the local changes in this runbook:

```bash
cargo test coherent_release_snapshot_never_mixes_active_and_historical_state
cargo test coherent_snapshot_and_core_owned_verification_support_physical_path_mapping
cargo test hashing_enforces_the_limit_against_bytes_actually_read
```

Validate the demo runner and client syntax:

```bash
python3 demo/l2-flat/demo.py check
```

Run the end-to-end simulated flow:

```bash
python3 demo/l2-flat/demo.py run
```

Run the dedicated IPv6 flow:

```bash
python3 demo/l2-flat/demo.py ipv6
```

## Common Failures

`401 Missing or invalid API key`:

Use the demo key on mutation endpoints:

```bash
-H "x-api-key: tempest-demo-key-2026"
```

`IO error: Address already in use` (`os error 48` on macOS, `os error 98` on Linux) when starting native Tempest:

The TFTP `--port` flag only changes the UDP TFTP listener. The HTTP API has its own port and defaults to `8080`. Either stop the process already listening on `8080`, or start native Tempest with a different API port:

```bash
cargo run -- --port 6969 --api-port 18081 --root "$TEMPEST_ROOT" --log-level debug
export NATIVE_API="http://127.0.0.1:18081"
```

`400 File path is outside TFTP root, not a regular file, or does not exist`:

For the Podman demo, use container paths such as `/tftpboot/releases/v3/vmlinuz`. For native local runs, use host absolute paths to regular files under the configured root.

`409 Deploy cutover is waiting for existing release pins to drain`:

A transfer is still pinned to the old release. Wait for it to complete, increase `drain_timeout_ms`, or intentionally retry after the slow transfer drains.

Native Tempest does not exit after `Ctrl-C`:

The first signal asks Tempest to drain in-flight transfers. Check the active count with `/api/v1/drain/status` if the HTTP API is still reachable. Send a second `Ctrl-C` or `SIGTERM` to force shutdown during local testing.

Prometheus target is down:

```bash
export DEMO_API="http://127.0.0.1:18080"

curl -sS "$DEMO_API/health"
cd demo/l2-flat
podman compose -f compose.yml ps
podman compose -f compose.yml logs prometheus
```

`listen tcp :3000: bind: address already in use` when starting the observability stack:

Host port `3000` is occupied, often by a local Grafana process. Re-run the observe command; the demo runner automatically falls back to a free host port starting at `13000` and prints the URL. To force a specific port, run:

```bash
TEMPEST_DEMO_GRAFANA_PORT=13000 python3 demo/l2-flat/demo.py observe
```

Grafana dashboard has no data:

Run at least one TFTP transfer, then check Prometheus target health and the datasource named `Tempest Prometheus`.

TFTP client times out:

Check that Tempest is listening on UDP `6969`, the demo container is healthy, and the requested logical file has been activated through `/api/v1/versions/switch` for the boot profile selected by the session, or for `default` when no session is registered.

## Current Local Simulation Limits

- The demo uses a Python TFTP client, not real PXE firmware.
- The IPv6 lane validates ULA transport and Tempest session behavior, not
  Router Advertisements, DHCPv6 boot discovery, link-local scope handling, or
  a particular UEFI implementation.
- The public-core demo exposes the integrity endpoints for the manual checks
  above but does not run an integrity controller.
- Tempest verifies retained bytes and release manifests; it does not download or repair corrupted artifacts.
- The Grafana stack is for local observation only and does not configure alert notification channels.
- The simulated L2 network does not inject packet loss or latency. Use a Linux VM or namespace setup with `tc` if you need network-fault testing.
