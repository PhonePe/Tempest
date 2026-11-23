<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Installing Tempest

## Requirements

- Linux or macOS for development; Linux is recommended for deployment.
- Rust 1.85 or newer when building from source.
- UDP port 69 for standard TFTP, or an unprivileged port for testing.
- A protected TCP port for the HTTP API, default 8080.
- Optional PostgreSQL or MySQL-compatible database for durable control state.

## Install

Tempest is distributed as source only. No prebuilt binaries, container images,
or crates.io packages are published; build from a signed `vX.Y.Z` tag (see
[`RELEASE.md`](RELEASE.md)) or from `main`.

```bash
git clone https://github.com/PhonePe/Tempest.git
cd Tempest
git checkout v0.1.0   # or stay on main
git tag -v v0.1.0     # verify the maintainer signature on the tag
```

The Cargo package is named `tempest-ignition`; the executable is named
`tempest`. The default build excludes SQLx and refuses
`persistence.enabled = true` at startup, so add `--features sql-persistence`
when the deployment uses a SQL control store.

### Native build

```bash
cargo build --release --locked --features sql-persistence
make check
sudo install -m 0755 target/release/tempest /usr/local/bin/tempest
sudo install -d -m 0750 /etc/tempest
sudo install -m 0640 config/tempest.toml /etc/tempest/tempest.toml
sudo install -m 0644 deploy/systemd/tempest.service /etc/systemd/system/tempest.service
```

### Pinned Linux archives

`make rc-linux-amd64`, `make rc-linux-arm64`, and `make rc-linux-amd64-gnu`
build in digest-pinned Linux builders with Podman (or `CONTAINER_ENGINE=docker`).
On a release tag, pass `RC_TAG=` so they write
`dist/tempest-<version>-<platform>.tar.gz` plus a `.sha256`; otherwise the name
carries an `-rc1` suffix:

| Archive | Use it for |
| --- | --- |
| `tempest-<version>-linux-amd64.tar.gz`, `tempest-<version>-linux-arm64.tar.gz` | Static musl binaries for any Linux host (recommended) |
| `tempest-<version>-linux-amd64-gnu.tar.gz` | glibc 2.31+ hosts after qualifying its throughput on the target kernel |

Each archive contains the `tempest` binary with SQL persistence, `LICENSE`,
`README.md`, the sample `tempest.toml`, and the example `tempest.service` unit.
Host the archives on your own artifact server to roll them out; the Salt
formula in [`salt/`](salt/README.md) automates a pinned, checksum-verified
install from there.

### Container image

```bash
make container-check CONTAINER_ENGINE=docker   # builds tempest:ci and runs --version
```

Tag and push that image to your own registry and deploy it by digest. See
[Container image](#container-image-deployment) for host networking requirements.

## Filesystem Layout

A typical Linux layout is:

```text
/usr/local/bin/tempest
/etc/tempest/tempest.toml
/etc/tempest/tempest.env
/tftpboot
/var/log/tempest
```

Create a dedicated service account. The artifact root should normally be
read-only to that account; enable WRQ only for a reviewed upload workflow.
Signing keys and API/database secrets should be readable only by the service
account and should not live under the TFTP root.

## Configuration

Start from [`config/tempest.toml`](config/tempest.toml). At minimum, review:

```toml
[server]
bind = "0.0.0.0"
port = 69
listener_shards = 0
root = "/tftpboot"
max_concurrent_transfers = 500
tftp_requests_per_ip_per_second = 50
http_requests_per_ip_per_second = 100
write_enabled = false

[api]
bind = "127.0.0.1"
port = 8080
enable_metrics = true
metrics_require_api_key = true
enable_versions_api = true
enable_audit_api = true
enable_native_http_boot = false
native_http_boot_filename = "boot.efi"
artifact_cache_max_bytes = 67108864
artifact_cache_max_file_bytes = 16777216
api_key = "env:TEMPEST_API_KEY"
# trusted_proxy_ips = ["127.0.0.1"]
```

Zero automatically selects one listener shard per available CPU on Linux,
bounded to 64, and one listener elsewhere. Set `listener_shards = 1` to force
the portable single-listener path, or retain an explicit measured Linux count
when CPU affinity should not change the fan-out.

Both bind fields accept IPv6 addresses. For predictable dual-stack operation,
run explicit IPv4 and IPv6 instances instead of relying on platform-specific
IPv4-mapped wildcard behavior. For example, an IPv6 instance on a routed ULA
may use:

```toml
[server]
bind = "fd12:3456:789a::109"

[api]
bind = "fd12:3456:789a::109"
```

Register the client's stable IPv6 address in the boot session when using TFTP
session selection or native source-IP HTTP Boot. The current configuration does
not represent a link-local scope identifier such as `%eth0`; use a routed ULA
or global address. IPv6 transport support does not itself qualify DHCPv6 or
firmware behavior, and phase DSCP marking currently applies only to IPv4 TFTP.

The control API requires an API key by default, including on loopback, because
port forwarding can expose a loopback listener. `api.allow_insecure_loopback =
true` removes that requirement for a loopback bind and is intended only for
local development. Tempest does not terminate TLS. Keep loopback behind an
authenticated reverse proxy or bind to a protected management network.
Forwarded client addresses are accepted only from explicitly listed socket
peers.

To use SQL persistence, build the feature and configure:

```toml
[persistence]
enabled = true
database_url = "env:TEMPEST_DATABASE_URL"
sync_interval_secs = 5
```

The database user must be able to create and mutate Tempest tables. Use a
dedicated database and least-privilege network policy.

## Container image deployment

The image built from the root [`Dockerfile`](Dockerfile) runs the
binary with SQL persistence as an unprivileged user. For simultaneous directly
connected L2 and FRR-routed L3 service, use the two-instance host-network
profile in [`deploy/container/README.md`](deploy/container/README.md). FRR
remains a separately managed host service and does not share the Tempest
container's privilege boundary.

## Binding Port 69

Prefer a service capability over running as root:

```bash
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/tempest
```

Alternatively use an unprivileged UDP port and redirect traffic at the host or
network boundary. Reapply file capabilities after replacing the binary.

## systemd Example

The `make rc-linux-*` archives include [`deploy/systemd/tempest.service`](deploy/systemd/tempest.service).
It runs as the `tempest` user with `CAP_NET_BIND_SERVICE` for port 69, a
read-only `/tftpboot`, and systemd-managed `/var/log/tempest` and `/run/tempest`
directories, under `ProtectSystem=strict` and `NoNewPrivileges`. It also
restricts sockets to IPv4, IPv6, Unix, and netlink, limits system calls to
systemd's `@system-service` set, and hides kernel tunables, modules, logs, and
devices. If a deployment needs more, relax only the directive it needs with a
drop-in (`systemctl edit tempest`). Create the user first:

```bash
sudo useradd --system --home-dir /var/lib/tempest --shell /usr/sbin/nologin tempest
sudo systemctl daemon-reload
sudo systemctl enable --now tempest
```

At startup the core server ensures the soft descriptor limit is at least
`2 * max_concurrent_transfers + 1024`. A linked composition with a custom
read-protocol provider requires `3 * max_concurrent_transfers + 1024` because
the provider receives a cloned verified artifact handle. Tempest derives the
applicable value, raises only the soft limit, and never exceeds the
operator-controlled hard limit. Startup fails with the required value when the
hard limit is too low. Keeping `LimitNOFILE` explicit remains recommended so
capacity is visible in deployment policy rather than inherited from a shell or
service-manager default.

If audit logging is enabled, set its path under an allowed writable directory.
If WRQ is enabled, replace the root's `ReadOnlyPaths` treatment with a narrowly
reviewed writable path.

## Verify

```bash
systemctl status tempest
curl --fail http://127.0.0.1:8080/health
curl --fail http://127.0.0.1:8080/ready
curl --fail -H "x-api-key: $TEMPEST_API_KEY" \
  http://127.0.0.1:8080/api/v1/info
```

TFTP serves only files that belong to a published release; files copied under
the artifact root are not served until they are published. Before testing TFTP,
publish the files that DHCP advertises to clients without a boot session as the
`default` boot profile release:

```bash
curl --fail -X POST http://127.0.0.1:8080/api/v1/versions/switch \
  -H "x-api-key: $TEMPEST_API_KEY" \
  -H 'content-type: application/json' \
  -d '{"boot_profile":"default","group_id":"bootstrap-v1",
       "files":[{"name":"ipxe.efi","path":"/tftpboot/ipxe.efi"}]}'
```

Without SQL persistence, release state is held in memory, so publish it again
after every restart before admitting boot traffic.

Use a TFTP client from the provisioning network to fetch a member of that
release, and verify the response source port changes from the well-known
listener to one stable transfer TID. A file under the root that is not in the
release must return TFTP ERROR 1. Test each firmware family and requested
option set used in production.

## Upgrade

1. Read [`CHANGELOG.md`](CHANGELOG.md) and [`UPGRADING.md`](UPGRADING.md).
2. Build the new tag with the same feature set and verify its checksum.
3. Stage it beside the current binary.
4. Call `POST /api/v1/drain` and wait for `drain_complete`.
5. Replace the binary, reapply capabilities, restart, and check `GET /ready`.
6. Call `POST /api/v1/undrain` only when a running process was drained without
   restart.

For multi-node operation, upgrade one node at a time and keep session affinity
within a boot epoch where possible.
