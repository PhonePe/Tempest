<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tempest

Tempest is a release-coherent TFTP and HTTP boot artifact server written in
Rust. It serves legacy PXE clients over standards-compatible TFTP, can serve a
managed first-stage image directly to native UEFI HTTP Boot firmware, and lets
header-capable iPXE stages fetch later artifacts over HTTP without leaving the
same boot profile, version group, and boot-session pin.

The Cargo package is named `tempest-ignition`. Its Rust library crate and
installed command are both named `tempest`, so code uses `tempest::...` and
operators invoke `tempest`.

Tempest `0.1.0` is its first public, pre-1.0 release. Its protocol and
release-consistency paths are tested, but operators should validate firmware
compatibility and capacity against their own fleet before production rollout.

## What Ships

The default open-source binary contains:

- TFTP RRQ and optional WRQ support for octet mode.
- RFC 1350 transfer-ID behavior and ERROR handling.
- RFC 2347 option negotiation, RFC 2348 `blksize`, RFC 2349 `timeout` and
  `tsize`, and RFC 7440 `windowsize`.
- Boot-phase classification with per-phase negotiation ceilings and metrics.
- An identity-validated, byte-bounded cache for frequently requested artifacts
  up to 2 MiB, with coalesced fills, replacement-safe validation, and
  allocation-free scatter/gather DATA delivery on the standard cached path.
- Optional Linux UDP segmentation for standard negotiated DATA windows,
  disabled by default with per-transfer fallback to ordinary batching.
- Profile-scoped version groups, boot-chain manifests, transfer pins, boot
  sessions, atomic activation, rollback, withdrawal, and drain-gated cutover.
  Retained history is capped at 100 groups; deployments return HTTP 409 when
  active or session-pinned releases leave no room for the new group.
- Session-gated HTTP artifact streaming through the same resolver used by
  TFTP: bearer-token delivery for header-capable clients and an opt-in, fixed
  source-IP-authorized URI for native UEFI HTTP Boot firmware.
- Health, readiness, metrics, drain, session, release, and audit HTTP APIs.
- Optional durable, group-committed JSONL delivery audit records and independent
  Ed25519 release-manifest signing.
- Optional DSCP marking, aggregate bandwidth governance, and bounded ingress
  rate limiting.
- Optional PostgreSQL or MySQL-compatible durable control state through the
  `sql-persistence` Cargo feature.

Advanced scheduling, custom wire formats, signed redirect policy, shared block
caches, ACK-derived pacing, and external priority providers are not built into
the default binary. They are supplied by separately linked crates through the
public contracts in [`src/extension.rs`](src/extension.rs). Tempest does not use
a dynamic plugin ABI.

The public Cargo workspace also contains
[`tempest-control-client`](crates/tempest-control-client), a typed, bounded HTTP
control client. Core and client share one source revision and lockfile and are
versioned independently. The default build selects only `tempest-ignition`; the
server does not depend on the client.

Provider compositions remain separate and consume public contracts. They select
only the providers they need; no private provider is part of this workspace.
Run `make check` to validate both public crates and their live HTTP contract.

### Experimental UDP Segmentation

`server.udp_segmentation_offload = true` enables bounded Linux `UDP_SEGMENT`
submissions for eligible standard TFTP windows. It preserves ordinary DATA
datagrams, negotiated options, transfer sockets, ACK handling and bandwidth
budgets. The default is `false`; non-Linux platforms ignore the setting.

- **Requirements:** Linux 4.18+. Startup probes the `UDP_SEGMENT` socket option
  on an unbound socket matching the configured TFTP address family (IPv4 or
  IPv6) and refuses the opt-in when unsupported, preventing older kernels from
  silently sending an unsegmented batch. Probe failures retain their underlying
  cause; IPv6-only listeners do not require IPv4.
- **Eligibility:** single-block windows, fewer than two active transfers,
  custom protocols, schedulers, shared blocks and pacing providers retain the
  ordinary sender.
- **Fallback:** unsupported-protocol errors (`ENOPROTOOPT`/`EOPNOTSUPP`)
  disable segmentation for that address family (IPv4 or IPv6) until restart.
  `EIO`/`EINVAL`/`EMSGSIZE` disable it only for the affected transfer, without
  retrying segmentation during that transfer; later transfers may try it again.
  Both classes fall back to `sendmmsg`; no negotiated block size is silently
  changed.
- **Metrics:** process-wide counters
  `tempest_tftp_udp_segmentation_batches_total` and
  `tempest_tftp_udp_segmentation_fallbacks_total` expose successful batch sends
  and syscall rejections, respectively.

Segmentation can tighten packet spacing and does not guarantee hardware offload
or a speedup. Validate the intended firmware, path MTU, kernels, NICs and packet
filters before enabling it. Software-client experiment results do not qualify
boot ROMs or prove performance of a different source revision. Release identity,
audit and filesystem verification remain enabled independently of this option.

## Quick Start

Tempest is distributed as source only; [`INSTALL.md`](INSTALL.md) covers native
builds, pinned Linux archives, and the container image. To build and run
from source:

Tempest requires Rust 1.85 or newer.

```bash
mkdir -p tftpboot
printf 'hello from tempest\n' > tftpboot/hello.txt
printf '[api]\nallow_insecure_loopback = true\n' > tempest-local.toml

cargo run -- \
  --config tempest-local.toml \
  --port 6969 \
  --api-port 8080 \
  --root "$PWD/tftpboot"
```

This development-only configuration explicitly permits unauthenticated control
on loopback; use an API key for a real deployment. From another terminal in the
same directory, verify startup and publish the public bootstrap release:

```bash
curl --fail http://127.0.0.1:8080/health
curl --fail http://127.0.0.1:8080/ready
curl --fail -X POST http://127.0.0.1:8080/api/v1/versions/switch \
  -H 'content-type: application/json' \
  --data "{\"boot_profile\":\"default\",\"group_id\":\"hello-v1\",\"files\":[{\"name\":\"hello.txt\",\"path\":\"$PWD/tftpboot/hello.txt\"}]}"
```

Use a TFTP client against UDP port `6969` to retrieve `hello.txt`. Files are
readable over TFTP only after registration in a managed release; placing them
under the root is insufficient. Without a live source-IP session, only members
of the active `default` release are public. With a session, reads stay within
its profile and pinned manifest. Missing members return TFTP ERROR 1, never a
raw-root fallback.

Binding the standard UDP port `69` may require an operating-system capability or
elevated service configuration; running the process as root is not recommended.

For a persistent setup, edit [`config/tempest.toml`](config/tempest.toml), then
run:

```bash
cargo build --release
./target/release/tempest --config config/tempest.toml
```

Inspect the exact configuration before a restart without binding sockets,
connecting to persistence, or creating the artifact root:

```bash
./target/release/tempest --config config/tempest.toml --check-config
./target/release/tempest --config config/tempest.toml --print-effective-config
```

Both commands require the named configuration file to exist, resolve supported
`env:` secrets, apply CLI overrides, and run configuration-level validation.
The print form resolves automatic listener fan-out and redacts API keys,
database URLs, and all extension-owned values. Its remaining paths, addresses,
and policy settings can still be operationally sensitive, so protect captured
output. Neither command proves filesystem, database, or socket availability.

`max_window_size` and each phase's `max_window_size` are negotiation ceilings;
clients that do not request RFC 7440 remain at the standard one-block window.

### TFTP admission and timeout policy

`server.max_tftp_transfers_per_ip` defaults to 16 (range 1–10000; zero cannot
disable it). It bounds the combined queued, reserved, and running RRQ/WRQ work
from one source IP through transport completion. All source ports share the
quota; duplicate RRQs on the same live client TID consume no extra permit.
The quota spans local listener shards, not cluster nodes, and excludes HTTP.
The client TID and permit are released before terminal audit work so the same
endpoint can request its next boot file; audit capacity is bounded separately.
Excess requests receive TFTP ERROR 0, `Client transfer limit reached`, before
global capacity or queue admission; they are never enqueued. These rejections
contribute to the `tempest_capacity_rejected_total` counter. The per-IP and
global caps are independent; a smaller global cap is valid. A per-IP cap at or
above the global cap cannot reserve capacity for other clients. Shared NAT
clients compete for one quota: this gives partial isolation, not guaranteed
fairness or protection against spoofed/distributed traffic. See
[deployment guidance](DEPLOYMENT.md#capacity-and-bandwidth).

`server.max_client_timeout_secs` defaults to 255 (range 1–255). With
`accept_client_timeout = true`, decimal RFC 2349 `timeout` requests from 1
through this ceiling are accepted at their exact whole-second interval. Larger
or invalid values are omitted from OACK, never clamped or counteroffered;
other requested options keep their own negotiation rules.
`accept_client_timeout = false` omits all timeout requests regardless of the
ceiling. An omitted timeout uses the server's bounded adaptive RTO policy;
compliant clients treat that option as unnegotiated. The ceiling is neither an
inactivity timer nor a total-transfer timer. Retry budgets remain
server-controlled by `max_retries`, including boot-phase overrides; phase
adaptive RTO settings apply only without a negotiated timeout. There is no
minimum-throughput eviction.

`server.max_transfer_duration_secs` sets an absolute TFTP network deadline:
300 seconds by default, configurable from 1 to 86400 inclusive; zero cannot
disable it. The deadline starts on entry to each RRQ/WRQ transfer and is not
refreshed by valid progress, duplicate packets, or retries. It spans read
OACK and DATA exchange, including runtime scheduling and pacing, and write DATA
reception plus final ACK dally. Preparation consumes elapsed time, but
unabortable setup is not interrupted. If the entire WRQ file arrives before the
deadline, final durable flush and publication may complete without timed
cancellation; subsequent dally still uses the original deadline.

An accepted RFC 2349 `timeout`, including 255 seconds, stays exact: the
server may terminate at the absolute deadline, but never retransmits early to
fit that budget. On expiry before completion, it attempts one standard TFTP
ERROR (code 0) from the transfer socket, without waiting or retransmitting;
notification loss or socket backpressure cannot delay cleanup. A committed
upload still receives a best-effort final ACK, not a deadline ERROR.
`accept_client_timeout = false` remains an independent opt-out from negotiating
that option, not an opt-out from the deadline. Raise the deadline before serving
large images or slow/lossy clients that need more than five minutes. The
[illustrative long-transfer profile](DEPLOYMENT.md#long-transfer-profile)
requires firmware and network validation, not an assumption of default support.
The deadline and per-IP quota provide bounded lifetime and partial isolation,
not guaranteed access under continuous new or distributed requests.

This lifetime is server policy, not an RFC-mandated five-minute limit or a
promise of five retries. [RFC 2349](https://www.rfc-editor.org/rfc/rfc2349)
specifies the accepted retransmission interval;
[RFC 2347](https://www.rfc-editor.org/rfc/rfc2347) permits option omission;
[RFC 1350](https://www.rfc-editor.org/rfc/rfc1350#section-7) defines ERROR-based
termination. Choose a lifetime above the slowest supported complete transfer,
including preparation, pacing, and loss recovery. No finite absolute deadline
can preserve arbitrarily slow transfers while also bounding their slot use.

### Cache and transport resources

Socket-buffer settings are deliberately bounded so raising concurrency cannot
imply unbounded kernel memory; the aggregate bound counts both the send and
receive allocation for every configured transfer socket.

HTTP unmanaged compatibility reads validate every request by default. TFTP
requires managed release membership regardless of cache contents.

- **Validation interval:** operators with an immutable, trusted artifact root
  can set `unmanaged_cache_validation_interval_ms` to at most 1000 to amortize
  `open`/`fstat` calls; replacements may then take that many milliseconds to
  become visible. Managed release bytes skip those calls only after matching
  the pinned size and SHA-256.
- **TFTP hot cache:** `hot_artifact_cache_max_bytes` and
  `hot_artifact_cache_max_file_bytes` bound retained memory explicitly;
  increase the latter for large managed images only when the total cache and
  host-memory budgets can accommodate it. Admitted artifacts of at least 4 MiB
  populate on a four-job background lane while cold and concurrent requesters
  stream from their already capability-opened handles, avoiding a full-file
  delay before the first DATA window. Smaller fills retain single-flight
  coalescing.
- **Non-Unix platforms:** stable Rust does not expose a portable file ID, so
  Tempest conservatively bypasses identity-based hot-cache and shared-block
  reuse instead of accepting a path/size/timestamp collision after replacement.
- **HTTP cache:** a separate 64 MiB cache holds artifacts up to 16 MiB by
  default. Managed snapshots become reusable only after matching the
  release-pinned size and SHA-256; unmanaged snapshots follow the bounded
  validation interval above. Configure `api.artifact_cache_max_bytes` and
  `api.artifact_cache_max_file_bytes`, or set both to zero to disable it,
  without changing TFTP cache capacity or eviction.

HTTP connection limits:

- HTTP accepts at most `api.max_connections` sockets (default 1024); excess
  connections wait in the operating system's listen backlog.
- A socket write that makes no progress for `api.write_timeout_secs` (default
  120 seconds) closes the connection and releases its transfer resources.
  Server-side pacing and artifact preparation do not consume that deadline. Set
  the timeout to zero to disable it.
- The listener serves HTTP/1.x directly, with no protocol-upgrade detection
  wait. Headers (including idle keep-alive) and request bodies each have an
  absolute `api.read_timeout_secs` deadline (default 30 seconds, range 1–3600).
  Body timeouts return 408 and close the connection; incomplete headers close at
  the transport. These deadlines exclude application processing and response
  delivery.
- Cold HTTP/TFTP artifact opens share 32 blocking worker slots, retained until
  blocking work finishes even if the requesting task is cancelled.

SQL session registrations use a bounded 256-request queue and group up to 32
pending registrations in one transaction. Overload returns 503; live session
capacity still returns 429. Successful responses follow durable commit and local
publication, and in-progress commits finish after callers disconnect. Duplicate
clients retain epoch, pin, and token replacement semantics. Reconciliation
reuses unchanged authenticated release metadata and maps while retaining
coherent session snapshots and active-file verification.

Cold managed-artifact hashing shares four blocking workers across transfers and
control operations. Concurrent verification of one cached identity shares its
result. The 10,000-entry verification cache evicts unused identities under
churn; when all candidate entries are in use, verification proceeds without
retention.

`listener_shards = 0` automatically selects one bounded `SO_REUSEPORT` listener
per available CPU on Linux and one listener elsewhere. Set it to one to force
the portable path or to an explicit measured Linux count when CPU affinity is
fixed.

## Developer Path

To understand Tempest, follow this order:

1. Run the [Quick Start](#quick-start) to see the default server operate.
2. Read [`src/lib.rs`](src/lib.rs) for the public crate surface and
   [`src/main.rs`](src/main.rs) for default-process startup and shutdown.
3. Follow one read request through [`src/server.rs`](src/server.rs),
   [`src/protocol/`](src/protocol/),
   [`src/features/versioning.rs`](src/features/versioning.rs), and
   [`src/api/`](src/api/).
4. Review [`config/tempest.toml`](config/tempest.toml) and
   [`docs/openapi.yaml`](docs/openapi.yaml) for the operational contracts.
5. Read [`EXTENSIONS.md`](EXTENSIONS.md) only when building a statically linked
   provider or composition.

To contribute, follow this order:

1. Read [`CONTRIBUTING.md`](CONTRIBUTING.md); coding agents must also follow
   [`AGENTS.md`](AGENTS.md).
2. Identify the owning module and preserve the invariants documented in its
   rustdoc and in [`AGENTS.md`](AGENTS.md). Open an issue or discussion before
   changing protocol behavior, release semantics, persistence, OpenAPI, or a
   public extension trait.
3. Make one focused behavioral change and add a test that fails without it.
4. Update the README, configuration, OpenAPI, rustdoc, or changelog when the
   public contract changes.
5. Run `make check`, then run the additional database, protocol, demo, or
   dependency checks routed by [`QUALITY.md`](QUALITY.md) and
   [`AGENTS.md`](AGENTS.md).
6. Open a pull request describing the problem, ownership boundary,
   compatibility and security impact, tests run, and documentation changes.

## Release-Coherent Boot Flow

1. A provisioning service activates a version group for a boot profile.
2. It registers the client IP and intended profile with `POST /api/v1/sessions`.
3. The first managed artifact request pins that boot epoch to the active
   boot-chain manifest.
4. Later TFTP RRQs, bearer-token HTTP GETs, and optional native HTTP Boot GETs
   resolve against the same manifest, even if a new group becomes active for
   new sessions.
5. Transfer and session pins are released on completion or expiry.

Register a session:

```bash
curl -X POST http://127.0.0.1:8080/api/v1/sessions \
  -H "x-api-key: $TEMPEST_API_KEY" \
  -H 'content-type: application/json' \
  -d '{
    "client_ip": "192.0.2.42",
    "boot_profile": "ubuntu-24.04",
    "client_mac": "02:00:00:00:00:42",
    "serial": "node-42",
    "trace_id": "provision-42",
    "ttl_seconds": 600
  }'
```

The response contains a one-time `artifact_token`, its expiry, and the current
boot epoch. Persist the token only for that provisioning attempt and present it
to the HTTP artifact route:

```bash
curl --fail \
  -H "Authorization: Bearer $TEMPEST_ARTIFACT_TOKEN" \
  http://127.0.0.1:8080/api/v1/artifacts/vmlinuz
```

Activate a coordinated release:

```bash
curl -X POST http://127.0.0.1:8080/api/v1/versions/switch \
  -H "x-api-key: $TEMPEST_API_KEY" \
  -H 'content-type: application/json' \
  -d '{
    "boot_profile": "ubuntu-24.04",
    "group_id": "ubuntu-24.04-r1",
    "cutover_policy": "preserve_sessions",
    "drain_timeout_ms": 30000,
    "files": [
      {"name": "vmlinuz", "path": "/tftpboot/releases/ubuntu-24.04-r1/vmlinuz"},
      {"name": "initrd.img", "path": "/tftpboot/releases/ubuntu-24.04-r1/initrd.img"}
    ]
  }'
```

An iPXE stage holding that token can then request
`/api/v1/artifacts/vmlinuz` and `/api/v1/artifacts/initrd.img`. The HTTP
responses include release identity headers such as the boot profile, group,
manifest digest, content hash, phase, and transport.

Native UEFI HTTP Boot clients normally cannot attach an authorization header.
For those clients, an operator may explicitly enable a single stable URI such
as `/boot/v1/boot.efi`. Tempest authorizes that route from the request source
IP (or one trusted proxy's single forwarded address), requires an active boot
session, and serves only the configured logical name from a managed release.
This allows DHCP to advertise the same URI to every machine while the
provisioning service selects the machine-specific profile through
`POST /api/v1/sessions`. See
[`docs/guides/PROVISIONING_HTTP_INTEGRATION.md`](docs/guides/PROVISIONING_HTTP_INTEGRATION.md).

### Manual and managed boot delivery

TFTP serves the default loader without a pre-created session on a
controlled provisioning network. HTTP artifact delivery requires a registered
session, using either its bearer token or the explicitly enabled native HTTP
Boot route's source-IP authorization. Changing Tempest or DHCP settings does
not rewrite URLs generated by the provisioning service; those must be changed
separately. A TFTP-only boot must fetch both its boot script and the
kernel/initrd over TFTP, not just the first-stage bootloader.

For managed boots, register a session with `new_epoch: true` and
`require_managed: true` when the client is ready to download. A generic loader
may first contact the provisioning API so firmware/DHCP delays do not consume
the download TTL. Verify the returned profile, manifest digest, and epoch. Reuse
the bearer capability for later HTTP requests; registering again rotates the
token. Persist the client-side capability securely if the provisioning service
needs to survive a restart. Keep both transports and session registration on
the same server until any replica has synchronized.

SQL-backed registration compares the issuer's prior session and selected release
with durable state under the mutation lock. A competing issuer or unseen release
cutover returns HTTP 409 without committing that registration batch; synchronize
before retrying. Session DELETE checks the durable token even when the local
cache is empty or stale. HTTP 409 means a replacement still owns the address,
whereas HTTP 204 confirms matching revocation or absence at the transaction.
Registration is not idempotent: after a lost response, do not assume the request
failed or blindly issue again. Persist attempt state and keep recovery fenced
until the uncertain capability expires or an operator reconciles the attempt.

Artifact bearer tokens are bound to the boot session client IP. Requests from
another resolved IP receive HTTP 403. A reverse proxy must be explicitly listed
in `api.trusted_proxy_ips` and overwrite `X-Forwarded-For` with exactly one
numeric client address; duplicate headers and chains are rejected. Keep boot
clients on an isolated network and restrict control API access at the firewall.
HTTP does not hide credentials or protect downloaded bytes from on-path changes.

## HTTP Surface

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Process liveness |
| `GET` | `/ready` | Readiness and drain state |
| `GET` | `/metrics` | Prometheus exposition when enabled; API-key authentication is separately configurable |
| `GET` | `/api/v1/info` | Process and transfer information |
| `GET` | `/api/v1/transfers/active` | Active-transfer count |
| `GET` | `/api/v1/drain/status` | Current drain state |
| `GET` | `/api/v1/versions` | Active artifact versions |
| `GET` | `/api/v1/versions/groups` | Version groups and manifest metadata |
| `GET` | `/api/v1/versions/snapshot` | Coherent active-version and retained-group snapshot |
| `GET` | `/api/v1/audit` | Recent audit entries when enabled |
| `GET` | `/api/v1/artifacts/{filename}` | Session-pinned HTTP artifact stream |
| `GET`, `HEAD` | `/boot/v1/{filename}` | Optional native HTTP Boot stream for the one configured managed artifact |
| `POST` | `/api/v1/sessions` | Register or advance a boot epoch |
| `DELETE` | `/api/v1/sessions/{client_ip}` | Revoke the current session using its artifact token as replacement-safe proof |
| `POST` | `/api/v1/versions/switch` | Prepare and activate a version group |
| `POST` | `/api/v1/versions/rollback` | Reactivate a retained group |
| `POST` | `/api/v1/versions/withdraw` | Withdraw the matching active group |
| `POST` | `/api/v2/versions/rollback` | Reactivate a retained group with required manifest identity |
| `POST` | `/api/v2/versions/withdraw` | Withdraw an active group with required manifest identity |
| `POST` | `/api/v2/delete/preview` | Preview exact retained metadata/file deletion and blockers |
| `POST` | `/api/v2/delete/confirm` | Remove unpinned inactive retained metadata only, with persistence disabled; never bytes |
| `POST` | `/api/v1/versions/verify` | Rehash retained artifacts through the capability root |
| `POST` | `/api/v1/drain` | Stop admitting new transfers |
| `POST` | `/api/v1/undrain` | Resume admission |

In-process integrations supply an OpenTelemetry 0.32 `Meter` through
`TftpServer::builder(config).with_meter(meter)`. Native observable instruments
read business state, and histograms record real transfer/cutover events; no
snapshot adapter or HTTP parser is needed. Core never initializes globals.
An independent per-server OTel reader always preserves standalone Prometheus,
including exact `u64` text values and session-profile counts up to configured
session capacity. See
[Native OpenTelemetry Metrics](EXTENSIONS.md#native-opentelemetry-metrics) for
lifecycle, cardinality views, and compatibility details.

HTTP instrumentation compositions can install
`TftpServerBuilder::with_http_observer` for normalized method, route template,
status, and response-production timing. Core retains routing and security
enforcement. See [the observation contract](EXTENSIONS.md#http-observation) for
cancellation, streaming, and bounded exporter requirements.

Control routes require `x-api-key`; health and readiness are unauthenticated.
Metrics require the API key by default, but operators may set
`api.metrics_require_api_key = false` for a trusted Prometheus network. That
exception applies only to `GET /metrics`, which remains rate-limited; protect
the listener with a firewall or private observability network because metrics
expose operational state. Artifact routes use their own session credentials: a
bearer token under `/api/v1/artifacts`, or source-IP session identity under the
disabled-by-default `/boot/v1` route. Verified managed artifacts advertise a
strong content ETag and accept one HTTP bytes range; stale `If-Range`,
multipart, and unmanaged requests receive the complete representation. An
explicitly named insecure loopback flag exists for local development. The
service does not terminate TLS; expose it through a protected management network
or a TLS-terminating proxy whose exact socket address is in `trusted_proxy_ips`
before honoring a forwarded client address.

The maintained API contract is documented in
[`docs/openapi.yaml`](docs/openapi.yaml).

The rolling upgrade procedure and per-release upgrade notes are documented in
[`UPGRADING.md`](UPGRADING.md).

## SQL Persistence

The default build has no SQLx dependency. Enable durable PostgreSQL, MySQL,
MariaDB, or Percona-compatible control state explicitly:

```bash
cargo build --release --features sql-persistence
```

```toml
[persistence]
enabled = true
database_url = "env:TEMPEST_DATABASE_URL"
sync_interval_secs = 5
```

A default build fails startup when `persistence.enabled = true`; it never
silently falls back to volatile state.

- **Snapshot freshness:** SQL refresh failures retain the last validated
  snapshot for at most `persistence.max_snapshot_age_secs` (default 300
  seconds, range 1-86400, greater than the ordinary sync interval). At that age
  new TFTP/HTTP reads are refused and `/ready` reports `503 STALE`; existing
  transfers finish. Successful refresh restores admission automatically. Remote
  withdrawals may remain unseen during this bounded interval.
- **Ordinary SQL mode:** selects a separate durable mode at startup and
  performs no deletion-specific probes or reader registration per download.
  Ordinary SQL publication does not consume the deletion-mode name budget.
- **Deletion mode:** inactive, unpinned group/manifest metadata can be deleted
  with `persistence.coordinated_deletion = true`. A database-held exclusive
  namespace lock enforces one updated serving process, while durable reader
  registrations, identity-CAS deletion and permanent tombstones preserve
  safety. Other SQL profiles refuse deletion. Bytes are never removed;
  abandoned reader rows block until reviewed offline recovery. Reader-row
  exhaustion durably disables deletion, not serving; 100 permanent tombstones
  exhaust deletion capacity without blocking downloads. Only deletion mode
  accumulates permanent managed names and enforces the 20,000-distinct-name
  cap. Queued admissions and serving-originated release/session mutations
  recheck the lease generation inside the durable revision transaction; lost
  owners cannot resume after replacement startup. See the
  [deletion contract](docs/guides/deletion.md#sql-single-serving-node-metadata-deletion).
- **Mode switch:** switching an already-selected database to deletion mode
  requires the explicit stopped migration in that guide.
- **Artifact names:** must be canonical relative paths (no repeated/trailing
  separators or dot components). Unicode names remain supported, including
  durable MySQL ownership tombstones.

## Extension Contracts

`TftpServer::builder` accepts optional implementations for:

| Contract | Responsibility |
| --- | --- |
| `TransferScheduler` | Grant transfer windows and send DATA through each transfer's own socket |
| `ProvisioningPriorityProvider` | Supply an optional scheduler weight for an inventory serial |
| `TransferPacing` | Derive per-transfer delays from ACK observations |
| `SharedBlockCache` | Share retained source blocks across concurrent readers |
| `ReadProtocolExtension` | Implement an explicitly negotiated custom read protocol |
| `ReadRequestRouter` | Select local delivery or a signed protocol-v2 redirect |
| `AdmissionPolicy` | Supply bounded queue capacity, priority, expiry, and launch delay |

Release resolution, path confinement, transfer slots, TFTP TIDs, and lifecycle
cleanup remain owned by Tempest. This is typed in-process composition rather
than a catch-all middleware pipeline: one provider can be installed for each
contract, different contract types can operate together, and same-contract
chaining requires an explicit composite provider. See
[`EXTENSIONS.md`](EXTENSIONS.md) before implementing a provider.

The optional
[`examples/custom_scheduler_composition/main.rs`](examples/custom_scheduler_composition/main.rs)
template demonstrates a complete composition binary. It is not required to
build or run the default Tempest server.

## Development

```bash
# Default dependency profile
cargo test --no-default-features

# SQL-enabled profile
cargo test --features sql-persistence

# Repository quality gate
make check

# API documentation
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features
```

Database test bodies require `TEMPEST_TEST_DATABASE_URL`; `make test-sql` runs
every SQL-feature test against one database, and CI runs it against PostgreSQL
and MySQL. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for change and test
expectations.

## Security Boundaries

- TFTP is unauthenticated and unencrypted. Use a controlled provisioning
  network and client-side image verification such as Secure Boot.
- Bearer HTTP artifact authorization requires the opaque token returned for an
  unexpired boot session.
- The optional native HTTP Boot route is intentionally source-IP authorized
  because firmware cannot reliably add headers. Enable it only on a controlled
  provisioning network without shared NAT; it serves exactly one configured
  logical name and never falls back to an unmanaged root file.
- Live session state is bounded by `server.max_boot_sessions` (1–1,000,000).
  Programmatic construction rejects values outside this range; file loading
  clamps them. SQL hydration fails closed if durable unexpired sessions exceed
  that node limit.
- Manifest signatures depend on external key protection and trusted verifier
  distribution. Audit JSONL is operational delivery evidence, not a signed or
  tamper-evident ledger; protect it with host filesystem controls and export it
  to an external system when stronger evidence is required.
- Process-local cutover is atomic. SQL-backed nodes converge by synchronization;
  Tempest does not claim a cluster-wide cutover barrier.
- Direct-root compatibility files are reachable only over HTTP, never TFTP,
  and are outside managed release identity unless another integrity mechanism
  covers them.

Report vulnerabilities according to [`SECURITY.md`](SECURITY.md).

## Documentation

- [`INSTALL.md`](INSTALL.md) - installation and service setup
- [`CONTRIBUTING.md`](CONTRIBUTING.md) - contribution workflow and pull-request expectations
- [`GOVERNANCE.md`](GOVERNANCE.md) - maintainer responsibilities and decision process
- [`AGENTS.md`](AGENTS.md) - coding-agent invariants and validation workflow
- [`QUALITY.md`](QUALITY.md) - robustness, benchmark, coverage, semver, and compatibility gates
- [`EXTENSIONS.md`](EXTENSIONS.md) - optional provider contracts and composition boundaries
- [`DEPLOYMENT.md`](DEPLOYMENT.md) - deployment patterns and boundaries
- [`docs/README.md`](docs/README.md) - maintained guides and protocol references
- [`docs/FIRMWARE_COMPATIBILITY.md`](docs/FIRMWARE_COMPATIBILITY.md) - exercised clients and compatibility report requirements
- [`deploy/container/README.md`](deploy/container/README.md) - hardened simultaneous L2 and FRR-routed L3 container profile
- [`CHANGELOG.md`](CHANGELOG.md) - release history
- [`RELEASE.md`](RELEASE.md) - maintainer release checklist

## License

Copyright 2026 PhonePe India Pvt. Ltd. Licensed under the Apache License,
Version 2.0; see [`LICENSE`](LICENSE) for the full text and [`NOTICE`](NOTICE).
Each file carries `SPDX-FileCopyrightText` and `SPDX-License-Identifier` tags.
