<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tempest Extension Guide

Tempest extensions are ordinary Rust crates linked into a composition binary.
They are not shared libraries, subprocess protocols, or dynamically loaded
plugins. This keeps protocol and lifecycle contracts type checked while letting
deployments choose implementations that are not dependencies of the default
binary.

Public, vendor-neutral clients and integrations live under `crates/` in this
workspace. [`tempest-control-client`](crates/tempest-control-client) consumes
the HTTP control contract and is versioned independently (see
[Control Client Sessions](#control-client-sessions)). Core does not depend on
it. Provider and deployment compositions remain in separate repositories and
choose their extension crates explicitly.

The public contracts live in [`src/extension.rs`](src/extension.rs), and are
installed with `TftpServer::builder`.

Public manifest, version-group, and audit-entry UTC timestamps use
`jiff::Timestamp`.

SQL compositions may recover abandoned readers with
`PersistenceStore::recover_abandoned_readers` only after every serving process
is stopped and fenced. The confirmation does not detect disconnected readers;
see [offline reader recovery](docs/guides/deletion.md#offline-reader-recovery).

Depend on a signed release tag under the `tempest` crate alias so imports stay
consistent with the examples. Tempest is not published to crates.io:

```toml
[dependencies]
tempest = { package = "tempest-ignition", git = "https://github.com/PhonePe/Tempest", tag = "v0.1.0" }
```

```rust,no_run
use std::sync::Arc;

use tempest::config::TempestConfig;
use tempest::server::TftpServer;

# fn build(
#     config: TempestConfig,
#     scheduler: Arc<dyn tempest::extension::TransferScheduler>,
# ) -> Result<TftpServer, tempest::error::TempestError> {
let server = TftpServer::builder(config)
    .with_scheduler(scheduler)
    .build()?;
# Ok(server)
# }
```

A complete, compile-checked composition binary is available at
[`examples/custom_scheduler_composition/main.rs`](examples/custom_scheduler_composition/main.rs).
It implements a minimal scheduler that preserves the supplied transfer socket,
installs it through the builder, and starts both TFTP and HTTP services:

```bash
cargo run --example custom_scheduler_composition -- config/tempest.toml
```

`ApiConfig` includes `max_connections`, `read_timeout_secs`, and
`write_timeout_secs`. TOML files that omit them receive defaults; Rust
compositions using exhaustive struct literals must provide these fields or use
`..ApiConfig::default()`. The HTTP listener explicitly serves HTTP/1.x;
enabling a transitive HTTP/2 dependency does not enable HTTP/2 or upgrades on
this listener. Those transports require their own bounded admission policy.

`ServerConfig` includes these resource-policy fields:

| Field | Rust type | Default | Inclusive range |
| --- | --- | --- | --- |
| `max_tftp_transfers_per_ip` | `usize` | 16 | 1–10000 |
| `max_client_timeout_secs` | `u8` | 255 | 1–255 |
| `max_transfer_duration_secs` | `u64` | 300 | 1–86400 |
| `udp_segmentation_offload` | `bool` | false | false/true |

TOML that omits these fields receives the defaults; exhaustive Rust literals
must set them or use `..ServerConfig::default()`. File loading and
`TftpServer::builder(...).build()` validate these ranges; zero cannot disable
them, even when `accept_client_timeout` is false. The per-IP and global transfer
caps are independent; a smaller global cap is valid. Explicitly raise the
300-second lifetime for large/slow transfers after firmware/network validation;
see the [illustrative profile](DEPLOYMENT.md#long-transfer-profile).

UDP segmentation requires Linux 4.18+ and a successful startup `UDP_SEGMENT`
socket-option probe on an unbound socket in the configured TFTP address family.
IPv6-only listeners do not require IPv4; failures retain the underlying cause.
It is an explicit optimization for standard windows with at least two blocks
and at least two active transfers. Custom protocols, schedulers, shared blocks
and pacing providers keep the ordinary sender. Unsupported-protocol capability
failures (`ENOPROTOOPT`/`EOPNOTSUPP`) disable it for that address family (IPv4
or IPv6) until restart. `EIO` and MTU/size rejections disable it only for the
affected transfer, without further segmentation attempts during that transfer;
later transfers may try it again. Sockets, datagrams, ACKs and governor charging
remain core-owned. Non-Linux platforms accept but ignore the flag.

The public `negotiate_options` and `negotiate_options_for_request` helpers keep
the full RFC timeout range of 1–255; the timeout ceiling is enforced by the
server path.

`ProtocolError::TransferDeadline { addr }` distinguishes absolute expiry from
retry exhaustion; exhaustive error matches must handle it. Both are recorded as
the `TimedOut` audit outcome.

`ServerState::resolve_file_for_boot_session` requires managed TFTP
membership. Its fallback-profile argument is not authorization: absent or
expired sessions can resolve only the public `default` release, including when
a session expires while waiting for the control lock. Live unpinned sessions
must resolve a member of their own active release before pinning. Missing
members fail closed. Pinned sessions are manifest-strict on both transports.

Optional provider methods have conservative defaults: `requires_preparation`
keeps preparation unless a provider explicitly promises it would return `None`
without required validation or side effects. `encoding_batch_size` defaults to
one; providers may opt into `encode_packets_async` only for deterministic
ordinary-file encoding independent of send/ACK feedback. Lookahead is capped at
32 packets and 64 KiB of input; core preserves send windows, packet-size checks,
and retransmission. `max_burst_packets` defaults to one (post-send pacing).
Opting into larger bursts treats the delay as a packet interval, credits elapsed
processing/ACK time, and caps bursts at 32 packets and the negotiated window.

The example is optional and is not used by the default Tempest binary. It is a
composition template, not a scheduling algorithm: replace `DirectScheduler`
with a bounded provider crate while retaining its socket, error, and lifecycle
behavior.

## Composition Model

This approach is middleware-like in that independently developed capabilities
can be embedded in one server process, but it is not a generic middleware
pipeline:

- the builder stores at most one implementation of each contract;
- different contract types can be installed and operate together;
- each contract runs at a documented lifecycle point instead of intercepting
  every request; and
- multiple implementations of one contract require an explicit composite
  provider that defines ordering, fallback, and error behavior.

Use the narrowest contract that owns the intended decision:

| Requirement | Integration surface |
| --- | --- |
| Order or pace outgoing TFTP DATA | `TransferScheduler` or `TransferPacing` |
| Reuse blocks across readers | `SharedBlockCache` |
| Add an explicitly negotiated TFTP wire behavior | `ReadProtocolExtension` |
| Redirect or proxy a verified release-managed RRQ | `ReadRequestRouter` |
| Rank and stagger requests while at capacity | `AdmissionPolicy` |
| Supply inventory-derived scheduling weight | `ProvisioningPriorityProvider` |
| Automate sessions, releases, rollback, or withdrawal | HTTP API or a control client |
| Observe HTTP response production | `TftpServerBuilder::with_http_observer` |
| Export native metrics in-process without scraping HTTP | `TftpServerBuilder::with_meter(opentelemetry::metrics::Meter)` |

There is intentionally no catch-all hook for arbitrary TFTP, HTTP, or lifecycle
interception. A proposal that does not fit one of these ownership boundaries
should first define its invariants, failure behavior, and required context. It
may need a focused new contract or a core change rather than a universal plugin
trait.

## Ownership Boundary

Deletion remains core-owned; providers cannot override active/pin checks or
force byte reclamation. The HTTP client exposes preview and exact confirmation
for retained group/manifest metadata only. SQL deletion requires the opt-in,
database-enforced single-serving-node profile; byte deletion remains blocked.
`PersistenceConfig` has `coordinated_deletion` (default false) and
`max_snapshot_age_secs` (default 300, range 1-86400, greater than the ordinary
sync interval). Exhaustive Rust literals must set them or use
`..Default::default()`. `ResolvedFile` has `durable_reader`; exhaustive literals
must initialize it to `None` for SQL-free resolution. Compositions must retain
any supplied registration through the complete response/body or transfer
lifetime (including clones), not merely through artifact opening. Direct
`VersionStore` resolution is not SQL serving admission: compositions must use
the `ServerState` resolvers for SQL-backed delivery. See the
[deletion contract](docs/guides/deletion.md), including caller-owned dependency
checks.

Attached stores enforce serving admission regardless of the CLI persistence
switch. Standalone HTTP/TFTP startup and state reconciliation participate too;
custom states requesting persistence/deletion without a store are rejected.
Deletion-enabled serving stores bind reader admission and all durable
release/session mutations to their captured namespace generation under the SQL
revision lock; poisoning is permanent until restart, but exact existing-reader
cleanup remains possible. Lease admission shares one five-second deadline across
initialization and mutex waiting; the probe then has its own five-second
timeout. Core resolvers defer deletion-mode probing to authoritative
first-pin/reader/ownership transactions rather than duplicating it before
lookup.

Ordinary SQL mode selects a durable incompatible namespace at startup and does
not register transfer readers or probe a lifetime lease on each read.
Compositions must call `ServerState::sync_persistent_state` periodically:
ordinary artifact admission refuses unvalidated snapshots or snapshots at the
age bound, even if a custom runtime ignores refresh errors.
`TempestError::PersistenceSnapshotStale` maps to HTTP 503; admitted transfers
keep their admitted state. A stopped, explicit mode migration is required before
enabling deletion on a database that already selected ordinary SQL mode.

Linux uses nix for safe `UDP_SEGMENT` control messages and the capability probe.
The current rustix API supplies `sendmmsg` but not that typed ancillary message;
nix avoids adding unsafe control-message construction in core. Both dependencies
are Linux-only for networking and remain covered by `cargo deny`.
Public stores used only for control-plane writing need not acquire a serving
lease. Do not use that distinction to bypass `ServerState` delivery admission.
Logical artifact names must be canonical slash-separated relative paths; aliases
with empty/dot components or trailing separators are rejected before lookup.
Unicode identity remains exact, without normalization or case folding.

Tempest always owns:

- parsing and validating initial RRQ/WRQ packets;
- rate limits, per-IP TFTP permits, global transfer-slot accounting, and drain
  state;
- boot profile, session, version-group, manifest, path, and quarantine
  resolution;
- opening and verifying managed artifacts;
- per-transfer UDP sockets and RFC 1350 transfer IDs;
- RFC option negotiation, the absolute TFTP deadline, window state,
  retransmission, metrics, audit, and lifecycle cleanup; and
- enforcement of negotiated DATA payload size.

An extension must not duplicate or bypass those responsibilities. Extensions
that cannot honor the contract should return an error; silent fallback can
weaken an operator-selected policy.

Providers cannot bypass per-IP admission, the timeout acceptance ceiling, or
the absolute deadline. Core accepts RFC 2349 intervals exactly only when enabled
and within the configured ceiling; otherwise it omits timeout without changing
other option rules and uses bounded adaptive retries. The ceiling is not an
inactivity or total timer. Retry counts remain server-controlled, including
boot-phase overrides; no minimum-throughput eviction is provided.

Core creates the absolute deadline on entry to each RRQ/WRQ transfer.
Preparation consumes elapsed time but unabortable setup is not interrupted. Read
OACK/DATA exchange, including runtime scheduling and pacing, shares that
deadline; provider waits must tolerate cancellation and release queued work
through existing lifecycle cleanup. Progress, duplicates, and retries cannot
extend the deadline. It also covers write DATA reception and final ACK dally,
but final durable WRQ flush/publication may finish without timed cancellation
once the entire file is received before the deadline. Dally uses the original
deadline afterward. Accepted RFC 2349 intervals (including 255 seconds) remain
exact; expiry ends the exchange rather than triggering an early retransmission.
Core attempts one nonblocking standard ERROR (code 0) directly on its transfer
socket before cleanup; this courtesy must not queue new provider work or
postpone expiry. Published writes still attempt a final ACK instead of a
deadline ERROR. `accept_client_timeout = false` still declines that option
without disabling the absolute deadline. Combined with per-IP admission, this
provides partial isolation, not guaranteed fairness or protection from
distributed saturation.

## Contracts

### `TransferScheduler`

A scheduler registers transfer metadata, reports an optional pacing ceiling,
and accepts complete encoded DATA datagrams. Cross-transfer schedulers should
override `schedule_window` so one bounded fairness decision covers the next
negotiated window; packet-only schedulers inherit an immediate adapter. Every
datagram must use the `UdpSocket` supplied with `send_packet`. Replacing it with
a shared socket would violate the server TID required by RFC 1350.

Queues must be bounded. Closing or saturating an implementation should apply
backpressure or return an error rather than silently sending out of policy.
`schedule_window` and `send_packet` report policy or I/O failures to core;
queued windows must be cancelled when their caller or transfer is cancelled.

### `ProvisioningPriorityProvider`

This is deliberately a narrow serial-to-weight lookup. It does not select boot
profiles, activate releases, or stage artifacts. Those operations use the HTTP
control API. Providers should bound input, time out external requests, cache
only bounded state, and return `None` when unavailable.

### `TransferPacing`

The factory creates state for one transfer. A session may observe accepted ACKs
and return the delay applied after a DATA send. Delays must remain finite and
bounded. Pacing does not own the scheduler ceiling or aggregate governor.

### `SharedBlockCache`

A cache opens a transfer-local session keyed by content identity and source
block size. `read` may return a retained block or `None` to request a filesystem
read. `publish` may expose a newly read block. Dropping the session must release
reader/writer registration. Storage must be bounded by bytes or entries and
must preserve short final-block length.

### `ReadProtocolExtension`

`prepare` receives a core-owned `VerifiedArtifactSource`, file size, negotiated
RFC block/window size, raw bounded RRQ options, optional managed content hash,
and client IP. It returns `None` when none of its supported options was
requested. Extensions read only from that source handle; they do not reopen an
artifact pathname after verification.

A per-transfer session may add OACK options, choose a source payload, skip a
block, encode DATA, and receive bounded loss feedback. Observe these invariants:

- Custom behavior activates only after an explicit client request.
- OACK values must completely describe the client-visible wire contract.
- `core_payload_size` reserves custom frame overhead from the negotiated
  `blksize`. For a one-byte frame marker, return `blksize - 1`.
- `encode_packet` returns a complete TFTP DATA datagram. The default
  `encode_packet_async` implementation delegates to it without copying a
  borrowed core-read payload. Providers with CPU-heavy transforms should
  override the asynchronous method, convert `ReadProtocolPayload` to owned
  bytes only when required, and use a bounded blocking-worker pool.
- Tempest independently rejects an encoded result longer than
  `4 + negotiated_blksize` bytes.
- `accounted_bytes` describes logical content bytes, not UDP framing bytes.
- Sparse block skipping is valid only with no earlier DATA in flight; negotiate
  `windowsize=1` for bitmap resume.
- Resume must bind skipped blocks to the expected content identity.
- `transfer_complete` is evaluated against the source payload budget, not
  blindly against the negotiated wire budget.
- Retransmission behavior must be deterministic for an absolute block index.
- A custom wire contract should ship with a versioned reference client and
  server/client round-trip tests.

### `ReadRequestRouter`

A router runs after core resolves the signed active manifest but before it opens
the local artifact. Its context contains bounded client options and the
immutable boot-profile, group, artifact-version, manifest, and declared content
identity. It returns `RouteDecision::Local` or a numeric
`RouteDecision::Redirect(peer)`. Core owns redirect construction, signing,
delivery, terminal audit, and verified-local fallback.
After a local managed artifact passes core verification, the bounded
`local_artifact_verified` callback may update router-local residency state.

A redirect selector must:

- use numeric, validated peer endpoints or an explicitly secured resolver;
- bound peer lists and retry state;
- activate only after `x-tempest-redirect=1` and a supported
  `x-tempest-protocol-version` are explicitly requested;
- return only a numeric endpoint from a bounded peer set;
- rely on core's canonical protocol-v2 signature over peer, filename, release
  identity, digest, and expiry;
- require the client to verify that signature and its final artifact SHA-256;
  and
- leave ordinary clients on the local RFC-compatible path.

The signed
redirect proves which peer and bytes core authorized, but deployments must
still protect peer access and transport metadata on untrusted networks.

### `AdmissionPolicy`

Tempest owns the bounded channel, priority heap, transfer-slot reservation, TTL
pruning, and task launch. The policy supplies queue capacity, maximum age,
priority, and launch delay. Tempest clamps capacity to 100,000 entries, age to
1-300 seconds, and launch delay to 30 seconds.

Before global capacity or queue admission, core reserves one per-source permit
for RRQ/WRQ, shared across local shards and all source ports (not HTTP or other
nodes). It counts queued, reserved, and running work through transport
completion; duplicate RRQs on the live client TID add no permit. The client TID
and permit are released before terminal audit work, which uses its own bounded
admission budget. Per-IP excess returns ERROR 0,
`Client transfer limit reached`, contributes to `capacity_rejected_total`, and
is never enqueued. No policy can override this rejection. See
[bounded identity accounting](DEPLOYMENT.md#tftp-per-source-admission).

Priorities should be finite. Larger values launch first, with FIFO order for
equal values. A stagger policy should derive delay from a bounded launch
sequence; it must not perform I/O or retain packet contents.

## Failure Observability

Core exports explicit fallible-contract failures as:

```text
tempest_extension_failures_total{contract="scheduler",operation="send_packet"}
```

The label set is fixed in core: scheduler `schedule_window`/`send_packet`, read
protocol `prepare`/`encode_packet`, and router `handle`. An oversized encoded
DATA datagram rejected by Tempest is attributed to read-protocol
`encode_packet`. Provider-, client-, artifact-, and error-text values are never
used as labels, keeping cardinality and scrape cost bounded.

The counter records returned errors and provider output rejected by core. It
does not treat intentional `None` or `RouteDecision::Local` results as failures,
and infallible contracts cannot contribute to it. Tempest does not catch Rust
panics across extension boundaries; providers must not use panics for expected
runtime failure.

## Native OpenTelemetry Metrics

Supply an OpenTelemetry **0.32** `opentelemetry::metrics::Meter` using
`TftpServer::builder(config).with_meter(meter).build()?`. Core registers native
instruments directly, with no shared custom metric crate, parser, replay, or
snapshot adapter. Repeated `with_meter` calls replace the previous meter.

Programmatic server construction requires `server.max_boot_sessions` in
`1..=1_000_000` and returns a configuration error before initializing telemetry
when it is outside that range. File loading clamps out-of-range values instead.

The supplied provider belongs to the composition: configure its resource,
exporter, identity attributes, views, temporality, and shutdown there. Core
never reads or installs a global provider and never shuts down the caller's
provider. Keep it alive, stop server work, then flush and shut it down. Separate
server instances must have distinct scopes or attributes on their meters to
avoid registering identical streams into one provider. No external endpoint or
vendor identity is configured by core. Instrumentation remains active when
`api.enable_metrics = false` and before the server run loop starts.

Core always owns a second, local `SdkMeterProvider` with a cumulative
`ManualReader`, even with a supplied meter. Histograms fan out each real event
to both meters. Each observable callback samples **only its own family**, using
a weak server reference; external providers cannot retain `ServerState`.
Construct the server inside its serving Tokio runtime to expose runtime
metrics. The optional runtime handle is captured then; callbacks on exporter
threads never call `Handle::current()` and work outside Tokio. When constructed
outside a runtime, runtime samples are absent (not misleading zero values).

Business atomics and maps are authoritative. Cumulative business
values use `u64`/`f64` observable counters, **never `Counter::add(total)`**;
instantaneous state uses observable gauges, including gauge names ending in
`_total`. Transfer completion and `cutover_duration.observe`/`cutover_finished`
record actual duration events, not reconstructed distributions. Histogram
boundaries are the inclusive `server::DURATION_BUCKETS`, in seconds, exactly:
`0.001, 0.005, 0.025, 0.1, 0.5, 1, 5, 15, 30, 60, 120, 300`.
Do not override them with external histogram views if wire parity is required.
The public `DurationHistogram` helper keeps its own atomic bookkeeping.

### Cardinality and temporality policy

Business profile state retains its **10,000 profiles plus default**, **24-hour
inactivity TTL**. Evicted observable series can reset when a profile returns;
exporters must handle those resets. SDK timestamps are provider/stream times,
not exact per-profile creation times. Sampling across families remains
best-effort rather than a global transaction.

The local provider sets **60,007 attribute sets per stream**, plus the SDK
overflow series, enough for three transports times all tracked transfer profiles
including default. The session-profile gauge `tempest_active_boot_sessions`
instead uses **twice `server.max_boot_sessions`** (with a minimum session
capacity of one), because every live session may have a distinct profile and
SDK 0.32.1 gauges retain the previous collection's labels until after the next
callback.
This covers full profile replacement between collections without losing counts;
stale labels are then evicted, so churn does not consume a lifetime allowance.
These limits are bounded, rather than the SDK's default 2,000 limit. External
providers must install equivalent or larger **bounded cardinality views** on
these native instruments (including scope/identity attributes introduced by
their meter). A provider default of 2,000 will lose profile detail. The bound
must also cover deployment-specific version/session profile and worker counts.

Native cumulative histogram series do **not** expire at the business-state TTL:
they retain lifetime totals until the provider is destroyed. Profile churn can
eventually exhaust the configured lifetime bound. OTel then records histogram
events under `otel.metric.overflow=true`; totals/counts are conserved but
profile identity is lost. **SDK 0.32 observable overflow is last-value, not
additive**: an undersized view can lose even aggregate business-counter totals.
Do not use the overflow value as a sum of dropped profiles. Monitor overflow and
size the provider for the actual bounded workload; tests explicitly exercise the
low-limit behavior. HTTP uses the valid Prometheus label `otel_metric_overflow`.
Delta external readers may release histogram aggregation state between exports,
but have different backend semantics; core does not choose that policy for you.

### Standalone Prometheus compatibility

The authenticated `/metrics` route does not depend on a supplied meter. Core
collects its local reader on the first scrape or maintenance tick, then
publishes text every five seconds, even if the HTTP route is disabled. Only text
is cached; external export samples live instruments independently of that cache.
Concurrent cold scrapes/maintenance are serialized. The encoder consumes
**standard SDK `ResourceMetrics`**, preserves exact `u64` integers (including
values beyond 2^53), escapes labels, and renders disjoint SDK buckets as
cumulative Prometheus buckets plus `+Inf`. No resource/scope labels, units, or
counter suffixes are appended. The generic Prometheus protobuf encoder was not
used because its floating-point values would lose that integer precision.

All 59 family names, HELP descriptions, types, and native label dimensions are
fixed and schema-tested. Before any observation, the SDK does not emit a
histogram datapoint: core emits its HELP/TYPE but does not invent zero events.
In particular a started/failed-only profile has no duration sample until its
first completion, and an unused cutover histogram has no `_count` sample yet.
Prometheus whitespace/family ordering is not a contract. Native integer
precision does not imply that signed-only OTLP/backend storage can represent
all `u64` values; that export policy belongs to the composition.

## Compatibility and Versioning

The traits are a public Rust API and follow the crate's semantic versioning.
Before `1.0`, a minor release may revise a trait when correctness requires it;
the changelog will call out migration steps. Composition workspaces should pin a
compatible Tempest version and run against both the minimum supported Rust
version and the current stable toolchain.

A provider change should include:

- unit tests for bounds and failure behavior;
- a behavior test through the actual public trait;
- a TID/socket test for packet senders or routers;
- server/client round trips for custom wire behavior; and
- documentation of runtime configuration and downgrade behavior.

## Repository Integration

Treat core, public integrations, and provider compositions as separate release
units. A released integration or composition should pin an approved Tempest
version or immutable source revision. Relative path dependencies are suitable
for local development only and must not become an undocumented production
requirement.

Changes spanning repositories proceed in dependency order:

1. Evolve the owning core trait or HTTP contract, with compatibility tests and
  migration notes.
2. Update public clients or vendor-neutral integrations.
3. Update provider implementations and composition binaries.
4. Validate the exact version combination, including a runtime scenario when
  wire, lifecycle, or configuration behavior changed.

Core changes must not name or special-case a private provider. Public
integrations must not depend on private adapters or identities. A provider that
needs an unavailable capability should propose a narrow public contract rather
than copy release, path, socket, or lifecycle ownership out of core.

## Safety

The Tempest crate forbids unsafe Rust. Extension crates are strongly encouraged
to do the same. An extension using unsafe code must document why a safe API was
insufficient, identify the invariants, and include focused tests or analysis for
that block.

## HTTP Observation

`with_http_observer` installs a read-only observation callback. The callback
receives `HttpObservation`: a normalized method, core route template (or no
match), status (or cancellation), and time until response headers. It cannot
change routes, requests, responses, authentication, or rate limiting. Raw paths,
query strings, headers, bearer tokens, and bodies are never supplied.
Response-body streaming and transport errors after headers are outside this
observation. Callbacks must not panic or block; exporters must use bounded
queues and drop telemetry at capacity. One callback is installed;
composition-owned fan-out must state its ordering and overload policy. Exporter
setup and shutdown remain owned by the composition. Private exporter
dependencies and their toolchain requirements must be resolved in that
composition, without raising core's MSRV implicitly.

```rust,no_run
use tempest::{config::TempestConfig, server::TftpServer};
let server = TftpServer::builder(TempestConfig::default())
    .with_http_observer(|event| {
        // Submit only to a bounded, nonblocking composition-owned exporter.
        let _ = (event.method, event.route, event.status, event.elapsed);
    })
    .build()?;
# Ok::<(), tempest::error::TempestError>(())
```

## Control Client Sessions

The typed control client's `RegisterSessionRequest` has `require_managed`: set
it to `false` for direct-root compatibility or `true` to require a pinned
release. The HTTP request flag is optional and defaults to false. Registration
responses also expose `boot_profile` and `manifest_digest`.
`ControlClient::revoke_session` accepts a redacted `RevokeSessionRequest` proof
and revokes only the current matching capability.
