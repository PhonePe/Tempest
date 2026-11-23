<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Deploying Tempest

This guide covers the default open-source binary. Compile-time extensions use
the same core but have their own composition configuration and operational
runbook.

## Single Node

A single node provides TFTP, the HTTP control/artifact service, process-local
release consistency, audit, DSCP, and optional bandwidth governance. Recommended
boundaries:

- UDP 69 is reachable only from provisioning clients.
- HTTP 8080 is loopback or restricted to the management plane unless boot
  clients use an artifact route; in that case expose only the required listener
  through the controlled provisioning network.
- The artifact root is immutable between release API operations, and TFTP
  serves only files published in a release.
- API and database secrets come from a protected environment file or secret
  manager.
- Signing keys are outside the artifact root and backup scope is explicit.

The Salt formula under [`salt/`](salt/) renders only settings supported by the
default binary.

## Simultaneous L2 and routed L3 containers

The production [`Dockerfile`](Dockerfile) builds one unprivileged image with
SQL persistence enabled. The dual-plane profile runs that image twice on each
Linux host: one process binds the directly connected L2 provisioning address,
and one binds the `/32` service VIP originated by the odd/even FRR pair. Both
processes mount the same immutable artifact tree and durable control store, but
retain separate transfer sockets, capacity, caches, and audit logs.

Use Linux host networking for this profile. TFTP changes from the well-known
listener port to a per-transfer ephemeral UDP port; publishing only UDP 69
through bridge NAT is therefore incomplete. Bind each process to its explicit
service IP rather than `0.0.0.0`, so the listener and ephemeral transfer sockets
use the address the client requested.

Run FRR under the host's own service management (for example systemd) instead
of adding routing capabilities to the Tempest image. For stateful TFTP, prefer
odd/even active/standby BGP selection. Equal-cost anycast is safe only after the
fabric has demonstrated stable, symmetric backend selection for the complete
reversed UDP five-tuple. Gate L3 prefix origination on the local L3 Tempest
`/ready` state; BGP peer health alone does not prove application readiness.

See [`deploy/container/README.md`](deploy/container/README.md) for the Compose
profile, hardened mounts/capabilities, worker allocation, FRR policy examples,
and failure-test procedure.

## TFTP and HTTP Roles

Legacy firmware can obtain the first-stage loader over TFTP. A client without a
boot session receives only members of the active `default` boot profile
release, so every bootfile DHCP advertises to such clients must be published in
that release. A header-capable
iPXE client may fetch larger artifacts from
`/api/v1/artifacts/{filename}` with the session's short-lived bearer token.
Native UEFI HTTP Boot firmware may instead fetch the one configured managed
artifact from a fixed `/boot/v1/{filename}` URI when
`api.enable_native_http_boot` is explicitly enabled. All three paths use the
same session and version resolver.

Do not send the control API key to boot clients. The general HTTP artifact
route requires the session bearer token and a resolved client address matching
that session. The native HTTP Boot route and TFTP associate clients with the
active source-IP session. Avoid shared NAT or address reuse on those paths.
Tempest honors a single forwarded client address only when the direct peer is
listed in `api.trusted_proxy_ips`; trust only a proxy that overwrites inbound
forwarding headers.

The optional [HTTPS artifact container](deploy/container/https/README.md) uses
Linux host networking to preserve client source addresses and listens on
unprivileged TCP 8443 as UID/GID 101, with all capabilities dropped and
`no-new-privileges` enabled. Client URLs and probes must include `:8443`; allow
that port through the provisioning firewall. Port 443 requires a separately
managed host TLS boundary with equivalent artifact-only access and trusted
client-identity handling. Do not lower the host's unprivileged-port sysctl or
add container privileges to make this example bind 443.

## Release Deployment

Place immutable artifacts beneath the configured root before calling the
versions API. Files under the root are not served over TFTP until they belong
to a published release. The API canonicalizes each path, requires a regular
file under the root, hashes each artifact, and builds the manifest before
cutover.

Choose a policy deliberately:

- `preserve_sessions`: normal rollout. Existing session pins remain on the old
  group; new sessions use the new group after affected transfers drain.
- `drain_all`: withdrawal of a known-bad release. Activation waits for affected
  transfer and session pins, subject to the bounded timeout.

A failed timeout or persistence revision conflict leaves the prior active group
in place. Rollback reactivates a retained verified group. Withdrawal requires
the requested group ID to match the active group.

## Audit Records and Manifest Trust

Release manifests are verified independently of audit history. Deployment nodes
that create signed manifests need the manifest private key; verifier-only nodes
need the public key. When `require_signed_manifests = true`, missing or invalid
manifest trust material fails closed.

The audit log is deliberately simpler: it is unsigned JSONL operational evidence
of what Tempest delivered, to which peer, by which transport, with which
artifact and manifest digest, at what terminal time, and with what outcome. It
is not a tamper-evident or externally authenticated ledger. Protect the audit
directory with host permissions and export records to a separately trusted log
service if the deployment requires stronger evidence.

Each JSONL object contains the local `sequence`, terminal `timestamp`, peer
identity (`client_ip` plus optional MAC/serial/profile), `file_path`,
`file_sha256`, block and retransmission counts, terminal `outcome`, optional
`trace_id`, and optional delivery identity. Delivery identity records the
transfer ID, release group, artifact version, manifest digest, boot phase, and
transport (`TFTP`, `HTTP`, or `HTTP_NATIVE`). The HTTP audit API returns the
same objects newest first.

| Location | Purpose |
| --- | --- |
| `<log_path>` | Active, durable, operator-readable JSONL write-ahead log |
| `<log_path>.rotated.<timestamp>.seq<next>` | Complete rotated JSONL segments |

Use Tempest's own size rotation rather than external `copytruncate` so the
writer retains control of durable appends and segment ordering. A finite
`rotate_keep_segments` value simply removes the oldest complete rotated segment.
Startup repairs only a crash-torn final JSON line and reads at most the bounded
tail needed to resume the sequence; retained history is not rescanned.

With audit enabled, terminal outcomes are serialized directly into large JSONL
group commits. One writer performs one `sync_data` per group and releases the
associated audit reservations only after that sync succeeds. The JSONL file is
the only durable audit write.

Each transaction contains at most 16,384 records or 16 MiB and waits at most
10 ms to collect a partial batch. The deadline does not grow under load. This
reduces sync frequency on storage with expensive durable commits; an abrupt
process or host failure can lose records in the current unsynced group, while a
graceful shutdown waits for the group to sync.
`audit.queue_max_bytes` bounds the memory represented by reservations awaiting
the writer. Every admission initially reserves the proven 8 KiB maximum encoded
record size, then shrinks to the actual encoded upper bound when its terminal
record is queued. A separate queue bound permits at most four full record
batches; neither bound is derived from transfer concurrency.

The metrics endpoint exports fixed-cardinality audit pipeline diagnostics.
`tempest_audit_admission_rejected_total` has fixed `byte_capacity`,
`writer_queue`, and `writer_failure` reasons.
`tempest_audit_queue_outstanding_records` and
`tempest_audit_queue_reserved_bytes` show live pressure. Over an observation
interval, `tempest_audit_jsonl_records_total /
tempest_audit_jsonl_batches_total` shows the effective batch size, while
`tempest_audit_jsonl_bytes_total` and
`tempest_audit_jsonl_commit_seconds_total` show durable write volume and time.
Compute ratios from counter deltas rather than process-lifetime totals.

## SQL Persistence

Build `--features sql-persistence` and configure PostgreSQL or a
MySQL-compatible URL. Persistence stores control metadata and boot sessions,
not artifact bytes. Every node must have the same immutable files at the paths
recorded in each manifest.

Durable revision checks serialize competing release writers. Nodes poll and
validate committed state before replacing their hot cache. This is convergence,
not cluster-wide linearizability:

- a remote node may serve its prior active snapshot until synchronization;
- transfer/session pin counts and cutover gates are node-local;
- session registration may not be visible immediately on another node; and
- drain on one node does not drain the fleet.

Use load-balancer affinity for a boot epoch, distribute artifacts before
activation, and health-check every node's local files. A stronger global cutover
requires an external orchestration barrier.

## Capacity and Bandwidth

Before rollout, use the
[isolated before/after policy test](docs/guides/tftp-client-policy-testing.md)
with saved installed and candidate executables. It tests synthetic traffic in a
private Linux network namespace, never against the live service. Keep binary
hashes and results with deployment evidence; do not run slot-holding probes on
production listeners.

Set `max_concurrent_transfers` from measured client, CPU, file-descriptor, and
network limits. At global capacity the default binary returns a TFTP error;
clients may retry. Advanced admission/stagger behavior is supplied through an
external `AdmissionPolicy`, not core TOML.

`server.max_tftp_transfers_per_ip` defaults to 16 (inclusive range 1–10000;
zero cannot disable it). One source IP shares a combined queued/reserved/running
RRQ/WRQ budget across all ports until transport completion. Duplicate RRQs
on the same live client TID add no permit. Excess receives ERROR 0,
`Client transfer limit reached`, before global/queue admission and is never
enqueued, even with an admission provider. Monitor the
`capacity_rejected_total` counter (Prometheus
`tempest_capacity_rejected_total`); it includes these rejections as well as
other capacity rejections, so it is not
a per-IP-only diagnostic. Transport completion releases the client TID and
source permit before terminal audit work, allowing the next boot-file request
from the same endpoint. Slow audit storage can exhaust the separate bounded
audit budget and reject new work; the per-IP cap does not isolate audit usage.

This quota is independent of request rate and global capacity, spans local
listener shards, and excludes HTTP; it is not cluster-wide. A smaller global
cap is valid. A per-IP cap at or above the global cap cannot reserve capacity
for other clients. Account for shared NAT and single-source load generators
before raising it: all those clients compete for the same quota. This is partial
isolation, not fair scheduling or authenticated identity. Distributed or spoofed
sources can still exhaust capacity; retain ingress firewall restrictions and
network anti-spoofing controls. The bounded identity map and fail-closed
behavior are described in
[TFTP per-source admission](#tftp-per-source-admission).

`tftp_requests_per_ip_per_second` limits datagrams arriving on the shared TFTP
listener from one source address in each one-second window. The default is 50;
raise it for measured request bursts or load generators that share a source IP.
The accepted range is 0 through 1,000,000. Zero explicitly disables this
ingress safeguard and should be confined to an isolated benchmark network.

`http_requests_per_ip_per_second` applies one shared per-source budget across
the control API, metrics, bearer artifact downloads, and native HTTP Boot. The
default is 100 requests per second, the accepted range is 0 through 1,000,000,
and zero has the same isolated-benchmark-only meaning as the TFTP setting.
Health and readiness probes are outside this limiter.

The HTTP artifact cache is independent of the TFTP hot cache. Its
`api.artifact_cache_max_bytes` and `api.artifact_cache_max_file_bytes` defaults
are 64 MiB and 16 MiB. Set both to zero to disable it; otherwise budget its
retained memory in addition to the configured TFTP cache. Managed entries need
an exact pinned digest and size; unmanaged entries reuse
`server.unmanaged_cache_validation_interval_ms`, including zero for a
capability open on every request.

On Linux, `listener_shards` can distribute initial RRQ/WRQ intake with
`SO_REUSEPORT`. The default value of zero selects one shard per available CPU,
bounded to 64; an explicit value fixes the fan-out, and one forces the portable
path. Non-Linux builds resolve zero to one and reject larger values. Shards
share the same exact per-IP request limiter, per-IP TFTP quota, active-transfer
ceiling, client-TID registry, audit writer, and capability root; transfer
sockets remain isolated per RFC 1350.
Tempest deliberately does not multiplex active transfers onto one server TID:
fresh transfer sockets prevent stale ACKs from being accepted after a client
port is reused and preserve ERROR 5 handling for packets from unknown TIDs.

The optional core bandwidth governor caps aggregate TFTP DATA and HTTP artifact
chunks at a long-run byte rate with a bounded burst. It does not reserve
capacity per client and does not replace host or switch QoS.

Boot-phase block/window settings are negotiation ceilings, not forced values.
A client that does not request larger blocks/windows remains on the standard
fallback.

### Long-transfer profile

The default absolute TFTP network deadline is 300 seconds (valid 1–86400;
zero cannot disable it). It is nonrenewable even with progress and must be
raised explicitly for legitimate longer RRQ/WRQ transfers. For illustration
only, merge these settings into the existing server table:

```toml
[server]
max_transfer_duration_secs = 1800
accept_client_timeout = true
max_client_timeout_secs = 5
max_tftp_transfers_per_ip = 16
```

This is **not a measured recommendation or firmware qualification**. Validate
with the intended firmware, image sizes, shared-IP concurrency, loss, latency,
pacing, and network path before rollout. Longer lifetime caps allow legitimate
slow transfers but also retain sockets, pins, and other resources longer; they
do not guarantee availability. No minimum-throughput eviction feature exists.

`max_client_timeout_secs` defaults to 255, with a valid range of 1–255. With
negotiation enabled, this example accepts client timeout requests 1–5 exactly
and omits larger or invalid requests from OACK, never clamping them to 5. Other
options keep their own negotiation rules. `accept_client_timeout = false`
omits all timeout requests regardless of the ceiling. Omission uses bounded
adaptive retries. This ceiling is **not an inactivity timeout or a
total-transfer timer**. Retry budgets remain server-controlled through
`max_retries`, with boot-phase overrides; phase adaptive intervals apply only
without a negotiated timeout. The absolute deadline remains independent and can
end an exchange before retries are exhausted.
See [deadline scope and completion exceptions](#tftp-absolute-deadline).

Protocol and design references:

- [RFC 2347](https://www.rfc-editor.org/rfc/rfc2347) permits option omission;
  [RFC 2349](https://www.rfc-editor.org/rfc/rfc2349) requires an accepted timeout
  to match the requested interval exactly.
- [tftpd-hpa `--refuse` documentation](https://manpages.debian.org/bookworm/tftpd-hpa/in.tftpd.8.en.html)
  illustrates server-side refusal of option negotiation; it is not a claim that
  its timeout policy is identical to Tempest's numeric acceptance ceiling.
- [nginx `limit_conn`](https://nginx.org/en/docs/http/ngx_http_limit_conn_module.html)
  is a per-key concurrency design reference, not equivalent UDP/TFTP admission
  semantics or evidence of Tempest fairness or performance.

### TFTP per-source admission

`server.max_tftp_transfers_per_ip` (default 16, range 1–10000, zero invalid)
counts combined queued, reserved, and running RRQ/WRQ work until transport
completion. A permit follows the client TID through queue handoff, execution,
and transport cleanup; all ports from one source IP share the count. Negotiated
RRQs retire their listener deduplication entry after ACK(0), but retain the
source permit, transfer socket, and release pin until transport completion.
Requests without OACK and WRQs retain the entry through transport completion.
A new request still needs its own source permit even after an earlier request
entry was retired. Transport permits are released before terminal audit
submission or fallback writing. Audit work retains its separate bounded
admission budget, not the per-source permit. HTTP does not count.
The map is shared across local listener shards, not nodes. IPv4-mapped IPv6
addresses canonicalize to IPv4. It tracks at most 100,000 live IP identities,
fails closed for new identities at capacity without evicting live permits,
and removes an entry when its count reaches zero.

Per-IP excess or identity-map exhaustion returns TFTP ERROR 0,
`Client transfer limit reached`, increments `tempest_capacity_rejected_total`,
and never enters global admission or the queue. The per-IP cap is independent
of `max_concurrent_transfers`; a smaller global cap is valid. If the per-IP cap
is at least the global cap, it cannot reserve capacity for other sources.
Shared NAT clients compete for one quota. Source identity is not authentication:
spoofing and distributed sources still require ingress firewall and network
anti-spoofing controls.

### TFTP absolute deadline

Core creates one absolute deadline on entry to each RRQ/WRQ transfer using
`server.max_transfer_duration_secs` (default 300, inclusive range 1–86400;
zero is invalid). Preparation counts against elapsed time, but unabortable
setup is not interrupted. The protocol exchange enforces the same deadline
across RRQ OACK and DATA, including runtime scheduler and pacing waits, and
across WRQ DATA reception and final ACK dally. Valid progress, duplicate
packets, and retries never refresh it.

Once the entire WRQ file has been received before the deadline, final durable
flush and publication are allowed to complete without timed cancellation.
Final ACK dally retains the original deadline rather than receiving a fresh
budget after publication. Thus the deadline bounds network exchange, not all
preparation or durable-completion work or the transfer task's total lifetime.
An accepted RFC 2349 timeout remains exact, even at 255 seconds; the server may
terminate at the absolute deadline but must not retransmit early to fit it.
Expiry before completion attempts one nonblocking TFTP ERROR (code 0) from
the owned transfer socket. Failure to send cannot delay cleanup or replace
the deadline outcome. A durably published WRQ still attempts its final ACK,
even when publication crossed the deadline; it is not reclassified as expired.
The configured lifetime is resource policy, not an RFC-prescribed duration.
Declining client timeout negotiation remains independent of this deadline.
Together with per-source admission this provides partial isolation, not a
fairness guarantee under continuous new or distributed requests. The
300-second default does not accommodate every legitimate long transfer;
operators must explicitly raise it and validate firmware/network behavior.
Longer caps also permit longer resource retention; see the
[illustrative deployment profile](#long-transfer-profile).

## Network and Host Hardening

- Run as a dedicated unprivileged user with only `CAP_NET_BIND_SERVICE` when
  port 69 is required.
- Keep WRQ disabled unless uploads are necessary.
- Apply firewall policy separately to UDP TFTP, TCP management routes, and TCP
  artifact traffic reachable by boot clients.
- Put the API behind TLS when it crosses a host boundary.
- Protect the provisioning VLAN from spoofing and untrusted clients.
- Use Secure Boot or equivalent client-side verification; TFTP itself offers no
  integrity or authenticity.
- Set the hard `RLIMIT_NOFILE` above `2 * max_concurrent_transfers + 1024` for
  the core server, or `3 * max_concurrent_transfers + 1024` for a composition
  with a custom read-protocol provider. Tempest derives the requirement from
  the installed composition, raises its soft limit only to that value, and
  rejects a configuration the process hard limit cannot support.
- Monitor file descriptors, active transfers, failures, retransmissions,
  release events, audit errors, and database synchronization.

## Health and Rollout

`/health` reports process liveness. `/ready` returns HTTP 200 `READY` when the
TFTP listener and critical services are usable; otherwise it returns HTTP 503
with `STARTING`, `DRAINING`, `DEGRADED`, or `STALE` (the SQL snapshot is older
than `persistence.max_snapshot_age_secs`). Load balancers should route only to
`READY` nodes.

For a binary rollout:

1. Remove or drain one node from service.
2. Wait for active transfers to reach zero.
3. Replace the binary and configuration using the same feature profile.
4. Reapply file capabilities.
5. Start and wait for `/ready`.
6. Republish release state if SQL persistence is disabled, then verify
   control-state sync and a real TFTP transfer of a release member.
7. Return the node and continue one at a time.

## Backup and Recovery

Back up configuration, database control state, the complete audit-log family,
and release-manifest keys according to separate retention policies. Artifact
storage should be reproducible from an artifact repository. Restoring only the
database without the exact artifact bytes will fail managed-file validation.

Test recovery with an isolated database and staging VLAN. Never point test
suites or demos at a production persistence database.
