<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tempest Go-Live Checklist

Use this checklist for the default open-source server. An extension composition
must add its own scheduler, router, custom-protocol, admission, and sidecar
checks.

## Release Artifact

- [ ] Source revision and Cargo.lock are recorded.
- [ ] `cargo fmt --all -- --check` passes.
- [ ] Strict all-target/all-feature Clippy passes.
- [ ] Default and `sql-persistence` test profiles pass.
- [ ] Rustdoc builds with warnings denied.
- [ ] Dependency advisory/license/source checks pass.
- [ ] The binary was built with the intended Rust version and Cargo features.
- [ ] Binary hash and architecture are recorded.
- [ ] No private keys, credentials, internal URLs, generated downloads, or
      confidential documents are present in the release package/history.

## Compatibility

- [ ] Each BIOS PXE, UEFI PXE, and iPXE implementation in scope has a recorded
      transfer test.
- [ ] Each native UEFI HTTP Boot implementation in scope has a recorded fixed-URI
      `GET` and `HEAD` test, or the native route remains disabled.
- [ ] Every bootfile advertised to clients without a boot session (DHCP
      Option 67) is a member of the active `default` release; Tempest has no
      raw-root TFTP fallback.
- [ ] Standard no-option RRQ works.
- [ ] Requested `blksize`, `timeout`, `tsize`, and `windowsize` combinations work.
- [ ] Server DATA originates from one stable ephemeral TID.
- [ ] Wrong-TID traffic receives or preserves RFC-compatible handling.
- [ ] Kernel, initrd, config, and image sizes used in production were exercised.
- [ ] Packet loss, timeout, retransmission, block rollover, and client abort
      behavior were tested where relevant.

## Release Consistency

- [ ] Every managed artifact path is immutable and beneath the configured root.
- [ ] A version group can be activated and listed with the expected hashes.
- [ ] One client pinned to release A remains on A while a new session uses B
      under `preserve_sessions`.
- [ ] Strict pinned membership rejects an artifact absent from the manifest.
- [ ] Rollback to a retained group works.
- [ ] Withdrawal rejects a stale or non-active group ID.
- [ ] `drain_all` and its timeout behavior match the operational runbook.
- [ ] HTTP artifact responses report the same profile/group/manifest identity as
      the session's TFTP path.
- [ ] Native HTTP Boot serves only the configured managed logical name and the
      same URI selects the expected profile for at least two client sessions.

## Security

- [ ] TFTP is reachable only from the provisioning network.
- [ ] API bind and TLS boundary are reviewed.
- [ ] API key is at least 16 characters and loaded from protected secret state.
- [ ] Service runs without root and has only required capabilities.
- [ ] WRQ is disabled or constrained to a reviewed writable path and size.
- [ ] Artifact root, audit log, database credentials, and manifest signing keys have
      least-privilege permissions.
- [ ] Manifest signing and verification roles use matching keys.
- [ ] Client-side signed boot verification is enabled where supported.
- [ ] Source-IP session assumptions are valid: no shared NAT, hidden proxy
      address, or uncontrolled address reuse.
- [ ] `api.enable_native_http_boot` is disabled unless native firmware needs it;
      when enabled, the advertised URI, managed filename, VLAN boundary, and
      trusted-proxy behavior have been reviewed.
- [ ] Security reporting contacts and private repository reporting are enabled.

## Persistence and Multi-Node

- [ ] The binary includes `sql-persistence` when persistence is enabled.
- [ ] PostgreSQL or MySQL backend tests passed against the selected engine.
- [ ] Database user and network policy are least privilege.
- [ ] All nodes hold identical artifact bytes at recorded paths before activation.
- [ ] Session affinity covers the expected synchronization interval.
- [ ] Operators understand that cutover gates and pins are node-local.
- [ ] Backup and restore of database state, artifacts, audit evidence, and keys
      has been rehearsed.

## Capacity and Observability

- [ ] `max_concurrent_transfers` is based on measured load, not only defaults.
- [ ] File-descriptor and socket limits exceed the tested concurrency envelope.
- [ ] Aggregate governor rate matches the provisioning NIC budget when enabled.
- [ ] Prometheus scrapes `/metrics` through the intended auth boundary.
- [ ] Alerts cover readiness, capacity rejection, failures, retransmissions,
      release-control failures, audit write failures, and database sync errors.
- [ ] Dashboard queries refer only to metrics emitted by the default binary.
- [ ] Logs are structured, retained, and free of secrets.
- [ ] Audit rotation and archival preserve every durable JSONL segment.

## Cutover

1. Deploy artifacts to every serving node and verify hashes.
2. Register a canary boot session and activate the target group in a canary
   profile.
3. Boot through both TFTP and HTTP stages; compare response/audit identity.
4. Observe readiness, failures, retransmissions, bandwidth, and release events.
5. Activate the production profile with the selected cutover policy.
6. Keep the prior verified group and rollback procedure available through the
   observation window.

## Rollback Triggers

Rollback or withdraw when managed artifact verification fails, boot-chain
compatibility fails, session pin behavior diverges, persistent control state
conflicts repeatedly, or client failure/tail latency exceeds the agreed rollout
threshold. Record the group, manifest digest, artifact hashes, client types, and
audit evidence before cleanup.
