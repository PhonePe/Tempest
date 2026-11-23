<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Dependency-aware deletion

## Shipped scope

Deletion is **not withdrawal**. Existing digest-bound withdrawal removes active
profile mappings while preserving retained manifests and pinned sessions.
The new deletion API can remove **one inactive, unpinned retained group and its
embedded manifest, without deleting bytes**, when persistence is disabled or
the SQL single-serving-node coordination profile below is enabled. Other
retained groups must preserve every managed logical-name ownership fence.
There is no standalone manifest object to delete independently of its group.

Both routes require the existing control authentication, body/rate limits and
`api.enable_versions_api`. SQL-free deletion needs no additional flag; default
and `--no-default-features` builds remain SQL-free. SQL deletion requires the
existing `sql-persistence` feature and `persistence.coordinated_deletion = true`.
Other SQL instances continue to report the coordination blocker.

Authentication is the configured `x-api-key`; there is no separate deletion
role or permission scope. The only keyless exception is the existing explicit
`api.allow_insecure_loopback = true` with a loopback API bind and no configured
key. A configured key is still required on loopback. Callers must supply
`Content-Type: application/json`. Disabling the versions API removes both routes
(404), rather than granting access to a less restricted deletion path.

## Preview and confirmation contract

`POST /api/v2/delete/preview` accepts an object with a `target`:

- Group: `{"kind":"retained_group","boot_profile":"default","group_id":"release-1"}`.
- Physical file: `{"kind":"file","path":"releases/v1/kernel"}`. This is a
  root-relative physical filename, not a logical name or absolute server path.

The response has `target`, `expected_identity` (64 lowercase hexadecimal characters),
`can_delete`, `blockers`, and `referring_groups`. For groups, identity is the
manifest digest, which binds profile, group, version, timestamp and member
identities. For files, it is an opaque domain-separated digest binding the
capability path, filesystem replacement/mutation metadata and stable byte digest.
No token state is allocated, no lock is retained, and previews do not expire by
time: they are observations whose identity and dependencies are rechecked.

`POST /api/v2/delete/confirm` takes exactly `target` and `expected_identity` from
the displayed preview. Group removal checks the identity and current active,
cutover, boot-session and transfer references under core's control/groups locks.
Active-snapshot selection and transfer pin acquisition share the groups lock,
closing the old-snapshot-after-withdrawal race. Rollback prepared before deletion
must still find the retained identity when it reserves activation. No await or
fallible filesystem work separates final validation from SQL-free publication.
For SQL, the durable transaction commits first; memory publication follows it.

Success is HTTP 200 with `deleted` (the target), `expected_identity`, and
`bytes_deleted:false`. Bytes and unrelated groups remain untouched. Removing the
last retained owner of any logical name is blocked, including after a previously
safe preview. Deletion cannot restore unmanaged HTTP compatibility for a managed
name. TFTP continues to require managed membership. Metadata-only deletion is not a
secure erase or storage reclamation operation.

Errors: 400 invalid identity/path or syntactically invalid JSON; 401 missing/invalid control authentication;
404 target missing/already removed or API disabled; 409 changed identity (text)
or blockers (`{"blockers":[...]}`); 408 request body read timeout;
413 configured body bound; 415 missing/unsupported JSON content type;
422 typed JSON mismatch/unknown fields; 429 control rate limit; 503 busy control/hash workers,
oversized/unstable/uninspectable file or snapshot capacity. No force, cascade,
automatic withdrawal, automatic session revocation or transitive deletion exists.

## Blockers

| Code | Meaning |
| --- | --- |
| `active_release` | Withdraw explicitly before considering metadata deletion. |
| `boot_session_pinned` | A local boot session retains the manifest; expired entries can conservatively block until cleanup. |
| `transfer_pinned` | A local transfer still references a member version. |
| `cutover_in_progress` | Deployment/rollback has reserved the profile. |
| `persistence_coordination_unavailable` | SQL coordination is disabled, unavailable, timed out, or at capacity. On an uncertain commit, refresh before retrying. Durable active, pinned-session, and live-reader refusals use `active_release`, `boot_session_pinned`, and `transfer_pinned`; a changed durable identity returns the stale-identity conflict. |
| `byte_deletion_unavailable` | All byte deletion is currently refused, including unmanaged files. |
| `retained_reference` | Known retained groups refer to the inspected bytes. |
| `reference_check_incomplete` | A reference could not be inspected or remote SQL state may differ. |
| `ownership_fence_required` | Another retained group in the same profile must preserve every managed logical name; last-owner deletion is unsupported. |

File previews hash at most 4 GiB, stream through a fixed buffer and use the shared
four-permit hashing budget with immediate refusal at capacity. Reference scans
inspect at most 100 retained groups/10,000 members without hashing every member.
Capability-confined nonblocking Unix opens reject directories, FIFOs and escaping
symlinks; device/inode comparison detects hardlink and in-root symlink aliases.
Missing references make the list incomplete, not safe. File preview identity and
references are advisory observations, not one atomic namespace snapshot. Slow
filesystem calls may still occupy a worker; cancellation does not spawn unlimited
replacement work because the worker owns its permit until completion.

## Deliberately missing online capabilities

**HTTP byte deletion:** the current unmanaged HTTP/read cache and WRQ publication paths
do not share a physical-file lifecycle lock. Path hashing followed by unlinking
cannot atomically compare the previewed inode against a concurrently replaced
directory entry. Drain status alone does not exclude all queued/starting work,
publishers, external writers or remote instances. Therefore a byte request never
unlinks anything, even when its referring-groups list is empty. Supporting it
requires core-owned read/publication/deletion exclusion, confinement-safe
compare-and-remove or namespace ownership, cache invalidation and durable cleanup
recovery. All referring retained groups must be removed explicitly first; a future
implementation must still reject any active/pinned dependency and never cascade.

## SQL single-serving-node metadata deletion

Enable `persistence.coordinated_deletion = true` on the one serving process.
Stop and fence every other server and credential sharing the database first so
they cannot return; running an ordinary-mode server alongside a coordinated
server is unsupported. Do not treat the configuration flag as evidence that the
mode migration described below has occurred.

Every SQL server selects a durable database mode before serving: ordinary mode
(protocol 2) or coordinated-deletion mode (protocol 3), recorded on first startup.
Ordinary mode releases its startup lock and
caches admission: downloads do not probe a lease, register readers, or scan
ownership metadata. Ordinary instances may coexist. A failed background refresh
retains the last validated snapshot and retries, but only within
`persistence.max_snapshot_age_secs` (default 300, range 1-86400, strictly greater
than the ordinary synchronization interval). An unvalidated or expired snapshot
refuses new TFTP/HTTP reads; HTTP artifacts return a non-disclosing 503 and
`/ready` returns `503 STALE`. Admitted transfers finish. Successful
refresh restores admission even when the durable revision has not changed.
Remote withdrawal is therefore bounded-stale during a disconnection, not
instantaneous. Zero cannot disable this bound. Initial hydration and durable
mutations still require SQL success. Invalid new snapshots and failed refreshes
never advance the validation time.

Reader capacity is maintained by a durable singleton counter under the same
state-revision transaction as insertion, exact release, and offline recovery.
Duplicate registrations/releases and rolled-back operations do not change the
count. Session batches deduplicate up to 32 `(profile, group)` pairs
and check tombstones/reservations in two bounded queries rather than per client.
MySQL startup inspects the namespace table instead of issuing DDL
against the lifetime-locked namespace; standalone control-plane clients can
connect while the serving owner remains active.

Deletion mode holds an exclusive namespace lock on one dedicated transaction
for process life. A competing updated server or a server configured for a
different mode fails startup/admission. Deletion admission probes that same
connection; loss poisons admission until restart, never silently reconnects.
One five-second admission deadline covers namespace initialization and waiting
for the shared lease-connection mutex. Waiting requests time out without
poisoning a healthy owner. Once a request holds the mutex, its SQL probe has its
own five-second timeout, so queueing behind slow probes never shortens it; a
probe that fails or times out still poisons the lease. Worst-case direct
admission (API mutations and startup) is therefore about ten seconds. Download
reader registration and cleanup remain inside their own five-second deadline,
which may cancel a probe partway; cancellation does not poison the lease or
release the namespace lock, and the next probe reuses the same connection.
Transient saturation or timeouts return HTTP 503 (TFTP: retry) rather than 500.
A lost lease reports `/ready` as `503 DEGRADED` immediately.
Artifact resolution checks cached mode selection before local lookup and defers
lease validation to the authoritative first-pin/reader/ownership transaction,
under the state-revision lock. Already-pinned requests do not pay an additional
preliminary lease probe. No artifact bytes are opened before durable admission.
In deletion mode the supervised runtime also stops on a failed persistence
refresh. Database failover, connection loss, and database-enforced transaction
timeouts can therefore stop this opt-in profile; it is not an HA deletion
protocol or a physical-file barrier. Configure database transaction timeouts
accordingly. No download is allowed to bypass a lost deletion-mode fence.

For an already-initialized ordinary-mode database, changing the flag alone is
refused. Stop and fence every server and any restart automation, verify that no
reader can resume, and back up the control database. An authorized database
operator may then run this explicit one-way migration, checking that exactly
one row changed, before starting the single deletion-enabled server:

```sql
UPDATE tempest_serving_namespace SET protocol = 3 WHERE id = 1 AND protocol = 2;
```

Do not run this while any ordinary node can still serve: ordinary nodes cache
their admission and cannot observe a forced live mode change. Returning to
ordinary mode after deletion history exists is not supported in place. Never
reset the protocol to 1 or clear reservations, safety markers, or tombstones to
force a startup. Mode migration is an offline operator responsibility, not an
automatic rolling-upgrade or per-deletion operation.

An exclusive startup advances a durable serving generation under the shared
state revision lock. Ordinary startups do not acquire a lifetime transaction
or participate in this generation. In deletion mode, reader admission, unmanaged ownership checks
and serving-originated release/session mutations recheck the same connection
and captured generation **inside their revision-locked SQL transaction**, after
any local or database lock wait. A queued request cannot mutate or register on
behalf of a lost owner after replacement admission. A store used solely as a
public control-plane writer, with no serving lease, remains supported; it must
still obey revision, reservation and tombstone checks. Exact reader cleanup is
exempt from serving admission so an old owner can finish its existing readers.

Composition-attached stores participate even when `persistence.enabled` is false:
that switch is not an escape from SQL admission. Standalone HTTP/TFTP startup,
state reconciliation, session registration and the public session resolvers enforce
admission, not just the CLI supervisor. A custom public state with persistence
enabled or coordinated deletion requested but no attached SQL store fails closed.
Registration through an embedded HTTP router returns 500 without issuing a token
or changing existing sessions when the required store is missing. File-based
configuration additionally requires `persistence.enabled = true` and a database
URL; the deletion flag alone never enables a SQL-free deletion fallback.

Every deletion-mode managed HTTP/TFTP resolution, including cached, no-session and already-
pinned reads, commits an exact durable reader row before opening/delivering
bytes. An Arc-backed RAII registration follows the HTTP stream or TFTP task
through completion, errors and cancellation. Rows never expire. Session expiry
or revocation cannot hide a live reader. Each cleanup attempt has a five-second
deadline; transient failures retry up to five times with backoff (0.5 to 8
seconds) before the row is retained. The semaphore permit remains held through
cleanup and its retries, bounding outstanding work to 4096 per store. Startup
refuses deletion mode unless `server.max_concurrent_transfers +
api.max_connections` fits within that budget. The global reader-row cap is also 4096. Failure, shutdown or
ambiguous registration may retain a durable blocker; it never grants deletion.
When the durable row cap fills, admission commits a permanent
`reader_tracking_exhausted` safety marker before serving without a new row.
That marker blocks every later deletion, even after rows are released, while
allowing downloads to continue. Automatic SQL history pruning honors the same
marker: a release mutation that would need to evict retained metadata is refused
atomically until offline recovery; mutations within retention bounds remain
available. Clearing it requires separately reviewed offline
recovery after fencing all possible readers, as described below. No row expires or is evicted. The
local cleanup semaphore remains an immediate backpressure limit for concurrent
registrations and cleanup tasks; a full local budget can still refuse admission.

Confirmation serializes on the existing revision lock and, in one transaction,
checks exact identity, inactivity, live durable sessions and every reader;
reserves deletion; persists an ownership tombstone; removes exactly one retained
group/embedded manifest; and increments profile/shared revisions. Publication
is durable-first. Reservations/tombstones survive success, permanently prevent
reuse of the deleted profile/group ID, and are honored by deployment, rollback,
withdrawal, all session-pin writers and retention. Unmanaged HTTP admission
checks a bounded, indexed SHA-256 set of permanently managed names,
conservatively across profiles, so stale memory cannot reopen a managed name.
It does not scan or decode group/tombstone JSON per read. The ownership index
retains at most 20,000 distinct names **in deletion mode only**; exceeding this cap
refuses a release mutation, not unrelated downloads. Ordinary SQL publication
does not add permanent names or enforce this lifetime cap. Fences are never removed.
Before deletion-mode admission, startup backfills retained releases and
tombstones under the revision lock, including names published in ordinary mode
since a previous backfill, and rejects oversized or malformed stored state.
The cap remains permanent in deletion mode; there is no ownership-index compaction
or online reset. Prefer stable logical names such as `vmlinuz` to names embedding
every kernel version. Tombstones retain names, not artifact manifests
or bytes. There are at most 100 reservations/tombstones; they are never evicted,
and the 101st deletion fails closed without disabling serving. There is no
tombstone compaction protocol.

Logical names are canonical relative slash-separated paths: empty components,
`.`/`..`, repeated/trailing separators and backslashes are rejected rather than
normalized after ownership lookup. This applies to managed names and the HTTP
unmanaged compatibility path. Canonical Unicode names remain valid, with no
Unicode normalization or case folding. MySQL tombstone JSON uses an explicit
`utf8mb4` column, separate from the ASCII identity-key columns. PostgreSQL uses
text JSON. Encoding failures block admission; they never drop a fence.

After an ambiguous confirmation, reconcile committed state before another
preview. A crash after SQL commit but before memory publication is safe: stale
managed reads fail SQL admission, stale writers fail tombstone/revision checks,
and reconciliation removes the obsolete local group. A lost namespace lock is
**not** authority for another node to clear old reader rows: the original reader
may still be finishing. Crash-abandoned/failed-cleanup rows require a separately
confirmed offline recovery after all possible reader processes are fenced and
stopped. No TTL cleanup, automatic reader reset, force endpoint or automated
orphan recovery is shipped.

### Offline Reader Recovery

First stop and fence **every** serving process sharing the database, including
disconnected instances that might still be delivering bytes. Loss of a namespace
lock or an empty session table is not proof that those transfers have stopped.
Back up the control database and retain the evidence of exclusion before running:

```bash
tempest --config config/tempest.toml --recover-sql-readers --confirm-all-servers-stopped
```

The command requires the `sql-persistence` build, configured persistence, and
`coordinated_deletion = true`. It never starts TFTP or HTTP listeners. It acquires
the exclusive deletion namespace and refuses a live owner or ordinary-mode
namespace. In one revision-locked transaction it removes at most 4096 abandoned
reader rows and resets the exhausted-reader safety marker. It prints
`recovered_readers=N`. Oversized state is refused rather than silently truncated.
Recovery requires the existing SQL coordination schema; it does not run startup
migrations or release-history retention, including before refusing admission.
The all-servers-stopped flag is an operator assertion, not an automatic check of
disconnected processes.

Reservations, tombstones, managed-name fences, releases, sessions and artifact
bytes are preserved. Recovery does not reclaim the permanent 100-deletion budget.
After an uncertain result, keep all serving processes stopped and repeat the same
offline command; do not infer success from a timeout. Restart serving only after
successful recovery. Rust compositions can use
`PersistenceStore::recover_abandoned_readers` under the same exclusion contract.

### Database Idle Timeouts

In deletion mode, background synchronization probes the lifetime lease every
`persistence.sync_interval_secs` (default 5 seconds), even with no downloads.
Keep that interval safely below MySQL `wait_timeout` and any PostgreSQL
`idle_in_transaction_session_timeout`. Database restarts, connection loss, or a
lease timeout still stop deletion-mode admission deliberately. Ordinary mode has
no lifetime lease and keeps its last validated serving snapshot only within the
configured maximum age on refresh failure; startup hydration, new session pins,
and control mutations still need SQL.

## Orchestrator contract

The caller must independently check and serialize its own drafts, journal,
pending operations and retained references. Core cannot see those dependencies.
Display the exact target, identity, scope (metadata only), dependency list and
blockers. Enable confirmation only for `can_delete:true` and an empty blocker
list, and only after caller-owned dependencies allow it. Unknown blockers fail
closed. Preserve the exact identity the operator saw; do not fetch a new identity
and silently retry after a conflict. An ambiguous timeout requires a snapshot
refresh to determine whether the old identity remains, not automatic deletion of
a replacement. File Delete must remain disabled in this release. SQL instances
outside the coordinated profile must show the explicit coordination blocker.

The public Rust client provides `preview_delete(&PreviewDeleteRequest)` and
`confirm_delete(&ConfirmDeleteRequest)`, returning `DeletePreview` and
`DeleteResult`. Non-success responses use existing `ControlError::Api`; JSON
blockers on errors are in its bounded message, not a separate typed variant.