<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tempest Agent Guidelines

This file applies to the entire repository. A more specific `AGENTS.md` in a
subdirectory may add or override guidance for that subtree.

## Mission

Tempest is a release-coherent TFTP and HTTP network-boot artifact server. Keep
protocol correctness, release integrity, bounded resource use, standard-client
compatibility, and operational performance intact together. Do not improve one
by silently weakening another.

Before changing behavior, read the relevant source plus:

- the owning module's rustdoc for request and state ownership;
- [`CONTRIBUTING.md`](CONTRIBUTING.md) for contribution and validation rules;
- [`EXTENSIONS.md`](EXTENSIONS.md) before changing composition contracts;
- [`SECURITY.md`](SECURITY.md) for vulnerability handling; and
- [`docs/openapi.yaml`](docs/openapi.yaml) for the maintained HTTP contract.

## Non-Negotiable Invariants

1. **TFTP transfer IDs:** each transfer owns its ephemeral UDP socket. A
   scheduler or router must use the supplied socket and validate both peer IP
   and port after a transfer ID is established.
2. **Standard-client compatibility:** ordinary clients receive RFC TFTP
   behavior. Custom payloads or control semantics activate only after explicit,
   versioned negotiation and must fit within negotiated `blksize`.
3. **Release coherence:** profile, version-group, transfer-pin, boot-session,
   manifest, cutover, rollback, and withdrawal semantics stay in core. A pinned
   session resolves strictly within its manifest.
4. **Durable-first mutation:** when SQL persistence is enabled, commit durable
   release/session state before publishing corresponding in-memory state.
5. **Filesystem confinement:** client names remain relative; canonical paths
   must be regular files beneath the configured root. Managed bytes are verified
   against their recorded identity before delivery.
6. **Bounded ingress and state:** packets, options, request bodies, sessions,
   maps, queues, caches, extension state, and whole-file transforms need explicit
   limits and safe behavior at capacity.
7. **Lifecycle cleanup:** transfer slots, version pins, scheduler registration,
   temporary files, extension sessions, and metrics complete correctly on every
   return, timeout, cancellation, and dropped HTTP body. Prefer RAII guards.
8. **Async runtime health:** do not add unbounded blocking filesystem,
   cryptographic, compression, or database work to Tokio worker threads. Use a
   bounded worker or `spawn_blocking` when work cannot be asynchronous.
9. **Optional profiles remain honest:** the default build has no SQLx dependency.
   Persistence requires `sql-persistence`; extension providers are statically
   linked by another composition and are not default-core features.
10. **Trust configuration fails clearly:** a configured key, persistence store,
    or required provider must not disappear through silent fallback.
11. **Package identity remains stable:** the Cargo package is
    `tempest-ignition`; its Rust library crate and installed executable are both
    `tempest`. Downstream manifests that need an explicit dependency alias use
    `tempest = { package = "tempest-ignition", ... }`. Do not change one of
    these names without updating package metadata, installation guidance,
    examples, and compatibility notes together.

## Ownership Boundaries

Tempest core always owns initial packet parsing, rate limiting, drain and
capacity state, release/session resolution, path checks, artifact opening and
verification, UDP sockets and TIDs, RFC negotiation, windows and retransmission,
metrics, audit, and cleanup.

Use the narrow public traits in [`src/extension.rs`](src/extension.rs) for
scheduling, external priority, pacing, shared blocks, negotiated read protocols,
request routing, and admission policy. Do not introduce a catch-all middleware
hook or let a provider bypass core ownership. Same-contract chaining requires an
explicit composite provider with documented ordering and failure behavior.

## Workspace and Downstream Boundaries

Core and public vendor-neutral clients share this Cargo workspace and lockfile.
Keep core independent of client crates. Change public HTTP contracts and their
typed clients atomically, and run `make check`, including the live contract test.
Crates are versioned independently and distributed as source only; see
[`RELEASE.md`](RELEASE.md).

Private compositions remain separate, consume only public contracts at one
approved Tempest revision, and must not patch core or import private modules.
Never introduce private provider code or identities into this workspace.
Experimental algorithms belong in an incubator until their contract, resource
bounds, fallback, and interoperability evidence are stable.

## Working Method

1. Inspect `git status` and preserve unrelated user changes.
2. Start from the failing behavior, owning symbol, or nearest focused test.
3. State one falsifiable local hypothesis and the cheapest check that can
   disprove it.
4. Make the smallest root-cause edit consistent with existing patterns.
5. Immediately run the focused test or compile check before widening scope.
6. Add or update a behavior test that fails without the fix. Test limits,
   cancellation, error paths, and fallback as well as success.
7. Update public docs and configuration in the same change when behavior,
   defaults, routes, features, or extension contracts change.
8. Finish with the appropriate validation profile below.

Do not perform unrelated refactors, broad formatting, dependency upgrades, or
generated-file churn. Do not commit, push, rewrite history, or remove user work
unless the user explicitly requests it.

## Validation Routing

Run a focused check first, then the broader gate warranted by the change.

| Changed surface | Required checks |
| --- | --- |
| Rust implementation | Focused test, then `make check` |
| Default dependency profile | `cargo test --no-default-features` |
| SQL persistence | `make test-sql` against isolated PostgreSQL and MySQL, or `make test-sql-all` with both, when persistence behavior changes |
| Packet, option, window, or transfer behavior | Focused protocol tests plus `make check`; `make test-uso-kernel` on Linux for segmentation changes; run the L2 demo for end-to-end wire changes |
| HTTP route or schema | Focused API tests, update and parse `docs/openapi.yaml`, then `make check` |
| Public Rust API or extension trait | Update rustdoc and `EXTENSIONS.md`; run doctests and compile a representative provider composition |
| Demo or container wiring | `python3 demo/l2-flat/demo.py check`; run `run` when behavior changed; finish with `down` |
| Build tooling or Salt formula | `make test-salt`; build an affected `make rc-linux-*` archive; lint workflows with actionlint |
| Dependencies | `cargo deny check` |

The repository gate is:

```bash
make check
```

It checks formatting, SPDX license headers, strict all-target/all-feature Clippy,
workspace library and binary tests, doctests, warning-free public rustdoc, and
the live client/server contract.

Database-backed test bodies require a disposable database. Run every
SQL-feature test once per database; a missing URL fails instead of skipping:

```bash
TEMPEST_TEST_DATABASE_URL='postgres://USER:PASSWORD@HOST/DB' make test-sql
TEMPEST_TEST_DATABASE_URL='mysql://USER:PASSWORD@HOST/DB' make test-sql
```

Never point tests at production or shared control state.

## Demo Profiles

[`demo/l2-flat/`](demo/l2-flat/) is the core-plus-SQL integration profile. It
builds an optimized Linux binary in the pinned Bookworm environment and does not
link extension providers. It validates TFTP and HTTP delivery, strict manifest
membership, release cutover, profile/session pinning, audit/metrics, and
PostgreSQL restart recovery.

```bash
python3 demo/l2-flat/demo.py check
python3 demo/l2-flat/demo.py run
python3 demo/l2-flat/demo.py down
```

Do not describe that profile as proving provider-supplied scheduling, pacing,
coalescing, custom wire formats, routing, or admission behavior. Provider
compositions belong in their own workspace and should reuse the core harness
through explicit binary/config overrides where available. Unit tests are not a
substitute for a runtime claim, and a standard-client fallback run is not a
custom-protocol round trip.

## Security and Performance Review

For remotely reachable changes, trace input from parse through allocation,
state mutation, output, and cleanup. Check malformed input, cardinality, byte
budgets, integer conversion, timeout/cancellation, peer identity, path escape,
information disclosure, secret handling, and fail-open behavior.

For hot-path changes, identify the workload before optimizing. Look for
per-packet allocation, whole-file buffering, global locks across `await`,
synchronous I/O on async workers, thundering-herd notifications, unbounded task
creation, repeated hashing, and high-cardinality metrics. Prefer measured fixes
over speculative micro-optimizations, and preserve a conservative fallback when
an optional optimization reaches capacity.

Never include credentials, private keys, customer data, internal endpoints,
private repository history, generated binaries, `target/`, demo downloads,
audit output, or Python bytecode in a change.

## Public Contract Updates

Keep these synchronized when applicable:

- `README.md` for shipped capability and user workflow;
- `CHANGELOG.md` for externally visible behavior;
- `config/tempest.toml` for public configuration;
- `docs/openapi.yaml` for HTTP behavior;
- `EXTENSIONS.md` and rustdoc for provider contracts.

Quantitative or runtime claims in public docs must state the workload and
environment and be backed by archived, reproducible commands and results. Do
not publish results, identities, configuration, or implementation details from
proprietary compositions.

Before declaring completion, report the exact checks run, distinguish exercised
runtime behavior from compile/unit coverage, and list residual risks or tests
that could not be executed.
