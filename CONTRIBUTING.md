<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contributing to Tempest

Tempest accepts focused bug fixes, documentation improvements, compatibility
reports, tests, and features that fit the public boot-artifact serving model.
Use an issue or discussion before starting a change that alters protocol
behavior, the HTTP contract, release semantics, persistence, or public extension
traits.

Automated coding agents must also follow [`AGENTS.md`](AGENTS.md), which records
the repository's ownership invariants and validation routing.

## Development Setup

Tempest requires Rust 1.85 or newer. `rust-toolchain.toml` pins the compiler
used for development, CI and release builds (currently 1.100.0) and installs
`rustfmt` and Clippy. `make msrv` checks the complete workspace and all targets,
with and without the SQL persistence profile, on Rust 1.85.

The minimum supported Rust version is a compatibility policy. Raising it
requires a documented reason, a changelog entry, and at least a minor release
while Tempest is pre-1.0; CI must pass on both the declared minimum and the
pinned toolchain. Upgrade the pinned toolchain in one change that also updates
the Rust image digests in `Dockerfile` and the Makefile release targets.
Raising the minimum likewise updates `MSRV_TOOLCHAIN` in the Makefile. The
workspace uses Cargo's rust-version-aware resolver, so fresh dependency
resolution stays compatible with the declared minimum.

Code style is enforced, not reviewed by taste: `rustfmt.toml` configures
`cargo fmt`, strict Clippy runs with warnings denied, and `.editorconfig`
sets whitespace for every other file type. Any editor works. With VS Code or
RustRover, use rust-analyzer with format-on-save and Clippy as the check
command.

Every new file starts with the two SPDX lines used throughout the repository
(`SPDX-FileCopyrightText` and `SPDX-License-Identifier: Apache-2.0`) in that
file type's comment syntax. `make license-check` enforces this as part of
`make check`, and `make license-format` adds missing headers.

See [`QUALITY.md`](QUALITY.md) for parser-robustness campaigns, performance
budgets, diagnostic coverage, semver checks, and compatibility evidence.

```bash
cargo test --no-default-features
cargo test --features sql-persistence
make check
```

Database test bodies require an isolated PostgreSQL or MySQL-compatible database.
Run every SQL-feature test, not a name filter, once per database:

```bash
TEMPEST_TEST_DATABASE_URL='postgres://USER:PASSWORD@HOST/DB' make test-sql
TEMPEST_TEST_DATABASE_URL='mysql://USER:PASSWORD@HOST/DB' make test-sql
```

With both databases available, one build covers both and the second run
repeats only the database-backed modules:

```bash
TEMPEST_TEST_POSTGRES_URL='postgres://USER:PASSWORD@HOST/DB' \
  TEMPEST_TEST_MYSQL_URL='mysql://USER:PASSWORD@HOST/DB' make test-sql-all
```

Without a URL, database tests skip so ordinary runs stay fast. `make test-sql`
and `make test-sql-all` set `TEMPEST_REQUIRE_TEST_DATABASE=1`, which turns a
missing URL into a test failure; CI database jobs rely on this so they cannot
pass without a database.

Do not point tests at a production or shared database. The cross-node session
regression and every SQL deletion-coordination test create a unique sibling
database and drop it after the test (also on assertion failure), so the test
account needs CREATE/DROP DATABASE permission on both PostgreSQL and MySQL.
Session batching and cancellation regressions use the same sibling-database
isolation so committed sessions cannot accumulate across runs or race global
revision assertions. This keeps full-state reconciliation separate from other
tests' invalid release fixtures; PostgreSQL cleanup may terminate connections
only to that generated database.

Each database test can hold about 30 server connections, so at most three run
at once regardless of `--test-threads`; this stays within default server limits
(PostgreSQL 100, MySQL 151). Set `TEMPEST_TEST_DATABASE_CONCURRENCY` to raise
it only when the server's `max_connections` allows.

## Change Expectations

- Keep changes scoped to one behavior or ownership boundary.
- Preserve RFC 1350 transfer-ID behavior and standard-client compatibility.
- Treat `src/extension.rs` as a public compatibility surface.
- Keep release resolution, path confinement, transfer slots, and lifecycle
  cleanup in Tempest rather than transferring ownership to an extension.
- Add a focused test that fails before the behavioral fix and passes after it.
- Update README, OpenAPI, configuration examples, and rustdoc when a public
  contract changes.
- Do not add generated binaries, build output, secrets, internal hostnames,
  customer data, private keys, or confidential design material.
- Avoid unrelated formatting, refactors, or dependency additions.

For a dependency addition, explain why the standard library or existing
workspace dependencies are insufficient. Dependencies must have an OSS-compatible
license and pass the repository supply-chain checks.

## Maintainability Budgets

These are review triggers, not mechanical gates. Do not split cohesive state
machines merely to satisfy a line count, and do not introduce forwarding
modules, generic frameworks, or microcrates that add more navigation than they
remove.

- Keep a production module near 1,500 lines or less. A module approaching 2,000
  lines should be split at an ownership boundary or carry a short pull-request
  explanation of the invariant that requires it to remain cohesive.
- Keep ordinary functions near 100 lines and orchestration functions near 200.
  A larger parser or protocol state machine should delegate independently
  testable preparation, I/O exchange, and terminal-accounting stages.
- Put substantial unit-test bodies in the module's sibling `tests.rs` file.
  Integration tests belong under `tests/`; production files should expose the
  runtime design rather than be dominated by fixtures.
- Add a crate only for an independently versioned public contract, trust
  boundary, or deployment unit. Prefer a private module for internal
  organization.
- Reuse existing dependencies unless a new dependency removes more maintained
  code and risk than it adds. Record that tradeoff in the pull request.

Review production and test line counts separately. Generated files, migrations,
protocol fixtures, and evidence documents are not useful signals of runtime
complexity.

## Validation

Before opening a pull request, run:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --no-default-features
cargo test --features sql-persistence
RUSTDOCFLAGS='-D warnings' cargo doc --no-deps --all-features
```

Run behavior-specific integration tests for protocol, release, HTTP, persistence,
or extension changes. Hardware and firmware compatibility reports should include
client implementation/version, requested options, packet capture when possible,
network conditions, artifact size/hash, and Tempest configuration.
Use the evidence levels and report requirements in
[`docs/FIRMWARE_COMPATIBILITY.md`](docs/FIRMWARE_COMPATIBILITY.md); do not promote
a matrix row from a single unrepeatable run.

## Cross-Repository Changes

Core and public integrations share this workspace. Change the owning core
contract and its typed client atomically, then update downstream compositions
against the resulting Tempest revision. Keep core independent of client and
provider crates. Downstream changes must identify the exact public revision
used for validation.

`make check` checks every workspace member and runs `make test-live`, which
starts the local server and exercises the client against it. The live runner
requires Bash, Python 3, curl, and permission to bind loopback sockets. Ordinary
`cargo test` reports the live test as ignored; the runner explicitly enables it
and requires all fixtures. Use `cargo test --locked --workspace` for unit tests.

`make test-salt` renders the Salt formula and needs Python 3.11 or newer (for
`tomllib`) with Jinja2 and PyYAML. If `python3` is older, as on stock macOS,
select another interpreter with `make test-salt PYTHON=python3.12`.

Ordinary UDP GSO fallback tests always exercise IPv4 and also exercise IPv6 when
loopback is available. They report and skip only the IPv6 cases when binding
`::1` returns `AddrNotAvailable` or `Unsupported`; other bind errors still fail.
The explicitly ignored IPv6 GSO kernel qualification tests require IPv6 and do
not skip unavailable loopback.

Do not add a core dependency on a private provider or local sibling checkout.
Public API changes should retain compatibility where possible; before `1.0`,
unavoidable breaking changes require a changelog entry, migration guidance, and
representative downstream compilation.

## Pull Requests

A pull request should state:

- the user-visible problem or requirement;
- the behavior and ownership boundary changed;
- compatibility and security implications;
- tests run and relevant output; and
- documentation or migration changes.

Maintainers may ask for a smaller change, a compatibility test, or a design
issue before merging. Contributions are licensed under Apache-2.0 according to
Section 5 of the project license.

### Developer Certificate of Origin

Please sign off each commit to certify the
[Developer Certificate of Origin](https://developercertificate.org/): that you
wrote the change or otherwise have the right to submit it under the project
license. `git commit -s` adds the required trailer:

```text
Signed-off-by: Your Name <you@example.com>
```

Use your real name and an email address you can be reached at. To sign off
commits already on your branch, run `git rebase --signoff main`.

## Security

Do not report suspected vulnerabilities in a public issue. Follow
[`SECURITY.md`](SECURITY.md).
