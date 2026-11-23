<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Quality Engineering

Tempest uses layered checks so correctness, security, performance, and
compatibility evidence are not inferred from one test type.

## Required Repository Gate

```bash
make check
cargo deny check
```

`make check` covers formatting, license headers, strict Clippy, unit/integration
tests, doctests, warning-free rustdoc, and the live client/server contract. SQL
behavior additionally requires `make test-sql` against disposable PostgreSQL and
MySQL test databases, or `make test-sql-all` with both. Protocol or release-path
changes require the L2 demo when they affect runtime behavior.

## Continuous Integration

GitHub Actions (`.github/workflows/`) call Makefile targets, so a job's logic is
defined once. Change a target, not a workflow file, when a check's behavior
should change. Each check runs in exactly one job per pipeline; a job does not
repeat work another job already covers.

| Check | Make target | When |
| --- | --- | --- |
| Format, Clippy, tests, doctests, rustdoc, license headers, live contract | `make check` | every PR (split into jobs) |
| Dependency policy | `cargo deny check` | every PR |
| All SQL-feature tests on PostgreSQL 16 and MySQL 8.4, with coverage | `make coverage-sql` | every PR |
| Linux UDP segmentation kernel tests (ignored by default) | `make test-uso-kernel` | every PR |
| Minimum supported Rust (1.85, minimal and all features) | `make msrv` | every PR |
| musl x86_64/ARM64 compile | `make cross-check` | every PR |
| OpenAPI version and lint | `make openapi-check` | every PR |
| macOS, Windows, Linux ARM64 runtime tests | `cargo test` | every PR |
| Production container build and smoke test | `make container-check` | every PR |
| Protocol fuzzing (200,000 inputs per target) | `make fuzz` | protocol PRs, weekly |
| Benchmark budgets | `make bench-check` | protocol PRs, weekly |
| Public API semver against the previous release tag | `ci/check-semver.sh` | relevant PRs, release tags |
| SonarQube analysis of the SQL test coverage | — | every PR with `SONAR_TOKEN`, `main` |
| Salt formula rendering | `make test-salt` | every PR |
| Newest stable and beta Rust (early warning, non-blocking) | `cargo clippy`, `cargo test` | weekly |
| Pinned Linux archives (built locally, not published) | `make rc-linux-*` | — |
| L2 flat-network demo | `demo/l2-flat/demo.py` | weekly, manual |

Database jobs set `TEMPEST_REQUIRE_TEST_DATABASE=1`, so a missing database
fails the job instead of silently skipping tests.

`make coverage-sql` (the `persistence` job) builds the SQL-feature tests once
under coverage instrumentation. It runs every test
against PostgreSQL, then reruns only the database-backed modules
(`SQL_TEST_MODULES` in the Makefile) against MySQL; the other tests do not touch
the database. A unit test fails if a database-backed test is added outside those
modules. Both runs merge into one LCOV report, which the SonarQube job reads
instead of running the tests again. `make check` runs the default feature
profile's tests, and `test-uso-kernel` runs only the kernel tests ignored
elsewhere. The SonarQube job imports no Clippy report: the strict Clippy gate
uses the same lints, so that report would always be empty.

## Parser Robustness

The isolated `fuzz/` workspace has no effect on Tempest's production dependency
graph. It requires nightly Rust and `cargo-fuzz`:

```bash
cargo install cargo-fuzz --locked
make fuzz
```

The repository toolchain file pins a stable release, so `make fuzz` selects
nightly explicitly. CI runs each target for exactly 200,000 generated inputs on
relevant pull requests and weekly. Treat a saved failure input as potentially
sensitive until its bytes and provenance are reviewed; never upload captured
production packets as corpus data.

## Performance Budgets

```bash
make bench
make bench-check
```

Criterion measures packet parsing, option negotiation, and window progression.
`make bench-check` enforces deliberately generous nanosecond ceilings from
[`benchmarks/protocol-budgets.json`](benchmarks/protocol-budgets.json). These
budgets catch gross regressions such as accidental blocking work, large
allocation, or changed complexity. They are not production throughput claims.

Update a budget only with a reviewed workload explanation, before/after results
on comparable hardware, and confirmation that the change is not hiding a real
regression. CI archives raw Bencher-format output.

## Coverage

Coverage CI publishes LCOV and text-summary artifacts for diagnosis. It runs the
all-features suite against PostgreSQL so SQL paths are measured. Two gates
apply: `make coverage-sql` fails when total line coverage drops below
`COVERAGE_MIN_LINES` (85%; measured at 90.75% in November 2026), and the
default "Sonar way" quality gate requires at least 80% coverage on new code.
Raise the floor as coverage grows; never lower it without a reviewed reason.
Risk-based tests for malformed input, limits, cancellation, fallback, and
release consistency still matter more than line count, and a coverage decrease
in remotely reachable or lifecycle code requires review.

## CI Caching

CI caches downloaded crates, compiled dependencies and installed tools with
`Swatinem/rust-cache` in each Rust job; it never caches workspace build
outputs, so every run still compiles and tests Tempest itself from source. Only
`main` writes caches; pull requests restore them, which keeps them from
evicting `main`'s entries.

CI builds use `CARGO_INCREMENTAL=0` and line-table debug info, which shortens
builds and shrinks caches without changing test behavior. Pin every installed
tool version so its cache key and behavior change only in reviewed commits.

## SonarQube

`make coverage-sql` writes LCOV coverage of the PostgreSQL and MySQL test runs
to `target/coverage/`.
[`sonar-project.properties`](sonar-project.properties) holds the shared
analysis settings: it separates inline Rust tests from
production sources, points at the coverage report, and waits for the quality
gate (`sonar.qualitygate.wait=true`, up to 300 seconds), so a failing gate fails
the analysis job. Strict Clippy in CI is the lint gate. CI supplies the
project identity and token, so no credential lives in the repository.

The `sonar` job in the `CI` workflow analyzes the `persistence` job's coverage
report with the pinned official scan action, in the `phonepe` organization as
`PhonePe_Tempest`.

1. An organization admin imports the GitHub repository into the `phonepe`
   SonarQube Cloud organization as `PhonePe_Tempest` and disables automatic
   analysis, because CI-based analysis is required for coverage import.
2. Add the `SONAR_TOKEN` repository secret. Without it, and on fork pull
   requests that receive no secrets, the job skips analysis and still passes.
3. Use the organization's default "Sonar way" gate, which judges new code only.
   After the first analysis on `main` succeeds, mark the `SonarQube analysis`
   check as required in branch protection for `main`; requiring it earlier only
   enforces a skipped job. Fork pull requests skip analysis, so maintainers
   review their findings after merge on `main`.

## Public API Compatibility

Semver checks compare each package with its previous release tag using
`cargo-semver-checks` on relevant pull requests and on release tags. They skip
before a package's first release. Public API or OpenAPI changes require
changelog and migration notes even when an automated check reports
compatibility.

CI parses the OpenAPI document, enforces its version relationship with the
crate, and lints the complete contract with a pinned Redocly CLI release.

`make test-live` builds the server and exercises `tempest-control-client` from
the same checkout, including digest-bound `/api/v2` rollback and withdrawal.
CI requires this test. Provider compositions validate one
exact public workspace revision downstream.

The scheduled L2 workflow runs the checked-in flat-network demo end to end and
always tears down its containers. It exercises the software reference clients,
release/session cutover, TFTP-to-HTTP identity, SQL persistence, and restart
recovery; it is not firmware certification or a production-capacity result.

## Platforms and Firmware

GitHub CI runs Linux x86_64, Linux ARM64, macOS, and Windows minimal profiles,
and cross-compiles the default dependency profile for x86_64 and ARM64 musl
targets.
A compile check is not a runtime claim.

Firmware evidence is maintained in
[`docs/FIRMWARE_COMPATIBILITY.md`](docs/FIRMWARE_COMPATIBILITY.md). Do not infer
BIOS, UEFI, or iPXE compatibility from the software reference client alone.
