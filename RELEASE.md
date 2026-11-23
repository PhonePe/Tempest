<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Release Process

Tempest core and the public control client share one workspace and lockfile but
are versioned independently. The core Cargo package is `tempest-ignition`; it
exports the `tempest` library crate and builds the `tempest` binary. The client
is `tempest-control-client`. Downstream compositions qualify one exact public
workspace revision.

GitHub (`https://github.com/PhonePe/Tempest`) is the canonical repository, and
releases are cut there.

## What a Release Ships

A release is a signed, annotated `vX.Y.Z` git tag plus its `CHANGELOG.md`
section. Tempest is distributed as source only: no prebuilt binaries, container
images, or crates.io packages are published, and both crates set
`publish = false`.

Users build from the tag as described in [`INSTALL.md`](INSTALL.md). The
`make rc-linux-*` targets build Linux archives in digest-pinned builders, from
the committed lockfile and the compiler pinned in `rust-toolchain.toml`, so
anyone deploying binaries builds the tagged source with the same toolchain.

## Versioning

Tempest is pre-1.0 and follows semantic versioning with the pre-1.0 convention:

- `0.MINOR.0` for any breaking change or new capability: public Rust API,
  extension traits, configuration (removed keys or changed defaults), HTTP
  contract, SQL schema migrations, upgrades that require stopping every node,
  or new features.
- `0.MINOR.PATCH` for fixes only: no migrations, no configuration or default
  changes, and nothing new in `UPGRADING.md`.

What counts as breaking:

- Rust API: whatever `cargo-semver-checks` reports against the previous tag. It
  runs on relevant pull requests, so breaks are visible before merge.
- HTTP: an incompatible change requires a new route version, such as `/api/v2`.
- Persistence: migrations are forward-only; a required stopped upgrade is a
  minor release with migration guidance.
- TFTP: standard-client behavior never breaks.

The client keeps its own versions and `tempest-control-client-vX.Y.Z` tags.
`docs/openapi.yaml` `info.version` always equals the core version.

## Release Cycle

Minor releases follow a six-week train aligned with Rust's release cadence.
Patch releases ship when needed.

| Week | Work |
| --- | --- |
| 1 | Move `rust-toolchain.toml` and the Rust image digests to the newest stable (see [`CONTRIBUTING.md`](CONTRIBUTING.md)); merge pending dependency updates. |
| 1-4 | Normal development on `main`. Every pull request updates `CHANGELOG.md` `[Unreleased]` and, when needed, `UPGRADING.md`. |
| 5 | Freeze: fixes only. Build release candidates and run [full qualification](#required-validation), then soak the candidate on representative boot infrastructure across supported firmware classes. |
| 6 | Merge the release commit, push the signed tag, and qualify downstream deployments against the release commit. |

The scheduled `Upcoming Rust` workflow builds `main` on the newest stable and
beta compilers, so the week-1 toolchain bump starts with known findings.

### Patch and Security Releases

- Patch releases follow the same steps. When `main` already contains unreleased
  changes, branch `release/0.N` from the `v0.N.0` tag, cherry-pick reviewed
  fixes, and tag `v0.N.P` there.
- Security fixes are developed in a private GitHub security advisory and
  released as patch tags for the latest minor and, for one cycle after a new
  minor, the previous minor ([`SECURITY.md`](SECURITY.md)).

## Preparing a Release

Open a `release: vX.Y.Z` pull request that:

1. Sets the version in `Cargo.toml` and `docs/openapi.yaml` `info.version`.
2. Moves `CHANGELOG.md` `[Unreleased]` entries under `## [X.Y.Z] - YYYY-MM-DD`.
   Never tag a version without a non-empty section; it is the release note.
3. Completes `UPGRADING.md` for configuration, HTTP, extension-trait,
   persistence, or wire behavior changes.
4. Confirms README, rustdoc, examples, OpenAPI, and sample configuration
   describe the same shipped capabilities.
5. Updates the firmware/client matrix only from accepted reproducible evidence;
   lists unexercised client classes as residual compatibility risk.

## Required Validation

Run these on the release commit before tagging:

```bash
make check
TEMPEST_TEST_POSTGRES_URL='postgres://USER:PASSWORD@HOST/DB' \
  TEMPEST_TEST_MYSQL_URL='mysql://USER:PASSWORD@HOST/DB' make test-sql-all
make test-uso-kernel   # on Linux
make msrv
cargo deny check
```

Run the L2 demo (`python3 demo/l2-flat/demo.py run`) for protocol,
release/session, HTTP artifact, persistence, or demo wiring changes. Public
extension-trait changes also require a representative downstream composition
build and relevant runtime tests. The tagged tree must contain no credentials,
private history, internal endpoints, generated artifacts, private design
material, or unexpected large files.

## Release Candidates

Release candidates are never tagged publicly; release tags must be exactly
`vX.Y.Z`. Build candidate archives locally in the pinned builders:

```bash
make rc-linux-amd64 RC_TAG=rc1
make rc-linux-arm64 RC_TAG=rc1
make rc-linux-amd64-gnu RC_TAG=rc1
```

Add `CONTAINER_ENGINE=docker` to use Docker instead of Podman. Each target runs
`make check`, builds with every production feature in its builder, checks the
binary's architecture and linkage, runs `tempest --version` in the builder, and
writes `dist/tempest-X.Y.Z-rc1-linux-*.tar.gz` with a `.sha256`. Builds for a
different architecture than the host run under emulation and are slower.

The glibc builder keeps a Debian Bullseye base for the glibc 2.31 floor and
installs the pinned Rust compiler with rustup, because Rust publishes no current
Bullseye images. Qualify the glibc archive on the target kernel before choosing
it over the static musl archive.

## Tagging

1. Merge the release pull request through normal review.
2. Confirm `Cargo.toml` and `docs/openapi.yaml` carry `X.Y.Z` and that
   `CHANGELOG.md` has a non-empty `[X.Y.Z]` section dated the day of the tag.
3. Push a signed, annotated tag on that exact commit:

   ```bash
   git tag -s vX.Y.Z -m "Tempest X.Y.Z"
   git push origin vX.Y.Z
   ```

4. The tag push runs the `Semver Compatibility` workflow against the previous
   tag; it must pass. For a package's first tag there is no baseline, so the
   check reports that and passes without comparing.

Never move or recreate a pushed tag. Correct a bad release with a new version.

## Post-release Verification

```bash
git fetch --tags origin && git tag -v vX.Y.Z
git checkout vX.Y.Z
make check
make rc-linux-amd64 RC_TAG= && cat dist/tempest-X.Y.Z-linux-amd64.tar.gz.sha256
```

Then require the live client/server contract at the release SHA, qualify
downstream compositions and Salt pillars against the release, and record
unsupported firmware, platform, database, or runtime scenarios.

## Control Client Releases

The client manifest is `crates/tempest-control-client/Cargo.toml`. Its versions
are independent of core and are released with signed
`tempest-control-client-vX.Y.Z` tags, following the same tagging steps. Semver
checks use the previous tag in each package's namespace.

## Repository Settings

Maintainers keep these GitHub settings in place:

1. Protect `main`, require the CI checks, and require approval before running
   workflows for first-time contributors.
2. Restrict tag creation for `v*` and `tempest-control-client-v*` to
   maintainers, and require signed tags.
3. Enable private vulnerability reporting, secret scanning, and push protection.

## Path to 1.0

Declare 1.0 when the HTTP v2 contract, configuration format, extension traits,
and persistence schema have gone two consecutive minor releases without breaking
changes; an upgrade from the previous minor needs no stopped upgrade; the
firmware matrix covers the supported client classes; and at least two
maintainers can approve releases.
