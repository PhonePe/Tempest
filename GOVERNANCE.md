<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Governance

Tempest is maintained through reviewable repository decisions. Maintainers are
responsible for release integrity, security response, compatibility policy, and
the ownership boundaries documented in [`AGENTS.md`](AGENTS.md) and
[`EXTENSIONS.md`](EXTENSIONS.md).

## Maintainers

This list is the single source of truth for maintainers.

- Krishna Prasanth ([@nixnado](https://github.com/nixnado))
- Vikram Kangotra ([@vikram-kangotra](https://github.com/vikram-kangotra))

## Decision Process

- Ordinary fixes and documentation changes require one maintainer approval and
  passing required checks.
- Protocol, OpenAPI, persistence, release-semantic, security-boundary, and
  public extension-trait changes require an issue or discussion before
  implementation.
- Breaking or security-sensitive changes require two qualified reviewers when
  two are available. A sole maintainer must document the risk, compatibility
  impact, and external review sought before release.
- Maintainers must disclose conflicts of interest and recuse themselves when an
  independent reviewer is available.

## Maintainer Responsibilities

Maintainers triage reports, review changes against the published invariants,
keep release and security documentation current, protect tag-signing keys,
and record the exact validation performed for each release. Repository
administration should be held by at least two independent accounts before the
project claims continuity beyond best effort.

## Becoming or Removing a Maintainer

A contributor may be nominated after sustained, technically sound contributions
and demonstrated care with compatibility and security boundaries. Existing
maintainers record appointments and removals in a public pull request. Access is
removed promptly when a maintainer steps down or can no longer protect project
credentials.

## Security and Conduct

Vulnerabilities follow [`SECURITY.md`](SECURITY.md); conduct reports follow
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Public issues must never contain
private report details.
