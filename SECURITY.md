<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security Policy

## Supported Versions

Tempest is distributed as source only; releases are signed `vX.Y.Z` tags (see
[`RELEASE.md`](RELEASE.md)). Security fixes land on `main` and in a patch tag
for the latest minor release, and for the previous minor during one release
cycle after a new minor, so SQL deployments that need a stopped upgrade can
schedule it. Older tags and forks are not supported unless an advisory states
otherwise.

Fixes are coordinated through private GitHub security advisories and announced
with the patch tag.

## Reporting a Vulnerability

Use the repository's private vulnerability reporting feature under the
**Security** tab, or email [oss@phonepe.com](mailto:oss@phonepe.com). Do not
report vulnerabilities in public issues, and do not post exploit details,
packet captures containing sensitive network data, credentials, keys, or
internal topology in any public channel.

Include, when available:

- affected version or commit;
- deployment and feature configuration;
- impact and required attacker position;
- minimal reproduction or malformed packet bytes;
- whether the issue affects TFTP, HTTP, persistence, audit, or an extension
  contract; and
- proposed disclosure constraints.

Maintainers will acknowledge a complete report as soon as practical, assess
severity and supported versions, and coordinate remediation and disclosure with
the reporter. Advisories credit the reporter unless they ask to stay anonymous,
and request a CVE identifier when the issue affects a tagged release. A
report may be closed as out of scope when it depends only on a boundary
explicitly documented below.

## Scope

In scope: the source in this repository, including the `tempest` server binary
and library, `tempest-control-client`, the build targets and Dockerfile, and
the Salt formula and deployment examples when used as documented.

Out of scope:

- the `demo/l2-flat` profile, which uses fixed demonstration credentials and
  must never be exposed beyond a local machine;
- extension providers and compositions maintained outside this repository;
- vulnerabilities in dependencies with no reachable path in Tempest. Report
  those upstream; dependency advisories are tracked with `cargo deny` and
  Dependabot.

## Security Boundaries

- TFTP is unauthenticated and unencrypted. Tempest does not protect TFTP bytes
  from an on-path attacker.
- HTTP control traffic requires an external TLS boundary when it leaves an
  isolated management network. The optional
  [HTTPS artifact profile](deploy/container/https/README.md) exposes only
  session-authenticated bearer artifact paths. It does not expose control
  routes or distribute the issuing CA's private key.
- Prometheus metrics require the API key by default. The explicit
  `api.metrics_require_api_key = false` exception affects only `GET /metrics`,
  which remains rate-limited; deployments using it must restrict listener
  access with a firewall, private observability network, or authenticated
  reverse proxy because metrics reveal operational state.
- HTTP artifact identity requires the opaque bearer token returned for an
  unexpired boot session and a resolved client IP matching that session. The
  digest is persisted, not the token. Source binding limits off-host replay;
  it does not prevent interception, on-path tampering, shared-NAT access, or
  address reuse. Plain HTTP requires an isolated provisioning network.
- The optional native HTTP Boot route uses source-IP session association
  because UEFI firmware cannot be assumed to attach an authorization header.
  It must be enabled explicitly, accepts only one configured logical name,
  requires a managed release member, and does not fall back to direct-root
  compatibility files. Shared NAT, address reuse, or an incorrectly trusted
  proxy weakens this boundary just as it does for TFTP.
- Manifest signatures rely on private-key protection and trusted verifier
  distribution. The audit JSONL is deliberately unsigned and must be protected
  by host access controls or exported to a separately trusted log system.
- SQL persistence coordinates durable control state but does not distribute
  artifact bytes or provide a cluster-wide cutover barrier.
- Direct-root compatibility files are reachable only over HTTP, never TFTP,
  and do not inherit managed release identity.
- DSCP markings are advisory and may be ignored or rewritten by the network.

Reports about path escape, unauthorized control mutation, memory or CPU
exhaustion beyond documented bounds, release-identity confusion, signature or
audit bypass, malformed-packet crashes, SQL state corruption, and extension
boundary violations are in scope.

## Deployment Guidance

Run Tempest with least privilege, bind the control API to a protected interface,
keep WRQ disabled unless required, protect signing keys separately from artifact
storage, protect the unsigned audit directory from untrusted writers, and use
client-side signed boot verification such as UEFI Secure Boot.
Review [`README.md`](README.md) and [`DEPLOYMENT.md`](DEPLOYMENT.md) before an
internet-adjacent or multi-node deployment.

Build deployments from a signed release tag and verify it with `git tag -v`, as
described in [`INSTALL.md`](INSTALL.md).
