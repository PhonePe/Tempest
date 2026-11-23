<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Documentation Map

The repository root contains the maintained project, security, deployment,
extension, quality, support, and release contracts. Start with
[`README.md`](../README.md), then follow its developer path.

## Maintained References

- [`openapi.yaml`](openapi.yaml) is the HTTP API contract.
- [`FIRMWARE_COMPATIBILITY.md`](FIRMWARE_COMPATIBILITY.md) records exercised
  client evidence and the requirements for adding a compatibility claim.
- [`guides/PROVISIONING_HTTP_INTEGRATION.md`](guides/PROVISIONING_HTTP_INTEGRATION.md)
  describes vendor-neutral release selection, boot-session registration, and
  bearer-token or native fixed-URI HTTP artifact delivery for provisioning
  orchestrators.
- [`guides/TEST_RUN.md`](guides/TEST_RUN.md) provides the local integration
  runbook.
- [`guides/deletion.md`](guides/deletion.md) defines the exact-identity
  retained-metadata deletion contract and SQL single-serving-node mode.
- [`guides/tftp-client-policy-testing.md`](guides/tftp-client-policy-testing.md)
  compares two Tempest binaries' TFTP client policy in an isolated network
  namespace before rollout.
- [`guides/TEMPEST_GO_LIVE.md`](guides/TEMPEST_GO_LIVE.md) is an operator
  readiness checklist.
- [`../deploy/container/README.md`](../deploy/container/README.md) describes the
  hardened dual-process container profile for simultaneous L2 and FRR-routed
  L3 service.

## Protocol and Design References

- TFTP: RFC 1350 (protocol), RFC 2347 (option extension), RFC 2348 (block
  size), RFC 2349 (timeout and transfer size), RFC 7440 (window size).
- DHCP boot options: RFC 2132 (Option 66 and 67), RFC 4578 (PXE client
  architecture), RFC 5970 (DHCPv6 network boot).
- UEFI HTTP Boot: UEFI Specification, section "HTTP Boot"
  (<https://uefi.org/specifications>).
- HTTP semantics and bearer tokens: RFC 9110, RFC 6750.
- DSCP marking: RFC 2474.
- Release-manifest signatures: Ed25519, RFC 8032. Content digests: SHA-256,
  FIPS 180-4.
- Aggregate rate limiting: the token-bucket algorithm, as used for traffic
  metering in RFC 2697.
- Linux UDP segmentation offload (`UDP_SEGMENT`) and `sendmmsg`: the `udp(7)`
  and `sendmmsg(2)` manual pages.

## Proposals

New design proposals belong in an issue or pull request; they should not add
another root-level design diary.
