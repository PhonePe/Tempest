<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Firmware and Client Compatibility

Tempest preserves standards-compatible TFTP behavior, but firmware
implementations vary in option support, retry timing, packet-size tolerance, and
network-driver quality. This matrix records exercised clients and must not be
read as certification for untested hardware.

## Evidence Levels

| Level | Meaning |
| --- | --- |
| Automated | Repeated in repository CI or the checked-in L2 harness |
| Reported | Reproduced by a contributor with the required evidence below |
| Not yet exercised | Supported by design but no qualifying report is recorded |
| Unsupported | Deliberately outside the current protocol profile |

## Current Matrix

| Client or firmware | Stage | Transport/options | Evidence | Status |
| --- | --- | --- | --- | --- |
| Checked-in Python reference client | Software TFTP client | IPv4 and IPv6 octet RRQ, 512-byte `blksize`, standard DATA/ACK | `demo/l2-flat` core-plus-SQL run | Automated |
| Checked-in bearer HTTP artifact client | Software HTTP client | IPv4 and IPv6 token-authorized complete-object GET | `demo/l2-flat` TFTP-to-HTTP flows | Automated |
| Checked-in native HTTP Boot client | Software HTTP client | IPv4 and IPv6 source-IP-authorized fixed-URI GET without custom headers | `demo/l2-flat` native HTTP flows, including IPv6 recovery | Automated |
| `tempest-control-client` | Control-plane client | `/api/v1` operations plus digest-bound `/api/v2` mutations | Same-checkout live contract test (`make test-live`) | Automated |
| Current iPXE | Second-stage network boot | Standard TFTP and HTTP handoff | No qualifying hardware/software report recorded | Not yet exercised |
| UEFI PXE firmware | Firmware first stage | Standard octet TFTP; options vary by vendor | No qualifying report recorded | Not yet exercised |
| UEFI HTTP Boot firmware | Firmware first stage | DHCP-advertised HTTP URI; firmware behavior varies by vendor | No qualifying hardware report recorded | Not yet exercised |
| Legacy BIOS PXE firmware | Firmware first stage | Conservative 512-byte octet TFTP | No qualifying report recorded | Not yet exercised |
| `netascii` and `mail` mode clients | Any | Historical TFTP modes | Core rejects these modes explicitly | Unsupported |

## Qualifying Compatibility Report

A report must include enough information for another contributor to reproduce
it:

- Tempest version or exact commit and enabled Cargo features;
- complete relevant configuration with secrets and internal addresses redacted;
- client or firmware vendor, model, version, architecture, and boot mode;
- DHCP/Option 67 setup and whether an intermediate bootloader was used;
- address family and, for IPv6, the Router Advertisement, DHCPv6, prefix,
  address-assignment, and boot-URI behavior;
- requested TFTP options and accepted OACK values;
- artifact names, sizes, and hashes;
- network topology, MTU, RTT, loss/jitter injection, and server OS/architecture;
- result for first-stage load, kernel, initrd, configuration, and HTTP handoff as
  applicable;
- bounded server/client logs and a redacted packet capture when it can be shared
  safely; and
- at least three successful repetitions or a minimal repeatable failure.

Do not include API keys, private artifact contents, customer inventory, private
addresses, or other confidential data. Vulnerabilities follow
[`../SECURITY.md`](../SECURITY.md), not the public compatibility process.

## Updating the Matrix

Submit the **Firmware compatibility report** issue form. A pull request that
changes this matrix should link the accepted report and state exactly which row
and evidence level changed. Reports against modified forks or private providers
must separate core behavior from composition-specific behavior.

A successful software client test does not automatically qualify a firmware
implementation, and a single successful fallback transfer does not prove custom
protocol interoperability or production capacity.

The automated IPv6 rows use a ULA-only Podman bridge and direct service
addresses. They establish Tempest application and transport behavior, not
DHCPv6 discovery, link-local interface scoping, or UEFI firmware compatibility.
