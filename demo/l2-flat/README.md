<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tempest L2 Flat-Network Demo

This demo runs Postgres, the open-source Tempest binary with SQL persistence, and disposable TFTP clients on one dual-stack Podman bridge network named `tempest-l2-demo`, with Aardvark DNS resolving the primary IPv4 server as `tempest`. A second, explicitly addressed IPv6 service is started only for the IPv6 validation lane. The demo does not link any extension provider.

## Statically Composed Binary

The same flow can validate a binary that links providers through Tempest's
public extension contracts. Supply an already built Linux binary and its
combined public/provider configuration:

```bash
TEMPEST_DEMO_BINARY=/absolute/path/to/composed-tempest \
TEMPEST_DEMO_CONFIG=/absolute/path/to/composed-tempest.toml \
  python3 demo/l2-flat/demo.py run
```

The harness copies that binary into the otherwise identical runtime image. It
does not infer which providers are linked; the composition repository remains
responsible for a checked-in configuration and provider-specific tests.

It demonstrates the release-coherent boot flow end to end:

1. Start the real Tempest binary from this source tree.
2. Seed two coordinated boot releases plus typical Option 67 paths such as `ipxe/undionly.kpxe`, `rhel9-efi/x86_64-efi/core.efi`, and `installer.ipxe`.
3. Activate release v1 in the backward-compatible `default` boot profile through `POST /api/v1/versions/switch`.
4. Before registering any session, verify that a readable raw root file outside the default release manifest receives TFTP ERROR code 1, then download the managed default PXE bootstrap with exact-byte verification, plus kernel, initrd, and OS-image artifacts, from a client container on the same L2 network.
5. Keep a v1 OS-image transfer pinned while attempting release v2 activation.
6. Observe the drain-gated cutover reject the v2 activation with HTTP 409 while the old pin is active.
7. Let the old pin drain, activate v2 in the same profile, then verify a fresh kernel request receives v2 content.
8. Activate `ubuntu-focal` and `rhel9` profiles with the same logical names, seed boot sessions from a dnsmasq-style wiring matrix, and verify both the advertised first-stage TFTP file and profile-selected logical downloads over TFTP and bearer-token Tempest HTTP.
9. Fetch the same fixed `/boot/v1/boot.efi` URI without a bearer header and verify source-IP session selection returns the current profile's managed EFI image.
10. Register an independent IPv6 boot session, then validate TFTP, bearer HTTP, fixed-URI native HTTP Boot, and post-restart session recovery over the ULA-only service address.
11. Confirm a pinned Focal wiring decision cannot be rebound to RHEL until the orchestrator declares `new_epoch=true` for a new PXE attempt.
12. Restart Tempest and verify the version groups, unexpired boot-session pin, and native fixed-URI selection recover from Postgres.
13. Print Prometheus metrics showing aggregate, boot-profile-labeled, and transport-labeled transfers, active sessions, and version groups.

The demo starts by activating the `default` profile, so sessionless TFTP requests for members of that release work without pre-registering a client session; other files under the root are refused. It then models the production boundary explicitly: dnsmasq would still choose DHCP Option 67 from tags such as `bios`, `efi64`, `!ipxe`, `ubuntu-focal`, or `rhel9`, while the provisioning layer posts that decision to Tempest as a boot session for the static demo client IP `10.89.60.42`. Each profile's advertised first-stage name is included in that profile's activated manifest, so the Option 67 TFTP download and later logical names such as `vmlinuz` and `initrd.img` remain under strict session-pinned membership. Some later downloads use `GET /api/v1/artifacts/{name}` with a session bearer token, proving that iPXE-style HTTP stages keep the same release identity. The demo also enables the native route and fetches `/boot/v1/boot.efi` without a header, proving that a stable DHCP URI can resolve the source-IP session to the profile-specific managed EFI image. The flow verifies that a Focal wiring decision cannot be rebound to `rhel9` while the session is pinned, and then repeats registration with `new_epoch=true` to model a re-PXE event. The profile/version/session control-plane state is stored in Postgres, including the boot epoch and pinned manifest identity, so restart proves recovery from durable state rather than process memory.

The wiring table in `demo.py` is intentionally a compact stand-in for dnsmasq or CoreDHCP rather than a DHCP server. For example, the demo case `focal-bios-pre-ipxe` represents `focal + bios + !ipxe` selecting `ipxe/undionly.kpxe` while seeding the Tempest session with boot profile `ubuntu-focal`; `rhel9-efi` represents `efi64 + rhel9` selecting `rhel9-efi/x86_64-efi/core.efi` while seeding boot profile `rhel9`. For native HTTP Boot, DHCP can return the same `/boot/v1/boot.efi` URI to every compatible machine; only the session registration varies. That is the same split expected in production: DHCP/DNS owns client classification and initial bootfile advertisement, core TFTP handles ROM/config-sensitive stages with DSCP and window policy, and Tempest HTTP handles native firmware or iPXE payloads while preserving version pinning, transport-labeled metrics, and profile-scoped logical resolution. A separately composed binary may add WFQ, admission, pacing, coalescing, or custom wire behavior through the public extension contracts; this demo does not exercise those providers.

## Default Manifest-Only TFTP

Without a boot session, TFTP serves **only members of the active `default`
release manifest**. Merely placing a file under the artifact root does not make
it available over TFTP; there is no raw-root fallback. Register and activate a
managed default release before advertising a sessionless bootstrap filename.
With a session, the selected profile and pinned manifest remain authoritative.

The live regression runs before session registration and verifies zero active
sessions. It seeds a readable `unmanaged-bootstrap.bin`, checks readability as
the server's runtime user and absence from the default release manifest, then
sends an ordinary option-free RRQ. Only a well-formed TFTP ERROR code 1 counts
as denial: timeouts, unrelated errors, OACK, or DATA fail the test. The file is
included in the filesystem integrity inventory, demonstrating that inventory
membership is not release authorization. The managed `pxelinux.0` download
must then exactly match the release-v1 bytes.

## Prerequisites

- Podman 4+ using Netavark networking.
- `podman-compose` or the `podman compose` plugin.
- Python 3 on the host for the demo runner.

On macOS, start Podman Machine first:

```bash
podman machine start
podman info --format '{{.Host.NetworkBackend}}'
```

The network backend should be `netavark`.

The harness detects the Podman VM architecture and passes an explicit
`linux/amd64` or `linux/arm64` platform to every build and service. Set
`TEMPEST_DEMO_PLATFORM` only when deliberately targeting one of those two
platforms; the runtime image and copied binary must use the same architecture.

## Run

From the repository root:

```bash
python3 demo/l2-flat/demo.py check
python3 demo/l2-flat/demo.py run
```

The `check` command validates Podman/Netavark availability, Python syntax, the rendered Compose model, and the Grafana dashboard JSON. The `run` command recreates the demo containers, builds a release-profile Linux Tempest binary from the current source tree, publishes Tempest on loopback UDP `16969` and loopback HTTP `18080`, pulls a small Python client image, and runs the flow. The demo containers still use UDP `6969` and HTTP `8080` internally. The demo client uses conservative 512-byte TFTP blocks so it works on flat lab bridges that drop large UDP fragments. Generated artifacts and downloads stay under `demo/l2-flat/`.

Preflight also runs four focused client tests to ensure the negative TFTP probe
does not mistake DATA/OACK, another error code, malformed packets, a wrong peer,
or a timeout for the expected denial.

To run only the IPv6 compatibility lane:

```bash
python3 demo/l2-flat/demo.py ipv6
```

This creates a ULA subnet (`fd89:60::/64`), registers the client as
`fd89:60::42`, and addresses the IPv6-only Tempest service directly at
`[fd89:60::11]`. It validates managed TFTP, bearer HTTP, unauthenticated
source-IP HTTP Boot, and SQL-backed session recovery. It does not run a DHCPv6
server or real firmware, so it is transport and application validation rather
than a claim that a particular NIC, UEFI implementation, or DHCPv6 setup can
boot successfully.

The published IPv4 ports remain configurable when they conflict with another
local service:

```bash
TEMPEST_DEMO_API_PORT=18081 \
TEMPEST_DEMO_TFTP_PORT=16970 \
  python3 demo/l2-flat/demo.py ipv6
```

Use `TEMPEST_DEMO_IPV6_CONFIG` to supply an alternate IPv6 configuration for a
statically composed binary. The configured listener addresses must match the
container's assigned IPv6 address unless the alternate configuration binds an
appropriate IPv6 wildcard.

Useful endpoints while the demo is up:

```bash
curl http://localhost:18080/health
curl http://localhost:18080/metrics
curl -H 'x-api-key: tempest-demo-key-2026' http://localhost:18080/api/v1/versions/groups
```

The observability stack publishes Prometheus on `http://localhost:9090` and Grafana on `http://localhost:3000` by default. The provisioned dashboard separates bearer `HTTP` from `HTTP_NATIVE`, compares their request and byte rates, breaks native requests down by boot profile, and shows the native failure ratio. If host port `3000` is already in use, `python3 demo/l2-flat/demo.py observe` automatically selects a free Grafana port starting at `13000` and prints the exact URL. To choose a port yourself, set `TEMPEST_DEMO_GRAFANA_PORT` before starting the stack.

## Tear Down

Stop containers and keep generated files:

```bash
python3 demo/l2-flat/demo.py down
```

Remove containers, volumes, and generated demo files:

```bash
python3 demo/l2-flat/demo.py clean
```

## Why Podman Instead Of Lima Here

A Lima VM is the better fit when the demo needs Linux network namespaces, `tc`, `iptables`, and failure injection. This Tempest flow only needs real L2 reachability, DNS, UDP, and the control API. Podman with Netavark provides that directly.

If you later want to demonstrate packet loss, queueing delay, or host-level network partitions around Tempest, this same compose setup can be run inside a Lima VM and extended with namespace or `tc` controls.
