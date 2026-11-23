<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Dual-plane container deployment

This profile runs the same Tempest image as two independent, least-privilege
processes on each Linux host:

- `tempest-l2` binds the node's directly connected provisioning address;
- `tempest-l3` binds a routed `/32` service VIP originated by host-managed FRR;
- both mount the same immutable artifact tree and use the same SQL control
  store, while keeping sockets, transfer capacity, caches, and audit logs
  process-local.

FRR intentionally is not installed in the Tempest image. Manage FRR with the
host's configuration management (for example Salt) and systemd so routing
privileges (`NET_ADMIN` and `NET_RAW`)
never enter the artifact-server container. The repository's FRR files are
policy examples, not a replacement for the site's routing configuration.

All example addresses and ASNs are documentation values. Replace them before
deployment.

## Why two containers and host networking

Tempest binds every transfer's ephemeral UDP socket to `server.bind`. One
process therefore serves one unambiguous data-plane address. Running a process
per plane prevents a wildcard listener from replying with the wrong source
address.

TFTP also switches from UDP port 69 to a server-selected transfer ID (an
ephemeral UDP port) after the initial request. Linux host networking preserves
that behavior without a broad NAT port range or userland proxy. Do not replace
`network_mode: host` with only `69:69/udp`; the initial RRQ may succeed while
the actual transfer times out. Host networking is required for this profile and
is not equivalent on Docker Desktop.

## Build once

Build, scan, sign, and publish one immutable image. The Dockerfile includes the
`sql-persistence` feature required by the example multi-process topology.

```bash
docker build \
  --build-arg TEMPEST_VERSION=0.1.0 \
  --build-arg TEMPEST_REVISION="$(git rev-parse HEAD)" \
  -t registry.example.invalid/tempest:0.1.0 .
```

The default builder and runtime references are tag-plus-multi-architecture-
digest pinned. Override `RUST_IMAGE` and `RUNTIME_IMAGE` only with reviewed,
patched digest-pinned references, then record the resulting Tempest image
digest in Salt pillar.

## Render each host

1. Copy [`.env.example`](.env.example) to a root-owned Compose environment
   file and set the immutable image digest plus host paths. This file contains
   interpolation values, not application secrets.
2. Render [`tempest.env.example`](tempest.env.example) to a mode-`0600` file
   from secret-backed Salt pillar. Supply `TEMPEST_API_KEY` and
   `TEMPEST_DATABASE_URL` there.
3. Copy the L2 and L3 TOML examples to the paths named by the Compose file.
   Copying artifacts into the artifact root does not make them servable: TFTP
   serves only members of a published release, so activate a release through
   `POST /api/v1/versions/switch` before advertising a bootfile.
   On the odd host, use its directly connected address in the L2 file; use the
   even host's address on the even host. Both L3 files use the routed service
   VIP.
4. Keep `listener_shards` equal to that plane's `TOKIO_WORKER_THREADS`. The
   sample six-vCPU split reserves one worker for compatibility L2 traffic and
   five for the preferred routed plane. Use `3 + 3` for equal simultaneous
   load, or measured CPU affinity for another topology. Never let two automatic
   all-CPU runtimes compete accidentally.
5. Create distinct audit directories owned by UID/GID `10001` and an artifact
   root readable by that identity. The Compose profile mounts artifacts
   read-only and gives each process only its own audit path.
6. Validate both files before starting. Inspection resolves environment-backed
   values but does not connect to SQL or create the artifact root:

```bash
docker run --rm --network none --read-only \
  --env-file /etc/tempest/tempest.env \
  --mount type=bind,src=/etc/tempest/tempest-l2.toml,dst=/etc/tempest/tempest.toml,readonly \
  registry.example.invalid/tempest@sha256:REPLACE \
  --config /etc/tempest/tempest.toml --check-config

docker run --rm --network none --read-only \
  --env-file /etc/tempest/tempest.env \
  --mount type=bind,src=/etc/tempest/tempest-l3.toml,dst=/etc/tempest/tempest.toml,readonly \
  registry.example.invalid/tempest@sha256:REPLACE \
  --config /etc/tempest/tempest.toml --check-config
```

Then start both instances with the host's rendered Compose environment:

```bash
docker compose \
  --env-file /etc/tempest/dual-plane.env \
  -f deploy/container/compose.dual-plane.yml \
  up -d
```

The container engine must run on Linux. A rootful engine is normally required
for host networking and port 69; the services still execute as UID 10001 with
all capabilities dropped except `NET_BIND_SERVICE`. If local policy permits an
unprivileged TFTP port instead, remove that capability and update DHCP/network
redirection accordingly.

## FRR odd/even policy

[`frr-odd.conf.example`](frr/frr-odd.conf.example) and
[`frr-even.conf.example`](frr/frr-even.conf.example) show a private-AS,
single-prefix export policy. The odd route has the preferred MED. The even
route has a higher MED and an AS-path prepend, providing a second selection
signal when both sessions reach the same upstream policy domain. The upstream
routers must enforce the intended preference; never assume they compare MED or
accept the example policy unchanged.

Use active/standby advertisement for TFTP unless the routed fabric has been
proven to preserve one backend for the entire reversed UDP five-tuple. Equal-cost
anycast can send ACKs for an ephemeral transfer ID to a different node, which
has no matching socket. HTTP can use ordinary ECMP, but sharing the same VIP
with TFTP makes the stricter TFTP rule authoritative.

FRR route presence is not application health. The host's service management must originate the
service `/32` only after the L3 instance reports `READY`, withdraw it promptly
when readiness fails, and leave the local VIP installed so the unprivileged
process can restart and bind. Make advertisement withdrawal a required rollout
and failure test; a static `network` statement by itself is insufficient
health gating.

The example outbound route-map permits only the service `/32` and denies every
other prefix. Add peer authentication from protected pillar when the fabric
supports it. Do not place BGP secrets in Compose environment files or the
repository.

## Readiness and verification

Run these checks on both odd and even hosts before allowing FRR to advertise:

```bash
docker compose --env-file /etc/tempest/dual-plane.env \
  -f deploy/container/compose.dual-plane.yml ps

curl --fail http://192.0.2.11:8080/ready
curl --fail http://198.51.100.69:8080/ready
ss -lunp | grep -E '(:69|tempest)'
vtysh -c 'show bgp ipv4 unicast 198.51.100.69/32'
```

From a client, fetch a member of the active `default` release (or of a
registered session's release) once through the node's L2 address and once
through the L3 VIP. Capture packets and confirm each transfer keeps one
server source address and one ephemeral TID. During an active large transfer,
restart the non-serving node and verify the flow is unaffected. Then drain the
serving node, withdraw its route, and verify a new transfer selects the peer.

SQL persistence shares committed profiles, releases, and sessions; it does not
share live transfer sockets, in-memory pins, caches, cutover barriers, or audit
files. Keep artifact bytes identical on both hosts and use the normal
multi-node rollout constraints in [`DEPLOYMENT.md`](../../DEPLOYMENT.md).
