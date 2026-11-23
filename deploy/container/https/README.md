<!-- SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# HTTPS artifact delivery

This optional profile terminates TLS in Nginx and forwards artifact requests to
Tempest on the same Linux host. The Rust binary continues to own authentication,
source-IP binding, release pins, verification, ranges, streaming, and audit. It
does not need a TLS feature or an integration-specific dependency.

The client-facing HTTPS listener exposes only `/api/v1/artifacts/` using
GET/HEAD. Clients must send their session's `Authorization: Bearer ...`
header and match its source-IP binding; access is not anonymous. Control routes,
metrics, and the optional native firmware route are not published by this profile.

## Listener port and host security

The example listens on TCP **8443**, not 443. Include the explicit `:8443` in
every client artifact URL, boot script, and HTTPS probe, for example
`https://boot.example.net:8443/api/v1/artifacts/vmlinuz`. Allow TCP 8443 only
from the intended provisioning clients in the host/network firewall. Omitting
the port selects HTTPS port 443, where this profile does not listen.

Linux host networking preserves the real socket peer for session source-IP
checks. Nginx runs as UID/GID 101 with a read-only filesystem,
`no-new-privileges`, and all capabilities dropped. Port 8443 avoids relying on
`cap_add: NET_BIND_SERVICE` surviving nonroot process execution. Do not weaken
the host's `net.ipv4.ip_unprivileged_port_start` sysctl to make port 443 work;
host networking shares the host network namespace. No port publishing or
host sysctl change is needed for this high-port profile.

If clients require port 443, use a **separately managed host TLS boundary**
instead of changing this container to root or adding capabilities. That
boundary must enforce the same artifact-only routes, TLS policy, and
authorization forwarding, and overwrite client-identity headers from its real
socket peer before forwarding directly to Tempest's loopback listener. Trust
only that boundary's actual backend source address in `api.trusted_proxy_ips`.
Simply placing another proxy in front of this example loses the client identity:
this Nginx configuration overwrites forwarding headers with its own direct peer.
The port-443 boundary and its runtime validation are outside this profile.

## Configure Tempest and the proxy

Merge these settings into the existing Tempest configuration:

```toml
[api]
bind = "127.0.0.1"
port = 8080
api_key = "env:TEMPEST_API_KEY"
trusted_proxy_ips = ["127.0.0.1"]
```

Keep the plaintext listener host-local. Management clients use a protected local
connection or a separately secured management proxy. Do not place the control
API key in a boot script. Bearer tokens remain short-lived session credentials;
HTTPS does not turn them into public artifacts or remove source-IP checks.

Copy [`nginx.conf.example`](nginx.conf.example) to the path in
[`TEMPEST_TLS_CONFIG`](.env.example). Set `server_name` to the DNS name used by
clients and bind `listen` to the intended provisioning address if the host has
multiple interfaces, keeping port 8443 (for example `192.0.2.11:8443 ssl`).
Configure a DNS SAN for that exact name in the certificate;
numeric-IP URLs require a matching IP SAN. The proxy overwrites incoming
`X-Forwarded-For` with its direct peer's address and keeps authorization and range
headers. Do not enable Nginx real-IP rewriting from untrusted request headers.
Shared NAT loses the distinct client addresses needed by Tempest's sessions.

For the dual-plane deployment, bind the two Tempest HTTP services to different
loopback ports, for example L2 `127.0.0.1:8081` and L3 `127.0.0.1:8082`, and trust
`127.0.0.1` in each. Render one HTTPS server/upstream pair per plane: the L2
address on port 8443 forwards to 8081 and the routed VIP on port 8443 forwards
to 8082. Keep the TFTP
`server.bind` addresses and host networking unchanged. Include an HTTPS artifact
probe alongside the existing readiness check before advertising the service VIP.

## Certificates and iPXE trust

Provision these files from the deployment's certificate authority:

```text
/etc/tempest/tls/
  releases/<certificate-version>/fullchain.pem
  releases/<certificate-version>/privkey.pem
  current -> releases/<certificate-version>
```

Use an RSA server certificate with SHA-256 signatures for the supplied TLS 1.2
ECDHE-RSA/AES-GCM profile. TLS 1.3 is also enabled for capable clients. The
certificate must be valid for server authentication and the URL name; include
the leaf first, followed by intermediates in `fullchain.pem`.
[Nginx documents the chain ordering and TLS directives](https://nginx.org/en/docs/http/ngx_http_ssl_module.html).

Build the iPXE image with HTTPS enabled and the public CA certificate in both
`TRUST=ca.pem` and `CERT=ca.pem`. `TRUST` selects its trust anchor; `CERT` embeds
the full root so private-CA validation does not depend on downloading it. During
CA rotation, distribute an image trusting and embedding both roots before
switching server chains. The CA private key belongs in the issuing service, not
the proxy, artifact tree, or firmware image. See
[iPXE's TLS and embedded certificate documentation](https://ipxe.org/crypto).

Give the proxy UID/GID 101 directory traversal and read access to its leaf key
(for example root:101 directories `0750`, key `0640`). Mount the whole
certificate directory read-only so an atomic `current` symlink replacement is
visible inside the container. Do not bind-mount individual leaf files: an atomic
host replacement can leave a container holding the old inode. Keep certificates
outside the artifact root. TLS server trust does not authenticate an initial
iPXE executable delivered over TFTP; validate that first stage using the
deployment's firmware/Secure Boot policy.

## Start and rotate

Set an immutable, reviewed Nginx image digest, configuration path, and certificate
directory in a root-owned environment file based on [`.env.example`](.env.example).
The image must supply Nginx's HTTP SSL module and OpenSSL with TLS 1.3 support.
On the Linux server:

```sh
docker compose --env-file /etc/tempest/https.env \
  -f deploy/container/https/compose.yml run --rm tempest-https -t
docker compose --env-file /etc/tempest/https.env \
  -f deploy/container/https/compose.yml up -d
```

Renew into a new version directory, verify the certificate/key pair and SANs,
then atomically replace `current`. Keep the previous version until the new
chain passes a client probe. Test and gracefully reload Nginx:

```sh
docker compose --env-file /etc/tempest/https.env \
  -f deploy/container/https/compose.yml exec tempest-https nginx -t
docker compose --env-file /etc/tempest/https.env \
  -f deploy/container/https/compose.yml exec tempest-https nginx -s reload
```

A failed config test must stop the rollout; restore the previous `current`
target. Graceful reload lets existing transfers finish using the prior workers
while new connections use the renewed certificate. Updating a server leaf under
the same trusted CA does not require rebuilding iPXE.

## Verify the deployed boundary

From the registered client's address, use a live token and an artifact that is a
member of the session's pinned release; files under the artifact root that are
not in that release are not served:

```sh
curl --fail --cacert ca.pem --tlsv1.2 --tls-max 1.2 \
  -H "Authorization: Bearer $TEMPEST_ARTIFACT_TOKEN" \
  -H 'Range: bytes=0-1023' -D response.headers -o artifact.part \
  https://boot.example.net:8443/api/v1/artifacts/vmlinuz
curl --cacert ca.pem -o /dev/null -w '%{http_code}\n' \
  https://boot.example.net:8443/api/v1/sessions
```

Expect `206` with the managed ETag, content range, and Tempest release-identity
headers for the first request and `404` for the control path. Repeat the download
with a forged `X-Forwarded-For`: it must still use the real client identity.
A missing token must return `401`, and a token from a different client address
must return `403`. Wrong-CA and wrong-hostname probes must fail certificate
verification. Finally, exercise the exact deployed iPXE binary against a real
managed kernel/initrd release; an OpenSSL or curl success alone does not qualify
firmware compatibility. Response buffering and proxy caching are disabled so
Tempest's admission, backpressure, ranges, and release selection remain active.
