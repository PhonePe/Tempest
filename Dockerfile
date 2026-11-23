# syntax=docker/dockerfile:1
# SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0

ARG RUST_IMAGE=docker.io/library/rust:1.100.0-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea
ARG RUNTIME_IMAGE=docker.io/library/debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

FROM ${RUST_IMAGE} AS builder

WORKDIR /build

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches
COPY crates/tempest-control-client ./crates/tempest-control-client

# The dual-plane deployment uses one durable control plane across the L2 and
# L3 processes, so the production image intentionally includes SQL support.
RUN cargo build --locked --release --features sql-persistence --bin tempest

FROM ${RUNTIME_IMAGE} AS runtime

ARG TEMPEST_VERSION=unknown
ARG TEMPEST_REVISION=unknown

LABEL org.opencontainers.image.title="Tempest" \
      org.opencontainers.image.description="Release-coherent TFTP and HTTP boot artifact server" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/PhonePe/Tempest" \
      org.opencontainers.image.documentation="https://github.com/PhonePe/Tempest/blob/main/INSTALL.md" \
      org.opencontainers.image.version="${TEMPEST_VERSION}" \
      org.opencontainers.image.revision="${TEMPEST_REVISION}"

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 tempest \
    && useradd --uid 10001 --gid tempest --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin tempest \
    && install -d -o tempest -g tempest -m 0750 /etc/tempest /tftpboot \
    && install -d -o tempest -g tempest -m 0700 /var/log/tempest

COPY --from=builder --chown=root:root /build/target/release/tempest /usr/local/bin/tempest

USER 10001:10001

# EXPOSE is documentation only. Production TFTP uses Linux host networking so
# every per-transfer ephemeral UDP port remains directly reachable.
EXPOSE 69/udp 8080/tcp

STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/tempest"]
CMD ["--config", "/etc/tempest/tempest.toml"]
