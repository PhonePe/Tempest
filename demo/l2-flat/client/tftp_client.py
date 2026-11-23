#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0

import argparse
import os
import socket
import sys
import time
import urllib.request


OP_RRQ = 1
OP_DATA = 3
OP_ACK = 4
OP_ERROR = 5
OP_OACK = 6


def _encode_rrq(filename, blksize, trace_id):
    parts = [OP_RRQ.to_bytes(2, "big"), filename.encode(), b"\0", b"octet\0"]
    if blksize:
        parts.extend([b"blksize\0", str(blksize).encode(), b"\0"])
    parts.extend([b"timeout\0", b"2\0", b"tsize\0", b"0\0"])
    if trace_id:
        parts.extend([b"x-trace-id\0", trace_id.encode(), b"\0"])
    return b"".join(parts)


def _parse_oack(payload):
    values = payload.rstrip(b"\0").split(b"\0")
    options = {}
    for i in range(0, len(values) - 1, 2):
        options[values[i].decode(errors="replace").lower()] = values[i + 1].decode(
            errors="replace"
        )
    return options


def _ack(block):
    return OP_ACK.to_bytes(2, "big") + block.to_bytes(2, "big")


def download(
    server,
    port,
    filename,
    output,
    blksize,
    ack_delay_ms,
    trace_id,
    address_family,
    expected_error=None,
):
    family = {
        "ipv4": socket.AF_INET,
        "ipv6": socket.AF_INET6,
    }[address_family]
    addresses = socket.getaddrinfo(
        server,
        port,
        family=family,
        type=socket.SOCK_DGRAM,
        proto=socket.IPPROTO_UDP,
    )
    if not addresses:
        raise OSError(f"no {address_family} UDP address found for {server}")
    address = addresses[0][4]
    rrq = _encode_rrq(filename, blksize, trace_id)
    if expected_error is not None:
        # Exercise an ordinary, option-free ROM request, not custom negotiation.
        rrq = OP_RRQ.to_bytes(2, "big") + filename.encode() + b"\0octet\0"
    expected_block = 1
    negotiated_blksize = blksize or 512
    server_tid = None
    last_packet = rrq
    started = time.monotonic()
    bytes_written = 0
    retries = 0

    os.makedirs(os.path.dirname(output), exist_ok=True)
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3.0)
        sock.sendto(rrq, address)
        with open(output, "wb") as handle:
            while True:
                try:
                    packet, peer = sock.recvfrom(65535)
                except socket.timeout:
                    retries += 1
                    if retries > 5:
                        raise TimeoutError(f"timed out waiting for {filename}")
                    sock.sendto(last_packet, server_tid or address)
                    continue

                retries = 0
                if expected_error is not None:
                    if (
                        peer[0] != address[0]
                        or len(packet) < 5
                        or int.from_bytes(packet[:2], "big") != OP_ERROR
                        or int.from_bytes(packet[2:4], "big") != expected_error
                        or not packet.endswith(b"\0")
                    ):
                        raise RuntimeError(
                            f"expected TFTP ERROR code {expected_error} for {filename}, "
                            f"got {packet[:64]!r} from {peer}"
                        )
                    print(
                        f"denied {filename}: TFTP ERROR code={expected_error}; no artifact data received",
                        flush=True,
                    )
                    return 0, time.monotonic() - started
                if len(packet) < 2:
                    continue

                opcode = int.from_bytes(packet[:2], "big")
                if opcode == OP_OACK:
                    server_tid = peer
                    options = _parse_oack(packet[2:])
                    negotiated_blksize = int(options.get("blksize", 512))
                    last_packet = _ack(0)
                    sock.sendto(last_packet, server_tid)
                    continue

                if opcode == OP_ERROR:
                    message = packet[4:].rstrip(b"\0").decode(errors="replace")
                    raise RuntimeError(f"server error for {filename}: {message}")

                if opcode != OP_DATA or len(packet) < 4:
                    continue

                server_tid = peer
                block = int.from_bytes(packet[2:4], "big")
                data = packet[4:]

                if block == expected_block:
                    handle.write(data)
                    bytes_written += len(data)
                    expected_block = (expected_block + 1) & 0xFFFF
                    if expected_block == 0:
                        expected_block = 1

                if ack_delay_ms > 0:
                    time.sleep(ack_delay_ms / 1000.0)
                last_packet = _ack(block)
                sock.sendto(last_packet, server_tid)

                if len(data) < negotiated_blksize:
                    elapsed = time.monotonic() - started
                    print(
                        f"downloaded {filename} bytes={bytes_written} seconds={elapsed:.3f} output={output}",
                        flush=True,
                    )
                    return bytes_written, elapsed


def http_download(url, output, api_key, artifact_token):
    started = time.monotonic()
    bytes_written = 0
    os.makedirs(os.path.dirname(output), exist_ok=True)
    request = urllib.request.Request(url)
    if api_key:
        request.add_header("x-api-key", api_key)
    if artifact_token:
        request.add_header("Authorization", f"Bearer {artifact_token}")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=15) as response, open(output, "wb") as handle:
        while True:
            chunk = response.read(64 * 1024)
            if not chunk:
                break
            handle.write(chunk)
            bytes_written += len(chunk)
        elapsed = time.monotonic() - started
        profile = response.headers.get("x-tempest-boot-profile", "")
        phase = response.headers.get("x-tempest-boot-phase", "")
        group = response.headers.get("x-tempest-group-id", "")
        digest = response.headers.get("x-tempest-content-sha256", "")
        print(
            f"downloaded {url} bytes={bytes_written} seconds={elapsed:.3f} "
            f"profile={profile} phase={phase} group={group} sha256={digest} output={output}",
            flush=True,
        )
        return bytes_written, elapsed


def main():
    parser = argparse.ArgumentParser(description="Small TFTP RRQ client for the Tempest L2 demo")
    parser.add_argument("--server", default="tempest")
    parser.add_argument("--port", type=int, default=6969)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file")
    source.add_argument("--http-url")
    parser.add_argument("--output", required=True)
    parser.add_argument("--blksize", type=int, default=8192)
    parser.add_argument(
        "--address-family",
        choices=("ipv4", "ipv6"),
        default="ipv4",
        help="UDP address family for TFTP; the default preserves the IPv4 PXE lane",
    )
    parser.add_argument("--ack-delay-ms", type=int, default=0)
    parser.add_argument("--trace-id")
    parser.add_argument("--api-key")
    parser.add_argument("--expect-marker")
    parser.add_argument("--expect-tftp-error", type=int, choices=range(9))
    args = parser.parse_args()
    if args.expect_tftp_error is not None and (args.http_url or args.expect_marker):
        parser.error("--expect-tftp-error requires --file and cannot use --expect-marker")

    try:
        if args.http_url:
            http_download(
                args.http_url,
                args.output,
                args.api_key,
                os.environ.get("TEMPEST_ARTIFACT_TOKEN"),
            )
        else:
            download(
                args.server,
                args.port,
                args.file,
                args.output,
                args.blksize,
                args.ack_delay_ms,
                args.trace_id,
                args.address_family,
                args.expect_tftp_error,
            )
        if args.expect_marker:
            with open(args.output, "rb") as handle:
                sample = handle.read(4096)
            if args.expect_marker.encode() not in sample:
                raise RuntimeError(f"marker {args.expect_marker!r} not found in {args.output}")
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
