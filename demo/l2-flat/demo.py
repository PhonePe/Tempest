#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0

import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parent
TFTP_ROOT = ROOT / "tftpboot"
DOWNLOADS = ROOT / "downloads"
BUILD = ROOT / "build"
UNMANAGED_BOOTSTRAP = "unmanaged-bootstrap.bin"
API_PORT = int(os.environ.get("TEMPEST_DEMO_API_PORT", "18080"))
API = f"http://127.0.0.1:{API_PORT}"
API_KEY = "tempest-demo-key-2026"
DEMO_CLIENT_IP = "10.89.60.42"
DEMO_TEMPEST_IP = "10.89.60.10"
DEMO_CLIENT_IPV6 = "fd89:60::42"
DEMO_TEMPEST_IPV6 = "fd89:60::11"
IPV4_API = f"http://{DEMO_TEMPEST_IP}:8080"
IPV6_API = f"http://[{DEMO_TEMPEST_IPV6}]:8080"
DEFAULT_GRAFANA_PORT = 3000
FALLBACK_GRAFANA_PORT_START = 13000
FALLBACK_GRAFANA_PORT_END = 13099
PODMAN_ARCHITECTURES = {
    "aarch64": "arm64",
    "arm64": "arm64",
    "amd64": "amd64",
    "x86_64": "amd64",
}
DEMO_DNSMASQ_WIRING = {
    "focal-bios-pre-ipxe": {
        "description": "dnsmasq tags: focal + bios + !ipxe -> Option 67 ipxe/undionly.kpxe, with provisioning intent ubuntu-focal",
        "boot_profile": "ubuntu-focal",
        "option67": "ipxe/undionly.kpxe",
        "option67_marker": "wiring:ipxe-bios",
        "client_mac": "aa:bb:cc:dd:ee:ff",
        "serial": "DEMO-FOCAL-BIOS-PREIPXE",
        "trace_id": "wiring-focal-bios-preipxe",
    },
    "rhel9-efi": {
        "description": "dnsmasq tags: efi64 + rhel9 -> Option 67 rhel9-efi/x86_64-efi/core.efi, with provisioning intent rhel9",
        "boot_profile": "rhel9",
        "option67": "rhel9-efi/x86_64-efi/core.efi",
        "option67_marker": "wiring:rhel9-efi-core",
        "client_mac": "aa:bb:cc:dd:ee:ff",
        "serial": "DEMO-RHEL9-EFI",
        "trace_id": "wiring-rhel9-efi",
    },
}


def run(cmd, *, redactions=(), **kwargs):
    display = " ".join(cmd)
    for secret in redactions:
        display = display.replace(secret, "<redacted>")
    print("$ " + display, flush=True)
    cwd = kwargs.pop("cwd", ROOT)
    return subprocess.run(cmd, cwd=cwd, check=True, text=True, **kwargs)


def run_optional(cmd, **kwargs):
    print("$ " + " ".join(cmd), flush=True)
    cwd = kwargs.pop("cwd", ROOT)
    return subprocess.run(cmd, cwd=cwd, check=False, text=True, **kwargs)


def compose_cmd():
    if shutil.which("podman-compose"):
        return ["podman-compose", "-f", "compose.yml"]
    result = subprocess.run(
        ["podman", "compose", "version"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if result.returncode == 0:
        return ["podman", "compose", "-f", "compose.yml"]
    raise SystemExit("Neither podman-compose nor 'podman compose' is available")


def tcp_port_available(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind(("0.0.0.0", port))
        except OSError:
            return False
    return True


def running_container(name):
    result = subprocess.run(
        ["podman", "inspect", "--format", "{{.State.Running}}", name],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def existing_grafana_host_port():
    if not running_container("tempest-grafana"):
        return None
    result = subprocess.run(
        ["podman", "port", "tempest-grafana", "3000/tcp"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        value = line.strip()
        if not value:
            continue
        try:
            return int(value.rsplit(":", 1)[1])
        except (IndexError, ValueError):
            continue
    return None


def grafana_observe_env():
    env = os.environ.copy()
    configured_port = env.get("TEMPEST_DEMO_GRAFANA_PORT")
    if configured_port:
        try:
            port = int(configured_port)
        except ValueError as exc:
            raise SystemExit("TEMPEST_DEMO_GRAFANA_PORT must be an integer") from exc
        return env, port

    existing_port = existing_grafana_host_port()
    if existing_port is not None:
        env["TEMPEST_DEMO_GRAFANA_PORT"] = str(existing_port)
        return env, existing_port

    if tcp_port_available(DEFAULT_GRAFANA_PORT):
        return env, DEFAULT_GRAFANA_PORT

    for port in range(FALLBACK_GRAFANA_PORT_START, FALLBACK_GRAFANA_PORT_END + 1):
        if tcp_port_available(port):
            env["TEMPEST_DEMO_GRAFANA_PORT"] = str(port)
            print(
                f"Host port {DEFAULT_GRAFANA_PORT} is busy; publishing Grafana on {port} instead",
                flush=True,
            )
            return env, port

    raise SystemExit(
        f"No free Grafana host port found in {FALLBACK_GRAFANA_PORT_START}-{FALLBACK_GRAFANA_PORT_END}"
    )


def preflight():
    if not shutil.which("podman"):
        raise SystemExit("podman is required")
    backend = subprocess.run(
        ["podman", "info", "--format", "{{.Host.NetworkBackend}}"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()
    if backend != "netavark":
        raise SystemExit(f"Podman Netavark networking is required; got {backend!r}")
    host_arch = subprocess.run(
        ["podman", "info", "--format", "{{.Host.Arch}}"],
        check=True,
        text=True,
        capture_output=True,
    ).stdout.strip()
    compose_arch = PODMAN_ARCHITECTURES.get(host_arch)
    if compose_arch is None:
        raise SystemExit(f"unsupported Podman host architecture: {host_arch!r}")
    detected_platform = f"linux/{compose_arch}"
    configured_platform = os.environ.setdefault(
        "TEMPEST_DEMO_PLATFORM", detected_platform
    )
    if configured_platform not in {"linux/amd64", "linux/arm64"}:
        raise SystemExit(
            "TEMPEST_DEMO_PLATFORM must be linux/amd64 or linux/arm64"
        )
    compose_cmd()


def build_binary():
    BUILD.mkdir(parents=True, exist_ok=True)
    binary_override = os.environ.get("TEMPEST_DEMO_BINARY")
    if binary_override:
        source = Path(binary_override).expanduser().resolve()
        if not source.is_file():
            raise SystemExit(f"TEMPEST_DEMO_BINARY is not a file: {source}")
        target = (BUILD / "tempest").resolve()
        if source != target:
            shutil.copy2(source, target)
        print(f"Using composed Tempest binary {source}", flush=True)
        return

    repo = ROOT.parent.parent
    run(
        [
            "podman",
            "run",
            "--rm",
            "--platform",
            os.environ["TEMPEST_DEMO_PLATFORM"],
            "-v",
            f"{repo}:/src:Z",
            "-w",
            "/src",
            "docker.io/library/rust:1-bookworm",
            "sh",
            "-c",
            "mkdir -p demo/l2-flat/build && CARGO_TARGET_DIR=demo/l2-flat/build/cargo-target cargo build --release --features sql-persistence && cp demo/l2-flat/build/cargo-target/release/tempest demo/l2-flat/build/tempest",
        ]
    )


def make_artifact(path, marker, size):
    path.parent.mkdir(parents=True, exist_ok=True)
    header = (marker + "\n").encode()
    pattern = (marker + "|tempest-demo|").encode()
    remaining = max(0, size - len(header))
    with open(path, "wb") as handle:
        handle.write(header)
        while remaining > 0:
            chunk = pattern[: min(len(pattern), remaining)]
            handle.write(chunk)
            remaining -= len(chunk)


def safe_trace_id(value):
    sanitized = "".join(ch if ch.isascii() and ch.isalnum() else "-" for ch in value)
    sanitized = "-".join(part for part in sanitized.split("-") if part)
    return sanitized[:96] or "artifact"


def seed_dnsmasq_wiring_artifacts():
    artifacts = {
        "ipxe/undionly.kpxe": ("wiring:ipxe-bios", 64 * 1024),
        "ipxe/ipxe.efi": ("wiring:ipxe-efi", 96 * 1024),
        "focal/pxelinux.0": ("wiring:focal-bios-pxelinux", 8 * 1024),
        "installer/pxelinux.0": ("wiring:installer-bios-pxelinux", 8 * 1024),
        "installer/vmlinuz": ("wiring:installer-kernel", 128 * 1024),
        "installer/initrd.bz2": ("wiring:installer-initrd", 192 * 1024),
        "jammy-efi/syslinux.efi": ("wiring:jammy-efi-syslinux", 96 * 1024),
        "jammy-efi/ldlinux.e64": ("wiring:jammy-efi-loader-lib", 32 * 1024),
        "jammy-efi/pxelinux.cfg/default": ("wiring:jammy-efi-config", 4 * 1024),
        "rhel9-efi/x86_64-efi/core.efi": ("wiring:rhel9-efi-core", 128 * 1024),
        "bookworm-efi/ipxe.efi": ("wiring:bookworm-efi-ipxe", 128 * 1024),
    }
    for relative, (marker, size) in artifacts.items():
        artifact_path = TFTP_ROOT / relative
        make_artifact(artifact_path, marker, size)
        os.chmod(artifact_path, 0o644)

    installer_script = TFTP_ROOT / "installer.ipxe"
    installer_script.parent.mkdir(parents=True, exist_ok=True)
    installer_script.write_text(
        "#!ipxe\n\n"
        "set server_root http://tempest:8080/api/v1/artifacts\n"
        "set kernel_url ${server_root}/vmlinuz\n"
        "set initrd_url ${server_root}/initrd.img\n"
        "echo loading kernel and initrd\n"
        "kernel ${kernel_url}\n"
        "initrd ${initrd_url}\n"
        "boot\n"
    )
    os.chmod(installer_script, 0o644)


def seed():
    for path in (TFTP_ROOT, DOWNLOADS):
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o777 if path == DOWNLOADS else 0o755)
    for release in ("v1", "v2"):
        base = TFTP_ROOT / "releases" / release
        marker = f"release-{release}"
        make_artifact(base / "pxelinux.0", f"{marker}:pxe", 8 * 1024)
        make_artifact(base / "boot.efi", f"{marker}:native-efi", 96 * 1024)
        make_artifact(base / "vmlinuz", f"{marker}:kernel", 256 * 1024)
        make_artifact(base / "initrd.img", f"{marker}:initrd", 384 * 1024)
        make_artifact(base / "rootfs.img", f"{marker}:osimage", 256 * 1024)
        os.chmod(base, 0o755)
        for artifact in base.iterdir():
            os.chmod(artifact, 0o644)
    for profile in ("ubuntu-focal", "rhel9"):
        base = TFTP_ROOT / "releases" / profile
        make_artifact(base / "pxelinux.0", f"{profile}:pxe", 8 * 1024)
        make_artifact(base / "boot.efi", f"{profile}:native-efi", 96 * 1024)
        make_artifact(base / "vmlinuz", f"{profile}:kernel", 256 * 1024)
        make_artifact(base / "initrd.img", f"{profile}:initrd", 384 * 1024)
        make_artifact(base / "rootfs.img", f"{profile}:osimage", 256 * 1024)
        os.chmod(base, 0o755)
        for artifact in base.iterdir():
            os.chmod(artifact, 0o644)
    seed_dnsmasq_wiring_artifacts()
    # Readable and integrity-listed, but deliberately absent from every release.
    raw_bootstrap = TFTP_ROOT / UNMANAGED_BOOTSTRAP
    make_artifact(raw_bootstrap, "unmanaged:must-not-be-served", 8 * 1024)
    os.chmod(raw_bootstrap, 0o644)
    write_integrity_manifest()
    print(f"Seeded demo artifacts under {TFTP_ROOT}", flush=True)


def write_integrity_manifest():
    TFTP_ROOT.mkdir(parents=True, exist_ok=True)
    entries = []
    manifest_path = TFTP_ROOT / "manifest.json"
    for path in sorted(TFTP_ROOT.rglob("*")):
        if not path.is_file() or path == manifest_path:
            continue
        relative = path.relative_to(TFTP_ROOT).as_posix()
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(256 * 1024), b""):
                digest.update(chunk)
        entries.append({"path": relative, "sha256": digest.hexdigest(), "size": path.stat().st_size})
    manifest = {
        "entries": entries,
        "signature": None,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    os.chmod(manifest_path, 0o644)
    print(f"Wrote integrity manifest with {len(entries)} entries to {manifest_path}", flush=True)


def request(method, path, payload=None, expected=(200,)):
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(f"{API}{path}", data=body, method=method)
    req.add_header("x-api-key", API_KEY)
    if body is not None:
        req.add_header("content-type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            data = response.read().decode()
            if response.status not in expected:
                raise RuntimeError(f"unexpected HTTP {response.status}: {data}")
            return response.status, data
    except urllib.error.HTTPError as exc:
        data = exc.read().decode()
        if exc.code not in expected:
            raise RuntimeError(f"unexpected HTTP {exc.code}: {data}") from exc
        return exc.code, data


def wait_ready(timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, _ = request("GET", "/ready", expected=(200, 503))
            if status == 200:
                print("Tempest readiness check passed", flush=True)
                return
        except Exception:
            pass
        time.sleep(1)
    raise SystemExit("Tempest did not become ready in time")


def wait_for_active_transfer(process, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        exit_code = process.poll()
        if exit_code is not None:
            raise SystemExit(
                f"slow TFTP client exited before its transfer became active: {exit_code}"
            )
        try:
            _, data = request("GET", "/api/v1/transfers/active", expected=(200,))
            count = json.loads(data).get("count")
            if isinstance(count, int) and count > 0:
                print("Observed the pinned release-v1 transfer", flush=True)
                return
        except (OSError, RuntimeError, ValueError, json.JSONDecodeError):
            pass
        time.sleep(0.1)
    raise SystemExit("slow TFTP transfer did not become active in time")


def deploy(release, timeout_ms, boot_profile="default", group_id=None, extra_files=None):
    files = [
        {"name": "pxelinux.0", "path": f"/tftpboot/releases/{release}/pxelinux.0"},
        {"name": "boot.efi", "path": f"/tftpboot/releases/{release}/boot.efi"},
        {"name": "vmlinuz", "path": f"/tftpboot/releases/{release}/vmlinuz"},
        {"name": "initrd.img", "path": f"/tftpboot/releases/{release}/initrd.img"},
        {"name": "rootfs.img", "path": f"/tftpboot/releases/{release}/rootfs.img"},
    ]
    files.extend(extra_files or [])
    return request(
        "POST",
        "/api/v1/versions/switch",
        {
            "boot_profile": boot_profile,
            "group_id": group_id or f"release-{release}",
            "files": files,
            "drain_timeout_ms": timeout_ms,
        },
        expected=(200, 409),
    )


def register_session(
    boot_profile,
    trace_id,
    new_epoch=False,
    expected=(201,),
    client_ip=DEMO_CLIENT_IP,
    client_mac="aa:bb:cc:dd:ee:ff",
    serial=None,
):
    return request(
        "POST",
        "/api/v1/sessions",
        {
            "client_ip": client_ip,
            "client_mac": client_mac,
            "serial": serial or f"DEMO-{boot_profile.upper()}",
            "boot_profile": boot_profile,
            "trace_id": trace_id,
            "ttl_seconds": 900,
            "new_epoch": new_epoch,
        },
        expected=expected,
    )


def register_wired_session(wiring, new_epoch=False, expected=(201,)):
    print(
        "Registering session from dnsmasq wiring: "
        f"{wiring['description']}; client_ip={DEMO_CLIENT_IP}; "
        f"boot_profile={wiring['boot_profile']}; option67={wiring['option67']}",
        flush=True,
    )
    return request(
        "POST",
        "/api/v1/sessions",
        {
            "client_ip": DEMO_CLIENT_IP,
            "client_mac": wiring["client_mac"],
            "serial": wiring["serial"],
            "boot_profile": wiring["boot_profile"],
            "trace_id": wiring["trace_id"],
            "ttl_seconds": 900,
            "new_epoch": new_epoch,
        },
        expected=expected,
    )


def artifact_token_from_registration(data):
    response = json.loads(data)
    token = response.get("artifact_token")
    if not isinstance(token, str) or not token:
        raise SystemExit("session registration did not return an artifact token")
    return token


def client_args(
    filename,
    output,
    marker,
    ack_delay_ms=0,
    server="tempest",
    address_family="ipv4",
):
    return [
        *compose_cmd(),
        "run",
        "--rm",
        "--no-deps",
        "client",
        "--server",
        server,
        "--port",
        "6969",
        "--file",
        filename,
        "--output",
        f"/downloads/{output}",
        "--blksize",
        "512",
        "--trace-id",
        f"demo-{safe_trace_id(filename)}",
        "--address-family",
        address_family,
        "--expect-marker",
        marker,
        "--ack-delay-ms",
        str(ack_delay_ms),
    ]


def download(
    filename,
    output,
    marker,
    ack_delay_ms=0,
    server="tempest",
    address_family="ipv4",
):
    run(
        client_args(
            filename,
            output,
            marker,
            ack_delay_ms,
            server,
            address_family,
        )
    )


def validate_default_manifest_only():
    # This lane runs before any session registration, against a fresh database.
    _, metrics = request("GET", "/metrics")
    if "tempest_active_boot_sessions_total 0" not in metrics.splitlines():
        raise SystemExit("default bootstrap regression requires no active boot sessions")
    _, data = request("GET", "/api/v1/versions/groups")
    groups = json.loads(data)["items"]
    default_group = next(
        group for group in groups
        if group["boot_profile"] == "default" and group["group_id"] == "release-v1"
    )
    names = {artifact["name"] for artifact in default_group["files"]}
    if UNMANAGED_BOOTSTRAP in names or "pxelinux.0" not in names:
        raise SystemExit("default manifest does not match bootstrap regression fixtures")
    # Check as the server's runtime user: a missing/unreadable fixture must not
    # turn this authorization regression into a false positive.
    run([
        "podman", "exec", "tempest-demo", "sh", "-c",
        f"test -f /tftpboot/{UNMANAGED_BOOTSTRAP} && test -r /tftpboot/{UNMANAGED_BOOTSTRAP}",
    ])
    run([
        *compose_cmd(), "run", "--rm", "--no-deps", "client",
        "--file", UNMANAGED_BOOTSTRAP,
        "--output", "/downloads/unmanaged-bootstrap-denied.bin",
        "--expect-tftp-error", "1",
    ])
    download("pxelinux.0", "pxelinux-v1.bin", "release-v1:pxe")
    if (DOWNLOADS / "pxelinux-v1.bin").read_bytes() != (
        TFTP_ROOT / "releases" / "v1" / "pxelinux.0"
    ).read_bytes():
        raise SystemExit("default managed bootstrap bytes differ from release-v1")
    print(
        "Validated no-session TFTP: readable raw root file denied outside default manifest; "
        "managed default bootstrap succeeded with exact release-v1 bytes",
        flush=True,
    )


def http_client_args(
    filename,
    output,
    marker,
    artifact_token,
    base_url=IPV4_API,
):
    quoted = urllib.parse.quote(filename, safe="/")
    return [
        *compose_cmd(),
        "run",
        "--rm",
        "--no-deps",
        "--env",
        f"TEMPEST_ARTIFACT_TOKEN={artifact_token}",
        "client",
        "--http-url",
        f"{base_url}/api/v1/artifacts/{quoted}",
        "--output",
        f"/downloads/{output}",
        "--expect-marker",
        marker,
    ]


def http_download(
    filename,
    output,
    marker,
    artifact_token,
    base_url=IPV4_API,
):
    run(
        http_client_args(filename, output, marker, artifact_token, base_url),
        redactions=(artifact_token,),
    )


def native_http_download(output, marker, base_url=IPV4_API):
    run(
        [
            *compose_cmd(),
            "run",
            "--rm",
            "--no-deps",
            "client",
            "--http-url",
            f"{base_url}/boot/v1/boot.efi",
            "--output",
            f"/downloads/{output}",
            "--expect-marker",
            marker,
        ]
    )


def wait_ipv6_ready(timeout=60):
    probe = [
        *compose_cmd(),
        "run",
        "--rm",
        "--no-deps",
        "client",
        "--http-url",
        f"{IPV6_API}/ready",
        "--output",
        "/downloads/ipv6-ready.txt",
        "--expect-marker",
        "READY",
    ]
    print(f"Waiting for Tempest IPv6 readiness on [{DEMO_TEMPEST_IPV6}]:8080", flush=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = subprocess.run(
            probe,
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            print("Tempest IPv6 readiness check passed", flush=True)
            return
        time.sleep(1)
    raise SystemExit("Tempest IPv6 service did not become ready in time")


def validate_ipv6_flow():
    _, data = register_session(
        "ubuntu-focal",
        "ipv6-focal-boot",
        client_ip=DEMO_CLIENT_IPV6,
        client_mac="aa:bb:cc:dd:ee:66",
        serial="DEMO-IPV6-FOCAL",
    )
    artifact_token = artifact_token_from_registration(data)

    run([*compose_cmd(), "up", "-d", "tempest-ipv6"])
    wait_ipv6_ready()

    download(
        "vmlinuz",
        "vmlinuz-focal-ipv6-tftp.bin",
        "ubuntu-focal:kernel",
        server=DEMO_TEMPEST_IPV6,
        address_family="ipv6",
    )
    http_download(
        "initrd.img",
        "initrd-focal-ipv6-http.img",
        "ubuntu-focal:initrd",
        artifact_token,
        base_url=IPV6_API,
    )
    native_http_download(
        "focal-ipv6-native-boot.efi",
        "ubuntu-focal:native-efi",
        base_url=IPV6_API,
    )

    print("Restarting the IPv6 service to verify durable IPv6 session recovery", flush=True)
    run([*compose_cmd(), "restart", "tempest-ipv6"])
    wait_ipv6_ready()
    native_http_download(
        "focal-ipv6-after-restart-native-boot.efi",
        "ubuntu-focal:native-efi",
        base_url=IPV6_API,
    )
    print(
        "Validated IPv6 TFTP, bearer HTTP, native source-IP HTTP Boot, and session recovery",
        flush=True,
    )


def metrics_summary():
    _, metrics = request("GET", "/metrics", expected=(200,))
    interesting = []
    prefixes = (
        "tempest_transfers_total",
        "tempest_transfers_by_profile_total",
        "tempest_transfers_by_transport_total",
        "tempest_transfers_by_transport_phase_total",
        "tempest_transfers_by_profile_transport_total",
        "tempest_transfer_bytes_total",
        "tempest_transfer_bytes_by_profile_total",
        "tempest_transfer_bytes_by_transport_total",
        "tempest_transfer_bytes_by_transport_phase_total",
        "tempest_transfer_bytes_by_profile_transport_total",
        "tempest_version_groups_total",
        "tempest_version_groups_by_profile",
        "tempest_active_versions",
        "tempest_active_versions_by_profile",
        "tempest_active_boot_sessions",
        "tempest_admission_",
    )
    for line in metrics.splitlines():
        if line.startswith(prefixes):
            interesting.append(line)
    print("\nMetrics summary:")
    print("\n".join(interesting), flush=True)


def up():
    preflight()
    seed()
    build_binary()
    run([*compose_cmd(), "up", "-d", "--build", "postgres", "tempest"])
    wait_ready()


def observe():
    up()
    env, grafana_port = grafana_observe_env()
    run([*compose_cmd(), "up", "-d", "prometheus", "grafana"], env=env)
    print("Prometheus: http://localhost:9090", flush=True)
    print(f"Grafana:    http://localhost:{grafana_port} (admin/tempest)", flush=True)


def down(volumes=False, ignore_errors=False):
    cmd = [*compose_cmd(), "down"]
    if volumes:
        cmd.append("-v")
    if ignore_errors:
        result = run_optional(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        result = run(cmd)
    if ignore_errors and result.returncode != 0:
        print("compose down did not complete cleanly; continuing", flush=True)


def check_python_syntax(paths):
    for source_path in paths:
        source = source_path.read_text()
        compile(source, str(source_path), "exec")


def check_grafana_dashboard():
    dashboard_path = ROOT.parent.parent / "grafana" / "tempest-dashboard.json"
    salt_path = (
        ROOT.parent.parent
        / "salt"
        / "tempest"
        / "files"
        / "grafana"
        / "dashboards"
        / "tempest-dashboard.json"
    )
    with open(dashboard_path) as dashboard_file:
        dashboard = json.load(dashboard_file)
    with open(salt_path) as salt_file:
        salt_dashboard = json.load(salt_file)
    if dashboard != salt_dashboard:
        raise SystemExit("Grafana dashboard and Salt-managed copy differ")

    panels = {panel.get("title"): panel for panel in dashboard.get("panels", [])}
    required_panels = {
        "HTTP Transfer Rate by Authorization Mode": ("HTTP_NATIVE", "transfers"),
        "HTTP Byte Throughput by Authorization Mode": ("HTTP_NATIVE", "bytes"),
        "Native HTTP Boot Transfer Rate by Profile": ("HTTP_NATIVE", "boot_profile"),
        "Native HTTP Boot Failure Ratio": ("HTTP_NATIVE", "failures"),
    }
    for title, fragments in required_panels.items():
        panel = panels.get(title)
        expressions = (
            " ".join(target.get("expr", "") for target in panel.get("targets", []))
            if panel
            else ""
        )
        if not all(fragment in expressions for fragment in fragments):
            raise SystemExit(f"Grafana panel is missing or incomplete: {title}")


def check():
    preflight()
    check_python_syntax([ROOT / "demo.py", *sorted((ROOT / "client").glob("*.py"))])
    run([
        "python3", "-B", "-m", "unittest", "discover",
        "-s", str(ROOT / "client"), "-p", "test_*.py",
    ])
    check_grafana_dashboard()
    run([*compose_cmd(), "config"], stdout=subprocess.DEVNULL)
    print("Demo preflight passed", flush=True)


def demo_run():
    preflight()
    down(volumes=True, ignore_errors=True)
    seed()
    build_binary()
    run([*compose_cmd(), "up", "-d", "--build", "postgres", "tempest"])
    wait_ready()
    status, data = deploy("v1", 30000)
    if status != 200:
        raise SystemExit(f"initial v1 deploy failed: {data}")
    print("Deployed release-v1", flush=True)

    validate_default_manifest_only()
    download("vmlinuz", "vmlinuz-v1.bin", "release-v1:kernel")
    download("initrd.img", "initrd-v1.img", "release-v1:initrd")

    slow = subprocess.Popen(
        client_args("rootfs.img", "rootfs-v1.img", "release-v1:osimage", 15),
        cwd=ROOT,
        text=True,
    )
    try:
        wait_for_active_transfer(slow)
        status, data = deploy("v2", 500)
        if status != 409:
            raise SystemExit(
                "expected cutover timeout while v1 rootfs was pinned, "
                f"got {status}: {data}"
            )
        print(
            "Drain-gated cutover blocked release-v2 while release-v1 rootfs was pinned",
            flush=True,
        )

        if slow.wait(timeout=60) != 0:
            raise SystemExit("slow rootfs download failed")
    finally:
        if slow.poll() is None:
            slow.terminate()
            try:
                slow.wait(timeout=5)
            except subprocess.TimeoutExpired:
                slow.kill()
                slow.wait(timeout=5)

    status, data = deploy("v2", 30000)
    if status != 200:
        raise SystemExit(f"v2 deploy after drain failed: {data}")
    print("Deployed release-v2 after old pins drained", flush=True)

    download("vmlinuz", "vmlinuz-v2.bin", "release-v2:kernel")

    focal_wiring = DEMO_DNSMASQ_WIRING["focal-bios-pre-ipxe"]
    rhel9_wiring = DEMO_DNSMASQ_WIRING["rhel9-efi"]
    status, data = deploy(
        "ubuntu-focal",
        30000,
        boot_profile="ubuntu-focal",
        group_id="ubuntu-focal-2026-06-14",
        extra_files=[
            {
                "name": focal_wiring["option67"],
                "path": f"/tftpboot/{focal_wiring['option67']}",
            }
        ],
    )
    if status != 200:
        raise SystemExit(f"ubuntu-focal deploy failed: {data}")
    status, data = deploy(
        "rhel9",
        30000,
        boot_profile="rhel9",
        group_id="rhel9-2026-06-14",
        extra_files=[
            {
                "name": rhel9_wiring["option67"],
                "path": f"/tftpboot/{rhel9_wiring['option67']}",
            }
        ],
    )
    if status != 200:
        raise SystemExit(f"rhel9 deploy failed: {data}")
    print("Deployed ubuntu-focal and rhel9 profiles with the same logical names", flush=True)

    _, data = register_wired_session(focal_wiring)
    artifact_token = artifact_token_from_registration(data)
    native_http_download("focal-native-boot.efi", "ubuntu-focal:native-efi")
    download(
        focal_wiring["option67"],
        "focal-option67.bin",
        focal_wiring["option67_marker"],
    )
    download("vmlinuz", "vmlinuz-focal-tftp.bin", "ubuntu-focal:kernel")
    http_download(
        "initrd.img",
        "initrd-focal-http.img",
        "ubuntu-focal:initrd",
        artifact_token,
    )
    validate_ipv6_flow()

    status, data = register_wired_session(rhel9_wiring, expected=(409,))
    if status != 409:
        raise SystemExit(f"expected pinned-session profile change conflict, got {status}: {data}")
    print("Pinned Focal session rejected RHEL profile change until a new PXE epoch", flush=True)

    _, data = register_wired_session(rhel9_wiring, new_epoch=True)
    artifact_token = artifact_token_from_registration(data)
    native_http_download("rhel9-native-boot.efi", "rhel9:native-efi")
    download(
        rhel9_wiring["option67"],
        "rhel9-option67.bin",
        rhel9_wiring["option67_marker"],
    )
    http_download("vmlinuz", "vmlinuz-rhel9-http.bin", "rhel9:kernel", artifact_token)

    print("Restarting Tempest to verify profile/version recovery from Postgres", flush=True)
    run([*compose_cmd(), "restart", "tempest"])
    wait_ready()

    _, groups_json = request("GET", "/api/v1/versions/groups", expected=(200,))
    groups_page = json.loads(groups_json)
    groups = groups_page.get("items") if isinstance(groups_page, dict) else None
    if not isinstance(groups, list):
        raise SystemExit("version group response did not contain a paginated items list")
    recovered_profiles = {group["boot_profile"] for group in groups}
    expected_profiles = {"default", "ubuntu-focal", "rhel9"}
    if not expected_profiles.issubset(recovered_profiles):
        raise SystemExit(
            f"persistent recovery missing profiles: expected {expected_profiles}, got {recovered_profiles}"
        )
    print("Recovered default, ubuntu-focal, and rhel9 version groups after restart", flush=True)

    _, data = register_wired_session(focal_wiring, new_epoch=True)
    artifact_token = artifact_token_from_registration(data)
    native_http_download(
        "focal-after-restart-native-boot.efi",
        "ubuntu-focal:native-efi",
    )
    http_download(
        "vmlinuz",
        "vmlinuz-focal-after-restart-http.bin",
        "ubuntu-focal:kernel",
        artifact_token,
    )

    metrics_summary()
    print("\nEnd-to-end L2 demo completed successfully.", flush=True)


def ipv6_demo_run():
    preflight()
    down(volumes=True, ignore_errors=True)
    seed()
    build_binary()
    run([*compose_cmd(), "up", "-d", "--build", "postgres", "tempest"])
    wait_ready()

    focal_wiring = DEMO_DNSMASQ_WIRING["focal-bios-pre-ipxe"]
    status, data = deploy(
        "ubuntu-focal",
        30000,
        boot_profile="ubuntu-focal",
        group_id="ubuntu-focal-2026-06-14",
        extra_files=[
            {
                "name": focal_wiring["option67"],
                "path": f"/tftpboot/{focal_wiring['option67']}",
            }
        ],
    )
    if status != 200:
        raise SystemExit(f"ubuntu-focal deploy failed: {data}")

    validate_ipv6_flow()
    print("\nDedicated IPv6 validation completed successfully.", flush=True)


def clean():
    # Some podman-compose releases stop processing `down -v` when an optional
    # service was never created. Stop the running services first, then remove
    # the project volumes in a separate best-effort pass.
    down(ignore_errors=True)
    down(volumes=True, ignore_errors=True)
    for path in (TFTP_ROOT, DOWNLOADS, BUILD):
        shutil.rmtree(path, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Tempest L2 flat-network demo harness")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("seed")
    sub.add_parser("manifest")
    sub.add_parser("check")
    sub.add_parser("up")
    sub.add_parser("observe")
    sub.add_parser("run")
    sub.add_parser("ipv6")
    sub.add_parser("down")
    sub.add_parser("clean")
    args = parser.parse_args()

    if args.cmd == "seed":
        seed()
    elif args.cmd == "manifest":
        write_integrity_manifest()
    elif args.cmd == "check":
        check()
    elif args.cmd == "up":
        up()
    elif args.cmd == "observe":
        observe()
    elif args.cmd == "run":
        demo_run()
    elif args.cmd == "ipv6":
        ipv6_demo_run()
    elif args.cmd == "down":
        down()
    elif args.cmd == "clean":
        clean()


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.returncode)
