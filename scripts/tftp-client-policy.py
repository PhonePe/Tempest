#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Compare local Tempest binaries using synthetic TFTP in a private Linux netns.

Python 3.10+ standard library only. No target host/port or host-network fallback.
Run as an unprivileged user; --output must name a new directory.
"""

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request


LISTENER = ("127.0.0.1", 16969)
API = "http://127.0.0.1:18081"
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
NEW_FIELDS = {"max_tftp_transfers_per_ip", "max_client_timeout_secs"}
SMALL = b"synthetic managed policy fixture\n"
LARGE = b"L" * 32768
CANCEL = b"\x00\x05\x00\x00synthetic client cancellation\x00"
QUOTA_ERROR = b"\x00\x05\x00\x00Client transfer limit reached\x00"
DEADLINE_ERROR = b"\x00\x05\x00\x00Transfer time limit exceeded\x00"
LOG_LIMIT = 1024 * 1024
CASES = ("timeout_at_ceiling", "timeout_above_ceiling", "per_ip_quota",
         "silent_oack", "silent_data", "progressing_ack")


class SetupError(RuntimeError):
    """An invalid experiment, never evidence of a policy failure."""


class PolicyFailure(AssertionError):
    """An observed wire/cleanup mismatch after successful setup."""


def require(condition, message):
    if not condition:
        raise PolicyFailure(message)


def pause(seconds):
    select.select([], [], [], max(0, seconds))


def digest(file_path):
    value = hashlib.sha256()
    with file_path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def write_json(file_path, value):
    file_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def child_limits():
    # The server reserves 1024 descriptors in addition to its transfer slots.
    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    ceiling = 2048 if hard == resource.RLIM_INFINITY else min(2048, hard)
    resource.setrlimit(resource.RLIMIT_NOFILE, (ceiling, ceiling))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (LOG_LIMIT, LOG_LIMIT))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))


def stop_process(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=1)


def environment(directory):
    # Do not inherit production secrets, proxy settings, config or logging knobs.
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": str(directory),
            "LANG": "C.UTF-8", "TOKIO_WORKER_THREADS": "2"}


def command(argv, log_path, seconds=3):
    """Bounded file-backed output, no unbounded communicate()/PIPE buffers."""
    with log_path.open("wb") as log:
        proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, cwd=log_path.parent,
                                env=environment(log_path.parent), preexec_fn=child_limits)
        try:
            try:
                code = proc.wait(timeout=seconds)
            except subprocess.TimeoutExpired as error:
                raise SetupError(f"command timed out: {log_path.name}") from error
        finally:
            stop_process(proc)
    return code, log_path.read_bytes()[:LOG_LIMIT].decode("utf-8", "replace")


def unsupported_field(output):
    # Match the diagnostic, not a field appearing in an expected-fields list.
    fields = re.findall(r"unknown field `([^`]+)`", output)
    if len(fields) == 1 and fields[0] in NEW_FIELDS:
        return fields[0]
    return None


def policy_scalars(rendered):
    """Read only integer/bool server scalars, not a general-purpose TOML parser."""
    values, section = {}, None
    for line in rendered.splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line
        elif section == "[server]":
            match = re.fullmatch(r"([a-z_]+)\s*=\s*([0-9]+|true|false)\s*(?:#.*)?", line)
            if match:
                key, value = match.groups()
                if key in values:
                    raise SetupError(f"duplicate effective setting: {key}")
                values[key] = {"true": True, "false": False}.get(value, value)
                if value.isdigit():
                    values[key] = int(value)
    return values


def settings(case):
    return {
        "bind": LISTENER[0], "port": LISTENER[1], "listener_shards": 1,
        "max_concurrent_transfers": 4, "max_tftp_transfers_per_ip": 2,
        "max_client_timeout_secs": 5 if case.startswith("timeout_") else 255,
        "max_transfer_duration_secs": (4 if case == "progressing_ack" else
                                       3 if case.startswith("silent_") else 15),
        "accept_client_timeout": True, "default_block_size": 512,
        "max_window_size": 1, "max_retries": 5,
        "retransmit_interval_ms": 500, "min_retransmit_interval_ms": 500,
        "max_retransmit_interval_ms": 1000,
        "tftp_requests_per_ip_per_second": 100,
        "http_requests_per_ip_per_second": 100,
        "listener_receive_buffer_bytes": 262144, "transfer_socket_buffer_bytes": 0,
        "log_level": "warn",
    }


def render_config(server):
    lines = ["boot_phases = []", "[server]"]
    lines.extend(f"{key} = {json.dumps(value)}" for key, value in server.items())
    lines.extend(["[api]", 'bind = "127.0.0.1"', "port = 18081",
                  "max_connections = 16", "allow_insecure_loopback = true",
                  "enable_versions_api = true", "enable_metrics = true",
                  "[audit]", "enabled = false", "[persistence]", "enabled = false"])
    return "\n".join(lines) + "\n"


def api(method, route, body=None):
    request = urllib.request.Request(
        API + route, method=method,
        data=None if body is None else json.dumps(body).encode(),
        headers={"content-type": "application/json"})
    try:
        with HTTP.open(request, timeout=0.5) as response:
            data = response.read(65537)
        if len(data) > 65536:
            raise ValueError("oversized API response")
        return json.loads(data)
    except (OSError, ValueError, urllib.error.URLError) as error:
        raise SetupError(f"isolated API failed: {route}: {error}") from error


def active():
    value = api("GET", "/api/v1/transfers/active")
    if not isinstance(value, dict) or type(value.get("count")) is not int:
        raise SetupError("invalid active-transfer response")
    return value["count"]


def wait_count(expected, seconds=0.8):
    end = time.monotonic() + seconds
    for _ in range(24):
        value = active()
        if value == expected or time.monotonic() >= end:
            return value
        pause(0.04)
    return value


class Server:
    def __init__(self, binary, directory, case, role, row):
        self.binary, self.directory, self.case = binary, directory, case
        self.role, self.row, self.proc, self.log = role, row, None, None

    def __enter__(self):
        try:
            self.start()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def start(self):
        self.directory.mkdir()
        root = self.directory / "artifacts"
        root.mkdir()
        for name, payload in (("small.bin", SMALL), ("next.bin", SMALL), ("large.bin", LARGE)):
            (root / name).write_bytes(payload)
        config = self.directory / "synthetic.toml"
        requested = {**settings(self.case), "root": str(root)}
        actual = dict(requested)
        self.row.update(requested_server_settings=requested, omitted_fields=[])
        for attempt in range(3):
            config.write_text(render_config(actual))
            config.chmod(0o600)
            code, text = command([str(self.binary), "--config", str(config), "--check-config"],
                                 self.directory / f"config-check-{attempt}.log")
            if code == 0:
                break
            field = unsupported_field(text)
            if self.role != "before" or field is None or field not in actual:
                raise SetupError("configuration rejected; see config-check log")
            self.row["omitted_fields"].append({"field": field, "requested": actual.pop(field),
                                               "reason": f"unknown field `{field}`"})
        else:
            raise SetupError("configuration still rejected after allowed omissions")
        self.row["configured_server_settings"] = actual
        code, effective = command(
            [str(self.binary), "--config", str(config), "--print-effective-config"],
            self.directory / "effective-config.toml")
        if code:
            raise SetupError("cannot obtain effective synthetic config")
        scalars = policy_scalars(effective)
        for key, value in actual.items():
            if isinstance(value, (int, bool)) and scalars.get(key) != value:
                raise SetupError(f"effective setting mismatch: {key}")
        self.row["effective_server_scalars"] = scalars
        self.row["effective_config_file"] = f"{self.role}/{self.case}/effective-config.toml"
        self.log = (self.directory / "server.log").open("wb")
        # All descendants remain in the worker's dedicated process group. The
        # outer supervisor always kills that group, even on failed startup.
        self.proc = subprocess.Popen(
            [str(self.binary), "--config", str(config)], stdout=self.log,
            stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, cwd=self.directory,
            env=environment(self.directory), preexec_fn=child_limits)
        end = time.monotonic() + 3
        for _ in range(40):
            self.alive()
            try:
                with HTTP.open(API + "/ready", timeout=0.15) as response:
                    if response.status == 200:
                        break
            except (OSError, urllib.error.URLError):
                pass
            if time.monotonic() >= end:
                raise SetupError("server readiness timed out")
            pause(0.05)
        else:
            raise SetupError("server readiness timed out")
        api("POST", "/api/v1/versions/switch", {
            "boot_profile": "default", "group_id": "synthetic-policy-release",
            "files": [{"name": name, "path": str(root / name)}
                      for name in ("small.bin", "next.bin", "large.bin")],
        })
        # Failure here is fixture/setup incompatibility, not baseline evidence.
        try:
            with client("127.0.0.3") as sock:
                download(sock)
            require(wait_count(0) == 0, "preflight transfer did not clean up")
        except PolicyFailure as error:
            raise SetupError(f"managed fixture preflight failed: {error}") from error
        self.row["setup_complete"] = True

    def alive(self):
        if self.proc.poll() is not None:
            raise SetupError("server exited unexpectedly; see server.log")

    def __exit__(self, *_):
        if self.proc is not None:
            stop_process(self.proc)
        if self.log is not None:
            self.log.close()


def client(ip="127.0.0.2"):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(0.8)
        sock.bind((ip, 0))
    except BaseException:
        sock.close()
        raise
    return sock


def rrq(name, timeout=None):
    fields = [name, "octet"]
    if timeout is not None:
        fields.extend(["timeout", str(timeout), "blksize", "512", "tsize", "0"])
    return b"\x00\x01" + b"\x00".join(value.encode("ascii") for value in fields) + b"\x00"


def ack(block):
    return struct.pack("!HH", 4, block)


def receive(sock, seconds=0.8, peer=None):
    sock.settimeout(max(0.001, seconds))
    try:
        data, source = sock.recvfrom(2048)
    except socket.timeout as error:
        raise PolicyFailure("no TFTP response within bounded observation") from error
    require(len(data) >= 4, "short TFTP response")
    require(source[0] == LISTENER[0], "response from unexpected server IP")
    if peer is not None:
        require(source == peer, "established transfer changed server IP/port")
    return data, source


def oack(data):
    require(data[:2] == b"\x00\x06" and data.endswith(b"\x00"), "expected terminated OACK")
    parts = data[2:-1].split(b"\x00")
    require(len(parts) % 2 == 0 and all(parts), "malformed OACK fields")
    try:
        pairs = [(parts[i].decode("ascii"), parts[i + 1].decode("ascii"))
                 for i in range(0, len(parts), 2)]
    except UnicodeDecodeError as error:
        raise PolicyFailure("non-ASCII OACK") from error
    require(len(dict(pairs)) == len(pairs), "duplicate OACK option")
    return dict(pairs)


def download(sock, name="small.bin"):
    sock.sendto(rrq(name), LISTENER)
    data, peer = receive(sock)
    require(peer != LISTENER, "DATA must use an ephemeral transfer TID")
    require(data == b"\x00\x03\x00\x01" + SMALL, "managed download bytes differ")
    sock.sendto(ack(1), peer)


def normalized_options(options):
    """An omitted blksize retains RFC 1350's requested default of 512."""
    return {"blksize": "512", **options}


def begin(sock, acknowledge=False):
    start = time.monotonic()
    sock.sendto(rrq("large.bin", 255), LISTENER)
    data, peer = receive(sock)
    require(peer != LISTENER, "OACK must use an ephemeral transfer TID")
    options = oack(data)
    require(normalized_options(options) == {"timeout": "255", "blksize": "512", "tsize": str(len(LARGE))},
            f"holder timeout must be accepted exactly: {options}")
    if acknowledge:
        sock.sendto(ack(0), peer)
        data, _ = receive(sock, peer=peer)
        require(data == b"\x00\x03\x00\x01" + LARGE[:512], "missing initial DATA(1)")
    return peer, start


def check(row, name, passed, **evidence):
    row["checks"].append({"name": name, "passed": bool(passed), **evidence})


def timeout_case(row, requested):
    with client() as sock:
        sock.sendto(rrq("small.bin", requested), LISTENER)
        data, peer = receive(sock)
        require(peer != LISTENER, "OACK must use transfer TID")
        options = oack(data)
        expected = {"blksize": "512", "tsize": str(len(SMALL))}
        if requested == 5:
            expected["timeout"] = "5"
        check(row, "exact_partial_negotiation", normalized_options(options) == expected,
              requested_timeout=requested, expected=expected, observed=options)
        sock.sendto(ack(0), peer)
        data, _ = receive(sock, peer=peer)
        check(row, "managed_bytes_after_oack", data == b"\x00\x03\x00\x01" + SMALL)
        sock.sendto(ack(1), peer)
    check(row, "transfer_cleanup", wait_count(0) == 0)


def quota_case(row):
    with contextlib.ExitStack() as stack:
        holders = [stack.enter_context(client()) for _ in range(2)]
        peers = [begin(sock)[0] for sock in holders]
        require(wait_count(2) == 2, "two holders did not occupy two slots")
        third = stack.enter_context(client())
        ports = [sock.getsockname()[1] for sock in holders + [third]]
        require(len(set(ports)) == 3, "quota test needs three distinct source ports")
        third.sendto(rrq("large.bin", 255), LISTENER)
        data, peer = receive(third)
        check(row, "rotating_port_per_ip_rejection", data == QUOTA_ERROR and peer == LISTENER,
              source_ip="127.0.0.2", source_ports=ports, response_hex=data.hex(),
              response_peer=list(peer), active_after_probe=active())
        # On the baseline the third holder may be admitted. Keep it open during
        # the other-IP download: at most three holders plus one healthy transfer.
        with client("127.0.0.3") as healthy:
            download(healthy)
        check(row, "other_ip_managed_download", True, source_ip="127.0.0.3")
        if data[:2] in (b"\x00\x06", b"\x00\x03") and peer != LISTENER:
            third.sendto(CANCEL, peer)
        require(wait_count(2) == 2, "probe/healthy transfers did not release slots")
        holders[0].sendto(CANCEL, peers[0])
        check(row, "client_error_releases_one_slot", wait_count(1) == 1)
        # Same socket/IP/port, DIFFERENT logical artifact; one other holder stays.
        download(holders[0], "next.bin")
        check(row, "same_endpoint_next_artifact", True, endpoint=list(holders[0].getsockname()))
        require(wait_count(1) == 1, "readmitted download did not release its slot")
        holders[1].sendto(CANCEL, peers[1])
        check(row, "all_slots_released", wait_count(0) == 0)


def lifetime_case(row, case):
    lifetime = settings(case)["max_transfer_duration_secs"]
    progress = case == "progressing_ack"
    with client() as sock:
        peer, start = begin(sock, acknowledge=case != "silent_oack")
        require(wait_count(1) == 1, "lifetime holder did not occupy a slot")
        end, next_ack = start + lifetime + 0.8, start + 0.7
        block, advances, terminal = 1, [], None
        awaiting_data = False
        for _ in range(32):
            now = time.monotonic()
            if now >= end:
                break
            wake = min(end, next_ack) if progress and not awaiting_data else end
            ready, _, _ = select.select([sock], [], [], max(0, wake - now))
            if ready:
                data, _ = receive(sock, peer=peer)
                elapsed = time.monotonic() - start
                if data[:2] == b"\x00\x05":
                    terminal = {"elapsed_seconds": round(elapsed, 4), "response_hex": data.hex()}
                    check(row, "absolute_deadline_packet", data == DEADLINE_ERROR and
                          lifetime - 0.15 <= elapsed <= lifetime + 0.8, **terminal)
                    break
                require(progress and awaiting_data, "unexpected early retransmission at timeout=255")
                require(data == struct.pack("!HH", 3, block) + b"L" * 512,
                        "advancing ACK did not produce next exact DATA block")
                advances.append(round(elapsed, 4))
                awaiting_data = False
            elif progress and not awaiting_data and time.monotonic() < end:
                sock.sendto(ack(block), peer)
                block += 1
                awaiting_data = True
                next_ack = time.monotonic() + 0.7
        if terminal is None:
            check(row, "absolute_deadline_packet", False,
                  observation_seconds=round(time.monotonic() - start, 4),
                  reason="no terminal packet inside finite lifetime observation")
        if progress:
            check(row, "slow_ack_forward_progress", len(advances) >= 4,
                  data_advance_times_seconds=advances, ack_interval_seconds=0.7)
        count = wait_count(0)
        check(row, "expiry_releases_slot_without_client_cancel", count == 0, active=count)
        if count:
            sock.sendto(CANCEL, peer)
            require(wait_count(0) == 0, "failed-lifetime holder could not be cancelled")
        download(sock, "next.bin")
        check(row, "same_endpoint_recovery", True,
              recovery_after="expiry" if count == 0 else "explicit_cleanup_after_failed_expiry")
        check(row, "recovery_cleanup", wait_count(0) == 0)


def comparison_ok(report):
    for role in ("before", "after"):
        rows = report[role]["scenarios"]
        if [row["name"] for row in rows] != list(CASES):
            return False
        if any(not row.get("setup_complete") or row["status"] == "ERROR" for row in rows):
            return False
    return all(row["status"] == "PASS" for row in report["after"]["scenarios"])


def verify_namespace(net_fd, user_fd):
    current = os.stat("/proc/self/ns/net")
    original = os.fstat(net_fd)
    if (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino):
        raise SetupError("refusing original network namespace")
    current_user, original_user = os.stat("/proc/self/ns/user"), os.fstat(user_fd)
    if (current_user.st_dev, current_user.st_ino) == (original_user.st_dev, original_user.st_ino):
        raise SetupError("refusing original user namespace")
    mapping = Path("/proc/self/uid_map").read_text().split()
    if len(mapping) != 3 or mapping[0] != "0" or mapping[1] == "0" or mapping[2] != "1":
        raise SetupError("expected a single non-root invoking UID mapped to namespace root")
    if [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise SetupError("private namespace must contain only loopback")
    return {"parent_netns_inode": original.st_ino, "private_netns_inode": current.st_ino,
            "uid_map": " ".join(mapping), "interfaces": ["lo"]}


def worker(args):
    report = {"schema_version": 1, "clock": "real monotonic seconds; no virtual time",
              "limitations": ["scaled 3/4-second lifetime, not a 300-second soak",
                              "IPv4 RRQ only; no WRQ, IPv6, firmware or distributed-load claim",
                              "baseline FAIL is finite observed behavior, not infinite retention"],
              "fixtures": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                           for name, data in (("small.bin", SMALL), ("next.bin", SMALL),
                                              ("large.bin", LARGE))}}
    started = time.monotonic()
    try:
        report["isolation"] = verify_namespace(*args.worker_fds)
        for fd in args.worker_fds:
            os.close(fd)
        code, _ = command(["/usr/sbin/ip" if Path("/usr/sbin/ip").exists() else "/usr/bin/ip",
                           "link", "set", "lo", "up"], args.output / "loopback.log")
        if code:
            raise SetupError("cannot enable private loopback")
        for role, binary in (("before", args.before_binary), ("after", args.after_binary)):
            report[role] = {"binary_name": binary.name, "binary_sha256": digest(binary), "scenarios": []}
            (args.output / role).mkdir()
            for case in CASES:
                row = {"name": case, "checks": [], "setup_complete": False}
                report[role]["scenarios"].append(row)
                case_start = time.monotonic()
                try:
                    with Server(binary, args.output / role / case, case, role, row) as server:
                        try:
                            if case.startswith("timeout_"):
                                timeout_case(row, 5 if case == "timeout_at_ceiling" else 255)
                            elif case == "per_ip_quota":
                                quota_case(row)
                            else:
                                lifetime_case(row, case)
                        finally:
                            server.alive()
                    row["status"] = "PASS" if all(c["passed"] for c in row["checks"]) else "FAIL"
                except PolicyFailure as error:
                    row.update(status="FAIL", error=str(error))
                except Exception as error:
                    row.update(status="ERROR", error=f"{type(error).__name__}: {error}")
                row["seconds"] = round(time.monotonic() - case_start, 4)
                write_json(args.output / "results.json", report)
                print(f"{role:6} {case:23} {row['status']}", flush=True)
            if digest(binary) != report[role]["binary_sha256"]:
                raise SetupError(f"{role} binary changed during execution")
        report["comparison_passed"] = comparison_ok(report)
    except BaseException as error:
        report.update(comparison_passed=False, setup_error=f"{type(error).__name__}: {error}")
    report["seconds"] = round(time.monotonic() - started, 4)
    write_json(args.output / "results.json", report)
    return 0 if report["comparison_passed"] else 1


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--before-binary", type=Path, required=True, help="trusted local Linux baseline executable")
    result.add_argument("--after-binary", type=Path, required=True, help="trusted local Linux candidate executable")
    result.add_argument("--output", type=Path, required=True, help="new private results directory")
    result.add_argument("--worker-fds", type=int, nargs=2, help=argparse.SUPPRESS)
    return result


def interrupted(signum, _frame):
    raise SetupError(f"interrupted by signal {signum}")


def supervisor_error(output, error):
    result_path = output / "results.json"
    try:
        report = json.loads(result_path.read_text())
    except (OSError, ValueError):
        report = {}
    report.update(comparison_passed=False, supervisor_error=f"{type(error).__name__}: {error}")
    write_json(result_path, report)


def main():
    args = parser().parse_args()
    if sys.platform != "linux":
        raise SetupError("Linux is required; no host-network fallback is permitted")
    if args.worker_fds:
        signal.signal(signal.SIGALRM, interrupted)
        signal.alarm(80)
        return worker(args)
    if os.geteuid() == 0 or os.getuid() == 0:
        raise SetupError("do not run as root/sudo; log in as a non-root user who owns the "
                         "binary bundle and output parent, then run python3 normally; "
                         "do not loosen private bundle permissions")
    if not shutil.which("unshare") or not shutil.which("ip"):
        raise SetupError("install util-linux and iproute2; unprivileged user namespaces must be enabled")
    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard < 1044:
        raise SetupError("file-descriptor hard limit must be at least 1044 (2048 recommended)")
    for field in ("before_binary", "after_binary"):
        binary = getattr(args, field).resolve(strict=True)
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise SetupError(f"{field} must be an executable regular file")
        with binary.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                raise SetupError(f"{field} must be a Linux ELF binary")
        setattr(args, field, binary)
    args.output = args.output.resolve()
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    # Keep descriptors to the ACTUAL original namespaces across self-reexec;
    # never trust a user-supplied namespace-name string as the isolation check.
    with contextlib.ExitStack() as stack:
        fds = [stack.enter_context(open(f"/proc/self/ns/{kind}", "rb")) for kind in ("net", "user")]
        numbers = tuple(stream.fileno() for stream in fds)
        argv = [shutil.which("unshare"), "--user", "--map-root-user", "--net",
                sys.executable, str(Path(__file__).resolve()),
                "--before-binary", str(args.before_binary), "--after-binary", str(args.after_binary),
                "--output", str(args.output), "--worker-fds", *map(str, numbers)]
        proc = None
        failure = None
        try:
            with (args.output / "launcher.log").open("wb") as log:
                proc = subprocess.Popen(argv, pass_fds=numbers, start_new_session=True,
                                        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                        env=environment(args.output), preexec_fn=child_limits)
                # Parent CPU limit is per process; worker wall alarm is 80s.
                try:
                    code = proc.wait(timeout=88)
                except subprocess.TimeoutExpired as error:
                    raise SetupError("isolated suite exceeded 88-second wall budget") from error
        except BaseException as error:
            failure = error
            raise
        finally:
            if proc is not None:
                # Only our newly created process group; never pkill/name matching.
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=1)
            if failure is not None:
                # Write after reaping: a worker's final report cannot overwrite
                # the supervisor's timeout/interruption diagnosis.
                supervisor_error(args.output, failure)
        result_path = args.output / "results.json"
        if not result_path.exists():
            write_json(result_path, {"comparison_passed": False,
                                    "setup_error": "namespace launcher failed; see launcher.log"})
        report = json.loads(result_path.read_text())
        for role in ("before", "after"):
            for row in report.get(role, {}).get("scenarios", []):
                print(f"{role:6} {row['name']:23} {row['status']}")
        ok = code == 0 and report.get("comparison_passed", False)
        print(f"{'PASS' if ok else 'ERROR/FAIL'}: {result_path}")
        return 0 if ok else 1


if __name__ == "__main__":
    os.umask(0o077)
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    try:
        sys.exit(main())
    except (SetupError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)