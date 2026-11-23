# SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Offline harness tests; never start Tempest or contact a network service."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import types
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location(
    "client_policy", Path(__file__).with_name("tftp-client-policy.py"))
policy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(policy)


class PolicyHarnessTests(unittest.TestCase):
    def test_default_blksize_omission_preserves_wire_evidence(self):
        observed = {"timeout": "255", "tsize": "33"}
        self.assertEqual(policy.normalized_options(observed),
                         {"blksize": "512", **observed})
        self.assertNotIn("blksize", observed)
        self.assertEqual(policy.normalized_options({"blksize": "1024"}),
                         {"blksize": "1024"})

    def test_rrq_and_ack_wire_encoding(self):
        self.assertEqual(policy.rrq("small.bin"), b"\0\1small.bin\0octet\0")
        self.assertEqual(policy.ack(7), b"\0\4\0\7")
        self.assertEqual(policy.rrq("large.bin", 255),
                         b"\0\1large.bin\0octet\0timeout\0" + b"255\0blksize\0" +
                         b"512\0tsize\0" + b"0\0")

    def test_oack_is_strict_and_partial_negotiation_is_supported(self):
        self.assertEqual(policy.oack(b"\0\6blksize\x00512\0tsize\x0031\0"),
                         {"blksize": "512", "tsize": "31"})
        for packet in (b"\0\3\0\1", b"\0\6timeout\0", b"\0\6a\0b",
                       b"\0\6a\0b\0a\0c\0", b"\0\6a\0\xff\0"):
            with self.subTest(packet=packet), self.assertRaises(policy.PolicyFailure):
                policy.oack(packet)

    def test_omission_allowlist_only_matches_unknown_diagnostic(self):
        for field in policy.NEW_FIELDS:
            self.assertEqual(policy.unsupported_field(f"Error: unknown field `{field}`"), field)
        for message in (
            "unknown field `max_transfer_duration_secs`",
            "unknown field `unrelated`, expected `max_client_timeout_secs`",
            "max_client_timeout_secs must be nonzero",
            "expected `max_tftp_transfers_per_ip`",
            "unknown field `max_client_timeout_secs`; unknown field `unexpected`",
        ):
            with self.subTest(message=message):
                self.assertIsNone(policy.unsupported_field(message))

    def test_effective_scalars_are_section_scoped(self):
        rendered = """# diagnostic output
[server]
max_client_timeout_secs = 5
max_tftp_transfers_per_ip = 2 # synthetic
accept_client_timeout = true
root = "/synthetic"
[api]
max_client_timeout_secs = 99
"""
        self.assertEqual(policy.policy_scalars(rendered), {
            "max_client_timeout_secs": 5, "max_tftp_transfers_per_ip": 2,
            "accept_client_timeout": True})
        with self.assertRaises(policy.SetupError):
            policy.policy_scalars("[server]\nport = 1\nport = 2\n")

    def test_generated_profiles_have_only_intended_differences(self):
        profiles = [policy.settings(case) for case in policy.CASES]
        for profile in profiles:
            self.assertEqual(profile["max_concurrent_transfers"], 4)
            self.assertEqual(profile["max_tftp_transfers_per_ip"], 2)
            self.assertTrue(profile["accept_client_timeout"])
            rendered = policy.render_config(profile)
            self.assertIn('bind = "127.0.0.1"', rendered)
            self.assertIn("enable_versions_api = true", rendered)
            self.assertIn("[persistence]\nenabled = false", rendered)
        self.assertEqual([p["max_client_timeout_secs"] for p in profiles], [5, 5, 255, 255, 255, 255])
        self.assertEqual([p["max_transfer_duration_secs"] for p in profiles], [15, 15, 15, 3, 3, 4])

    def test_comparison_requires_full_baseline_and_green_candidate(self):
        def report():
            return {role: {"scenarios": [
                {"name": case, "setup_complete": True, "status": "PASS"}
                for case in policy.CASES]} for role in ("before", "after")}

        value = report()
        self.assertTrue(policy.comparison_ok(value))  # existing baseline protections are fine
        value["before"]["scenarios"][0]["status"] = "FAIL"
        self.assertTrue(policy.comparison_ok(value))
        for role in ("before", "after"):
            for defect in ("error", "setup", "missing"):
                value = report()
                if defect == "error":
                    value[role]["scenarios"][0]["status"] = "ERROR"
                elif defect == "setup":
                    value[role]["scenarios"][0]["setup_complete"] = False
                else:
                    value[role]["scenarios"].pop()
                with self.subTest(role=role, defect=defect):
                    self.assertFalse(policy.comparison_ok(value))
        value = report()
        value["after"]["scenarios"][0]["status"] = "FAIL"
        self.assertFalse(policy.comparison_ok(value))

    def test_environment_does_not_inherit_secrets_or_proxies(self):
        with mock.patch.dict(policy.os.environ, {"HTTPS_PROXY": "invalid", "TEMPEST_API_KEY": "synthetic"}):
            env = policy.environment(Path("/synthetic"))
        self.assertNotIn("HTTPS_PROXY", env)
        self.assertNotIn("TEMPEST_API_KEY", env)
        self.assertEqual(env["TOKIO_WORKER_THREADS"], "2")

    def test_receive_validates_both_ip_and_established_tid(self):
        sock = mock.Mock()
        sock.recvfrom.return_value = (b"\0\3\0\1", ("127.0.0.1", 32100))
        self.assertEqual(policy.receive(sock, peer=("127.0.0.1", 32100))[1][1], 32100)
        for peer in (("127.0.0.1", 32101), ("127.0.0.2", 32100)):
            with self.subTest(peer=peer), self.assertRaises(policy.PolicyFailure):
                policy.receive(sock, peer=peer)
        sock.recvfrom.side_effect = policy.socket.timeout()
        with self.assertRaises(policy.PolicyFailure):
            policy.receive(sock)

    def test_failed_startup_cleans_up(self):
        server = policy.Server(Path("/synthetic"), Path("/synthetic"), "silent_data", "before", {})
        proc = mock.Mock()
        proc.poll.return_value = None
        log = mock.Mock()

        def fail():
            server.proc, server.log = proc, log
            raise policy.SetupError("readiness failed")

        with mock.patch.object(server, "start", side_effect=fail), self.assertRaises(policy.SetupError):
            server.__enter__()
        proc.terminate.assert_called_once()
        proc.wait.assert_called_once_with(timeout=0.5)
        log.close.assert_called_once()

    def test_process_cleanup_escalates_with_finite_waits(self):
        proc = mock.Mock()
        proc.poll.return_value = None
        proc.wait.side_effect = [subprocess.TimeoutExpired("synthetic", 0.5), 0]
        policy.stop_process(proc)
        proc.kill.assert_called_once()
        self.assertEqual(proc.wait.call_args_list, [mock.call(timeout=0.5), mock.call(timeout=1)])

    def test_same_namespace_fails_before_interface_setup(self):
        identity = types.SimpleNamespace(st_dev=1, st_ino=2)
        with mock.patch.object(policy.os, "stat", return_value=identity), \
                mock.patch.object(policy.os, "fstat", return_value=identity), \
                self.assertRaisesRegex(policy.SetupError, "original network"):
            policy.verify_namespace(10, 11)

    def test_namespace_requires_nonroot_mapping_and_only_loopback(self):
        current = types.SimpleNamespace(st_dev=1, st_ino=2)
        original = types.SimpleNamespace(st_dev=1, st_ino=3)
        with mock.patch.object(policy.os, "stat", return_value=current), \
                mock.patch.object(policy.os, "fstat", return_value=original), \
                mock.patch.object(Path, "read_text", return_value="0 1000 1\n"), \
                mock.patch.object(policy.socket, "if_nameindex", return_value=[(1, "lo")]):
            self.assertEqual(policy.verify_namespace(10, 11)["interfaces"], ["lo"])
            with mock.patch.object(Path, "read_text", return_value="0 0 1\n"), \
                    self.assertRaisesRegex(policy.SetupError, "non-root"):
                policy.verify_namespace(10, 11)
            with mock.patch.object(policy.socket, "if_nameindex", return_value=[(1, "lo"), (2, "eth0")]), \
                    self.assertRaisesRegex(policy.SetupError, "only loopback"):
                policy.verify_namespace(10, 11)

    def test_config_fallback_records_only_two_known_omissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            row = {}
            server = policy.Server(Path("/synthetic"), Path(temporary) / "case",
                                   "silent_data", "before", row)
            responses = [
                (1, "unknown field `max_tftp_transfers_per_ip`"),
                (1, "unknown field `max_client_timeout_secs`"),
                (0, "configuration valid"),
                (1, "stop before starting any server"),
            ]
            with mock.patch.object(policy, "command", side_effect=responses), \
                    self.assertRaisesRegex(policy.SetupError, "effective"):
                server.start()
            self.assertEqual({item["field"] for item in row["omitted_fields"]}, policy.NEW_FIELDS)
            config = (server.directory / "synthetic.toml").read_text()
            self.assertNotIn("max_client_timeout_secs", config)
            self.assertNotIn("max_tftp_transfers_per_ip", config)
            self.assertIn("max_transfer_duration_secs = 3", config)

    def test_after_and_unrelated_baseline_config_errors_are_fatal(self):
        for role, field in (("after", "max_client_timeout_secs"),
                            ("before", "max_transfer_duration_secs")):
            with tempfile.TemporaryDirectory() as temporary:
                server = policy.Server(Path("/synthetic"), Path(temporary) / "case",
                                       "silent_data", role, {})
                with mock.patch.object(policy, "command", return_value=(1, f"unknown field `{field}`")), \
                        self.assertRaisesRegex(policy.SetupError, "configuration rejected"):
                    server.start()

    def test_cli_has_no_network_target(self):
        options = policy.parser()._option_string_actions
        self.assertNotIn("--host", options)
        self.assertNotIn("--port", options)
        self.assertNotIn("--target", options)

    def test_baseline_timeout_failure_is_retained_while_download_continues(self):
        row = {"checks": []}
        sock = mock.MagicMock()
        sock.__enter__.return_value = sock
        peer = ("127.0.0.1", 32100)
        responses = [
            (b"\0\6timeout\x00255\0blksize\x00512\0tsize\0" + str(len(policy.SMALL)).encode() + b"\0", peer),
            (b"\0\3\0\1" + policy.SMALL, peer),
        ]
        with mock.patch.object(policy, "client", return_value=sock), \
                mock.patch.object(policy, "receive", side_effect=responses), \
                mock.patch.object(policy, "wait_count", return_value=0):
            policy.timeout_case(row, 255)
        self.assertEqual([item["passed"] for item in row["checks"]], [False, True, True])
        self.assertEqual(row["checks"][0]["observed"]["timeout"], "255")

    def test_progress_simulation_checks_original_deadline_and_recovery(self):
        # This fake clock exercises the Python observer, not server runtime.
        for expires in (True, False):
            now, pending = [0.0], []
            sock = mock.MagicMock()
            sock.__enter__.return_value = sock
            peer = ("127.0.0.1", 32100)
            row = {"checks": []}

            def send(packet, _peer):
                if packet[:2] == b"\0\4":
                    block = int.from_bytes(packet[2:4], "big") + 1
                    pending.append((policy.struct.pack("!HH", 3, block) + b"L" * 512, peer))

            def select_fake(_read, _write, _errors, delay):
                if pending:
                    return [sock], [], []
                if expires and now[0] + delay >= 4:
                    now[0] = 4.0
                    pending.append((policy.DEADLINE_ERROR, peer))
                    return [sock], [], []
                now[0] += delay
                return [], [], []

            sock.sendto.side_effect = send
            counts = [1, 0, 0] if expires else [1, 1, 0, 0]
            with mock.patch.object(policy, "client", return_value=sock), \
                    mock.patch.object(policy, "begin", return_value=(peer, 0.0)), \
                    mock.patch.object(policy, "wait_count", side_effect=counts), \
                    mock.patch.object(policy, "download") as download, \
                    mock.patch.object(policy.time, "monotonic", side_effect=lambda: now[0]), \
                    mock.patch.object(policy.select, "select", side_effect=select_fake), \
                    mock.patch.object(policy, "receive", side_effect=lambda *a, **kw: pending.pop(0)):
                policy.lifetime_case(row, "progressing_ack")
            checks = {item["name"]: item for item in row["checks"]}
            self.assertEqual(checks["absolute_deadline_packet"]["passed"], expires)
            self.assertTrue(checks["slow_ack_forward_progress"]["passed"])
            self.assertEqual(checks["expiry_releases_slot_without_client_cancel"]["passed"], expires)
            self.assertEqual(checks["same_endpoint_recovery"]["recovery_after"],
                             "expiry" if expires else "explicit_cleanup_after_failed_expiry")
            download.assert_called_once_with(sock, "next.bin")

    def test_root_is_rejected_without_launching_anything(self):
        args = ["runner", "--before-binary", "before", "--after-binary", "after", "--output", "out"]
        with mock.patch.object(policy.sys, "argv", args), \
                mock.patch.object(policy.sys, "platform", "linux"), \
                mock.patch.object(policy.os, "geteuid", return_value=0), \
                mock.patch.object(policy.subprocess, "Popen") as spawn, \
                self.assertRaisesRegex(policy.SetupError, "do not run as root"):
            policy.main()
        spawn.assert_not_called()

    def test_supervisor_error_preserves_partial_checks_and_invalidates_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary)
            policy.write_json(output / "results.json", {"comparison_passed": True, "before": {"scenarios": []}})
            policy.supervisor_error(output, policy.SetupError("wall budget"))
            report = policy.json.loads((output / "results.json").read_text())
            self.assertFalse(report["comparison_passed"])
            self.assertIn("before", report)
            self.assertIn("wall budget", report["supervisor_error"])


if __name__ == "__main__":
    unittest.main()