# SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0

import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tftp_client import download


class ExpectedTftpErrorTests(unittest.TestCase):
    def probe(self, packet, peer=("127.0.0.1", 12345), timeout=False):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "denied.bin"
            with patch("tftp_client.socket.getaddrinfo") as addresses, \
                    patch("tftp_client.socket.socket") as socket_factory:
                addresses.return_value = [
                    (socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("127.0.0.1", 6969))
                ]
                sock = socket_factory.return_value.__enter__.return_value
                if timeout:
                    sock.recvfrom.side_effect = socket.timeout
                else:
                    sock.recvfrom.return_value = packet, peer
                try:
                    result = download(
                        "localhost", 6969, "raw.bin", str(output), 512, 0,
                        None, "ipv4", expected_error=1,
                    )
                    self.assertEqual(result[0], 0)
                    sock.sendto.assert_called_once_with(
                        b"\x00\x01raw.bin\x00octet\x00", ("127.0.0.1", 6969)
                    )
                finally:
                    self.assertEqual(output.read_bytes(), b"")

    def test_accepts_only_explicit_file_not_found(self):
        self.probe(b"\x00\x05\x00\x01File not found\x00")

    def test_rejects_success_wrong_error_and_malformed_responses(self):
        for packet in (
            b"\x00\x03\x00\x01raw data",
            b"\x00\x06blksize\x00512\x00",
            b"\x00\x05\x00\x00Server at capacity\x00",
            b"\x00\x05\x00\x02Access violation\x00",
            b"\x00\x05\x00\x01Missing terminator",
            b"\x00\x05\x00\x01",
            b"",
        ):
            with self.subTest(packet=packet), self.assertRaises(RuntimeError):
                self.probe(packet)

    def test_rejects_wrong_peer(self):
        with self.assertRaises(RuntimeError):
            self.probe(b"\x00\x05\x00\x01Not found\x00", ("127.0.0.2", 12345))

    def test_timeout_is_not_a_denial(self):
        with self.assertRaises(TimeoutError):
            self.probe(None, timeout=True)


if __name__ == "__main__":
    unittest.main()