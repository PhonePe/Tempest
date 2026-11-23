# SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Render the Salt install state with a minimal pillar.get substitute.

Run with Python 3.11+, Jinja2 and PyYAML (all supplied by Salt's Python
environment). No Salt daemon, network, or installed Tempest service is used.
"""

import copy
from pathlib import Path
import unittest

from jinja2 import Environment, FileSystemLoader, StrictUndefined
import yaml


SALT_ROOT = Path(__file__).resolve().parents[1]


def deep_merge(base, overrides):
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def render_install(install):
    def pillar_get(key, default, merge=False):
        assert key == "tempest" and merge
        return deep_merge(copy.deepcopy(default), {"install": install})

    environment = Environment(loader=FileSystemLoader(SALT_ROOT), undefined=StrictUndefined)
    template = environment.get_template("tempest/install.sls")
    return yaml.safe_load(template.render(salt={"pillar.get": pillar_get}))


RELEASE = {
    "method": "release",
    "release": {
        "version": "0.1.0",
        "platform": "linux-arm64",
        "sha256": "ab" * 32,
        "base_url": "https://artifacts.example.invalid/tempest",
    },
}


class ReleaseInstallTests(unittest.TestCase):
    def test_pinned_release_downloads_verifies_and_installs_the_archive_binary(self):
        states = render_install(RELEASE)
        archive = dict(pair for item in states["tempest-release-archive"]["archive.extracted"] for pair in item.items())
        self.assertEqual(
            archive["source"],
            "https://artifacts.example.invalid/tempest/v0.1.0/tempest-0.1.0-linux-arm64.tar.gz",
        )
        self.assertEqual(archive["source_hash"], "sha256=" + "ab" * 32)
        self.assertEqual(archive["name"], "/opt/tempest/0.1.0")
        binary = dict(pair for item in states["tempest-binary"]["file.managed"] for pair in item.items())
        self.assertEqual(binary["source"], "/opt/tempest/0.1.0/tempest-0.1.0-linux-arm64/tempest")
        self.assertEqual(binary["name"], "/usr/local/bin/tempest")
        capability = dict(pair for item in states["tempest-bind-service-capability"]["cmd.run"] for pair in item.items())
        self.assertIn({"file": "tempest-binary"}, capability["require"])

    def test_unpinned_release_refuses_to_download(self):
        for missing in ("version", "sha256", "base_url"):
            with self.subTest(missing=missing):
                install = copy.deepcopy(RELEASE)
                install["release"][missing] = ""
                states = render_install(install)
                self.assertIn("tempest-release-pin-required", states)
                self.assertNotIn("tempest-release-archive", states)
                self.assertNotIn("tempest-binary", states)

    def test_binary_method_still_copies_the_salt_file(self):
        states = render_install({"method": "binary"})
        binary = dict(pair for item in states["tempest-binary"]["file.managed"] for pair in item.items())
        self.assertEqual(binary["source"], "salt://artifacts/tempest/tempest")
        self.assertNotIn("tempest-release-archive", states)


if __name__ == "__main__":
    unittest.main()
