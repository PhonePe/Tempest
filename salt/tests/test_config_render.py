# SPDX-FileCopyrightText: 2026 PhonePe India Pvt. Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Render the actual Salt template with a minimal pillar.get substitute.

Run with Python 3.11+ and Jinja2 (also supplied by Salt's Python environment).
No Salt daemon, network, or installed Tempest service is used.
"""

import copy
import json
from pathlib import Path
import tomllib
import unittest

from jinja2 import Environment, FileSystemLoader, StrictUndefined


SALT_ROOT = Path(__file__).resolve().parents[1]


def render_api(overrides):
    def pillar_get(key, default, merge=False):
        assert key == "tempest" and merge
        values = copy.deepcopy(default)
        values["api"].update(overrides)
        return values

    environment = Environment(loader=FileSystemLoader(SALT_ROOT), undefined=StrictUndefined)
    environment.filters["json"] = json.dumps
    template = environment.get_template("tempest/files/tempest.toml.jinja")
    return tomllib.loads(template.render(salt={"pillar.get": pillar_get}))["api"]


class ApiConfigTests(unittest.TestCase):
    def test_defaults_keep_native_boot_disabled_and_metrics_protected(self):
        api = render_api({})
        self.assertEqual(api["bind"], "127.0.0.1")
        self.assertFalse(api["enable_native_http_boot"])
        self.assertEqual(api["native_http_boot_filename"], "boot.efi")
        self.assertTrue(api["metrics_require_api_key"])
        self.assertEqual(api["trusted_proxy_ips"], [])

    def test_configured_auth_and_native_boot_survive_rendering(self):
        overrides = {
            "api_key": "env:TEMPEST_API_KEY",
            "enable_native_http_boot": True,
            "native_http_boot_filename": "boot/entry.efi",
            "trusted_proxy_ips": ["127.0.0.1", "::1"],
        }
        api = render_api(overrides)
        for key, value in overrides.items():
            self.assertEqual(api[key], value)

    def test_proxy_trust_can_be_explicitly_cleared(self):
        self.assertEqual(render_api({"trusted_proxy_ips": []})["trusted_proxy_ips"], [])

    def test_strings_are_serialized_not_interpolated_as_toml(self):
        # Escaping must remain correct even before Tempest validates logical names.
        for name in ['boot/quoted"name', "boot/back\\slash"]:
            with self.subTest(name=name):
                api = render_api({"native_http_boot_filename": name})
                self.assertEqual(api["native_http_boot_filename"], name)


if __name__ == "__main__":
    unittest.main()
