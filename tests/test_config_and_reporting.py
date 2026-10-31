"""Tests for Round 5: reconflow.toml config, SARIF reporting, and webhook digest."""

import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from reconflow import config, notify, report


class TestConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg_file = Path(self.tmp.name) / "reconflow.toml"

    def tearDown(self):
        self.tmp.cleanup()

    def test_toml_fallback_and_load(self):
        content = """
        [general]
        output = "custom_output"
        threads = 30
        timeout = 8
        rate = 75

        [pipeline]
        stages = ["subdomains", "http", "vulns"]
        skip = ["ports"]

        [notify]
        webhook_url = "https://discord.com/api/webhooks/test"
        """
        self.cfg_file.write_text(content, encoding="utf-8")

        parsed = config.load_config(str(self.cfg_file))
        self.assertEqual(parsed["general"]["output"], "custom_output")
        self.assertEqual(parsed["general"]["threads"], 30)
        self.assertEqual(parsed["general"]["rate"], 75)
        self.assertEqual(parsed["pipeline"]["stages"], ["subdomains", "http", "vulns"])

        # Test applying to CLI args
        args = Namespace(
            output="output",
            threads=None,
            timeout=5,
            rate=None,
            stages=None,
            skip=None,
            webhook_url=None,
        )
        updated = config.apply_config_to_args(args, parsed)
        self.assertEqual(updated.output, "custom_output")
        self.assertEqual(updated.threads, 30)
        self.assertEqual(updated.timeout, 8)
        self.assertEqual(updated.rate, 75)
        self.assertEqual(updated.stages, "subdomains,http,vulns")
        self.assertEqual(updated.skip, "ports")
        self.assertEqual(updated.webhook_url, "https://discord.com/api/webhooks/test")

    def test_cli_flags_override_config(self):
        content = """
        [general]
        threads = 40
        """
        self.cfg_file.write_text(content, encoding="utf-8")
        parsed = config.load_config(str(self.cfg_file))

        # Explicit threads from CLI
        args = Namespace(threads=15)
        updated = config.apply_config_to_args(args, parsed)
        self.assertEqual(updated.threads, 15)


class TestSARIFReport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_build_and_export_sarif(self):
        domain = "example.com"
        findings = [
            {
                "template_id": "cve-2024-1111",
                "name": "Remote Code Execution",
                "severity": "critical",
                "host": "api.example.com",
                "matched_at": "https://api.example.com/v1/exec",
                "description": "RCE vulnerability found",
            },
            {
                "template_id": "cors-misconfig",
                "name": "CORS Misconfiguration",
                "severity": "medium",
                "host": "app.example.com",
                "matched_at": "https://app.example.com",
                "description": "Permissive CORS origin",
            },
        ]

        sarif_doc = report.build_sarif_report(domain, findings)
        self.assertEqual(sarif_doc["version"], "2.1.0")
        self.assertEqual(len(sarif_doc["runs"]), 1)

        run = sarif_doc["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0]["id"], "cve-2024-1111")
        self.assertEqual(rules[0]["defaultConfiguration"]["level"], "error")
        self.assertEqual(rules[1]["defaultConfiguration"]["level"], "warning")

        results = run["results"]
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["level"], "error")
        self.assertEqual(results[1]["level"], "warning")

        exported_path = report.export_sarif(domain, findings, self.out_dir)
        self.assertTrue(exported_path.exists())
        saved_json = json.loads(exported_path.read_text(encoding="utf-8"))
        self.assertEqual(saved_json["version"], "2.1.0")


class TestWebhookDigest(unittest.TestCase):
    def test_format_diff_digest(self):
        domain = "example.com"
        diff_res = {
            "new_subdomains": ["dev.example.com", "api.example.com"],
            "new_live": ["https://dev.example.com [200]"],
            "new_ports": {"api.example.com": [8443]},
            "new_urls": ["https://api.example.com/v1/users"],
            "new_findings": [
                {
                    "template_id": "cve-2024-0001",
                    "name": "Critical Auth Bypass",
                    "severity": "critical",
                    "host": "https://dev.example.com",
                }
            ],
            "lead_hints": {
                "https://dev.example.com": ["Development host: check debug flags"]
            },
        }

        digest = notify.format_diff_digest(domain, diff_res)
        self.assertIn("reconflow alert: example.com", digest)
        self.assertIn("New Subdomains (2)", digest)
        self.assertIn("dev.example.com", digest)
        self.assertIn("New Live Hosts (1)", digest)
        self.assertIn("New Open Ports", digest)
        self.assertIn("8443", digest)
        self.assertIn("New Endpoints (1)", digest)
        self.assertIn("/v1/users", digest)
        self.assertIn("Vulnerability Findings (1)", digest)
        self.assertIn("Critical Auth Bypass", digest)
        self.assertIn("Top Lead Hints", digest)
