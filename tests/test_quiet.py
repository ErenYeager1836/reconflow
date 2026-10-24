"""Tests for the piping-safe --silent/--quiet/-q scan mode."""
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from reconflow import scan
from reconflow.cli import build_parser


class QuietModeTests(unittest.TestCase):
    def test_cli_accepts_three_aliases(self):
        parser = build_parser()
        for flag in ("-q", "--quiet", "--silent"):
            with self.subTest(flag=flag):
                self.assertTrue(parser.parse_args(["scan", "example.com", flag]).silent)
        self.assertFalse(parser.parse_args(["scan", "example.com"]).silent)

    def _run(self, quiet, mocked_hosts, mocked_subs):
        with tempfile.TemporaryDirectory() as folder:
            args = SimpleNamespace(
                domain="example.com",
                output=folder,
                silent=quiet,
                json_report=True,
                screenshots=False,
                keep_wildcard=True,
                threads=1,
                timeout=1,
                scope=None,
            )
            stdout, stderr = io.StringIO(), io.StringIO()
            text = [
                f"{x['url']} [{x.get('status_code', 200)}] [Some title]"
                for x in mocked_hosts
            ]
            with patch.object(scan, "check_tools"), patch.object(
                scan, "find_subdomains", return_value=mocked_subs
            ), patch.object(scan, "detect_wildcard", return_value=set()), patch.object(
                scan, "probe_hosts", return_value=(text, mocked_hosts)
            ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                result = scan.run(args)

            csv_dir = Path(folder) / "example.com"
            self.assertTrue((csv_dir / "report.md").exists())
            self.assertTrue((csv_dir / "runs").is_dir())
            return stdout.getvalue(), stderr.getvalue(), result

    def test_quiet_pipes_exact_live_urls_without_progress(self):
        hosts = [
            {"url": "https://api.example.com", "status_code": 200},
            {"url": "https://shop.example.com", "status_code": 403},
        ]
        stdout, stderr, _ = self._run(
            True, hosts, ["api.example.com", "shop.example.com"]
        )
        self.assertEqual(stdout.splitlines(), [
            "https://api.example.com",
            "https://shop.example.com",
        ])
        self.assertIn("Report saved", stderr)
        self.assertNotIn("Report saved", stdout)

    def test_no_live_hosts_falls_back_to_discovered_subdomains(self):
        stdout, stderr, _ = self._run(
            True, [], ["api.example.com", "shop.example.com"]
        )
        self.assertEqual(stdout.splitlines(), [
            "api.example.com", "shop.example.com"
        ])
        self.assertIn("Report saved", stderr)

    def test_duplicate_hosts_emit_once(self):
        hosts = [
            {"url": "https://api.example.com", "status_code": 200},
            {"url": "https://api.example.com", "status_code": 301},
        ]
        stdout, _, _ = self._run(True, hosts, ["api.example.com"])
        self.assertEqual(stdout.splitlines(), ["https://api.example.com"])

    def test_normal_mode_keeps_human_progress(self):
        stdout, _, _ = self._run(
            False, [{"url": "https://api.example.com"}], ["api.example.com"]
        )
        self.assertIn("Report saved", stdout)
        self.assertNotEqual(stdout.strip(), "https://api.example.com")


if __name__ == "__main__":
    unittest.main()
