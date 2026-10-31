"""Unit tests for safety gates, scope enforcement, rate limiting, and dry-run."""

import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from reconflow import scan
from reconflow.cli import build_parser
from reconflow.pipeline import Pipeline, filter_in_scope_targets, warn_intrusive
from reconflow.plugins import (
    DnsxPlugin,
    HttpxPlugin,
    KatanaPlugin,
    NaabuPlugin,
    NucleiPlugin,
    SubfinderPlugin,
)
from reconflow.scope import load_scope


class TestScopeHardGate(unittest.TestCase):
    """Verify that every stage drops out-of-scope targets and logs them."""

    def setUp(self):
        with tempfile.NamedTemporaryFile("w+", delete=False, encoding="utf-8") as f:
            f.write("*.example.com\n!admin.example.com\n192.168.1.0/24\n")
            f.flush()
            self.scope_path = f.name
        self.scope_data = load_scope(self.scope_path)

    def tearDown(self):
        Path(self.scope_path).unlink(missing_ok=True)

    def test_filter_in_scope_targets_drops_and_logs(self):
        targets = [
            "api.example.com",
            "admin.example.com",
            "malicious.org",
            "https://shop.example.com/login",
            "https://evil.com/phish",
        ]
        logs = []
        filtered = filter_in_scope_targets(targets, self.scope_data, log_fn=logs.append)
        self.assertEqual(filtered, ["api.example.com", "https://shop.example.com/login"])
        # Verify exact required log message format
        self.assertTrue(any("out of scope, skip admin.example.com" in log for log in logs))
        self.assertTrue(any("out of scope, skip malicious.org" in log for log in logs))
        self.assertTrue(any("out of scope, skip https://evil.com/phish" in log for log in logs))

    def test_pipeline_http_stage_drops_out_of_scope_before_tool(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            pipeline = Pipeline(
                domain="example.com",
                output_dir=out_dir,
                stages=["http"],
                silent=True,
                scope_data=self.scope_data,
            )
            pipeline.context.subdomains = ["api.example.com", "admin.example.com", "evil.com"]
            mock_http_out = json.dumps({"url": "https://api.example.com", "status_code": 200})
            with patch("reconflow.plugins.HttpxPlugin.is_installed", return_value=True), \
                 patch("reconflow.plugins.HttpxPlugin.run_command_safe",
                       return_value=(0, mock_http_out + "\n", "")):
                ctx = pipeline.run()
                self.assertEqual(len(ctx.live_hosts), 1)

    def test_no_scope_file_restricts_to_domain_and_subdomains(self):
        """When no scope file is loaded, limit to target domain and subdomains by default."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            logs = []
            pipeline = Pipeline(
                domain="example.com",
                output_dir=out_dir,
                stages=["urls"],
                silent=False,
                scope_data=None,  # No scope file
            )
            # Inspect that default scope was generated
            self.assertTrue(pipeline.context.scope_data.get("is_default"))

            # Mock URL collection tool returning both in-scope and out-of-scope URLs
            mock_urls = (
                "https://example.com/login\n"
                "https://api.example.com/v1/users\n"
                "https://evil.com/leak\n"
                "https://notexample.com/fake\n"
            )
            with patch("reconflow.plugins.WaybackurlsPlugin.is_installed", return_value=True), \
                 patch("reconflow.plugins.WaybackurlsPlugin.run_command_safe",
                       return_value=(0, mock_urls, "")), \
                 patch("reconflow.plugins.KatanaPlugin.is_installed", return_value=False), \
                 patch("reconflow.plugins.GauPlugin.is_installed", return_value=False):
                pipeline.context.log = logs.append
                ctx = pipeline.run()

                # Verify in-scope URLs are accepted
                collected_urls = [r["url"] for r in ctx.urls]
                self.assertIn("https://example.com/login", collected_urls)
                self.assertIn("https://api.example.com/v1/users", collected_urls)

                # Verify out-of-scope URLs are dropped
                self.assertNotIn("https://evil.com/leak", collected_urls)
                self.assertNotIn("https://notexample.com/fake", collected_urls)

                # Verify exact dropped & logged messages
                self.assertTrue(
                    any("out of scope, skip https://evil.com/leak" in log for log in logs)
                )
                self.assertTrue(
                    any("out of scope, skip https://notexample.com/fake" in log for log in logs)
                )

                # Verify warning message at scan start
                self.assertTrue(
                    any("No scope file loaded: limiting to example.com and subdomains" in log
                        for log in logs)
                )

    def test_mining_drops_and_logs_out_of_scope_urls(self):
        """Discovered out-of-scope hosts in JS mining must be dropped and logged."""
        from reconflow import mining
        logs = []
        js = """
        const inScope = "https://app.example.com/api";
        const outScope = "https://evil-analytics.com/track";
        """
        res = mining.mine_js_content(
            js,
            base_url="https://example.com",
            target_domain="example.com",
            log_fn=logs.append,
        )
        self.assertIn("https://app.example.com/api", res["endpoints"])
        self.assertNotIn("https://evil-analytics.com/track", res["endpoints"])
        self.assertTrue(
            any("out of scope, skip https://evil-analytics.com/track" in log for log in logs)
        )


class TestRateLimitingAndThreads(unittest.TestCase):
    """Test CLI rate limiting and thread limits propagated to tools."""

    def test_cli_flags_parsing(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "example.com", "--rate", "25", "--threads", "15"])
        self.assertEqual(args.rate, 25)
        self.assertEqual(args.threads, 15)

    def test_plugins_command_generation_with_rate_and_threads(self):
        subfinder = SubfinderPlugin()
        cmd = subfinder.build_command("example.com", threads=20, rate=50)
        self.assertIn("-t", cmd)
        self.assertIn("20", cmd)
        self.assertIn("-rl", cmd)
        self.assertIn("50", cmd)

        dnsx = DnsxPlugin()
        cmd = dnsx.build_command("subs.txt", threads=30, rate=75)
        self.assertIn("-t", cmd)
        self.assertIn("30", cmd)
        self.assertIn("-rl", cmd)
        self.assertIn("75", cmd)

        httpx = HttpxPlugin()
        cmd = httpx.build_command("subs.txt", threads=10, rate=40)
        self.assertIn("-threads", cmd)
        self.assertIn("10", cmd)
        self.assertIn("-rate-limit", cmd)
        self.assertIn("40", cmd)

        katana = KatanaPlugin()
        cmd = katana.build_command("urls.txt", threads=8, rate=30)
        self.assertIn("-concurrency", cmd)
        self.assertIn("8", cmd)
        self.assertIn("-rate-limit", cmd)
        self.assertIn("30", cmd)

        naabu = NaabuPlugin()
        cmd = naabu.build_command("subs.txt", threads=12, rate=100)
        self.assertIn("-c", cmd)
        self.assertIn("12", cmd)
        self.assertIn("-rate", cmd)
        self.assertIn("100", cmd)

        nuclei = NucleiPlugin()
        cmd = nuclei.build_command("live.txt", threads=5, rate=20)
        self.assertIn("-c", cmd)
        self.assertIn("5", cmd)
        self.assertIn("-rate-limit", cmd)
        self.assertIn("20", cmd)

    def test_default_rate_limit_and_unlimited(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            # Default rate is 50 when not specified
            pipeline_def = Pipeline(domain="example.com", output_dir=out_dir, rate=None)
            self.assertEqual(pipeline_def.context.rate, 50)

            # Test dry run output shows 50 req/s
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                pipeline_def.dry_run_plan()
                self.assertIn("Rate Limit:    50 req/s", mock_stdout.getvalue())

            # Test rate 0 means unlimited
            pipeline_unlimited = Pipeline(domain="example.com", output_dir=out_dir, rate=0)
            self.assertEqual(pipeline_unlimited.context.rate, 0)
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout:
                pipeline_unlimited.dry_run_plan()
                self.assertIn("Rate Limit:    unlimited", mock_stdout.getvalue())

            # Test tools build commands without rate flags when rate=0
            subfinder = SubfinderPlugin()
            cmd = subfinder.build_command("example.com", rate=0)
            self.assertNotIn("-rl", cmd)

            httpx = HttpxPlugin()
            cmd_h = httpx.build_command("subs.txt", rate=0)
            self.assertNotIn("-rate-limit", cmd_h)


class TestNucleiSafeguards(unittest.TestCase):
    """Test default safe templates vs intrusive flags and warnings."""

    def test_default_nuclei_command_is_safe(self):
        nuclei = NucleiPlugin()
        cmd = nuclei.build_command("targets.txt", intrusive=False)
        self.assertIn("-tags", cmd)
        self.assertIn("technologies,exposure,misconfiguration,takeover", cmd)
        self.assertIn("-exclude-severity", cmd)
        self.assertIn("high,critical", cmd)
        self.assertNotIn("-severity", cmd)

    def test_intrusive_nuclei_command_allows_aggressive(self):
        nuclei = NucleiPlugin()
        cmd = nuclei.build_command("targets.txt", intrusive=True)
        self.assertIn("-severity", cmd)
        self.assertIn("info,low,medium,high,critical", cmd)
        self.assertNotIn("-exclude-severity", cmd)

    def test_warn_intrusive_writes_to_stderr(self):
        with patch("sys.stderr", new_callable=io.StringIO) as mock_stderr:
            warn_intrusive()
            output = mock_stderr.getvalue()
            self.assertIn("[WARNING] INTRUSIVE SCANNING ENABLED", output)
            self.assertIn("--intrusive", output)


class TestDryRunMode(unittest.TestCase):
    """Test dry run mode shows plan and commands without executing subprocesses."""

    def test_cli_dry_run_flag(self):
        parser = build_parser()
        args = parser.parse_args(["scan", "example.com", "--dry-run"])
        self.assertTrue(args.dry_run)

    def test_dry_run_execution(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            args = SimpleNamespace(
                domain="example.com",
                output=tmpdir,
                stages="subdomains,http",
                skip=None,
                threads=10,
                timeout=5,
                rate=50,
                dry_run=True,
                intrusive=False,
                all_vulns=False,
                scope=None,
                silent=False,
                keep_wildcard=False,
                json_report=False,
                csv=False,
                screenshots=False,
            )
            with patch("sys.stdout", new_callable=io.StringIO) as mock_stdout, \
                 patch.object(SubfinderPlugin, "run_command_safe") as mock_sub_run, \
                 patch.object(HttpxPlugin, "run_command_safe") as mock_http_run, \
                 patch.object(SubfinderPlugin, "is_installed", return_value=True), \
                 patch.object(SubfinderPlugin, "get_version", return_value="v2.17.0"), \
                 patch.object(SubfinderPlugin, "get_binary_path",
                              return_value="/usr/bin/subfinder"), \
                 patch.object(HttpxPlugin, "is_installed", return_value=True), \
                 patch.object(HttpxPlugin, "get_version", return_value="v1.6.8"), \
                 patch.object(HttpxPlugin, "get_binary_path",
                              return_value="/usr/bin/httpx"):
                result = scan.run(args)
                self.assertTrue(result["dry_run"])
                # External tool commands must never execute during dry run
                self.assertFalse(mock_sub_run.called)
                self.assertFalse(mock_http_run.called)

                stdout_text = mock_stdout.getvalue()
                self.assertIn("reconflow scan [DRY RUN]", stdout_text)
                self.assertIn(
                    "No scope file loaded: limiting to example.com and subdomains",
                    stdout_text,
                )
                self.assertIn("Target Domain: example.com", stdout_text)
                self.assertIn("Rate Limit:    50 req/s", stdout_text)
                self.assertIn("Command:", stdout_text)
                self.assertIn("subfinder", stdout_text)
                self.assertIn("httpx", stdout_text)
                self.assertIn("(version:", stdout_text)


if __name__ == "__main__":
    unittest.main()
