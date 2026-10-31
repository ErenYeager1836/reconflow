"""Unit tests for reconflow CLI, subcommand routing, and scan runner."""

import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from reconflow import __version__
from reconflow.cli import build_parser, main
from reconflow.scan import run as run_scan


class TestCLI(unittest.TestCase):
    """Test suite for CLI argument parser and command routing."""

    def setUp(self):
        self.parser = build_parser()

    def test_version_output(self):
        """CLI --version should report the package version."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            with self.assertRaises(SystemExit) as cm:
                self.parser.parse_args(["--version"])
            self.assertEqual(cm.exception.code, 0)
            self.assertIn(__version__, mock_out.getvalue())

    def test_scan_subcommand_defaults(self):
        """Parsing 'scan example.com' sets default parameters."""
        args = self.parser.parse_args(["scan", "example.com"])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.domain, "example.com")
        self.assertEqual(args.output, "output")
        self.assertEqual(args.threads, 10)
        self.assertEqual(args.timeout, 5)
        self.assertFalse(args.keep_wildcard)
        self.assertFalse(args.json_report)
        self.assertFalse(args.screenshots)

    def test_scan_subcommand_custom_flags(self):
        """Parsing 'scan' with all custom flags properly assigns attributes."""
        args = self.parser.parse_args([
            "scan",
            "target.test",
            "-o",
            "custom_output",
            "--threads",
            "25",
            "--timeout",
            "15",
            "--keep-wildcard",
            "--json",
            "--screenshots",
        ])
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.domain, "target.test")
        self.assertEqual(args.output, "custom_output")
        self.assertEqual(args.threads, 25)
        self.assertEqual(args.timeout, 15)
        self.assertTrue(args.keep_wildcard)
        self.assertTrue(args.json_report)
        self.assertTrue(args.screenshots)

    @patch("reconflow.scan.run")
    def test_main_dispatch_scan(self, mock_scan_run):
        """main(['scan', 'example.com']) should route to scan.run."""
        main(["scan", "example.com", "--threads", "15"])
        self.assertTrue(mock_scan_run.called)
        called_args = mock_scan_run.call_args[0][0]
        self.assertEqual(called_args.domain, "example.com")
        self.assertEqual(called_args.threads, 15)

    def test_diff_subcommand_defaults(self):
        """Parsing 'diff example.com' sets default parameters."""
        args = self.parser.parse_args(["diff", "example.com"])
        self.assertEqual(args.command, "diff")
        self.assertEqual(args.domain, "example.com")
        self.assertEqual(args.output, "output")
        self.assertFalse(args.json_report)

    @patch("reconflow.diff.run")
    def test_main_dispatch_diff(self, mock_diff_run):
        """main(['diff', 'example.com']) should route to diff.run."""
        main(["diff", "example.com", "--json"])
        self.assertTrue(mock_diff_run.called)
        called_args = mock_diff_run.call_args[0][0]
        self.assertEqual(called_args.domain, "example.com")
        self.assertTrue(called_args.json_report)

    def test_main_no_args_prints_help(self):
        """main([]) without args should print help and exit cleanly with 0."""
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            with self.assertRaises(SystemExit) as cm:
                main([])
            self.assertEqual(cm.exception.code, 0)
            self.assertIn("reconflow", mock_out.getvalue())
            self.assertIn("subcommands", mock_out.getvalue())


class TestScanRunner(unittest.TestCase):
    """Test suite for reconflow.scan pipeline execution."""

    def test_run_scan_missing_domain(self):
        """run_scan with empty domain should exit with error message."""
        mock_args = MagicMock(domain=None)
        with self.assertRaises(SystemExit) as cm:
            run_scan(mock_args)
        self.assertIn("Error: Target domain is required", str(cm.exception))

    @patch("reconflow.scan.check_tools")
    @patch("reconflow.scan.find_subdomains")
    @patch("reconflow.scan.detect_wildcard")
    @patch("reconflow.scan.probe_hosts")
    def test_run_scan_mocked_flow(
        self,
        mock_probe,
        mock_wildcard,
        mock_subdomains,
        mock_check_tools,
    ):
        """run_scan should execute end-to-end and generate outputs."""
        mock_subdomains.return_value = ["sub.example.com", "example.com"]
        mock_wildcard.return_value = set()
        mock_probe.return_value = (["https://sub.example.com [200]"], None)

        with tempfile.TemporaryDirectory() as tmpdir:
            args = MagicMock(
                domain="example.com",
                output=tmpdir,
                threads=10,
                timeout=5,
                keep_wildcard=False,
                json_report=False,
                json=False,
                screenshots=False,
            )
            result = run_scan(args)

            self.assertEqual(result["domain"], "example.com")
            self.assertEqual(len(result["subdomains"]), 2)
            self.assertEqual(len(result["live"]), 1)

            out_dir = Path(tmpdir) / "example.com"
            report_file = out_dir / "report.md"
            self.assertTrue(report_file.exists())
            content = report_file.read_text(encoding="utf-8")
            self.assertIn("# reconflow report: example.com", content)
            self.assertIn("https://sub.example.com [200]", content)

    @patch("reconflow.scan.resolve_httpx_binary", return_value=None)
    @patch("shutil.which", return_value=None)
    def test_check_tools_missing(self, mock_which, mock_httpx):
        """check_tools should exit with installation links when tools are missing."""
        from reconflow.scan import check_tools

        mock_which.return_value = None
        with self.assertRaises(SystemExit) as cm:
            check_tools(["subfinder", "httpx"])
        err_msg = str(cm.exception)
        self.assertIn("Missing required tools", err_msg)
        self.assertIn("projectdiscovery/subfinder", err_msg)
        self.assertIn("projectdiscovery/httpx", err_msg)

    @patch("reconflow.scan.resolve_httpx_binary", return_value="/usr/bin/tool")
    @patch("shutil.which", return_value="/usr/bin/tool")
    def test_check_tools_present(self, mock_which, mock_httpx):
        """check_tools should pass silently when all tools are installed."""
        from reconflow.scan import check_tools

        check_tools(["subfinder", "httpx"])

    @patch("subprocess.Popen")
    def test_probe_hosts_integer_timeout_and_ignores_error_lines(self, mock_popen):
        """probe_hosts should pass integer timeout to httpx and ignore non-JSON errors."""
        from reconflow.scan import probe_hosts

        mock_proc = MagicMock()
        mock_proc.stdout = iter([
            'invalid value "5.0" for flag -timeout: parse error\n',
            '{"url": "https://valid.test", "status_code": 200, "title": "OK"}\n',
        ])
        mock_proc.wait.return_value = None
        mock_proc.returncode = 0
        mock_proc.__enter__.return_value = mock_proc
        mock_proc.__exit__.return_value = None
        mock_popen.return_value = mock_proc

        with tempfile.TemporaryDirectory() as tmpdir:
            subs_file = Path(tmpdir) / "subs.txt"
            subs_file.write_text("valid.test\n", encoding="utf-8")
            out_file = Path(tmpdir) / "live.txt"

            lines, hosts_data = probe_hosts(
                subs_file,
                out_file,
                timeout=5.0,
                json_report=True,
            )

            # Check that cmd received string integer '5' and stdin is DEVNULL
            called_cmd = mock_popen.call_args[0][0]
            self.assertIn("-timeout", called_cmd)
            timeout_idx = called_cmd.index("-timeout")
            self.assertEqual(called_cmd[timeout_idx + 1], "5")
            self.assertEqual(mock_popen.call_args[1].get("stdin"), subprocess.DEVNULL)

            # Check that error line was NOT counted as live host
            self.assertEqual(len(lines), 1)
            self.assertIn("https://valid.test", lines[0])
            self.assertEqual(len(hosts_data), 1)
            self.assertEqual(hosts_data[0]["url"], "https://valid.test")


if __name__ == "__main__":
    unittest.main()
