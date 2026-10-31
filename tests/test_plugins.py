"""Unit tests for tool plugins, execution safety, and record normalization."""

import json
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

from reconflow.plugins import (
    DnsxPlugin,
    GauPlugin,
    HttpxPlugin,
    KatanaPlugin,
    NaabuPlugin,
    NucleiPlugin,
    SubfinderPlugin,
    WaybackurlsPlugin,
    get_all_plugins,
    get_plugin,
    get_plugins_for_stage,
)


class TestToolPluginBase(unittest.TestCase):
    """Test generic plugin infrastructure and safe subprocess execution."""

    def test_run_command_safe_success(self):
        plugin = SubfinderPlugin()
        cmd = [sys.executable, "-c", "print('hello recon')"]
        code, stdout, stderr = plugin.run_command_safe(cmd)
        self.assertEqual(code, 0)
        self.assertEqual(stdout.strip(), "hello recon")
        self.assertEqual(stderr, "")

    def test_run_command_safe_with_stdin(self):
        plugin = SubfinderPlugin()
        code, stdout, stderr = plugin.run_command_safe(
            [sys.executable, "-c", "import sys; print(sys.stdin.read().upper().strip())"],
            input_data="stdin content",
        )
        self.assertEqual(code, 0)
        self.assertEqual(stdout.strip(), "STDIN CONTENT")

    def test_run_command_safe_timeout(self):
        plugin = SubfinderPlugin()
        code, stdout, stderr = plugin.run_command_safe(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            timeout=1,
        )
        self.assertEqual(code, -1)
        self.assertIn("timed out after 1s", stderr)

    def test_run_command_safe_binary_not_found(self):
        plugin = SubfinderPlugin()
        code, stdout, stderr = plugin.run_command_safe(["non_existent_binary_xyz_123"])
        self.assertEqual(code, 127)
        self.assertIn("Binary not found", stderr)

    def test_get_plugins_registry(self):
        all_plugins = get_all_plugins()
        self.assertEqual(len(all_plugins), 8)
        self.assertIsNotNone(get_plugin("subfinder"))
        self.assertIsNotNone(get_plugin("nuclei"))
        self.assertIsNone(get_plugin("unknown_tool"))

        url_plugins = get_plugins_for_stage("urls")
        url_names = {p.name for p in url_plugins}
        self.assertEqual(url_names, {"katana", "gau", "waybackurls"})


class TestPluginImplementations(unittest.TestCase):
    """Test specific commands and parsers for each tool plugin."""

    def test_subfinder_plugin(self):
        p = SubfinderPlugin()
        cmd = p.build_command("example.com", all_sources=True)
        self.assertIn("subfinder", cmd[0])
        self.assertIn("-d", cmd)
        self.assertIn("example.com", cmd)
        self.assertIn("-all", cmd)

        stdout = "api.example.com\nadmin.example.com\n[INF] banner line\n\n"
        records = p.parse_output(stdout)
        self.assertEqual(records, [
            {"host": "api.example.com", "source": "subfinder"},
            {"host": "admin.example.com", "source": "subfinder"},
        ])

    def test_dnsx_plugin(self):
        p = DnsxPlugin()
        cmd = p.build_command("subs.txt", threads=25)
        self.assertIn("dnsx", cmd[0])
        self.assertIn("-silent", cmd)
        self.assertIn("-json", cmd)
        self.assertIn("-t", cmd)
        self.assertIn("25", cmd)

        stdout = json.dumps({
            "host": "api.example.com",
            "a": ["192.0.2.1"],
            "cname": ["cname.example.com"],
            "status_code": "NOERROR",
        }) + "\nfallback.example.com 198.51.100.2\n"

        records = p.parse_output(stdout)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["host"], "api.example.com")
        self.assertEqual(records[0]["ips"], ["192.0.2.1"])
        self.assertEqual(records[0]["cnames"], ["cname.example.com"])
        self.assertEqual(records[1]["host"], "fallback.example.com")
        self.assertEqual(records[1]["ips"], ["198.51.100.2"])

    def test_httpx_plugin(self):
        p = HttpxPlugin()
        cmd = p.build_command("subs.txt", threads=30, timeout=10)
        self.assertIn("httpx", cmd[0])
        self.assertIn("-status-code", cmd)
        self.assertIn("-title", cmd)
        self.assertIn("-tech-detect", cmd)
        self.assertIn("-threads", cmd)
        self.assertIn("30", cmd)
        self.assertIn("-timeout", cmd)
        self.assertIn("10", cmd)

        stdout = json.dumps({
            "url": "https://api.example.com",
            "input": "api.example.com",
            "status_code": 200,
            "title": "API Gateway",
            "tech": ["Nginx", "Python"],
            "cname": ["lb.example.com"],
            "webserver": "nginx",
        }) + "\n"

        records = p.parse_output(stdout)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["url"], "https://api.example.com")
        self.assertEqual(records[0]["host"], "api.example.com")
        self.assertEqual(records[0]["status_code"], 200)
        self.assertEqual(records[0]["title"], "API Gateway")
        self.assertEqual(records[0]["technologies"], ["Nginx", "Python"])

    def test_katana_plugin(self):
        p = KatanaPlugin()
        cmd = p.build_command("urls.txt")
        self.assertIn("katana", cmd[0])
        self.assertIn("-list", cmd)
        self.assertIn("urls.txt", cmd)

        stdout = json.dumps({
            "request": {"endpoint": "https://example.com/api/v1/users"},
        }) + "\nhttps://example.com/login\n"

        records = p.parse_output(stdout)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["url"], "https://example.com/api/v1/users")
        self.assertEqual(records[0]["source"], "katana")
        self.assertEqual(records[1]["url"], "https://example.com/login")

    def test_gau_plugin(self):
        p = GauPlugin()
        cmd = p.build_command("example.com")
        self.assertIn("gau", cmd[0])
        self.assertIn("--subs", cmd)
        self.assertIn("example.com", cmd)

        stdout = "https://example.com/admin\nhttp://example.com/test?id=1\n"
        records = p.parse_output(stdout)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["url"], "https://example.com/admin")
        self.assertEqual(records[0]["source"], "gau")

        # Test version extraction
        with patch.object(p, "is_installed", return_value=True), \
             patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(stdout="gau version: 2.2.4\n", stderr="")
            self.assertEqual(p.get_version(), "v2.2.4")

    def test_waybackurls_plugin(self):
        p = WaybackurlsPlugin()
        cmd = p.build_command("example.com")
        self.assertIn("waybackurls", cmd[0])
        self.assertIn("example.com", cmd)

        stdout = "https://example.com/index.php\nhttps://example.com/docs/\n"
        records = p.parse_output(stdout)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["url"], "https://example.com/index.php")
        self.assertEqual(records[0]["source"], "waybackurls")

    def test_naabu_plugin(self):
        p = NaabuPlugin()
        cmd = p.build_command("example.com")
        self.assertIn("naabu", cmd[0])
        self.assertIn("-top-ports", cmd)
        self.assertIn("100", cmd)

        stdout = json.dumps({"host": "api.example.com", "ip": "192.0.2.1", "port": 8443}) + "\n"
        records = p.parse_output(stdout)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["host"], "api.example.com")
        self.assertEqual(records[0]["ip"], "192.0.2.1")
        self.assertEqual(records[0]["port"], 8443)

    def test_nuclei_plugin(self):
        p = NucleiPlugin()
        cmd = p.build_command("targets.txt", tags="cve,misconfig")
        self.assertIn("nuclei", cmd[0])
        self.assertIn("-list", cmd)
        self.assertIn("-tags", cmd)
        self.assertIn("cve,misconfig", cmd)

        stdout = json.dumps({
            "template-id": "git-config-disclosure",
            "info": {
                "name": "Git Config Disclosure",
                "severity": "medium",
                "description": "Git configuration is publicly accessible.",
            },
            "host": "api.example.com",
            "matched-at": "https://api.example.com/.git/config",
            "matcher-name": "git-status",
        }) + "\n"

        records = p.parse_output(stdout)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["template_id"], "git-config-disclosure")
        self.assertEqual(records[0]["name"], "Git Config Disclosure")
        self.assertEqual(records[0]["severity"], "medium")
        self.assertEqual(records[0]["matched_at"], "https://api.example.com/.git/config")


class TestHttpxCollisionResolution(unittest.TestCase):
    """Test resolution and identity verification of ProjectDiscovery httpx vs Python httpx."""

    def setUp(self):
        self.plugin = HttpxPlugin()
        self.plugin.reset_resolution()

    @patch("subprocess.run")
    @patch("reconflow.plugins._find_binary_candidates")
    def test_httpx_pd_correct_resolution(self, mock_candidates, mock_run):
        """(a) Correct ProjectDiscovery httpx is verified and used."""
        mock_candidates.return_value = ["/usr/local/bin/httpx"]
        mock_proc = MagicMock()
        mock_proc.stdout = "[INF] Current Version: v1.6.8\nprojectdiscovery.io\n"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        path = self.plugin.resolve(force=True)
        self.assertEqual(path, "/usr/local/bin/httpx")
        self.assertTrue(self.plugin.is_installed())
        self.assertEqual(self.plugin.get_binary_path(), "/usr/local/bin/httpx")
        self.assertEqual(self.plugin.get_version(), "v1.6.8")
        self.assertIsNone(self.plugin.get_clashed_path())

    @patch("subprocess.run")
    @patch("reconflow.plugins._find_binary_candidates")
    def test_httpx_python_on_path_first_with_pd_later(self, mock_candidates, mock_run):
        """(b) Python httpx is on PATH first; reconflow skips it and selects PD httpx later."""
        mock_candidates.return_value = [
            "/usr/bin/httpx",
            "/home/user/go/bin/httpx",
        ]

        def fake_run(cmd, **kwargs):
            mock_proc = MagicMock()
            if cmd[0] == "/usr/bin/httpx":
                # Simulates the Python CLI failing -version with unrecognized option
                mock_proc.stdout = "Usage: httpx [OPTIONS] URL\nError: No such option '-e'."
                mock_proc.stderr = ""
                mock_proc.returncode = 1
            elif cmd[0] == "/home/user/go/bin/httpx":
                mock_proc.stdout = "projectdiscovery.io\n[INF] Current Version: v1.12.0"
                mock_proc.stderr = ""
                mock_proc.returncode = 0
            else:
                mock_proc.returncode = 127
            return mock_proc

        mock_run.side_effect = fake_run

        path = self.plugin.resolve(force=True)
        self.assertEqual(path, "/home/user/go/bin/httpx")
        self.assertTrue(self.plugin.is_installed())
        self.assertEqual(self.plugin.get_binary_path(), "/home/user/go/bin/httpx")
        self.assertEqual(self.plugin.get_version(), "v1.12.0")
        self.assertEqual(self.plugin.get_clashed_path(), "/usr/bin/httpx")

    @patch("subprocess.run")
    @patch("reconflow.plugins._find_binary_candidates")
    def test_httpx_only_wrong_python_cli_found(self, mock_candidates, mock_run):
        """(c) Only the wrong Python httpx CLI is found; tool is treated as MISSING."""
        mock_candidates.return_value = ["/usr/bin/httpx"]
        mock_proc = MagicMock()
        mock_proc.stdout = "Usage: httpx [OPTIONS] URL\nError: No such option '-e'."
        mock_proc.stderr = ""
        mock_proc.returncode = 1
        mock_run.return_value = mock_proc

        path = self.plugin.resolve(force=True)
        self.assertIsNone(path)
        self.assertFalse(self.plugin.is_installed())
        self.assertIsNone(self.plugin.get_binary_path())
        self.assertEqual(self.plugin.get_clashed_path(), "/usr/bin/httpx")

        reason = self.plugin.get_missing_reason()
        expected = (
            "httpx found at /usr/bin/httpx but it is not ProjectDiscovery httpx "
            "(name clash with the Python httpx CLI). Install: go install -v "
            "github.com/projectdiscovery/httpx/cmd/httpx@latest, or set the path in "
            "reconflow.toml."
        )
        self.assertEqual(reason, expected)

    @patch.dict(os.environ, {"RECONFLOW_HTTPX": "/opt/custom/httpx"})
    @patch("pathlib.Path.is_file", return_value=True)
    def test_env_override_checked_first(self, mock_isfile):
        """RECONFLOW_HTTPX environment variable is prioritized as a candidate."""
        from reconflow.plugins import _find_binary_candidates

        candidates = _find_binary_candidates("httpx", ["httpx"])
        self.assertIn("/opt/custom/httpx", candidates)
        self.assertEqual(candidates[0], "/opt/custom/httpx")

    @patch("subprocess.run")
    @patch("reconflow.plugins._find_binary_candidates")
    def test_other_pd_tools_identity_verification(self, mock_candidates, mock_run):
        """Identity check applies to other ProjectDiscovery tools like subfinder."""
        from reconflow.plugins import SubfinderPlugin

        sub_plugin = SubfinderPlugin()
        sub_plugin.reset_resolution()

        mock_candidates.return_value = ["/usr/bin/subfinder"]
        mock_proc = MagicMock()
        mock_proc.stdout = "[INF] Current Version: v2.17.0\nprojectdiscovery.io\n"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        path = sub_plugin.resolve(force=True)
        self.assertEqual(path, "/usr/bin/subfinder")
        self.assertTrue(sub_plugin.is_installed())


if __name__ == "__main__":
    unittest.main()
