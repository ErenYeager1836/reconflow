"""Unit tests for reconflow doctor diagnostic subcommand."""

import io
import unittest
from unittest.mock import patch

from reconflow.cli import main
from reconflow.doctor import check_toolchain


class TestDoctor(unittest.TestCase):
    """Test doctor tool diagnostics and CLI routing."""

    def test_check_toolchain_renders_table(self):
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            missing_count = check_toolchain()
            output = mock_out.getvalue()
            self.assertIn("reconflow doctor", output)
            self.assertIn("subfinder", output)
            self.assertIn("dnsx", output)
            self.assertIn("httpx", output)
            self.assertIn("naabu", output)
            self.assertIn("katana", output)
            self.assertIn("gau", output)
            self.assertIn("waybackurls", output)
            self.assertIn("nuclei", output)
            self.assertIsInstance(missing_count, int)

    def test_cli_dispatch_doctor(self):
        with patch("reconflow.doctor.check_toolchain") as mock_check:
            with self.assertRaises(SystemExit) as cm:
                main(["doctor"])
            self.assertEqual(cm.exception.code, 0)
            self.assertTrue(mock_check.called)

    def test_doctor_httpx_clash_message(self):
        """Doctor reports clear name clash message when only Python httpx is found."""
        from reconflow.plugins import get_plugin

        httpx_plugin = get_plugin("httpx")
        reason = (
            "httpx found at /usr/bin/httpx but it is not ProjectDiscovery httpx "
            "(name clash with the Python httpx CLI). Install: go install -v "
            "github.com/projectdiscovery/httpx/cmd/httpx@latest, or set the path in "
            "reconflow.toml."
        )
        with patch.object(httpx_plugin, "is_installed", return_value=False), \
             patch.object(httpx_plugin, "get_missing_reason", return_value=reason), \
             patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            check_toolchain()
            out = mock_out.getvalue()
            self.assertIn("name clash with the Python httpx CLI", out)
            self.assertIn("/usr/bin/httpx", out)


if __name__ == "__main__":
    unittest.main()
