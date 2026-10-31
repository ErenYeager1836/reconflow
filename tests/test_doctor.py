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


if __name__ == "__main__":
    unittest.main()
