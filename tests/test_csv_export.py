"""CSV export regression tests (no network calls or scanning tools required)."""
import argparse
import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reconflow.cli import build_parser
from reconflow.report import CSV_COLUMNS, export_csv
from reconflow.scan import run as run_scan


class TestCSVExport(unittest.TestCase):
    def test_cli_flag_is_opt_in(self):
        parser = build_parser()
        self.assertFalse(parser.parse_args(["scan", "example.com"]).csv)
        self.assertTrue(parser.parse_args(["scan", "example.com", "--csv"]).csv)

    def test_header_and_rfc4180_escaping(self):
        with tempfile.TemporaryDirectory() as folder:
            path = export_csv("example.com", [
                {
                    "url": "https://api.example.com:443/path?q=1",
                    "ip": "203.0.113.2",
                    "status_code": 200,
                    "title": 'Hello, "world"\nNew line',
                    "technologies": ["React", "Django"],
                    "cname": "edge.example.net",
                    "takeover_risk": False,
                }
            ], folder)
            content = path.read_text(encoding="utf-8")
            self.assertIn('"Hello, ""world""\nNew line"', content)
            with path.open(newline="", encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(len(rows), 1)
            self.assertEqual(tuple(rows[0]), CSV_COLUMNS)
            self.assertEqual(rows[0]["subdomain"], "api.example.com")
            self.assertEqual(rows[0]["ip"], "203.0.113.2")
            self.assertEqual(rows[0]["title"], 'Hello, "world"\nNew line')
            self.assertEqual(rows[0]["technologies"], "React; Django")
            self.assertEqual(rows[0]["takeover_risk"], "False")

    def test_missing_fields_and_explicit_subdomain(self):
        with tempfile.TemporaryDirectory() as folder:
            path = export_csv("example.com", [
                {"subdomain": "sub.example.com", "status_code": 0},
                {"url": "https://x.example.com"},
                {"title": "no host"},
            ], folder)
            with path.open(newline="", encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual([r["subdomain"] for r in rows],
                             ["sub.example.com", "x.example.com", "example.com"])
            self.assertEqual(rows[0]["status_code"], "0")
            self.assertEqual(rows[2]["ip"], "")
            self.assertEqual(rows[2]["cname"], "")

    def test_no_hosts_produces_header_only(self):
        with tempfile.TemporaryDirectory() as folder:
            path = export_csv("example.com", [], folder)
            with path.open(newline="", encoding="utf-8") as stream:
                rows = list(csv.reader(stream))
            self.assertEqual(rows, [list(CSV_COLUMNS)])

    @patch("reconflow.scan.check_tools")
    @patch("reconflow.scan.find_subdomains", return_value=[])
    def test_scan_flag_generates_csv_without_network(self, _find, _check):
        with tempfile.TemporaryDirectory() as folder:
            args = argparse.Namespace(
                domain="example.com", output=folder, csv=True,
                json_report=False, screenshots=False, scope=None,
                keep_wildcard=False, threads=1, timeout=1,
            )
            result = run_scan(args)
            file = Path(result["output_dir"]) / "report.csv"
            self.assertTrue(file.is_file())
            with file.open(newline="", encoding="utf-8") as stream:
                self.assertEqual(next(csv.reader(stream)), list(CSV_COLUMNS))


if __name__ == "__main__":
    unittest.main()
