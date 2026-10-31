"""Tests for SQLite state storage, resume capability, and extended diffing."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from reconflow import db, diff, scan


class TestSQLiteDB(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "reconflow.db"

    def tearDown(self):
        self.tmp.cleanup()

    def test_run_lifecycle_and_stages(self):
        db.record_run_start(self.db_path, "run_01", "example.com")
        last = db.get_last_run(self.db_path, "example.com")
        self.assertIsNotNone(last)
        self.assertEqual(last["id"], "run_01")
        self.assertEqual(last["status"], "running")
        self.assertEqual(last["stages_completed"], [])

        db.record_stage_completed(self.db_path, "run_01", "subdomains")
        db.record_stage_completed(self.db_path, "run_01", "http")
        # duplicate stage recording should be idempotent
        db.record_stage_completed(self.db_path, "run_01", "http")

        stages = db.get_completed_stages(self.db_path, "run_01")
        self.assertEqual(stages, ["subdomains", "http"])

        db.record_run_complete(self.db_path, "run_01", "completed")
        last = db.get_last_run(self.db_path, "example.com")
        self.assertEqual(last["status"], "completed")

    def test_save_and_retrieve_entities(self):
        run_id = "run_test"
        domain = "example.com"
        db.record_run_start(self.db_path, run_id, domain)

        # Subdomains
        db.save_subdomains(self.db_path, domain, run_id, ["a.example.com", "b.example.com"])
        subs = db.get_subdomains(self.db_path, domain, run_id)
        self.assertEqual(subs, ["a.example.com", "b.example.com"])

        # DNS
        db.save_dns_records(
            self.db_path,
            domain,
            run_id,
            [{"host": "a.example.com", "ips": ["1.2.3.4"], "cnames": ["cdn.net"]}],
        )

        # Hosts
        db.save_hosts(
            self.db_path,
            domain,
            run_id,
            [
                {
                    "host": "a.example.com",
                    "url": "https://a.example.com",
                    "status_code": 200,
                    "title": "Welcome",
                    "technologies": ["Nginx"],
                }
            ],
        )
        hosts = db.get_hosts(self.db_path, domain, run_id)
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]["url"], "https://a.example.com")
        self.assertEqual(hosts[0]["technologies"], ["Nginx"])

        # URLs
        db.save_urls(self.db_path, domain, run_id, ["https://a.example.com/login"])
        urls = db.get_urls(self.db_path, domain, run_id)
        self.assertEqual(len(urls), 1)
        self.assertEqual(urls[0]["url"], "https://a.example.com/login")

        # Ports
        db.save_ports(
            self.db_path,
            domain,
            run_id,
            [{"host": "a.example.com", "ip": "1.2.3.4", "port": 8443}],
        )
        ports = db.get_ports(self.db_path, domain, run_id)
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0]["port"], 8443)

        # Findings
        db.save_findings(
            self.db_path,
            domain,
            run_id,
            [
                {
                    "template_id": "cve-2023-1234",
                    "name": "Sample CVE",
                    "severity": "medium",
                    "host": "a.example.com",
                    "matched_at": "https://a.example.com/vuln",
                    "matcher_name": "status",
                }
            ],
        )
        findings = db.get_findings(self.db_path, domain, run_id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["template_id"], "cve-2023-1234")

        # Aggregate get_run_data
        data = db.get_run_data(self.db_path, run_id)
        self.assertEqual(len(data["subdomains"]), 2)
        self.assertEqual(len(data["hosts"]), 1)
        self.assertEqual(len(data["urls"]), 1)
        self.assertEqual(len(data["ports"]), 1)
        self.assertEqual(len(data["findings"]), 1)


class TestExtendedDiff(unittest.TestCase):
    def test_diff_new_ports_urls_and_findings(self):
        old_data = {
            "subdomains": ["a.com"],
            "hosts": [{"url": "https://a.com", "status_code": 200}],
            "ports": [{"host": "a.com", "port": 80}],
            "urls": ["https://a.com/index.html"],
            "findings": [
                {
                    "template_id": "tech-detect",
                    "host": "https://a.com",
                    "matcher_name": "nginx",
                    "name": "Nginx Detect",
                    "severity": "info",
                }
            ],
        }

        new_data = {
            "subdomains": ["a.com", "b.com"],
            "hosts": [
                {"url": "https://a.com", "status_code": 200},
                {"url": "https://b.com", "status_code": 200},
            ],
            "ports": [
                {"host": "a.com", "port": 80},
                {"host": "a.com", "port": 8080},
                {"host": "b.com", "port": 443},
            ],
            "urls": [
                "https://a.com/index.html",
                "https://a.com/api/v1/users",
            ],
            "findings": [
                {
                    "template_id": "tech-detect",
                    "host": "https://a.com",
                    "matcher_name": "nginx",
                    "name": "Nginx Detect",
                    "severity": "info",
                },
                {
                    "template_id": "cve-2024-9999",
                    "host": "https://b.com",
                    "matcher_name": "version",
                    "name": "Critical RCE",
                    "severity": "critical",
                },
            ],
        }

        res = diff.compare(old_data, new_data)
        self.assertIn("b.com", res["new_subdomains"])
        self.assertEqual(res["new_ports"]["a.com"], [8080])
        self.assertEqual(res["new_ports"]["b.com"], [443])
        self.assertEqual(res["new_urls"], ["https://a.com/api/v1/users"])
        self.assertEqual(len(res["new_findings"]), 1)
        self.assertEqual(res["new_findings"][0]["template_id"], "cve-2024-9999")

        formatted = diff.format_diff(res, "run1", "run2")
        self.assertIn("NEW OPEN PORTS", formatted)
        self.assertIn("8080", formatted)
        self.assertIn("NEW ENDPOINTS / URLS", formatted)
        self.assertIn("/api/v1/users", formatted)
        self.assertIn("NEW VULNERABILITY FINDINGS", formatted)
        self.assertIn("[CRITICAL] Critical RCE", formatted)


class TestResumeScan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out_dir = Path(self.tmp.name) / "output"
        self.domain = "resume.example.com"
        self.target_dir = self.out_dir / self.domain
        self.target_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.target_dir / "reconflow.db"

    def tearDown(self):
        self.tmp.cleanup()

    @patch("reconflow.scan.probe_hosts")
    @patch("reconflow.scan.find_subdomains")
    def test_resume_skips_completed_stages(self, mock_find, mock_probe):
        run_id = "test_incomplete_run"
        runs_dir = self.target_dir / "runs" / run_id
        runs_dir.mkdir(parents=True, exist_ok=True)

        # Seed subdomains.txt and SQLite db with "subdomains" stage marked completed
        (self.target_dir / "subdomains.txt").write_text(
            "sub.resume.example.com\n", encoding="utf-8"
        )
        db.record_run_start(self.db_path, run_id, self.domain)
        db.record_stage_completed(self.db_path, run_id, "subdomains")
        db.save_subdomains(self.db_path, self.domain, run_id, ["sub.resume.example.com"])

        # Configure probe mock
        mock_probe.return_value = (
            ["https://sub.resume.example.com"],
            [{
                "host": "sub.resume.example.com",
                "url": "https://sub.resume.example.com",
                "status_code": 200,
            }],
        )

        args = MagicMock()
        args.domain = self.domain
        args.output = str(self.out_dir)
        args.resume = True
        args.dry_run = False
        args.silent = True
        args.stages = "subdomains,http"
        args.skip = None
        args.scope = None
        args.rate = None
        args.threads = 5
        args.timeout = 2
        args.intrusive = False
        args.all_vulns = False
        args.keep_wildcard = True
        args.json_report = False
        args.csv = False
        args.screenshots = False

        with patch("reconflow.scan.resolve_httpx_binary", return_value="httpx"):
            res = scan._run_scan(args)

        # find_subdomains should NOT be called because subdomains was already completed!
        mock_find.assert_not_called()
        # probe_hosts SHOULD be called for the remaining http stage
        mock_probe.assert_called_once()

        self.assertEqual(res["run_id"], run_id)
        # Verify db now has http stage completed and run status is completed
        last_run = db.get_last_run(self.db_path, self.domain)
        self.assertEqual(last_run["status"], "completed")
        self.assertIn("http", last_run["stages_completed"])
