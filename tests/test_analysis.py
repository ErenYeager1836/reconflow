"""Tests for Round 4 analysis features: takeover detection, JS mining, and lead scoring."""

import json
import tempfile
import unittest
from pathlib import Path

from reconflow import db, leads, mining, report, takeover


class TestSubdomainTakeover(unittest.TestCase):
    def test_github_pages_detection(self):
        cnames = ["foo.github.io"]
        body = "404: There isn't a GitHub Pages site here."
        res = takeover.check_host_takeover("blog.example.com", cnames=cnames, response_body=body)
        self.assertIsNotNone(res)
        self.assertEqual(res["service"], "GitHub Pages")
        self.assertEqual(res["confidence"], "candidate, verify manually")
        self.assertIn("github.io", res["cname"])

    def test_aws_s3_detection(self):
        cnames = ["assets.example.com.s3.amazonaws.com"]
        body = (
            "<Error><Code>NoSuchBucket</Code>"
            "<Message>The specified bucket does not exist</Message></Error>"
        )
        res = takeover.check_host_takeover("assets.example.com", cnames=cnames, response_body=body)
        self.assertIsNotNone(res)
        self.assertEqual(res["service"], "AWS S3")
        self.assertEqual(res["confidence"], "candidate, verify manually")

    def test_dangling_cname_without_body(self):
        cnames = ["myapp.herokuapp.com"]
        res = takeover.check_host_takeover("app.example.com", cnames=cnames, response_body="")
        self.assertIsNotNone(res)
        self.assertEqual(res["service"], "Heroku")
        self.assertEqual(res["confidence"], "candidate, verify manually")

    def test_benign_host_no_match(self):
        cnames = ["mycdn.cloudflare.net"]
        body = "<html><body>Welcome</body></html>"
        res = takeover.check_host_takeover("www.example.com", cnames=cnames, response_body=body)
        self.assertIsNone(res)

    def test_detect_takeovers_aggregation(self):
        hosts_data = [
            {
                "url": "https://docs.example.com",
                "cname": ["docs.github.io"],
                "body": "There isn't a GitHub Pages site here",
            },
            {
                "url": "https://normal.example.com",
                "cname": ["normal.example.com"],
                "body": "OK",
            },
        ]
        candidates = takeover.detect_takeovers(hosts_data)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["host"], "docs.example.com")
        self.assertEqual(candidates[0]["service"], "GitHub Pages")


class TestJSMining(unittest.TestCase):
    def test_mask_secret(self):
        raw = "AKIAIOSFODNN7EXAMPLE"
        masked = mining.mask_secret(raw, prefix_len=4)
        self.assertEqual(masked, "AKIA****************")
        self.assertNotIn("EXAMPLE", masked)
        self.assertEqual(len(masked), len(raw))

    def test_mine_js_content_endpoints_and_subdomains(self):
        js = """
        const API_URL = "/api/v2/users";
        const auth = 'https://auth.example.com/oauth/token';
        const cdn = "//static.example.com/bundle.js";
        const internalRoute = "/admin/dashboard?export=csv";
        """
        res = mining.mine_js_content(
            js, base_url="https://app.example.com", target_domain="example.com"
        )
        endpoints = res["endpoints"]
        self.assertTrue(any("/api/v2/users" in ep for ep in endpoints))
        self.assertTrue(any("admin/dashboard" in ep for ep in endpoints))
        self.assertIn("auth.example.com", res["subdomains"])
        self.assertIn("static.example.com", res["subdomains"])

    def test_mine_js_secrets_masked(self):
        js = """
        // AWS credentials
        const awsKey = "AKIA1234567890ABCDEF";
        // Google API key (39 chars: AIza + 35 chars)
        const gKey = "AIzaSyD-1234567890abcdefghijklmnopqrstu";
        // Slack webhook / token
        const slack = "xoxb-1234567890-abcdef123456";
        """
        res = mining.mine_js_content(js)
        secrets = res["secrets"]
        self.assertEqual(len(secrets), 3)

        types = [s["type"] for s in secrets]
        self.assertIn("AWS Access Key ID", types)
        self.assertIn("Google API Key", types)
        self.assertIn("Slack Token", types)

        # Ensure no plaintext secret leaked
        for s in secrets:
            self.assertTrue("*" in s["masked"])
            self.assertNotIn("ABCDEF", s["masked"])
            self.assertNotIn("ghijklmn", s["masked"])

    def test_filter_js_urls(self):
        urls = [
            "https://example.com/app.js",
            "https://example.com/main.js?v=1.2",
            "https://example.com/index.html",
            "https://example.com/style.css",
        ]
        js_urls = mining.filter_js_urls(urls)
        self.assertEqual(len(js_urls), 2)
        self.assertIn("https://example.com/app.js", js_urls)
        self.assertIn("https://example.com/main.js?v=1.2", js_urls)

    def test_fake_aws_key_never_stored_or_exported_in_plaintext(self):
        """Verify fake AWS key through mining, database storage, and reports is never raw."""
        fake_key = "AKIAIOSFODNN7EXAMPLE"
        js = f'const AWS_KEY = "{fake_key}";'

        # 1. Mining
        mined = mining.mine_js_content(js)
        self.assertEqual(len(mined["secrets"]), 1)
        masked_val = mined["secrets"][0]["masked"]
        self.assertEqual(masked_val, "AKIA****************")
        self.assertNotIn("EXAMPLE", masked_val)
        self.assertNotIn(fake_key, masked_val)

        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            domain = "example.com"
            run_id = "test_run_secrets"

            # 2. Database storage
            db_path = out_dir / "reconflow.db"
            findings = [
                {
                    "template_id": "exposed-aws-key",
                    "name": "Exposed AWS Access Key",
                    "severity": "high",
                    "host": "api.example.com",
                    "matched_at": "https://api.example.com/app.js",
                    "matcher_name": "aws-access-key-id",
                    "description": f"Exposed secret: {masked_val}",
                }
            ]
            db.save_findings(db_path, domain, run_id, findings)
            live_hosts = [
                {
                    "url": "https://api.example.com",
                    "subdomain": "api.example.com",
                    "ip": "93.184.216.34",
                    "status_code": 200,
                    "title": f"API Portal [{masked_val}]",
                }
            ]
            db.save_hosts(db_path, domain, run_id, live_hosts)

            # Assert (a): SQLite DB contains no raw key
            db_bytes = db_path.read_bytes().decode("latin1", errors="ignore")
            self.assertNotIn(fake_key, db_bytes)
            persisted_findings = db.get_findings(db_path, domain)
            self.assertEqual(len(persisted_findings), 1)
            self.assertIn("AKIA****************", persisted_findings[0]["description"])
            self.assertNotIn(fake_key, persisted_findings[0]["description"])

            # 3. Reports
            # Assert (b): JSON report
            json_dict = report.build_json_report(
                domain, run_id, "2026-10-31", ["api.example.com"], live_hosts
            )
            json_str = json.dumps(json_dict)
            self.assertNotIn(fake_key, json_str)
            self.assertIn("AKIA****************", json_str)

            # Assert (c): Markdown report
            md_str = report.build_markdown_report(
                domain, run_id, "2026-10-31", ["api.example.com"], live_hosts
            )
            self.assertNotIn(fake_key, md_str)
            self.assertIn("AKIA****************", md_str)

            # Assert (d): CSV report
            csv_path = report.export_csv(domain, live_hosts, out_dir)
            csv_str = csv_path.read_text(encoding="utf-8")
            self.assertNotIn(fake_key, csv_str)
            self.assertIn("AKIA****************", csv_str)

            # Assert (e): SARIF report
            sarif_path = report.export_sarif(domain, findings, out_dir)
            sarif_str = sarif_path.read_text(encoding="utf-8")
            self.assertNotIn(fake_key, sarif_str)
            self.assertIn("AKIA****************", sarif_str)


class TestLeadScoring(unittest.TestCase):
    def test_score_lead(self):
        score_high = leads.score_lead("https://admin.staging.example.com/api/v1/actuator/heapdump")
        score_low = leads.score_lead("https://example.com/about-us")
        self.assertGreater(score_high, 50)
        self.assertEqual(score_low, 0)

        score_params = leads.score_lead("https://example.com/login?redirect=https://evil.com")
        self.assertGreater(score_params, 20)

    def test_rank_leads(self):
        targets = [
            "https://example.com/about",
            "https://admin.example.com/login",
            "https://api.example.com/swagger/index.html",
        ]
        ranked = leads.rank_leads(targets)
        self.assertEqual(len(ranked), 3)
        self.assertEqual(ranked[0]["target"], "https://admin.example.com/login")
        self.assertEqual(ranked[1]["target"], "https://api.example.com/swagger/index.html")
        self.assertEqual(ranked[2]["target"], "https://example.com/about")
