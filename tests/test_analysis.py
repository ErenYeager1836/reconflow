"""Tests for Round 4 analysis features: takeover detection, JS mining, and lead scoring."""

import unittest

from reconflow import leads, mining, takeover


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
