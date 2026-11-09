"""
tests.test_wave3_vulns
-----------------------
Unit tests for Wave 3: Vulnerability & External OSINT modules:
- cve_correlate.py (NVD CVE API v2.0 lookup, technology parsing, rate limiting)
- github_leaks.py (GitHub code search API, query templating, leak detection)
- audits.py (Cloud storage detection, CNAME audit, WAF detection, security headers, favicons)
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from reconflow.audits import (
    audit_email_security,
    audit_sensitive_files,
    detect_cloud_assets,
    detect_waf,
    fingerprint_favicons,
    grade_security_headers,
)
from reconflow.cve_correlate import _query_nvd, correlate_cves
from reconflow.github_leaks import search_github_leaks


class TestWave3CVECorrelate(unittest.TestCase):
    """Test suite for cve_correlate.py NVD correlation."""

    def test_query_nvd_parsing(self):
        """Verify _query_nvd parses CVE ID, CVSS score, and description from NVD v2.0 JSON."""
        fake_nvd_resp = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-12345",
                        "descriptions": [
                            {"lang": "en", "value": "A critical vulnerability in Apache."}
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {
                                    "baseScore": 9.8, "baseSeverity": "CRITICAL"
                                }}
                            ]
                        },
                    }
                }
            ]
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(fake_nvd_resp).encode("utf-8")

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value.__enter__.return_value = mock_resp
            results = _query_nvd("apache:2.4.49", timeout=2)

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["cve_id"], "CVE-2023-12345")
        self.assertEqual(results[0]["cvss_score"], 9.8)
        self.assertEqual(results[0]["severity"], "CRITICAL")

    def test_correlate_cves_filters_generic_and_writes_json(self):
        """Verify correlate_cves ignores generic tags and writes cve_correlation.json."""
        httpx_records = [
            {"technologies": ["html5", "cloudflare", "Apache:2.4.49"]},
            {"tech": ["css", "WordPress:6.0"]},
        ]
        fake_cve = [{
            "cve_id": "CVE-2023-9999", "summary": "Sample issue",
            "cvss_score": 7.5, "severity": "HIGH",
        }]

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with patch("reconflow.cve_correlate._query_nvd", return_value=fake_cve):
                findings = correlate_cves(
                    httpx_records=httpx_records,
                    output_dir=tmp_path,
                    delay_between_requests=0.01,
                )

            queried_techs = [f["technology"] for f in findings]
            self.assertNotIn("html5", queried_techs)
            self.assertNotIn("cloudflare", queried_techs)

            out_file = tmp_path / "cve_correlation.json"
            self.assertTrue(out_file.is_file())
            saved = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(len(saved), len(findings))


class TestWave3GitHubLeaks(unittest.TestCase):
    """Test suite for github_leaks.py secret searching."""

    def test_github_leaks_without_token(self):
        """Verify search_github_leaks gracefully skips when no token is configured."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with patch.dict("os.environ", {}, clear=True):
                res = search_github_leaks("example.com", tmp_path, token=None)
            self.assertEqual(res, [])

    def test_github_leaks_with_token(self):
        """Verify search_github_leaks executes queries and parses repository matches."""
        fake_gh_resp = {
            "items": [
                {
                    "repository": {"full_name": "target-corp/infra-config"},
                    "path": "deploy/.env.prod",
                    "html_url": (
                        "https://github.com/target-corp/infra-config/blob/main/deploy/.env.prod"
                    ),
                    "score": 1.0,
                }
            ]
        }
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps(fake_gh_resp).encode("utf-8")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with patch("urllib.request.urlopen") as mock_urlopen, patch("time.sleep"):
                mock_urlopen.return_value.__enter__.return_value = mock_resp
                results = search_github_leaks(
                    "example.com", tmp_path, token="ghp_test123", max_queries=1
                )

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["repo"], "target-corp/infra-config")
            self.assertEqual(results[0]["path"], "deploy/.env.prod")

            out_file = tmp_path / "github_leaks.json"
            self.assertTrue(out_file.is_file())
            saved = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(len(saved), 1)


class TestWave3Audits(unittest.TestCase):
    """Test suite for audits.py defensive auditing modules."""

    def test_detect_cloud_assets(self):
        """Verify detect_cloud_assets regex identifies S3 and GCS bucket references."""
        urls = [
            "https://my-company-assets.s3.amazonaws.com/logo.png",
            "https://storage.googleapis.com/backup-data/archive.zip",
            "https://example.com/index.html",
        ]
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            res = detect_cloud_assets(urls, [], tmp_path)
            self.assertEqual(len(res), 2)
            providers = {r["provider"] for r in res}
            self.assertIn("AWS S3", providers)
            self.assertIn("Google Cloud Storage", providers)

            out_file = tmp_path / "cloud_assets.json"
            self.assertTrue(out_file.is_file())

    def test_audit_sensitive_files(self):
        """Verify audit_sensitive_files flags exposed Git and config files."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"ref: refs/heads/main\n"

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.return_value.__enter__.return_value = mock_resp
                findings = audit_sensitive_files(
                    ["https://admin.example.com"], tmp_path, timeout=1
                )

            git_findings = [f for f in findings if f["file"] == "/.git/HEAD"]
            self.assertEqual(len(git_findings), 1)
            self.assertIn("Exposed Git repository", git_findings[0]["description"])

            out_file = tmp_path / "sensitive_files.json"
            self.assertTrue(out_file.is_file())

    def test_detect_waf_fingerprint(self):
        """Verify detect_waf identifies Cloudflare from response headers."""
        mock_resp = MagicMock()
        mock_resp.headers = {"cf-ray": "84829104-IAD", "server": "cloudflare"}

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.return_value.__enter__.return_value = mock_resp
                results = detect_waf(["https://example.com"], tmp_path, timeout=1)

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["waf"], "Cloudflare")
            self.assertTrue(results[0]["protected"])

            out_file = tmp_path / "waf_detection.json"
            self.assertTrue(out_file.is_file())

    def test_audit_email_security(self):
        """Verify audit_email_security parses SPF and DMARC enforcement policies."""
        def fake_query_doh(name, rtype, timeout=5):
            if rtype == "MX":
                return ["10 mail.example.com"]
            if rtype == "TXT" and "_dmarc" in name:
                return ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
            if rtype == "TXT":
                return ["v=spf1 include:_spf.google.com -all"]
            return []

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with patch("reconflow.audits._query_doh", side_effect=fake_query_doh):
                res = audit_email_security("example.com", tmp_path, timeout=1)

            self.assertEqual(res["spf"]["status"], "HardFail (Strict)")
            self.assertFalse(res["spf"]["spoofable"])
            self.assertEqual(res["dmarc"]["policy"], "Reject (Enforced)")
            self.assertFalse(res["dmarc"]["spoofable"])
            self.assertTrue(res["mx_present"])

            out_file = tmp_path / "email_security.json"
            self.assertTrue(out_file.is_file())

    def test_grade_security_headers_perfect_score(self):
        """Verify grade_security_headers assigns A+ when all defensive headers are present."""
        mock_resp = MagicMock()
        mock_resp.headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.return_value.__enter__.return_value = mock_resp
                grades = grade_security_headers(["https://secure.example.com"], tmp_path, timeout=1)

            self.assertEqual(len(grades), 1)
            self.assertEqual(grades[0]["grade"], "A+")
            self.assertEqual(grades[0]["score"], 100)
            self.assertEqual(len(grades[0]["missing_headers"]), 0)

            out_file = tmp_path / "security_grades.json"
            self.assertTrue(out_file.is_file())

    def test_fingerprint_favicons_matching(self):
        """Verify fingerprint_favicons matches Spring Boot MD5 hash."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b"favicon_bytes"

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with patch("urllib.request.urlopen") as mock_urlopen, patch("hashlib.md5") as mock_md5:
                mock_urlopen.return_value.__enter__.return_value = mock_resp
                mock_hash_obj = MagicMock()
                mock_hash_obj.hexdigest.return_value = "9f1700676b701a2f6442f9b8c322b2b1"
                mock_md5.return_value = mock_hash_obj

                findings = fingerprint_favicons(["https://app.example.com"], tmp_path, timeout=1)

            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["technology"], "Spring Boot")
            self.assertTrue(findings[0]["matched"])

            out_file = tmp_path / "favicon_fingerprints.json"
            self.assertTrue(out_file.is_file())


if __name__ == "__main__":
    unittest.main()
