"""
tests.test_wave3_vulns
-----------------------
Unit tests for Wave 3: Vulnerability & External OSINT modules:
- cve_correlate.py (NVD CVE API v2.0 lookup, technology parsing, rate limiting)
- github_leaks.py (GitHub code search API, query templating, leak detection)
- audits.py (Cloud storage detection, CNAME audit, WAF detection, security headers, favicons)
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from reconflow.cve_correlate import _query_nvd, correlate_cves
from reconflow.github_leaks import search_github_leaks
from reconflow.audits import (
    audit_cname_records,
    audit_email_security,
    audit_sensitive_files,
    detect_cloud_assets,
    detect_waf,
    fingerprint_favicons,
    grade_security_headers,
)


# ==========================================
# CVE Correlate Tests
# ==========================================

def test_query_nvd_parsing():
    """Verify _query_nvd parses CVE ID, CVSS score, and description from NVD v2.0 JSON."""
    fake_nvd_resp = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-12345",
                    "descriptions": [{"lang": "en", "value": "A critical vulnerability in Apache."}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
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

    assert len(results) == 1
    assert results[0]["cve_id"] == "CVE-2023-12345"
    assert results[0]["cvss_score"] == 9.8
    assert results[0]["severity"] == "CRITICAL"


def test_correlate_cves_filters_generic_and_writes_json(tmp_path):
    """Verify correlate_cves ignores generic tags and writes cve_correlation.json."""
    httpx_records = [
        {"technologies": ["html5", "cloudflare", "Apache:2.4.49"]},
        {"tech": ["css", "WordPress:6.0"]},
    ]

    fake_cve = [{"cve_id": "CVE-2023-9999", "summary": "Sample issue", "cvss_score": 7.5, "severity": "HIGH"}]

    with patch("reconflow.cve_correlate._query_nvd", return_value=fake_cve):
        findings = correlate_cves(
            httpx_records=httpx_records,
            output_dir=tmp_path,
            delay_between_requests=0.01,
        )

    # Should only query Apache and WordPress (skipping html5, cloudflare, css)
    queried_techs = [f["technology"] for f in findings]
    assert "html5" not in queried_techs
    assert "cloudflare" not in queried_techs
    assert "Apache:2.4.49" in queried_techs or "WordPress:6.0" in queried_techs

    out_file = tmp_path / "cve_correlation.json"
    assert out_file.is_file()
    saved = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(saved) == len(findings)


# ==========================================
# GitHub Leaks Tests
# ==========================================

def test_github_leaks_without_token(tmp_path):
    """Verify search_github_leaks gracefully skips when no token is configured."""
    with patch.dict("os.environ", {}, clear=True):
        res = search_github_leaks("example.com", tmp_path, token=None)
    assert res == []


def test_github_leaks_with_token(tmp_path):
    """Verify search_github_leaks executes queries and parses repository matches."""
    fake_gh_resp = {
        "items": [
            {
                "repository": {"full_name": "target-corp/infra-config"},
                "path": "deploy/.env.prod",
                "html_url": "https://github.com/target-corp/infra-config/blob/main/deploy/.env.prod",
                "score": 1.0,
            }
        ]
    }
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(fake_gh_resp).encode("utf-8")

    with patch("urllib.request.urlopen") as mock_urlopen, \
         patch("time.sleep"):  # skip 2s sleep in test
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        results = search_github_leaks(
            domain="example.com",
            output_dir=tmp_path,
            token="ghp_testtoken123",
            max_queries=1,
        )

    assert len(results) == 1
    assert results[0]["repo"] == "target-corp/infra-config"
    assert results[0]["path"] == "deploy/.env.prod"

    out_file = tmp_path / "github_leaks.json"
    assert out_file.is_file()
    saved = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(saved) == 1


# ==========================================
# Audits Suite Tests
# ==========================================

def test_detect_cloud_assets(tmp_path):
    """Verify detect_cloud_assets regex identifies S3 and GCS bucket references."""
    urls = [
        "https://my-company-assets.s3.amazonaws.com/logo.png",
        "https://storage.googleapis.com/backup-data/archive.zip",
        "https://example.com/index.html",
    ]
    res = detect_cloud_assets(urls, [], tmp_path)
    assert len(res) == 2
    providers = {r["provider"] for r in res}
    assert "AWS S3" in providers
    assert "Google Cloud Storage" in providers

    out_file = tmp_path / "cloud_assets.json"
    assert out_file.is_file()


def test_audit_sensitive_files(tmp_path):
    """Verify audit_sensitive_files flags exposed Git and config files."""
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.read.return_value = b"ref: refs/heads/main\n"

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        findings = audit_sensitive_files(["https://admin.example.com"], tmp_path, timeout=1)

    git_findings = [f for f in findings if f["file"] == "/.git/HEAD"]
    assert len(git_findings) == 1
    assert "Exposed Git repository" in git_findings[0]["description"]

    out_file = tmp_path / "sensitive_files.json"
    assert out_file.is_file()


def test_detect_waf_fingerprint(tmp_path):
    """Verify detect_waf identifies Cloudflare from response headers."""
    mock_resp = MagicMock()
    mock_resp.headers = {"cf-ray": "84829104-IAD", "server": "cloudflare"}

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        results = detect_waf(["https://example.com"], tmp_path, timeout=1)

    assert len(results) == 1
    assert results[0]["waf"] == "Cloudflare"
    assert results[0]["protected"] is True

    out_file = tmp_path / "waf_detection.json"
    assert out_file.is_file()


def test_audit_email_security(tmp_path):
    """Verify audit_email_security parses SPF and DMARC enforcement policies."""
    def fake_query_doh(name, rtype, timeout=5):
        if rtype == "MX":
            return ["10 mail.example.com"]
        if rtype == "TXT" and "_dmarc" in name:
            return ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]
        if rtype == "TXT":
            return ["v=spf1 include:_spf.google.com -all"]
        return []

    with patch("reconflow.audits._query_doh", side_effect=fake_query_doh):
        res = audit_email_security("example.com", tmp_path, timeout=1)

    assert res["spf"]["status"] == "HardFail (Strict)"
    assert res["spf"]["spoofable"] is False
    assert res["dmarc"]["policy"] == "Reject (Enforced)"
    assert res["dmarc"]["spoofable"] is False
    assert res["mx_present"] is True

    out_file = tmp_path / "email_security.json"
    assert out_file.is_file()


def test_grade_security_headers_perfect_score(tmp_path):
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

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        grades = grade_security_headers(["https://secure.example.com"], tmp_path, timeout=1)

    assert len(grades) == 1
    assert grades[0]["grade"] == "A+"
    assert grades[0]["score"] == 100
    assert len(grades[0]["missing_headers"]) == 0

    out_file = tmp_path / "security_grades.json"
    assert out_file.is_file()


def test_fingerprint_favicons_matching(tmp_path):
    """Verify fingerprint_favicons matches Spring Boot MD5 hash."""
    mock_resp = MagicMock()
    mock_resp.status = 200
    # MD5 of b"fake_spring_boot" will not match, so let's mock hashlib.md5
    mock_resp.read.return_value = b"favicon_bytes"

    with patch("urllib.request.urlopen") as mock_urlopen, \
         patch("hashlib.md5") as mock_md5:
        mock_urlopen.return_value.__enter__.return_value = mock_resp
        mock_hash_obj = MagicMock()
        mock_hash_obj.hexdigest.return_value = "9f1700676b701a2f6442f9b8c322b2b1"  # Spring Boot
        mock_md5.return_value = mock_hash_obj

        findings = fingerprint_favicons(["https://app.example.com"], tmp_path, timeout=1)

    assert len(findings) == 1
    assert findings[0]["technology"] == "Spring Boot"
    assert findings[0]["matched"] is True

    out_file = tmp_path / "favicon_fingerprints.json"
    assert out_file.is_file()
