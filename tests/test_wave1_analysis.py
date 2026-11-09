"""Unit tests for reconflow Wave 1 modules: jwt_analyzer, params_analyzer, cache_audit."""

import base64
import hashlib
import hmac
import json
import unittest
from unittest.mock import MagicMock, patch

from reconflow.cache_audit import audit_host_cache
from reconflow.jwt_analyzer import analyze_jwt, decode_jwt, extract_jwts
from reconflow.params_analyzer import analyze_parameters, classify_parameter


def _make_jwt(header: dict, payload: dict, secret: str = "secret", alg: str = "HS256") -> str:
    def b64(d: dict) -> str:
        raw = json.dumps(d).encode("utf-8")
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    h_b64 = b64(header)
    p_b64 = b64(payload)
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")

    if alg == "none" or not secret:
        return f"{h_b64}.{p_b64}."

    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")
    return f"{h_b64}.{p_b64}.{sig_b64}"


class TestJwtAnalyzer(unittest.TestCase):
    def test_extract_jwts(self):
        token = _make_jwt({"alg": "HS256"}, {"sub": "12345"})
        text = f"User authenticated with Bearer {token} in header"
        extracted = extract_jwts(text)
        self.assertEqual(len(extracted), 1)
        self.assertEqual(extracted[0], token)

    def test_decode_jwt(self):
        header = {"typ": "JWT", "alg": "HS256"}
        payload = {"sub": "user_123", "role": "admin"}
        token = _make_jwt(header, payload)
        h, p, s = decode_jwt(token)
        self.assertEqual(h["alg"], "HS256")
        self.assertEqual(p["sub"], "user_123")
        self.assertEqual(p["role"], "admin")

    def test_alg_none_vulnerability(self):
        token = _make_jwt({"alg": "none"}, {"sub": "admin"}, secret="")
        report = analyze_jwt(token)
        self.assertEqual(report["risk_level"], "CRITICAL")
        titles = [v["title"] for v in report["vulnerabilities"]]
        self.assertTrue(any("Insecure Algorithm" in t for t in titles))

    def test_weak_hmac_secret_cracked(self):
        token = _make_jwt({"alg": "HS256"}, {"sub": "user", "exp": 9999999999}, secret="password")
        report = analyze_jwt(token)
        self.assertEqual(report["risk_level"], "CRITICAL")
        titles = [v["title"] for v in report["vulnerabilities"]]
        self.assertTrue(any("Weak / Default HMAC Secret Key" in t for t in titles))

    def test_missing_exp_claim(self):
        strong_sec = "a_very_strong_unbruteable_secret_key_12345"
        token = _make_jwt({"alg": "HS256"}, {"sub": "user"}, secret=strong_sec)
        report = analyze_jwt(token)
        titles = [v["title"] for v in report["vulnerabilities"]]
        self.assertTrue(any("Missing Expiration Claim" in t for t in titles))


class TestParamsAnalyzer(unittest.TestCase):
    def test_classify_ssrf_parameters(self):
        self.assertIn("ssrf_open_redirect", classify_parameter("redirect_url"))
        self.assertIn("ssrf_open_redirect", classify_parameter("callback"))
        self.assertIn("ssrf_open_redirect", classify_parameter("target"))

    def test_classify_idor_parameters(self):
        self.assertIn("idor_bola", classify_parameter("user_id"))
        self.assertIn("idor_bola", classify_parameter("account_id"))
        self.assertIn("idor_bola", classify_parameter("uuid"))

    def test_classify_admin_parameters(self):
        self.assertIn("admin_bypass", classify_parameter("is_admin"))
        self.assertIn("admin_bypass", classify_parameter("debug"))
        self.assertIn("admin_bypass", classify_parameter("impersonate"))

    def test_classify_lfi_parameters(self):
        self.assertIn("path_traversal_lfi", classify_parameter("filepath"))
        self.assertIn("path_traversal_lfi", classify_parameter("template"))

    def test_analyze_parameters_matrix(self):
        urls = [
            "https://example.com/api?user_id=123&redirect=https://google.com",
            "https://example.com/page?file=report.pdf&debug=true",
        ]
        result = analyze_parameters([], urls)
        self.assertGreater(result["total_parameters_evaluated"], 0)
        self.assertGreater(result["total_high_value_flagged"], 0)
        categories = result["categories"]
        self.assertIn("ssrf_open_redirect", categories)
        self.assertIn("idor_bola", categories)
        self.assertIn("admin_bypass", categories)
        self.assertIn("path_traversal_lfi", categories)


class TestCacheAudit(unittest.TestCase):
    @patch("urllib.request.urlopen")
    def test_sensitive_data_public_cache(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {
            "Cache-Control": "public, max-age=3600",
            "Set-Cookie": "session_id=secret123; Path=/",
            "CF-Cache-Status": "HIT",
        }
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        result = audit_host_cache("https://example.com/api/user")
        self.assertTrue(result["is_vulnerable"])
        self.assertEqual(result["cdn_detected"], "Cloudflare")
        types = [f["type"] for f in result["findings"]]
        self.assertIn("SENSITIVE_DATA_PUBLIC_CACHE", types)

    @patch("urllib.request.urlopen")
    def test_safe_cache_control(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.headers = {
            "Cache-Control": "no-store, no-cache, private",
            "Set-Cookie": "session_id=secret123; Path=/",
        }
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        result = audit_host_cache("https://example.com/api/user")
        self.assertFalse(result["is_vulnerable"])
        self.assertEqual(len(result["findings"]), 0)


if __name__ == "__main__":
    unittest.main()
