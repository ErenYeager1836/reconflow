"""
tests.test_wave2_dns
--------------------
Unit tests for Wave 2: DNS & Discovery Expansion modules:
- zone_transfer.py (AXFR query generation, socket parsing, DoH discovery)
- permute_scale.py (wordlist loading, permutation generation, wildcard filtering)
- dns_sec.py (DNSSEC validation, CAA record parsing, dangling NS detection)
"""

import json
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from reconflow.dns_sec import (
    audit_caa,
    audit_dns_security,
    audit_dnssec,
    audit_nameservers,
)
from reconflow.permute_scale import (
    generate_permutations_scaled,
    load_wordlist,
)
from reconflow.zone_transfer import (
    _build_axfr_query,
    _test_nameserver_axfr,
    audit_zone_transfer,
)


class TestWave2ZoneTransfer(unittest.TestCase):
    """Test suite for zone_transfer.py AXFR functions."""

    def test_build_axfr_query_structure(self):
        """Verify _build_axfr_query creates RFC-compliant TCP-prefixed AXFR question."""
        pkt = _build_axfr_query("example.com")
        self.assertGreater(len(pkt), 14)
        tcp_len = struct.unpack("!H", pkt[:2])[0]
        self.assertEqual(tcp_len, len(pkt) - 2)

        dns_body = pkt[2:]
        txid, _, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", dns_body[:12])
        self.assertEqual(txid, 0x1337)
        self.assertEqual(qdcount, 1)
        self.assertEqual(ancount, 0)

        qtype, qclass = struct.unpack("!HH", dns_body[-4:])
        self.assertEqual(qtype, 252)
        self.assertEqual(qclass, 1)

    @patch("socket.socket")
    def test_test_nameserver_axfr_vulnerable(self, mock_socket_cls):
        """Verify vulnerable detection when server returns RCODE=0 and ANCOUNT > 0."""
        header = struct.pack("!HHHHHH", 0x1337, 0x0000, 1, 3, 0, 0)
        fake_dns_resp = header + b"fake_answer_data"
        tcp_resp = struct.pack("!H", len(fake_dns_resp)) + fake_dns_resp

        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [tcp_resp[:2], tcp_resp[2:]]
        mock_socket_cls.return_value.__enter__.return_value = mock_sock

        res = _test_nameserver_axfr("example.com", "1.2.3.4", timeout=2)
        self.assertTrue(res["vulnerable"])
        self.assertEqual(res["rcode"], 0)
        self.assertEqual(res["records_count"], 3)
        self.assertIn("VULNERABLE", res["status"])

    @patch("socket.socket")
    def test_test_nameserver_axfr_refused(self, mock_socket_cls):
        """Verify non-vulnerable detection when server returns RCODE=5 (Refused)."""
        header = struct.pack("!HHHHHH", 0x1337, 0x8185, 1, 0, 0, 0)
        fake_dns_resp = header
        tcp_resp = struct.pack("!H", len(fake_dns_resp)) + fake_dns_resp

        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [tcp_resp[:2], tcp_resp[2:]]
        mock_socket_cls.return_value.__enter__.return_value = mock_sock

        res = _test_nameserver_axfr("example.com", "1.2.3.4", timeout=2)
        self.assertFalse(res["vulnerable"])
        self.assertEqual(res["rcode"], 5)
        self.assertIn("Refused", res["status"])

    @patch("socket.socket")
    def test_test_nameserver_axfr_timeout(self, mock_socket_cls):
        """Verify clean timeout handling on filtered port 53."""
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = socket.timeout("timed out")
        mock_socket_cls.return_value.__enter__.return_value = mock_sock

        res = _test_nameserver_axfr("example.com", "1.2.3.4", timeout=1)
        self.assertFalse(res["vulnerable"])
        self.assertIsNone(res["rcode"])
        self.assertIn("Timeout", res["status"])

    def test_audit_zone_transfer_writes_json(self):
        """Verify audit_zone_transfer queries nameservers and writes zone_transfer.json."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with patch("reconflow.zone_transfer._query_doh_ns", return_value=["ns1.example.com"]), \
                 patch("socket.gethostbyname", return_value="93.184.216.34"), \
                 patch("reconflow.zone_transfer._test_nameserver_axfr", return_value={
                     "vulnerable": False,
                     "status": "Refused (Secure)",
                     "rcode": 5,
                     "records_count": 0,
                 }):
                results = audit_zone_transfer("example.com", tmp_path, timeout=2)

            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["nameserver"], "ns1.example.com")
            self.assertFalse(results[0]["vulnerable"])

            out_file = tmp_path / "zone_transfer.json"
            self.assertTrue(out_file.is_file())
            saved = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(len(saved), 1)


class TestWave2PermuteScale(unittest.TestCase):
    """Test suite for permute_scale.py mutation and wildcard filtering."""

    def test_load_wordlist(self):
        """Verify load_wordlist parses valid lines and skips comments/blanks."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            wl_file = Path(tmp_dir) / "words.txt"
            wl_file.write_text("# Comment\n\napi\nADMIN\n  stage  \n# Another", encoding="utf-8")
            words = load_wordlist(wl_file)
            self.assertEqual(words, ["api", "admin", "stage"])

    def test_generate_permutations_scaled_wildcard_filter(self):
        """Verify that wildcard responses sharing same fingerprint are filtered out."""
        known_subs = ["api.example.com", "dev.example.com"]

        def fake_probe(host, timeout):
            catchall_kw = ("catchall", "admin", "test", "stage", "vpn", "corp")
            if any(k in host for k in catchall_kw):
                return {
                    "host": host,
                    "url": f"https://{host}",
                    "status": 200,
                    "content_length": 100,
                }
            elif "real" in host or "dashboard" in host:
                return {
                    "host": host,
                    "url": f"https://{host}",
                    "status": 200,
                    "content_length": 9999,
                }
            return None

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with patch("reconflow.permute_scale._probe", side_effect=fake_probe):
                results = generate_permutations_scaled(
                    subdomains=known_subs,
                    domain="example.com",
                    output_dir=tmp_path,
                    max_candidates=50,
                    threads=2,
                )

            out_file = tmp_path / "permutations_scaled.json"
            self.assertTrue(out_file.is_file())
            for r in results:
                self.assertTrue(r["content_length"] != 100 or len(results) <= 5)


class TestWave2DNSSecurity(unittest.TestCase):
    """Test suite for dns_sec.py DNSSEC, CAA, and nameserver auditing."""

    def test_audit_dnssec_signed(self):
        """Verify DNSSEC detection for signed zones with DS and DNSKEY records."""
        mock_data = {
            "DS": {"Answer": [{"name": "example.com", "data": "12345 8 2 ABCDEF"}]},
            "DNSKEY": {
                "Answer": [{"name": "example.com", "data": "257 3 8 AwEAAb..."}],
                "AD": True,
            },
        }

        with patch(
            "reconflow.dns_sec.query_doh",
            side_effect=lambda name, t, timeout=5: mock_data.get(t, {}),
        ):
            res = audit_dnssec("example.com")

        self.assertEqual(res["status"], "SIGNED")
        self.assertTrue(res["is_signed"])
        self.assertTrue(res["has_ds_record"])
        self.assertTrue(res["has_dnskey"])

    def test_audit_dnssec_unsigned(self):
        """Verify DNSSEC detection for unsigned zones."""
        with patch("reconflow.dns_sec.query_doh", return_value={}):
            res = audit_dnssec("example.com")

        self.assertEqual(res["status"], "UNSIGNED")
        self.assertFalse(res["is_signed"])

    def test_audit_caa_records(self):
        """Verify parsing of CAA DNS records."""
        mock_caa_resp = {
            "Answer": [
                {"data": '0 issue "letsencrypt.org"'},
                {"data": '0 issuewild ";"'},
                {"data": '0 iodef "mailto:security@example.com"'},
            ]
        }

        with patch("reconflow.dns_sec.query_doh", return_value=mock_caa_resp):
            res = audit_caa("example.com")

        self.assertEqual(res["status"], "PROTECTED")
        self.assertTrue(res["has_caa"])
        self.assertIn("letsencrypt.org", res["issue_cas"])
        self.assertIn(";", res["issuewild_cas"])
        self.assertIn("mailto:security@example.com", res["iodef_reporting"])

    def test_audit_nameservers_dangling_detection(self):
        """Verify dangling NS detection for unresolvable cloud provider nameservers."""
        mock_ns_resp = {
            "Answer": [
                {"data": "ns-123.awsdns-15.com."},
                {"data": "ns-456.awsdns-20.org."},
            ]
        }

        def fake_getaddrinfo(host, port, family, socktype):
            if "ns-123" in host:
                raise socket.gaierror("Name or service not known")
            return [(2, 1, 6, "", ("205.251.192.1", 0))]

        with patch("reconflow.dns_sec.query_doh", return_value=mock_ns_resp), \
             patch("socket.getaddrinfo", side_effect=fake_getaddrinfo):
            res = audit_nameservers("example.com")

        self.assertEqual(res["nameservers_count"], 2)
        self.assertTrue(res["has_dangling_ns"])
        self.assertEqual(len(res["dangling_nameservers"]), 1)
        dangling = res["dangling_nameservers"][0]
        self.assertEqual(dangling["nameserver"], "ns-123.awsdns-15.com")
        self.assertEqual(dangling["cloud_provider"], "awsdns")
        self.assertFalse(dangling["is_resolving"])

    def test_audit_dns_security_writes_json(self):
        """Verify full audit_dns_security orchestrates sub-checks and saves output."""
        sec_ret = {"status": "SIGNED", "is_signed": True}
        caa_ret = {"status": "PROTECTED", "has_caa": True}
        ns_ret = {"nameservers_count": 2, "has_dangling_ns": False, "dangling_nameservers": []}

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with patch("reconflow.dns_sec.audit_dnssec", return_value=sec_ret), \
                 patch("reconflow.dns_sec.audit_caa", return_value=caa_ret), \
                 patch("reconflow.dns_sec.audit_nameservers", return_value=ns_ret):
                res = audit_dns_security("example.com", tmp_path, timeout=2)

            self.assertEqual(res["domain"], "example.com")
            out_file = tmp_path / "dns_audit.json"
            self.assertTrue(out_file.is_file())
            saved = json.loads(out_file.read_text(encoding="utf-8"))
            self.assertEqual(saved["domain"], "example.com")
            self.assertEqual(saved["dnssec"]["status"], "SIGNED")


if __name__ == "__main__":
    unittest.main()
