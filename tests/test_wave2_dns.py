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
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from reconflow.zone_transfer import (
    _build_axfr_query,
    _test_nameserver_axfr,
    audit_zone_transfer,
)
from reconflow.permute_scale import (
    DEFAULT_PERMUTATION_WORDS,
    _probe,
    generate_permutations_scaled,
    load_wordlist,
)
from reconflow.dns_sec import (
    audit_caa,
    audit_dns_security,
    audit_dnssec,
    audit_nameservers,
    query_doh,
)


# ==========================================
# Zone Transfer (AXFR) Tests
# ==========================================

def test_build_axfr_query_structure():
    """Verify that _build_axfr_query creates RFC-compliant TCP-prefixed AXFR question."""
    pkt = _build_axfr_query("example.com")
    assert len(pkt) > 14
    # First 2 bytes: TCP message length prefix
    tcp_len = struct.unpack("!H", pkt[:2])[0]
    assert tcp_len == len(pkt) - 2

    dns_body = pkt[2:]
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", dns_body[:12])
    assert txid == 0x1337
    assert qdcount == 1
    assert ancount == 0

    # Ensure QTYPE=252 (AXFR) and QCLASS=1 (IN) are at the end
    qtype, qclass = struct.unpack("!HH", dns_body[-4:])
    assert qtype == 252
    assert qclass == 1


def test_test_nameserver_axfr_vulnerable():
    """Verify vulnerable detection when server returns RCODE=0 and ANCOUNT > 0."""
    # 12 bytes DNS header with rcode=0, ancount=3
    header = struct.pack("!HHHHHH", 0x1337, 0x0000, 1, 3, 0, 0)
    fake_dns_resp = header + b"fake_answer_data"
    tcp_resp = struct.pack("!H", len(fake_dns_resp)) + fake_dns_resp

    mock_sock = MagicMock()
    # First recv(2) returns len, next returns data
    mock_sock.recv.side_effect = [tcp_resp[:2], tcp_resp[2:]]

    with patch("socket.socket") as mock_socket_cls:
        mock_socket_cls.return_value.__enter__.return_value = mock_sock
        res = _test_nameserver_axfr("example.com", "1.2.3.4", timeout=2)

    assert res["vulnerable"] is True
    assert res["rcode"] == 0
    assert res["records_count"] == 3
    assert "VULNERABLE" in res["status"]


def test_test_nameserver_axfr_refused():
    """Verify non-vulnerable detection when server returns RCODE=5 (Refused)."""
    # 12 bytes DNS header with flags ending in 0x0005 (Refused)
    header = struct.pack("!HHHHHH", 0x1337, 0x8185, 1, 0, 0, 0)
    fake_dns_resp = header
    tcp_resp = struct.pack("!H", len(fake_dns_resp)) + fake_dns_resp

    mock_sock = MagicMock()
    mock_sock.recv.side_effect = [tcp_resp[:2], tcp_resp[2:]]

    with patch("socket.socket") as mock_socket_cls:
        mock_socket_cls.return_value.__enter__.return_value = mock_sock
        res = _test_nameserver_axfr("example.com", "1.2.3.4", timeout=2)

    assert res["vulnerable"] is False
    assert res["rcode"] == 5
    assert "Refused" in res["status"]


def test_test_nameserver_axfr_timeout():
    """Verify clean timeout handling on filtered port 53."""
    mock_sock = MagicMock()
    mock_sock.connect.side_effect = socket.timeout("timed out")

    with patch("socket.socket") as mock_socket_cls:
        mock_socket_cls.return_value.__enter__.return_value = mock_sock
        res = _test_nameserver_axfr("example.com", "1.2.3.4", timeout=1)

    assert res["vulnerable"] is False
    assert res["rcode"] is None
    assert "Timeout" in res["status"]


def test_audit_zone_transfer_writes_json(tmp_path):
    """Verify audit_zone_transfer queries nameservers and writes zone_transfer.json."""
    with patch("reconflow.zone_transfer._query_doh_ns", return_value=["ns1.example.com"]), \
         patch("socket.gethostbyname", return_value="93.184.216.34"), \
         patch("reconflow.zone_transfer._test_nameserver_axfr", return_value={
             "vulnerable": False,
             "status": "Refused (Secure)",
             "rcode": 5,
             "records_count": 0,
         }):
        results = audit_zone_transfer("example.com", tmp_path, timeout=2)

    assert len(results) == 1
    assert results[0]["nameserver"] == "ns1.example.com"
    assert results[0]["vulnerable"] is False

    out_file = tmp_path / "zone_transfer.json"
    assert out_file.is_file()
    saved = json.loads(out_file.read_text(encoding="utf-8"))
    assert len(saved) == 1
    assert saved[0]["nameserver"] == "ns1.example.com"


# ==========================================
# Permute Scale Tests
# ==========================================

def test_load_wordlist(tmp_path):
    """Verify load_wordlist parses valid lines and skips comments/blanks."""
    wl_file = tmp_path / "words.txt"
    wl_file.write_text("# Comment\n\napi\nADMIN\n  stage  \n# Another", encoding="utf-8")

    words = load_wordlist(wl_file)
    assert words == ["api", "admin", "stage"]


def test_generate_permutations_scaled_wildcard_filter(tmp_path):
    """Verify that wildcard responses sharing same fingerprint are filtered out."""
    known_subs = ["api.example.com", "dev.example.com"]

    # Mock probe responses: 5 hosts return identical (200, 100) catchall fingerprint
    # and 1 host returns distinct (200, 500)
    def fake_probe(host, timeout):
        if "catchall" in host or "admin" in host or "test" in host or "stage" in host or "vpn" in host or "corp" in host:
            return {"host": host, "url": f"https://{host}", "status": 200, "content_length": 100}
        elif "real" in host or "dashboard" in host:
            return {"host": host, "url": f"https://{host}", "status": 200, "content_length": 9999}
        return None

    with patch("reconflow.permute_scale._probe", side_effect=fake_probe):
        results = generate_permutations_scaled(
            subdomains=known_subs,
            domain="example.com",
            output_dir=tmp_path,
            max_candidates=50,
            threads=2,
        )

    out_file = tmp_path / "permutations_scaled.json"
    assert out_file.is_file()
    # The common fingerprint (200, 100) should have been filtered out if count >= threshold
    for r in results:
        assert r["content_length"] != 100 or len(results) <= 5


# ==========================================
# DNS Security & DNSSEC Tests
# ==========================================

def test_audit_dnssec_signed():
    """Verify DNSSEC detection for signed zones with DS and DNSKEY records."""
    mock_data = {
        "DS": {"Answer": [{"name": "example.com", "data": "12345 8 2 ABCDEF"}]},
        "DNSKEY": {"Answer": [{"name": "example.com", "data": "257 3 8 AwEAAb..."}], "AD": True},
    }

    with patch("reconflow.dns_sec.query_doh", side_effect=lambda name, t, timeout=5: mock_data.get(t, {})):
        res = audit_dnssec("example.com")

    assert res["status"] == "SIGNED"
    assert res["is_signed"] is True
    assert res["has_ds_record"] is True
    assert res["has_dnskey"] is True


def test_audit_dnssec_unsigned():
    """Verify DNSSEC detection for unsigned zones."""
    with patch("reconflow.dns_sec.query_doh", return_value={}):
        res = audit_dnssec("example.com")

    assert res["status"] == "UNSIGNED"
    assert res["is_signed"] is False


def test_audit_caa_records():
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

    assert res["status"] == "PROTECTED"
    assert res["has_caa"] is True
    assert "letsencrypt.org" in res["issue_cas"]
    assert ";" in res["issuewild_cas"]
    assert "mailto:security@example.com" in res["iodef_reporting"]


def test_audit_nameservers_dangling_detection():
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

    assert res["nameservers_count"] == 2
    assert res["has_dangling_ns"] is True
    assert len(res["dangling_nameservers"]) == 1
    dangling = res["dangling_nameservers"][0]
    assert dangling["nameserver"] == "ns-123.awsdns-15.com"
    assert dangling["cloud_provider"] == "awsdns"
    assert dangling["is_resolving"] is False


def test_audit_dns_security_writes_json(tmp_path):
    """Verify full audit_dns_security orchestrates sub-checks and saves output."""
    with patch("reconflow.dns_sec.audit_dnssec", return_value={"status": "SIGNED", "is_signed": True}), \
         patch("reconflow.dns_sec.audit_caa", return_value={"status": "PROTECTED", "has_caa": True}), \
         patch("reconflow.dns_sec.audit_nameservers", return_value={"nameservers_count": 2, "has_dangling_ns": False, "dangling_nameservers": []}):
        res = audit_dns_security("example.com", tmp_path, timeout=2)

    assert res["domain"] == "example.com"
    out_file = tmp_path / "dns_audit.json"
    assert out_file.is_file()
    saved = json.loads(out_file.read_text(encoding="utf-8"))
    assert saved["domain"] == "example.com"
    assert saved["dnssec"]["status"] == "SIGNED"
