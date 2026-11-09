"""
reconflow.zone_transfer
-------------------------
Audits authoritative DNS nameservers for DNS Zone Transfer (AXFR) misconfigurations.
If a nameserver allows unrestricted AXFR queries, an attacker can extract the entire
internal and external DNS zone map without brute-forcing.

Implementation is 100% standard library (socket + struct + urllib for DoH discovery),
requiring zero external tools or dependencies.
"""

from __future__ import annotations

import json
import socket
import struct
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List


def _query_doh_ns(domain: str, timeout: int = 5) -> List[str]:
    """Query Cloudflare and Google DoH for authoritative NS records."""
    clean_domain = domain.strip().strip(".").lower()
    endpoints = [
        f"https://cloudflare-dns.com/dns-query?name={clean_domain}&type=NS",
        f"https://dns.google/resolve?name={clean_domain}&type=NS",
    ]
    for url in endpoints:
        try:
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/dns-json", "User-Agent": "reconflow-axfr/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                answers = data.get("Answer", [])
                ns_list = [
                    a.get("data", "").rstrip(".")
                    for a in answers
                    if a.get("data")
                ]
                if ns_list:
                    return sorted(set(ns_list))
        except Exception:
            continue
    return []


def _build_axfr_query(domain: str) -> bytes:
    """Build a raw DNS AXFR (QTYPE=252, QCLASS=1) TCP message prefixed with 2-byte length."""
    # 12-byte DNS header: TXID=0x1337, Flags=0x0000, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    header = struct.pack("!HHHHHH", 0x1337, 0x0000, 1, 0, 0, 0)

    # QNAME encoding (e.g., \x07example\x03com\x00)
    labels = domain.strip().strip(".").split(".")
    qname = b"".join(bytes([len(lbl)]) + lbl.encode("ascii", errors="ignore") for lbl in labels)
    qname += b"\x00"

    # QTYPE=252 (AXFR), QCLASS=1 (IN)
    question = qname + struct.pack("!HH", 252, 1)
    dns_packet = header + question

    # TCP length prefix (2 bytes, big-endian)
    return struct.pack("!H", len(dns_packet)) + dns_packet


def _test_nameserver_axfr(domain: str, ns_ip: str, timeout: int = 6) -> Dict[str, Any]:
    """Send an AXFR request to a nameserver over TCP port 53 and evaluate response."""
    msg = _build_axfr_query(domain)

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ns_ip, 53))
            s.sendall(msg)

            # Read 2-byte response length
            raw_len = s.recv(2)
            if len(raw_len) < 2:
                return {
                    "vulnerable": False,
                    "status": "Connection closed",
                    "rcode": None,
                    "records_count": 0,
                }

            resp_len = struct.unpack("!H", raw_len)[0]
            resp_data = b""
            while len(resp_data) < resp_len:
                chunk = s.recv(resp_len - len(resp_data))
                if not chunk:
                    break
                resp_data += chunk

        if len(resp_data) < 12:
            return {
                "vulnerable": False,
                "status": "Malformed response",
                "rcode": None,
                "records_count": 0,
            }

        # Parse DNS header (12 bytes: ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
        _, flags, _, ancount, _, _ = struct.unpack("!HHHHHH", resp_data[0:12])
        rcode = flags & 0x000F

        if rcode == 0 and ancount > 0:
            return {
                "vulnerable": True,
                "status": "VULNERABLE (AXFR open)",
                "rcode": 0,
                "records_count": ancount,
            }
        elif rcode == 5:
            return {
                "vulnerable": False,
                "status": "Refused (Secure)",
                "rcode": 5,
                "records_count": 0,
            }
        else:
            return {
                "vulnerable": False,
                "status": f"Not allowed (RCODE {rcode})",
                "rcode": rcode,
                "records_count": 0,
            }
    except (socket.timeout, TimeoutError):
        return {
            "vulnerable": False,
            "status": "Timeout (Port 53 filtered)",
            "rcode": None,
            "records_count": 0,
        }
    except ConnectionRefusedError:
        return {"vulnerable": False, "status": "Port 53 closed", "rcode": None, "records_count": 0}
    except Exception as e:
        return {"vulnerable": False, "status": f"Error: {e}", "rcode": None, "records_count": 0}


def audit_zone_transfer(domain: str, output_dir: Path, timeout: int = 5) -> List[Dict[str, Any]]:
    """
    Check all authoritative nameservers for DNS zone transfer misconfiguration.
    Writes findings to output_dir / 'zone_transfer.json'.
    """
    clean_domain = domain.strip().strip(".").lower()
    print(f"[*] Discovering authoritative nameservers for {clean_domain}...")
    nameservers = _query_doh_ns(clean_domain, timeout=timeout)

    if not nameservers:
        print(f"[*] No authoritative nameservers resolved for {clean_domain}")
        return []

    print(f"[*] Testing {len(nameservers)} nameserver(s) for open AXFR zone transfer...")
    results: List[Dict[str, Any]] = []
    vuln_count = 0

    for ns in nameservers:
        try:
            ns_ip = socket.gethostbyname(ns)
        except (socket.gaierror, OSError):
            results.append({
                "nameserver": ns,
                "ip": None,
                "vulnerable": False,
                "status": "Unresolvable nameserver hostname",
                "rcode": None,
                "records_count": 0,
            })
            continue

        test_res = _test_nameserver_axfr(clean_domain, ns_ip, timeout=timeout)
        is_vuln = bool(test_res.get("vulnerable", False))
        if is_vuln:
            vuln_count += 1
            print(f"[!] CRITICAL: DNS Zone Transfer is OPEN on {ns} ({ns_ip})!")

        results.append({
            "nameserver": ns,
            "ip": ns_ip,
            "vulnerable": is_vuln,
            "status": test_res.get("status"),
            "rcode": test_res.get("rcode"),
            "records_count": test_res.get("records_count", 0),
        })

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "zone_transfer.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")

    if vuln_count > 0:
        print(f"[!] CRITICAL: {vuln_count} nameserver(s) vulnerable to full zone transfer!")
    else:
        print(f"[+] All {len(results)} nameserver(s) secured against AXFR zone transfer")

    return results
