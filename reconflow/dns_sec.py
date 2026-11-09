"""
reconflow.dns_sec
-----------------
Audits DNSSEC security posture, CAA (Certificate Authority Authorization) records,
and checks for dangling or unregistered authoritative nameservers (NS takeover).
Uses standard DoH (DNS-over-HTTPS via RFC 8484) with no external library dependencies.
"""

from __future__ import annotations

import json
import socket
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

DOH_PROVIDERS: List[str] = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
]

# Known cloud DNS providers susceptible to dangling NS or zone claiming if deleted
VULNERABLE_NS_PATTERNS: List[str] = [
    "awsdns",
    "azure-dns",
    "nsone.net",
    "ns1.com",
    "googledomains.com",
    "digitalocean.com",
    "linode.com",
]


def query_doh(name: str, record_type: str, timeout: int = 5) -> Dict[str, Any]:
    """Query DNS over HTTPS (DoH) via JSON API."""
    clean_name = name.strip().strip(".").lower()
    params = urllib.parse.urlencode({"name": clean_name, "type": record_type})
    headers = {"Accept": "application/dns-json", "User-Agent": "reconflow-dns-audit/1.0"}

    for doh_url in DOH_PROVIDERS:
        full_url = f"{doh_url}?{params}"
        req = urllib.request.Request(full_url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                if isinstance(data, dict):
                    return data
        except Exception:
            continue
    return {}


def audit_dnssec(domain: str, timeout: int = 5) -> Dict[str, Any]:
    """Check if the domain has DNSSEC enabled, signed, or missing."""
    clean_domain = domain.strip().strip(".").lower()
    ds_resp = query_doh(clean_domain, "DS", timeout=timeout)
    dnskey_resp = query_doh(clean_domain, "DNSKEY", timeout=timeout)

    has_ds = bool(ds_resp.get("Answer"))
    has_dnskey = bool(dnskey_resp.get("Answer"))
    ad_flag = bool(ds_resp.get("AD") or dnskey_resp.get("AD"))

    if has_ds and has_dnskey:
        status = "SIGNED"
        desc = "DNSSEC is enabled and active. Domain is protected against DNS spoofing."
    elif has_ds and not has_dnskey:
        status = "MISCONFIGURED"
        desc = "Parent zone has DS record but DNSKEY is missing or invalid (DNS resolution broken)."
    elif not has_ds and has_dnskey:
        status = "PARTIAL"
        desc = "Zone is signed locally with DNSKEY but parent delegation has no DS record."
    else:
        status = "UNSIGNED"
        desc = "DNSSEC is not enabled. Domain is susceptible to DNS cache poisoning/spoofing."

    ds_records = [a.get("data", "") for a in ds_resp.get("Answer", []) if a.get("data")]

    return {
        "status": status,
        "is_signed": status == "SIGNED",
        "description": desc,
        "has_ds_record": has_ds,
        "has_dnskey": has_dnskey,
        "authenticated_data": ad_flag,
        "ds_records": ds_records,
    }


def audit_caa(domain: str, timeout: int = 5) -> Dict[str, Any]:
    """Inspect RFC 6844 Certificate Authority Authorization (CAA) records."""
    clean_domain = domain.strip().strip(".").lower()
    caa_resp = query_doh(clean_domain, "CAA", timeout=timeout)
    answers = caa_resp.get("Answer", [])

    parsed_caa: List[Dict[str, str]] = []
    for a in answers:
        raw_data = str(a.get("data", ""))
        # DoH formats CAA answers as e.g. '0 issue "letsencrypt.org"'
        parts = raw_data.replace('"', '').split()
        if len(parts) >= 3:
            parsed_caa.append({
                "flag": parts[0],
                "tag": parts[1],
                "value": " ".join(parts[2:]),
            })
        elif raw_data:
            parsed_caa.append({"raw": raw_data})

    issue_allowed = [c["value"] for c in parsed_caa if c.get("tag") == "issue"]
    issuewild_allowed = [c["value"] for c in parsed_caa if c.get("tag") == "issuewild"]
    iodef = [c["value"] for c in parsed_caa if c.get("tag") == "iodef"]

    has_caa = len(parsed_caa) > 0
    if has_caa:
        summary = f"Restricted: allows {', '.join(issue_allowed or ['none'])} to issue certificates"
    else:
        summary = "Missing CAA: any CA in the WebPKI can issue valid certificates for this domain"

    return {
        "has_caa": has_caa,
        "status": "PROTECTED" if has_caa else "MISSING",
        "summary": summary,
        "records": parsed_caa,
        "issue_cas": issue_allowed,
        "issuewild_cas": issuewild_allowed,
        "iodef_reporting": iodef,
    }


def audit_nameservers(domain: str, timeout: int = 5) -> Dict[str, Any]:
    """Enumerate authoritative nameservers and detect dangling/unresolvable delegations."""
    clean_domain = domain.strip().strip(".").lower()
    ns_resp = query_doh(clean_domain, "NS", timeout=timeout)
    answers = ns_resp.get("Answer", [])

    nameservers: List[str] = []
    for a in answers:
        ns = a.get("data", "").rstrip(".")
        if ns:
            nameservers.append(ns)

    ns_details: List[Dict[str, Any]] = []
    dangling_ns: List[Dict[str, Any]] = []

    for ns in nameservers:
        resolved_ips: List[str] = []
        is_dangling = False
        error_msg = ""

        try:
            infos = socket.getaddrinfo(ns, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            resolved_ips = sorted(list(set(item[4][0] for item in infos)))
        except (socket.gaierror, OSError) as e:
            is_dangling = True
            error_msg = str(e)

        cloud_provider = None
        ns_lower = ns.lower()
        for pat in VULNERABLE_NS_PATTERNS:
            if pat in ns_lower:
                cloud_provider = pat
                break

        item_dict = {
            "nameserver": ns,
            "ips": resolved_ips,
            "is_resolving": not is_dangling,
            "is_dangling": is_dangling,
            "cloud_provider": cloud_provider,
            "error": error_msg,
        }
        ns_details.append(item_dict)

        if is_dangling:
            dangling_ns.append(item_dict)

    return {
        "nameservers_count": len(nameservers),
        "nameservers": nameservers,
        "details": ns_details,
        "dangling_nameservers": dangling_ns,
        "has_dangling_ns": len(dangling_ns) > 0,
    }


def audit_dns_security(domain: str, output_dir: Path, timeout: int = 5) -> Dict[str, Any]:
    """Run complete DNS infrastructure, DNSSEC, CAA, and Nameserver audit."""
    clean_domain = domain.strip().strip(".").lower()
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Auditing DNS infrastructure for {clean_domain} (DNSSEC, CAA, Nameservers)...")

    dnssec = audit_dnssec(clean_domain, timeout=timeout)
    caa = audit_caa(clean_domain, timeout=timeout)
    ns = audit_nameservers(clean_domain, timeout=timeout)

    result = {
        "domain": clean_domain,
        "dnssec": dnssec,
        "caa": caa,
        "nameservers": ns,
    }

    out_file = output_dir / "dns_audit.json"
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")

    status_str = (
        f"DNSSEC: {dnssec['status']} | CAA: {caa['status']} | NS: {ns['nameservers_count']}"
    )
    if ns["has_dangling_ns"]:
        status_str += f" | CRITICAL: {len(ns['dangling_nameservers'])} dangling NS!"
        print(f"[!] CRITICAL: Found dangling nameservers on {clean_domain}! Check {out_file.name}")
    else:
        print(f"[+] DNS security audit complete ({status_str}) -> {out_file.name}")

    return result
