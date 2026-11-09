"""
reconflow.audits
-----------------
Comprehensive defensive asset auditing suite:
1. Cloud Asset Identification (AWS S3, GCP Storage, Azure Blob, DigitalOcean)
2. Network ASN & IP range mapping via RDAP
3. HTTP Header & CORS policy audit
4. DNS CNAME validation for dangling provider records (Subdomain Takeover)
5. Certificate Transparency (CT) log harvesting (crt.sh)
6. Exposed sensitive configuration and dev files audit
7. WAF & reverse proxy fingerprinting
8. Route harvesting from /robots.txt and /sitemap.xml
9. Email security & DNS governance (SPF and DMARC)
10. Differential recon change detection (subdomains, hosts, ports)
11. Subdomain Permutations & Mutation Engine
12. SSL/TLS Certificate Security & Expiration Audit
13. Favicon technology fingerprinting
14. RFC 9116 security.txt policy harvester
15. Defensive HTTP response header security grading (A+ to F)
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Regular expressions for public cloud storage endpoints
CLOUD_PATTERNS: Dict[str, re.Pattern] = {
    "AWS S3": re.compile(
        r"(?:https?://)?([a-z0-9.-]+\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com"
        r"|s3\.amazonaws\.com/[a-z0-9.-]+)",
        re.IGNORECASE,
    ),
    "Google Cloud Storage": re.compile(
        r"(?:https?://)?(storage\.googleapis\.com/[a-z0-9_.-]+"
        r"|[a-z0-9_.-]+\.storage\.googleapis\.com)",
        re.IGNORECASE,
    ),
    "Azure Blob Storage": re.compile(
        r"(?:https?://)?([a-z0-9.-]+\.blob\.core\.windows\.net(?:/[a-z0-9.-]+)?)",
        re.IGNORECASE,
    ),
    "DigitalOcean Space": re.compile(
        r"(?:https?://)?([a-z0-9.-]+\.[a-z0-9-]+\.digitaloceanspaces\.com)",
        re.IGNORECASE,
    ),
}

# Known third-party service provider CNAME signatures susceptible to takeover
KNOWN_SERVICE_PROVIDERS: List[str] = [
    ".github.io",
    ".herokuapp.com",
    ".s3-website",
    ".s3.amazonaws.com",
    ".azurewebsites.net",
    ".zendesk.com",
    ".myshopify.com",
    ".fastly.net",
    ".pantheonsite.io",
    ".ghost.io",
    ".surge.sh",
    ".bitbucket.io",
]

PERMUTATION_WORDS: List[str] = [
    "dev", "stage", "staging", "test", "qa", "uat", "admin", "api",
    "internal", "corp", "vpn", "mail", "portal", "app", "v2", "beta",
    "prod", "demo", "gateway", "auth", "sso", "dashboard", "preview",
]


def detect_cloud_assets(
    urls: List[str], live_hosts: List[str], output_dir: Path
) -> List[Dict[str, Any]]:
    """Identify cloud storage bucket references mentioned in discovered URLs and hosts."""
    print("[*] Scanning discovered assets for cloud storage bucket references...")
    candidates = set(urls) | set(live_hosts)
    found_assets: Dict[str, Dict[str, str]] = {}

    for item in candidates:
        for provider, pattern in CLOUD_PATTERNS.items():
            matches = pattern.findall(item)
            for m in matches:
                clean = m.split("?")[0].rstrip("/")
                if clean not in found_assets:
                    found_assets[clean] = {"provider": provider, "source": item}

    results = [{"asset": k, **v} for k, v in found_assets.items()]
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "cloud_assets.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"[+] Identified {len(results)} cloud storage reference(s) -> {out_file.name}")
    return results


def lookup_asn_ranges(
    live_hosts: List[str], output_dir: Path, timeout: int = 5
) -> Dict[str, Any]:
    """Resolve IPs for live hosts and query ASN/network metadata via public RDAP."""
    print("[*] Resolving host IPs and querying ASN / network ranges...")
    host_ip_map: Dict[str, List[str]] = {}
    for h in live_hosts:
        host = h.split("://", 1)[-1].split("/", 1)[0].split(":")[0]
        try:
            ip = socket.gethostbyname(host)
            host_ip_map.setdefault(ip, []).append(host)
        except (socket.gaierror, OSError):
            continue

    asn_results: Dict[str, Any] = {}
    for ip, hosts in list(host_ip_map.items())[:20]:  # Cap to first 20 IPs to stay fast
        try:
            url = f"https://rdap.arin.net/registry/ip/{ip}"
            req = urllib.request.Request(
                url, headers={"User-Agent": "reconflow-audit/1.0", "Accept": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                handle = data.get("handle", "Unknown")
                name = data.get("name", "Unknown")
                asn_results[ip] = {
                    "network_name": name,
                    "handle": handle,
                    "hosts": hosts,
                }
        except Exception:
            asn_results[ip] = {
                "network_name": "Standard Network",
                "handle": "N/A",
                "hosts": hosts,
            }

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "asn_ranges.json"
    out_file.write_text(json.dumps(asn_results, indent=2), encoding="utf-8")
    print(f"[+] Mapped {len(asn_results)} network ranges across live hosts -> {out_file.name}")
    return asn_results


def audit_http_headers(
    live_hosts: List[str], output_dir: Path, timeout: int = 5
) -> List[Dict[str, Any]]:
    """Inspect HTTP response headers for CORS policies and missing security protections."""
    print("[*] Auditing CORS headers and security policies across live hosts...")
    audit_findings: List[Dict[str, Any]] = []

    for host in live_hosts[:25]:
        target_url = host if host.startswith("http") else f"https://{host}"
        try:
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": "reconflow-audit/1.0", "Origin": "https://example.com"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}

                cors_origin = headers.get("access-control-allow-origin")
                cors_creds = headers.get("access-control-allow-credentials")

                missing_sec_headers: List[str] = []
                for sec_h in ["strict-transport-security", "content-security-policy"]:
                    if sec_h not in headers:
                        missing_sec_headers.append(sec_h)

                audit_findings.append({
                    "url": target_url,
                    "cors_origin": cors_origin or "none",
                    "cors_credentials": cors_creds or "false",
                    "missing_security_headers": missing_sec_headers,
                })
        except Exception:
            continue

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "headers_audit.json"
    out_file.write_text(json.dumps(audit_findings, indent=2), encoding="utf-8")
    print(f"[+] Audited HTTP headers across {len(audit_findings)} endpoints -> {out_file.name}")
    return audit_findings


def audit_cname_records(
    subdomains: List[str], output_dir: Path
) -> List[Dict[str, Any]]:
    """Check DNS CNAME records for subdomains pointing to external cloud services."""
    print("[*] Auditing DNS CNAME records for third-party cloud services...")
    flagged: List[Dict[str, Any]] = []

    for sub in subdomains:
        try:
            canonical = socket.getfqdn(sub)
            if canonical and canonical != sub:
                for provider in KNOWN_SERVICE_PROVIDERS:
                    if provider in canonical.lower():
                        # Verify if the canonical name currently resolves to an IP
                        resolves = True
                        try:
                            socket.gethostbyname(canonical)
                        except (socket.gaierror, OSError):
                            resolves = False

                        flagged.append({
                            "subdomain": sub,
                            "cname": canonical,
                            "provider": provider.strip("."),
                            "active_dns": resolves,
                        })
                        break
        except Exception:
            continue

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "cname_audit.json"
    out_file.write_text(json.dumps(flagged, indent=2), encoding="utf-8")
    print(f"[+] Flagged {len(flagged)} external service CNAME record(s) -> {out_file.name}")
    return flagged


def fetch_ct_subdomains(
    domain: str, output_dir: Path, timeout: int = 10
) -> List[str]:
    """Fetch subdomains from public Certificate Transparency logs (crt.sh)."""
    clean_domain = domain.strip().strip(".").lower()
    print(f"[*] Querying Certificate Transparency logs for {clean_domain}...")
    url = f"https://crt.sh/?q=%25.{clean_domain}&output=json"
    discovered: Set[str] = set()
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "reconflow-audit/1.0", "Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            if isinstance(data, list):
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in str(name).splitlines():
                        sub = sub.strip().lower()
                        if sub.startswith("*."):
                            sub = sub[2:]
                        if sub and (sub == clean_domain or sub.endswith(f".{clean_domain}")):
                            discovered.add(sub)
    except Exception as e:
        print(f"[!] Warning: crt.sh query failed or timed out: {e}")

    result = sorted(discovered)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "ct_subdomains.txt"
    out_file.write_text("\n".join(result), encoding="utf-8")
    print(
        f"[+] Found {len(result)} subdomains in Certificate Transparency logs "
        f"-> {out_file.name}"
    )
    return result


SENSITIVE_PATHS: List[Tuple[str, str, List[str]]] = [
    ("/.git/HEAD", "Exposed Git repository", ["ref: refs/"]),
    ("/.env", "Environment config file", ["DB_", "APP_", "AWS_", "SECRET", "KEY="]),
    ("/.well-known/security.txt", "Security policy disclosure", ["Contact:"]),
    ("/swagger.json", "Swagger API Specification", ["swagger", "openapi", "paths"]),
    ("/openapi.json", "OpenAPI Specification", ["openapi", "paths", "info"]),
    ("/actuator/health", "Spring Boot Actuator Health", ["UP", "DOWN", "status"]),
    ("/actuator/env", "Spring Boot Actuator Environment", ["propertySources", "activeProfiles"]),
    ("/docker-compose.yml", "Docker Compose configuration", ["version:", "services:"]),
    ("/phpinfo.php", "PHP Info configuration dump", ["PHP Version"]),
    ("/robots.txt", "Robots policy disclosure", ["User-agent"]),
]


def audit_sensitive_files(
    live_hosts: List[str], output_dir: Path, timeout: int = 5
) -> List[Dict[str, Any]]:
    """Audit live hosts for commonly exposed configuration and sensitive dev files."""
    print("[*] Auditing live hosts for exposed sensitive files and dev artifacts...")
    findings: List[Dict[str, Any]] = []

    for host in live_hosts[:25]:
        base_url = host.rstrip("/")
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"

        for path, description, patterns in SENSITIVE_PATHS:
            target = f"{base_url}{path}"
            try:
                req = urllib.request.Request(
                    target,
                    headers={"User-Agent": "reconflow-audit/1.0"},
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status == 200:
                        body = resp.read(4096).decode("utf-8", errors="ignore")
                        if any(p in body for p in patterns):
                            findings.append({
                                "url": target,
                                "file": path,
                                "description": description,
                                "status": resp.status,
                            })
            except Exception:
                continue

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "sensitive_files.json"
    out_file.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"[+] Flagged {len(findings)} exposed sensitive file(s) -> {out_file.name}")
    return findings


WAF_SIGNATURES: Dict[str, Dict[str, List[str]]] = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "server": ["cloudflare"],
    },
    "AWS CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop"],
        "server": ["cloudfront"],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "x-akamai-request-id"],
        "server": ["akamaighost"],
    },
    "Fastly": {
        "headers": ["x-fastly-request-id", "fastly-debug-digest"],
        "server": ["fastly"],
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "server": ["incapsula"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri"],
    },
}


def detect_waf(
    live_hosts: List[str], output_dir: Path, timeout: int = 5
) -> List[Dict[str, Any]]:
    """Inspect HTTP response headers to fingerprint WAF / CDN reverse proxies."""
    print("[*] Fingerprinting Web Application Firewalls (WAF) & reverse proxies...")
    results: List[Dict[str, Any]] = []

    for host in live_hosts[:30]:
        target_url = host if host.startswith("http") else f"https://{host}"
        detected_waf: Optional[str] = None
        server_banner = "Unknown"
        try:
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": "reconflow-audit/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                server_banner = headers.get("server", "Unknown")

                for waf_name, rules in WAF_SIGNATURES.items():
                    for h in rules["headers"]:
                        if h in headers:
                            detected_waf = waf_name
                            break
                    if detected_waf:
                        break
                    for s in rules["server"]:
                        if s in server_banner.lower():
                            detected_waf = waf_name
                            break
                    if detected_waf:
                        break
        except Exception:
            continue

        results.append({
            "url": target_url,
            "waf": detected_waf or "Direct / No WAF Detected",
            "server": server_banner,
            "protected": detected_waf is not None,
        })

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "waf_detection.json"
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    protected_count = sum(1 for r in results if r["protected"])
    print(
        f"[+] Fingerprinted {len(results)} hosts: "
        f"{protected_count} behind CDN/WAF -> {out_file.name}"
    )
    return results


def harvest_sitemaps(
    live_hosts: List[str], output_dir: Path, timeout: int = 5
) -> Dict[str, Any]:
    """Extract paths from /robots.txt and /sitemap.xml across live hosts."""
    print("[*] Harvesting routes from /robots.txt and /sitemap.xml...")
    discovered_routes: Set[str] = set()
    sitemap_details: Dict[str, List[str]] = {}

    for host in live_hosts[:15]:
        base_url = host.rstrip("/")
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"

        routes_for_host: List[str] = []

        try:
            req = urllib.request.Request(
                f"{base_url}/robots.txt",
                headers={"User-Agent": "reconflow-audit/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    text = resp.read(8192).decode("utf-8", errors="ignore")
                    for line in text.splitlines():
                        line = line.strip()
                        if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                            parts = line.split(":", 1)
                            if len(parts) == 2:
                                val = parts[1].strip()
                                if val and val != "/":
                                    routes_for_host.append(val)
                                    discovered_routes.add(val)
        except Exception:
            pass

        try:
            req = urllib.request.Request(
                f"{base_url}/sitemap.xml",
                headers={"User-Agent": "reconflow-audit/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    xml_data = resp.read(16384).decode("utf-8", errors="ignore")
                    matches = re.findall(r"<loc>(https?://[^<]+)</loc>", xml_data, re.IGNORECASE)
                    for m in matches[:50]:
                        routes_for_host.append(m)
                        discovered_routes.add(m)
        except Exception:
            pass

        if routes_for_host:
            sitemap_details[base_url] = sorted(set(routes_for_host))

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "sitemap_routes.json"
    out_file.write_text(json.dumps(sitemap_details, indent=2), encoding="utf-8")

    txt_file = output_dir / "discovered_routes.txt"
    txt_file.write_text("\n".join(sorted(discovered_routes)), encoding="utf-8")

    print(
        f"[+] Harvested {len(discovered_routes)} unique route(s) across "
        f"{len(sitemap_details)} hosts"
    )
    return sitemap_details


def _query_doh(name: str, rtype: str, timeout: int = 5) -> List[str]:
    """Query DNS over HTTPS (DoH) via Cloudflare or Google DNS."""
    clean_name = name.strip().strip(".").lower()
    endpoints = [
        f"https://cloudflare-dns.com/dns-query?name={clean_name}&type={rtype}",
        f"https://dns.google/resolve?name={clean_name}&type={rtype}",
    ]
    for url in endpoints:
        try:
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/dns-json", "User-Agent": "reconflow-audit/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                answers = data.get("Answer", [])
                return [str(a.get("data", "")).strip('"') for a in answers if a.get("data")]
        except Exception:
            continue
    return []


def audit_email_security(domain: str, output_dir: Path, timeout: int = 5) -> Dict[str, Any]:
    """Audit domain email spoofing protections (SPF and DMARC policies via DoH)."""
    clean_domain = domain.strip().strip(".").lower()
    print(f"[*] Auditing email security & DNS policies for {clean_domain}...")
    result: Dict[str, Any] = {
        "domain": clean_domain,
        "spf": {"record": None, "status": "Missing", "spoofable": True},
        "dmarc": {"record": None, "policy": "Missing", "spoofable": True},
        "mx_present": False,
    }

    mx_records = _query_doh(clean_domain, "MX", timeout=timeout)
    if mx_records:
        result["mx_present"] = True

    txt_records = _query_doh(clean_domain, "TXT", timeout=timeout)
    for r in txt_records:
        if r.startswith("v=spf1"):
            result["spf"]["record"] = r
            if "-all" in r:
                result["spf"]["status"] = "HardFail (Strict)"
                result["spf"]["spoofable"] = False
            elif "~all" in r:
                result["spf"]["status"] = "SoftFail (Permissive)"
                result["spf"]["spoofable"] = False
            elif "+all" in r or "?all" in r:
                result["spf"]["status"] = "Permissive (+all / ?all)"
                result["spf"]["spoofable"] = True
            else:
                result["spf"]["status"] = "Configured"
                result["spf"]["spoofable"] = False
            break

    dmarc_records = _query_doh(f"_dmarc.{clean_domain}", "TXT", timeout=timeout)
    for r in dmarc_records:
        if "v=DMARC1" in r:
            result["dmarc"]["record"] = r
            if "p=reject" in r:
                result["dmarc"]["policy"] = "Reject (Enforced)"
                result["dmarc"]["spoofable"] = False
            elif "p=quarantine" in r:
                result["dmarc"]["policy"] = "Quarantine (Enforced)"
                result["dmarc"]["spoofable"] = False
            elif "p=none" in r:
                result["dmarc"]["policy"] = "None (Monitoring Only - Spoofable)"
                result["dmarc"]["spoofable"] = True
            else:
                result["dmarc"]["policy"] = "Configured"
                result["dmarc"]["spoofable"] = False
            break

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "email_security.json"
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    spf_status = result["spf"]["status"]
    dmarc_policy = result["dmarc"]["policy"]
    print(f"[+] Email Security: SPF={spf_status}, DMARC={dmarc_policy} -> {out_file.name}")
    return result


def compute_differential(
    output_dir: Path,
    domain: str,
    current_subs: List[str],
    current_live: List[str],
    current_ports: Dict[str, List[int]],
) -> Dict[str, Any]:
    """Compare current scan results against previous snapshot to identify changed assets."""
    clean_domain = domain.strip().strip(".").lower()
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    snapshot_file = output_dir / "previous_run.json"

    prev_data: Dict[str, Any] = {}
    if snapshot_file.exists():
        try:
            prev_data = json.loads(snapshot_file.read_text(encoding="utf-8"))
        except Exception:
            prev_data = {}

    prev_subs = set(prev_data.get("subdomains", []))
    prev_live = set(prev_data.get("live_hosts", []))
    prev_ports = prev_data.get("ports", {})

    new_subs = sorted(list(set(current_subs) - prev_subs)) if prev_subs else []
    removed_subs = sorted(list(prev_subs - set(current_subs))) if prev_subs else []
    new_live = sorted(list(set(current_live) - prev_live)) if prev_live else []
    removed_live = sorted(list(prev_live - set(current_live))) if prev_live else []

    new_ports: Dict[str, List[int]] = {}
    for host, ports in current_ports.items():
        prev_h_ports = set(prev_ports.get(host, []))
        diff_p = sorted(list(set(ports) - prev_h_ports))
        if diff_p:
            new_ports[host] = diff_p

    diff_result: Dict[str, Any] = {
        "domain": clean_domain,
        "has_baseline": bool(prev_subs or prev_live),
        "new_subdomains": new_subs,
        "removed_subdomains": removed_subs,
        "new_live_hosts": new_live,
        "removed_live_hosts": removed_live,
        "new_ports": new_ports,
    }

    out_file = output_dir / "diff.json"
    out_file.write_text(json.dumps(diff_result, indent=2), encoding="utf-8")

    current_snapshot = {
        "subdomains": current_subs,
        "live_hosts": current_live,
        "ports": current_ports,
    }
    snapshot_file.write_text(json.dumps(current_snapshot, indent=2), encoding="utf-8")

    if diff_result["has_baseline"]:
        print(f"[+] Diff: +{len(new_subs)} new subdomains, +{len(new_live)} new live hosts, "
              f"+{len(new_ports)} hosts with new ports")
    else:
        print("[+] Diff: Saved baseline snapshot for future change tracking")

    return diff_result


def generate_permutations(
    subdomains: List[str],
    domain: str,
    output_dir: Path,
    max_candidates: int = 300,
    threads: int = 15,
) -> List[str]:
    """Generate intelligent permutations of discovered subdomains and test DNS resolution."""
    clean_domain = domain.strip().strip(".").lower()
    print("[*] Generating subdomain permutations and testing DNS resolution...")
    candidates: Set[str] = set()

    clean_subs: List[str] = []
    suffix = f".{clean_domain}"
    for s in subdomains:
        s_clean = s.lower().strip().strip(".")
        if s_clean.endswith(suffix):
            prefix = s_clean[: -len(suffix)]
            if prefix and "." not in prefix:
                clean_subs.append(prefix)

    clean_subs = sorted(set(clean_subs))[:15]

    for base in clean_subs:
        for word in PERMUTATION_WORDS:
            candidates.add(f"{word}-{base}.{clean_domain}")
            candidates.add(f"{base}-{word}.{clean_domain}")
            candidates.add(f"{word}.{base}.{clean_domain}")
            candidates.add(f"{base}1.{clean_domain}")
            candidates.add(f"{base}2.{clean_domain}")

    for word in PERMUTATION_WORDS:
        candidates.add(f"{word}.{clean_domain}")

    existing_set = {s.strip().strip(".").lower() for s in subdomains}
    candidate_list = [c for c in sorted(candidates) if c not in existing_set][:max_candidates]

    def _resolve(host: str) -> Optional[str]:
        try:
            socket.gethostbyname(host)
            return host
        except (socket.gaierror, OSError):
            return None

    resolved: List[str] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for result in executor.map(_resolve, candidate_list):
            if result:
                resolved.append(result)

    resolved = sorted(resolved)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "permutations.txt"
    out_file.write_text("\n".join(resolved), encoding="utf-8")
    print(f"[+] Identified {len(resolved)} active permutation subdomain(s) -> {out_file.name}")
    return resolved


def audit_ssl_certificates(
    live_hosts: List[str], output_dir: Path, timeout: int = 5
) -> List[Dict[str, Any]]:
    """Inspect SSL/TLS certificates for expiration dates, self-signed certs, and SANs."""
    print("[*] Auditing SSL/TLS certificates and certificate validity...")
    audit_results: List[Dict[str, Any]] = []
    seen_hosts: Set[str] = set()

    for item in live_hosts[:30]:
        host = item.split("://", 1)[-1].split("/", 1)[0].split("?")[0]
        port = 443
        if ":" in host:
            h_part, p_part = host.split(":", 1)
            try:
                port = int(p_part)
                host = h_part
            except ValueError:
                pass

        if host in seen_hosts:
            continue
        seen_hosts.add(host)

        try:
            is_valid = True
            cert: Dict[str, Any] = {}
            tls_version = "Unknown"

            # 1. Attempt verified connection
            try:
                v_ctx = ssl.create_default_context()
                with socket.create_connection((host, port), timeout=timeout) as v_sock:
                    with v_ctx.wrap_socket(v_sock, server_hostname=host) as v_ssock:
                        cert = v_ssock.getpeercert() or {}
                        tls_version = v_ssock.version() or "Unknown"
            except ssl.SSLCertVerificationError:
                is_valid = False
            except Exception:
                is_valid = False

            # 2. If unverified or empty cert, connect with unverified context to get TLS version
            if not cert:
                ctx = ssl._create_unverified_context()
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        tls_version = ssock.version() or tls_version

            expiry_date_str = str(cert.get("notAfter", ""))
            days_remaining: Optional[int] = None
            if expiry_date_str:
                try:
                    exp_dt = datetime.strptime(expiry_date_str, "%b %d %H:%M:%S %Y %Z")
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_remaining = (exp_dt - now).days
                except Exception:
                    pass

            issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
            subject_dict = dict(x[0] for x in cert.get("subject", ()))
            common_iss = issuer_dict.get("commonName", "Unknown")
            issuer_org = issuer_dict.get("organizationName", common_iss)
            common_name = subject_dict.get("commonName", host)

            sans = [val for typ, val in cert.get("subjectAltName", ()) if typ == "DNS"]

            is_self_signed = (
                (issuer_dict == subject_dict and bool(issuer_dict))
                or (not is_valid and not cert)
            )
            is_expiring = bool(days_remaining is not None and days_remaining < 30)

            audit_results.append({
                "host": host,
                "port": port,
                "valid": is_valid,
                "common_name": common_name,
                "issuer": (
                    issuer_org if is_valid else "Untrusted / Self-signed"
                ),
                "days_remaining": days_remaining,
                "self_signed": is_self_signed,
                "expiring_soon": is_expiring,
                "tls_version": tls_version,
                "sans": sans[:10],
            })
        except Exception:
            continue

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "ssl_audit.json"
    out_file.write_text(json.dumps(audit_results, indent=2), encoding="utf-8")
    flagged = sum(1 for r in audit_results if r.get("self_signed") or r.get("expiring_soon"))
    print(
        f"[+] Audited {len(audit_results)} SSL/TLS hosts: "
        f"{flagged} certificate warning(s) -> {out_file.name}"
    )
    return audit_results


KNOWN_FAVICONS: Dict[str, str] = {
    "9f1700676b701a2f6442f9b8c322b2b1": "Spring Boot",
    "0488faca4c3c69c6cf5e40e0beae7d4a": "Jenkins",
    "e9d564ff9f14371fa9d1c75cff02170b": "Apache Tomcat",
    "124b89569e5d4e0828753abdf70c5384": "Jira / Atlassian",
    "60c386629bf57a5814e548846c4f74ab": "Django",
    "c5e933d1c1a9231f471e988be0896eb3": "Laravel",
    "a0c918a0e88beee0840b3ffb6e680a6d": "GitLab",
    "3b573514a6e3d23190df11176b6bf041": "WordPress",
    "485e94be06e682d334582f31f80ec326": "PhpMyAdmin",
    "582ee54ccb7a70183350ad5c29215017": "Kibana",
}


def fingerprint_favicons(
    live_hosts: List[str], output_dir: Path, timeout: int = 5
) -> List[Dict[str, Any]]:
    """Download and hash /favicon.ico to fingerprint underlying web application stacks."""
    print("[*] Fingerprinting web application frameworks via favicon hashes...")
    findings: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    for host in live_hosts[:30]:
        base_url = host.rstrip("/")
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"

        if base_url in seen:
            continue
        seen.add(base_url)

        target = f"{base_url}/favicon.ico"
        try:
            req = urllib.request.Request(
                target,
                headers={"User-Agent": "reconflow-audit/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    data = resp.read(65536)
                    if data:
                        md5_hash = hashlib.md5(data).hexdigest()
                        tech = KNOWN_FAVICONS.get(md5_hash, "Custom / Unknown Favicon")
                        findings.append({
                            "url": base_url,
                            "favicon_url": target,
                            "md5": md5_hash,
                            "technology": tech,
                            "matched": tech != "Custom / Unknown Favicon",
                        })
        except Exception:
            continue

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "favicon_fingerprints.json"
    out_file.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    matched_count = sum(1 for f in findings if f["matched"])
    print(
        f"[+] Downloaded {len(findings)} favicons: "
        f"{matched_count} framework match(es) -> {out_file.name}"
    )
    return findings


def harvest_security_txt(
    domain: str,
    live_hosts: List[str],
    output_dir: Path,
    timeout: int = 5,
) -> Dict[str, Any]:
    """Harvest and parse RFC 9116 security.txt policies and vulnerability disclosure contacts."""
    clean_domain = domain.strip().strip(".").lower()
    print(f"[*] Harvesting RFC 9116 security.txt disclosure policies for {clean_domain}...")
    candidates = [f"https://{clean_domain}"] + [h for h in live_hosts[:10] if clean_domain in h]
    result: Dict[str, Any] = {
        "domain": clean_domain,
        "found": False,
        "url": None,
        "contact": [],
        "expires": None,
        "encryption": None,
        "policy": None,
        "hiring": None,
        "acknowledgments": None,
    }

    paths = ["/.well-known/security.txt", "/security.txt"]

    for base in candidates:
        base_url = base.rstrip("/")
        if not base_url.startswith("http"):
            base_url = f"https://{base_url}"

        for path in paths:
            target = f"{base_url}{path}"
            try:
                req = urllib.request.Request(
                    target,
                    headers={"User-Agent": "reconflow-audit/1.0"},
                )
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if resp.status == 200:
                        text = resp.read(8192).decode("utf-8", errors="ignore")
                        if "contact:" in text.lower():
                            result["found"] = True
                            result["url"] = target
                            for line in text.splitlines():
                                line = line.strip()
                                if not line or line.startswith("#"):
                                    continue
                                if ":" in line:
                                    field, val = line.split(":", 1)
                                    f_low = field.strip().lower()
                                    v_clean = val.strip()
                                    if f_low == "contact":
                                        result["contact"].append(v_clean)
                                    elif f_low in ("expires", "encryption", "policy",
                                                   "hiring", "acknowledgments"):
                                        result[f_low] = v_clean
                            break
            except Exception:
                continue
        if result["found"]:
            break

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "security_txt.json"
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    status_str = f"Found at {result['url']}" if result["found"] else "Not found"
    print(f"[+] RFC 9116 security.txt: {status_str} -> {out_file.name}")
    return result


SECURITY_HEADERS: Dict[str, Tuple[str, int, str]] = {
    "strict-transport-security": ("HSTS", 25, "Enforces HTTPS encryption"),
    "content-security-policy": ("CSP", 25, "Restricts script execution & prevents XSS"),
    "x-frame-options": ("XFO", 15, "Protects against clickjacking attacks"),
    "x-content-type-options": ("XCTO", 15, "Prevents MIME-type sniffing"),
    "referrer-policy": ("Referrer", 10, "Controls sensitive URL referrer leakage"),
    "permissions-policy": ("Permissions", 10, "Restricts sensitive browser APIs"),
}


def grade_security_headers(
    live_hosts: List[str], output_dir: Path, timeout: int = 5
) -> List[Dict[str, Any]]:
    """Analyze defensive HTTP response headers and assign an A+ to F security posture grade."""
    print("[*] Analyzing and grading defensive HTTP response headers...")
    grades: List[Dict[str, Any]] = []

    for host in live_hosts[:30]:
        target_url = host if host.startswith("http") else f"https://{host}"
        try:
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": "reconflow-audit/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                score = 0
                present: List[Dict[str, str]] = []
                missing: List[Dict[str, str]] = []

                for header, (short_name, weight, description) in SECURITY_HEADERS.items():
                    if header in headers:
                        score += weight
                        present.append({
                            "header": header,
                            "name": short_name,
                            "value": headers[header],
                        })
                    else:
                        missing.append({
                            "header": header,
                            "name": short_name,
                            "description": description,
                        })

                if score >= 90:
                    letter = "A+"
                elif score >= 80:
                    letter = "A"
                elif score >= 70:
                    letter = "B"
                elif score >= 50:
                    letter = "C"
                elif score >= 30:
                    letter = "D"
                else:
                    letter = "F"

                grades.append({
                    "url": target_url,
                    "score": score,
                    "grade": letter,
                    "present_headers": present,
                    "missing_headers": missing,
                })
        except Exception:
            continue

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "security_grades.json"
    out_file.write_text(json.dumps(grades, indent=2), encoding="utf-8")
    avg_score = int(sum(g["score"] for g in grades) / len(grades)) if grades else 0
    print(
        f"[+] Graded {len(grades)} endpoints: "
        f"Average defensive score {avg_score}/100 -> {out_file.name}"
    )
    return grades
