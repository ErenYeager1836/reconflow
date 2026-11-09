"""
reconflow.cache_audit
---------------------
Audits CDN edge caching policies, detects Web Cache Deception risks (public caching
of sensitive Set-Cookie / Auth data), and identifies unkeyed header reflection.
"""

import json
import ssl
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Any, Optional

CACHE_HEADERS = [
    "cache-control",
    "pragma",
    "expires",
    "age",
    "cf-cache-status",
    "x-cache",
    "x-cache-hits",
    "x-varnish",
    "akamai-cache-status",
    "x-drupal-cache",
    "fastly-debug-digest",
    "x-served-by",
]

SENSITIVE_PATH_KEYWORDS = [
    "/api", "/login", "/auth", "/oauth", "/admin", "/account", "/user", "/profile", "/dashboard"
]


def audit_host_cache(url: str, timeout: int = 5) -> Dict[str, Any]:
    """Inspect caching headers and detect unsafe caching of credentials or sessions."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "reconflow-cache-audit/1.0",
            "X-Forwarded-Host": "reconflow-unkeyed-probe.test",
        }
    )

    findings: List[Dict[str, str]] = []
    response_headers: Dict[str, str] = {}
    cdn_detected = None

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            for ch in CACHE_HEADERS:
                if ch in headers:
                    response_headers[ch] = headers[ch]

            # Detect CDN vendor from headers
            if "cf-cache-status" in headers:
                cdn_detected = "Cloudflare"
            elif (
                "fastly-debug-digest" in headers
                or "fastly" in headers.get("x-served-by", "").lower()
            ):
                cdn_detected = "Fastly"
            elif "akamai-cache-status" in headers:
                cdn_detected = "Akamai"
            elif "x-varnish" in headers:
                cdn_detected = "Varnish"
            elif "x-cache" in headers and "cloudfront" in headers.get("x-cache", "").lower():
                cdn_detected = "AWS CloudFront"

            cc = headers.get("cache-control", "").lower()
            set_cookie = headers.get("set-cookie", "")

            # 1. Critical flaw: Set-Cookie cached publicly
            has_public_cookie = (
                set_cookie and (
                    "public" in cc
                    or ("max-age" in cc and "no-store" not in cc and "private" not in cc)
                )
            )
            if has_public_cookie:
                findings.append({
                    "type": "SENSITIVE_DATA_PUBLIC_CACHE",
                    "severity": "CRITICAL",
                    "description": (
                        "Endpoint sets cookies while Cache-Control allows public CDN caching "
                        "(Web Cache Deception risk)."
                    ),
                })

            # 2. Dynamic route without no-store
            if any(k in url.lower() for k in SENSITIVE_PATH_KEYWORDS):
                if "no-store" not in cc and "no-cache" not in cc:
                    findings.append({
                        "type": "MISSING_CACHE_CONTROL_ON_DYNAMIC",
                        "severity": "LOW",
                        "description": (
                            "Sensitive/dynamic endpoint lacks explicit no-store/no-cache directive."
                        ),
                    })

            # 3. Unkeyed header reflection check
            location = headers.get("location", "")
            if "reconflow-unkeyed-probe.test" in location:
                findings.append({
                    "type": "UNKEYED_HEADER_REFLECTION",
                    "severity": "HIGH",
                    "description": (
                        "X-Forwarded-Host reflected in Location header, "
                        "potential Cache Poisoning vector."
                    ),
                })

            return {
                "url": url,
                "status_code": resp.status,
                "cdn_detected": cdn_detected,
                "cache_control": headers.get("cache-control", "none"),
                "headers": response_headers,
                "findings": findings,
                "is_vulnerable": len(findings) > 0,
            }
    except Exception as e:
        return {
            "url": url,
            "error": str(e),
            "findings": [],
            "is_vulnerable": False,
        }


def audit_cache_policies(
    live_hosts: List[str],
    output_dir: Optional[Path] = None,
    threads: int = 10,
    timeout: int = 5
) -> List[Dict[str, Any]]:
    """Audit caching policies across live hosts."""
    results: List[Dict[str, Any]] = []
    # Extract clean URLs
    urls = []
    for h in live_hosts:
        raw_url = h.split()[0].strip()
        if raw_url.startswith("http://") or raw_url.startswith("https://"):
            urls.append(raw_url)
        else:
            urls.append(f"https://{raw_url}")

    with ThreadPoolExecutor(max_workers=min(threads, 20)) as pool:
        results = list(pool.map(lambda u: audit_host_cache(u, timeout=timeout), urls))

    if output_dir:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out_file = output_dir / "cache_audit.json"
        out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")

    return results
