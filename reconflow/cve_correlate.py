"""
reconflow.cve_correlate
-------------------------
Correlates detected web technologies from live hosts (e.g., via httpx fingerprinting)
against the National Vulnerability Database (NVD) CVE API v2.0.

Free and requires no API key by default (rate-limited by NVD), but supports an optional
NVD API key via parameter or NVD_API_KEY environment variable for higher throughput.
Zero external dependencies (uses standard library urllib).
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

NVD_API: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Generic technology tags from httpx -tech-detect to skip to avoid noisy irrelevant CVE queries
SKIP_TECH: Set[str] = {
    "html5", "javascript", "css", "json", "cloudflare", "hsts", "http/2",
    "http/3", "tls", "ssl", "font-awesome", "google-font-api",
}


def _query_nvd(
    keyword: str, timeout: int = 15, api_key: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Query the NVD REST API v2.0 for a specific technology keyword."""
    encoded_kw = urllib.parse.quote(keyword.strip())
    url = f"{NVD_API}?keywordSearch={encoded_kw}&resultsPerPage=5"
    headers = {
        "User-Agent": "reconflow-cve-correlate/1.0",
        "Accept": "application/json",
    }
    key = api_key or os.environ.get("NVD_API_KEY")
    if key:
        headers["apiKey"] = key.strip()

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))

        results: List[Dict[str, Any]] = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            summary = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
            metrics = cve.get("metrics", {})
            score = None
            severity = "UNKNOWN"
            for key_metric in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(key_metric, [])
                if metric_list and isinstance(metric_list, list):
                    cvss_data = metric_list[0].get("cvssData", {})
                    score = cvss_data.get("baseScore")
                    severity = cvss_data.get(
                        "baseSeverity", metric_list[0].get("baseSeverity", "UNKNOWN")
                    )
                    break

            if cve_id:
                results.append({
                    "cve_id": cve_id,
                    "summary": summary[:250],
                    "cvss_score": score,
                    "severity": str(severity).upper(),
                })
        return results
    except urllib.error.HTTPError as e:
        if e.code in (403, 429):
            print("[!] NVD rate limit reached — throttling...")
            time.sleep(6)
        return []
    except Exception:
        return []


def correlate_cves(
    httpx_records: List[Dict[str, Any]],
    output_dir: Path,
    timeout: int = 15,
    api_key: Optional[str] = None,
    delay_between_requests: Optional[float] = None,
) -> List[Dict[str, Any]]:
    """
    Extract technologies from httpx probe records, query NVD for known CVEs,
    and save structured results to output_dir / 'cve_correlation.json'.
    """
    tech_versions: Set[str] = set()
    for rec in httpx_records or []:
        # rec can have 'technologies' or 'tech'
        raw_tech = rec.get("technologies") or rec.get("tech") or []
        if isinstance(raw_tech, list):
            for tech in raw_tech:
                if not isinstance(tech, str):
                    continue
                name = tech.split(":")[0].strip().lower()
                if name and name not in SKIP_TECH and len(name) > 2:
                    tech_versions.add(tech.strip())

    if not tech_versions:
        print("[*] No specific technologies detected to correlate against CVEs")
        return []

    effective_key = api_key or os.environ.get("NVD_API_KEY")
    # If key present, NVD allows 50 req/30s (~0.6s delay); unauth allows 5 req/30s (~6s delay)
    if delay_between_requests is not None:
        sleep_interval = delay_between_requests
    else:
        sleep_interval = 0.8 if effective_key else 6.0

    print(
        f"[*] Correlating {len(tech_versions)} detected technologies against NVD "
        f"({'API key enabled' if effective_key else 'unauthenticated mode'})..."
    )

    findings: List[Dict[str, Any]] = []
    for tech in sorted(tech_versions):
        cves = _query_nvd(tech, timeout=timeout, api_key=effective_key)
        if cves:
            findings.append({"technology": tech, "cves": cves})
        time.sleep(sleep_interval)

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "cve_correlation.json"
    out_file.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    total_cves = sum(len(f["cves"]) for f in findings)
    print(
        f"[+] Found {total_cves} potential CVE(s) across "
        f"{len(findings)} technologies -> {out_file.name}"
    )
    return findings
