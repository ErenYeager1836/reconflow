"""
reconflow.github_leaks
------------------------
Searches GitHub's public code search API for references to the target domain,
identifying leaked credentials, internal hostnames, and exposed configurations.

Requires a GitHub personal access token (a free classic PAT or fine-grained token with
public read access suffices). GitHub's code search API enforces authentication.
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
from typing import Any, Dict, List, Optional

API_URL: str = "https://api.github.com/search/code"

# Targeted search templates to locate high-signal exposure
QUERY_TEMPLATES: List[str] = [
    '"{domain}" password',
    '"{domain}" api_key',
    '"{domain}" secret',
    '"{domain}" filename:.env',
    '"{domain}" filename:config',
    '"{domain}" authorization bearer',
]


def search_github_leaks(
    domain: str,
    output_dir: Path,
    token: Optional[str] = None,
    timeout: int = 10,
    max_queries: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Search GitHub public code repositories for sensitive disclosures matching domain.
    Writes findings to output_dir / 'github_leaks.json'.
    """
    clean_domain = domain.strip().strip(".").lower()
    auth_token = token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    if not auth_token:
        print(
            "[!] --github-token or GITHUB_TOKEN env var not provided. "
            "GitHub requires authentication for public code search. Skipping."
        )
        return []

    print(f"[*] Searching public GitHub code repositories for leaks referencing {clean_domain}...")
    headers = {
        "Authorization": f"Bearer {auth_token.strip()}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "reconflow-github-leaks/1.0",
    }

    findings: List[Dict[str, Any]] = []
    templates = QUERY_TEMPLATES[:max_queries] if max_queries else QUERY_TEMPLATES

    for template in templates:
        query = template.format(domain=clean_domain)
        url = f"{API_URL}?q={urllib.parse.quote(query)}&per_page=10"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))

            items = data.get("items", [])
            for item in items:
                repo = item.get("repository", {})
                findings.append({
                    "query": query,
                    "repo": repo.get("full_name", ""),
                    "path": item.get("path", ""),
                    "url": item.get("html_url", ""),
                    "score": item.get("score", 0.0),
                })
        except urllib.error.HTTPError as e:
            if e.code in (401, 403):
                print(
                    f"[!] GitHub API rate limit or no permission ({e.code}). Stopping early."
                )
                break
            if e.code == 422:
                # Query syntax rejected by GitHub API
                continue
        except Exception as e:
            print(f"[!] GitHub search query failed ({query}): {e}")

        time.sleep(2)  # Respect GitHub search rate limits

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "github_leaks.json"
    out_file.write_text(json.dumps(findings, indent=2), encoding="utf-8")

    print(f"[+] Found {len(findings)} potential GitHub code reference(s) -> {out_file.name}")
    return findings
