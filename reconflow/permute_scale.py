"""
reconflow.permute_scale
-------------------------
Large-scale DNS permutation engine with wildcard DNS filtering and HTTP verification.

Two major enhancements over basic permutation:
1. DNS-only resolution produces massive false positives on wildcard-DNS domains
   (where *.domain resolves). This module performs an HTTP confirmation pass and
   clusters response fingerprints (status + content length) to filter out catch-all pages.
2. Supports external SecLists-style wordlists (e.g., subdomains-top1million-5000.txt)
   or defaults to an internal high-value prefix dictionary.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_PERMUTATION_WORDS: List[str] = [
    "dev", "stage", "staging", "test", "qa", "uat", "admin", "api",
    "internal", "corp", "vpn", "mail", "portal", "app", "v2", "beta",
    "prod", "demo", "gateway", "auth", "sso", "dashboard", "preview",
    "login", "secure", "status", "grafana", "jenkins", "k8s", "git",
]


def load_wordlist(path: str | Path) -> List[str]:
    """Load words from an external wordlist file, ignoring comments and blanks."""
    p = Path(path)
    if not p.is_file():
        return []
    words: List[str] = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        w = line.strip().lower()
        if w and not w.startswith("#"):
            words.append(w)
    return words


def _probe(host: str, timeout: int = 6) -> Optional[Dict[str, Any]]:
    """Probe host over HTTPS/HTTP for web services, ignoring self-signed SSL errors."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for scheme in ("https", "http"):
        try:
            req = urllib.request.Request(
                f"{scheme}://{host}",
                headers={"User-Agent": "reconflow-permute/1.0"},
            )
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read(2048)
                return {
                    "host": host,
                    "url": f"{scheme}://{host}",
                    "status": resp.status,
                    "content_length": len(body),
                }
        except urllib.error.HTTPError as e:
            # Server responded with an HTTP status code (403, 401, 500, etc.), so the host exists
            return {
                "host": host,
                "url": f"{scheme}://{host}",
                "status": e.code,
                "content_length": 0,
            }
        except Exception:
            continue
    return None


def generate_permutations_scaled(
    subdomains: List[str],
    domain: str,
    output_dir: Path,
    wordlist_path: Optional[str] = None,
    max_candidates: int = 5000,
    threads: int = 30,
    timeout: int = 6,
) -> List[Dict[str, Any]]:
    """
    Generate mutations and permutations across known subdomains, probe them over HTTP,
    and filter out wildcard DNS catch-all responses.
    """
    clean_domain = domain.strip().strip(".").lower()

    if wordlist_path and Path(wordlist_path).is_file():
        words = load_wordlist(wordlist_path)
        print(f"[*] Loaded {len(words)} words from {wordlist_path}")
    else:
        # Fall back to reconflow.audits if available, else default list
        try:
            from reconflow.audits import PERMUTATION_WORDS
            words = list(PERMUTATION_WORDS)
        except Exception:
            words = list(DEFAULT_PERMUTATION_WORDS)

    # Extract distinct subdomain prefixes
    clean_subs: List[str] = []
    suffix = f".{clean_domain}"
    for s in subdomains:
        s_clean = s.strip().strip(".").lower()
        if s_clean.endswith(suffix):
            prefix = s_clean[: -len(suffix)]
            if prefix and "." not in prefix:
                clean_subs.append(prefix)
    clean_subs = sorted(set(clean_subs))[:25]

    candidates_set = set()
    for word in words:
        candidates_set.add(f"{word}.{clean_domain}")
    for base in clean_subs:
        for word in words:
            candidates_set.add(f"{word}-{base}.{clean_domain}")
            candidates_set.add(f"{base}-{word}.{clean_domain}")
            candidates_set.add(f"{word}.{base}.{clean_domain}")

    existing = {s.strip().strip(".").lower() for s in subdomains}
    candidates = sorted(c for c in candidates_set if c not in existing)

    if len(candidates) > max_candidates:
        print(f"[!] {len(candidates)} candidates generated, capping at {max_candidates}")
        candidates = candidates[:max_candidates]

    print(f"[*] Probing {len(candidates)} permutation candidate(s) over HTTP...")

    raw_results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for result in executor.map(lambda h: _probe(h, timeout), candidates):
            if result:
                raw_results.append(result)

    # Wildcard filter: if many "confirmed" hosts share one (status, content_length)
    # fingerprint, they represent a catch-all page rather than distinct hosts.
    fingerprints = Counter((r["status"], r["content_length"]) for r in raw_results)
    threshold = max(4, int(len(raw_results) * 0.3))
    common_fp = {
        fp for fp, count in fingerprints.items()
        if count >= threshold and len(raw_results) > 5
    }
    confirmed = [r for r in raw_results if (r["status"], r["content_length"]) not in common_fp]
    filtered_wildcard = len(raw_results) - len(confirmed)

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / "permutations_scaled.json"
    out_file.write_text(json.dumps(confirmed, indent=2), encoding="utf-8")

    print(
        f"[+] Confirmed {len(confirmed)} real permutation host(s) via HTTP "
        f"(filtered {filtered_wildcard} wildcard-DNS false positive(s))"
    )
    return confirmed
