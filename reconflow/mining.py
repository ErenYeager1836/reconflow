"""reconflow.mining - JavaScript and endpoint mining with masked secrets detection.

Safely mines crawled JavaScript files for endpoints, discovered subdomains,
and exposed secrets/tokens. All discovered credentials are strictly masked
(e.g., AKIA****************) and never output or stored in plaintext.
"""

import re
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

# Endpoints and path patterns in JS code
ENDPOINT_REGEXES = [
    re.compile(
        r"""(?:["']|`)(/(?:api|v[0-9]|rest|graphql|oauth|auth|admin|"""
        r"""user|v1|v2|v3)[a-zA-Z0-9_\-\./?=&%]*)(?:["']|`)""",
        re.IGNORECASE,
    ),
    re.compile(
        r"""(?:["']|`)(https?://[a-zA-Z0-9_\-\.]+(?:/[a-zA-Z0-9_\-\./?=&%]*)?)(?:["']|`)""",
        re.IGNORECASE,
    ),
    re.compile(
        r"""(?:path|endpoint|url|route)\s*[:=]\s*(?:["']|`)(/[a-zA-Z0-9_\-\./?=&%]+)(?:["']|`)""",
        re.IGNORECASE,
    ),
]

# Patterns for discovering subdomains inside JS code
SUBDOMAIN_REGEX = re.compile(
    r"""(?:["']|`|//)([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+"""
    r"""\.[a-zA-Z]{2,})(?:["']|`|/|:)"""
)

# Common secret signatures with prefix length to retain for identification
SECRET_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "pattern": re.compile(r"""\b(AKIA[0-9A-Z]{16})\b"""),
        "prefix_len": 4,
    },
    {
        "name": "Google API Key",
        "pattern": re.compile(r"""\b(AIza[0-9A-Za-z\-_]{35})\b"""),
        "prefix_len": 4,
    },
    {
        "name": "GitHub Personal Access Token",
        "pattern": re.compile(r"""\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})\b"""),
        "prefix_len": 4,
    },
    {
        "name": "Slack Token",
        "pattern": re.compile(r"""\b(xox[baprs]-[0-9a-zA-Z\-]{10,48})\b"""),
        "prefix_len": 5,
    },
    {
        "name": "Stripe Live Secret Key",
        "pattern": re.compile(r"""\b(sk_live_[0-9a-zA-Z]{24})\b"""),
        "prefix_len": 8,
    },
    {
        "name": "JSON Web Token (JWT)",
        "pattern": re.compile(
            r"""\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]{10,})\b"""
        ),
        "prefix_len": 6,
    },
]


def mask_secret(raw: str, prefix_len: int = 4) -> str:
    """Mask a secret string preserving only the leading prefix for identification."""
    if not raw:
        return ""
    if len(raw) <= prefix_len:
        return "*" * len(raw)
    prefix = raw[:prefix_len]
    masked = prefix + ("*" * (len(raw) - prefix_len))
    return masked


def mine_js_content(
    content: str,
    base_url: str = "",
    target_domain: Optional[str] = None,
    log_fn: Optional[Any] = None,
) -> Dict[str, Any]:
    """Parse JavaScript content for endpoints, subdomains, and masked secrets."""
    endpoints: Set[str] = set()
    subdomains: Set[str] = set()
    secrets: List[Dict[str, Any]] = []
    seen_secrets: Set[str] = set()

    # 1. Mine endpoints
    for reg in ENDPOINT_REGEXES:
        for match in reg.finditer(content):
            ep = match.group(1).strip()
            # Ignore binary/image asset false positives
            if ep.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2")):
                continue
            if ep.startswith("http://") or ep.startswith("https://"):
                if target_domain:
                    parsed_host = urlparse(ep).netloc.split(":")[0].lower()
                    t_low = target_domain.lower()
                    if (
                        parsed_host
                        and not parsed_host.endswith(f".{t_low}")
                        and parsed_host != t_low
                    ):
                        msg1 = f"[*] [scope] Skipped out-of-scope host: {ep}"
                        msg2 = f"[*] [scope] out of scope, skip {ep}"
                        if log_fn:
                            log_fn(msg1)
                            log_fn(msg2)
                        else:
                            print(msg1)
                            print(msg2)
                        continue
                endpoints.add(ep)
            elif base_url:
                endpoints.add(urljoin(base_url, ep))
            else:
                endpoints.add(ep)

    # 2. Mine subdomains
    for match in SUBDOMAIN_REGEX.finditer(content):
        host = match.group(1).strip().lower()
        # Filter out common extensions or TLD-only matches
        if target_domain:
            t_low = target_domain.lower()
            if not host.endswith(f".{t_low}") and host != t_low:
                msg1 = f"[*] [scope] Skipped out-of-scope host: {host}"
                msg2 = f"[*] [scope] out of scope, skip {host}"
                if log_fn:
                    log_fn(msg1)
                    log_fn(msg2)
                else:
                    print(msg1)
                    print(msg2)
                continue
        if "." in host and not host.endswith((".js", ".json", ".html", ".png", ".jpg", ".css")):
            subdomains.add(host)

    # 3. Detect exposed secrets with mandatory masking
    lines = content.splitlines()
    for line_idx, line in enumerate(lines, start=1):
        for sec in SECRET_PATTERNS:
            for match in sec["pattern"].finditer(line):
                raw = match.group(1)
                masked = mask_secret(raw, prefix_len=sec["prefix_len"])
                if masked not in seen_secrets:
                    seen_secrets.add(masked)
                    secrets.append({
                        "type": sec["name"],
                        "masked": masked,
                        "line": line_idx,
                    })

    return {
        "endpoints": sorted(endpoints),
        "subdomains": sorted(subdomains),
        "secrets": secrets,
    }


def filter_js_urls(urls: List[str]) -> List[str]:
    """Filter a list of URLs down to JavaScript asset files."""
    js_urls = []
    for u in urls:
        path = urlparse(u).path.lower()
        if path.endswith(".js") or ".js?" in u.lower():
            js_urls.append(u)
    return js_urls
