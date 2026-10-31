"""reconflow.takeover - Subdomain takeover candidate detection.

Maintains a curated database of CNAME fingerprints and service signatures.
All detections are marked as 'candidate, verify manually' to prevent false promises.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

TAKEOVER_SIGNATURES = [
    {
        "service": "GitHub Pages",
        "cname": ["github.io", "github.map.fastly.net"],
        "fingerprints": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html",
        ],
    },
    {
        "service": "AWS S3",
        "cname": ["s3.amazonaws.com", "s3-website", "s3.dualstack."],
        "fingerprints": [
            "The specified bucket does not exist",
            "NoSuchBucket",
        ],
    },
    {
        "service": "Heroku",
        "cname": ["herokudns.com", "herokuapp.com"],
        "fingerprints": [
            "No such app",
            "Heroku | No such app",
            "<title>No such app</title>",
        ],
    },
    {
        "service": "Azure",
        "cname": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net"],
        "fingerprints": [
            "404 Web Site not found",
            "The resource you are looking for has been removed",
        ],
    },
    {
        "service": "Shopify",
        "cname": ["myshopify.com"],
        "fingerprints": [
            "Sorry, this shop is currently unavailable",
            "Only one step left!",
        ],
    },
    {
        "service": "Fastly",
        "cname": ["fastly.net", "fastlylb.net"],
        "fingerprints": [
            "Fastly error: unknown domain",
        ],
    },
    {
        "service": "Pantheon",
        "cname": ["pantheonsite.io"],
        "fingerprints": [
            "The gods are wise, but do not know this site",
            "404 error unknown site",
        ],
    },
    {
        "service": "Ghost",
        "cname": ["ghost.io"],
        "fingerprints": [
            "The thing you were looking for is no longer here",
            "404: Page not found",
        ],
    },
    {
        "service": "Tumblr",
        "cname": ["domains.tumblr.com"],
        "fingerprints": [
            "Whatever you were looking for doesn't seem to exist",
            "There's nothing here.",
        ],
    },
    {
        "service": "Zendesk",
        "cname": ["zendesk.com"],
        "fingerprints": [
            "Help Center Closed",
            "No such help center",
        ],
    },
    {
        "service": "Bitbucket",
        "cname": ["bitbucket.io"],
        "fingerprints": [
            "Repository not found",
            "The page you're looking for cannot be found",
        ],
    },
    {
        "service": "WordPress",
        "cname": ["wordpress.com"],
        "fingerprints": [
            "Do you want to register",
            "doesn't exist on WordPress.com",
        ],
    },
    {
        "service": "Cargo Collective",
        "cname": ["cargocollective.com"],
        "fingerprints": [
            "404 Not Found",
            "If you're the site owner",
        ],
    },
    {
        "service": "Surge.sh",
        "cname": ["surge.sh"],
        "fingerprints": [
            "project not found",
        ],
    },
]


def check_host_takeover(
    host: str,
    cnames: Optional[List[str]] = None,
    response_body: str = "",
    title: str = "",
) -> Optional[Dict[str, Any]]:
    """Check if host and response data match a known takeover candidate signature."""
    cnames = [c.lower().rstrip(".") for c in (cnames or [])]
    combined_body = f"{title}\n{response_body}"

    for sig in TAKEOVER_SIGNATURES:
        service = sig["service"]
        # 1. Match CNAME pattern if CNAMEs are provided
        matched_cname = None
        if cnames:
            for c in cnames:
                for c_pat in sig["cname"]:
                    if c_pat.lower() in c:
                        matched_cname = c
                        break
                if matched_cname:
                    break

        # 2. Check body fingerprints
        matched_fp = None
        for fp in sig["fingerprints"]:
            if fp.lower() in combined_body.lower():
                matched_fp = fp
                break

        # If both matched or CNAME matched with body pattern
        if matched_cname and matched_fp:
            return {
                "host": host,
                "cname": matched_cname,
                "service": service,
                "matched_fingerprint": matched_fp,
                "confidence": "candidate, verify manually",
                "reason": (
                    f"CNAME '{matched_cname}' matches {service} and "
                    f"response contains '{matched_fp}'"
                ),
            }
        elif matched_cname and not response_body:
            # Dangling CNAME pointer observed without HTTP probe
            return {
                "host": host,
                "cname": matched_cname,
                "service": service,
                "matched_fingerprint": None,
                "confidence": "candidate, verify manually",
                "reason": f"Dangling CNAME '{matched_cname}' points to {service}",
            }

    return None


def detect_takeovers(
    hosts_data: List[Dict[str, Any]],
    dns_records: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Scan probed hosts and DNS records for potential subdomain takeover candidates."""
    candidates = []
    seen = set()

    # Build DNS CNAME lookup
    dns_cnames: Dict[str, List[str]] = {}
    if dns_records:
        for r in dns_records:
            h = (r.get("host") or "").lower()
            cnames = r.get("cnames") or []
            if h and cnames:
                dns_cnames.setdefault(h, []).extend(cnames)

    for h_data in hosts_data:
        url = h_data.get("url") or ""
        host = (
            h_data.get("host") or urlparse(url).hostname or url
        ).lower()
        if not host or host in seen:
            continue

        cnames = h_data.get("cname") or []
        if isinstance(cnames, str):
            cnames = [cnames]
        if host in dns_cnames:
            cnames.extend(dns_cnames[host])

        title = h_data.get("title") or ""
        body = h_data.get("body") or ""

        match = check_host_takeover(host, cnames=cnames, response_body=body, title=title)
        if match:
            seen.add(host)
            candidates.append(match)

    return candidates
