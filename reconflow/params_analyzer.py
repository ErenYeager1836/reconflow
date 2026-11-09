"""
reconflow.params_analyzer
-------------------------
Classifies discovered URL query parameters into high-value bug bounty attack surface
matrices (SSRF/Open Redirect, IDOR/BOLA, Admin/Bypass, SQLi/Command, and LFI/Path Traversal).
"""

import json
from pathlib import Path
from typing import Dict, List, Set, Any, Optional
import urllib.parse

PARAM_CATEGORIES = {
    "ssrf_open_redirect": {
        "label": "SSRF / Open Redirect",
        "description": "Parameters that take external URLs, hostnames, or callback destinations",
        "keywords": {
            "url", "redirect", "next", "return", "target", "dest", "destination",
            "r", "callback", "webhook", "feed", "proxy", "host", "domain",
            "checkout_url", "continue", "to", "link", "out", "forward", "uri",
            "endpoint", "service", "site"
        }
    },
    "idor_bola": {
        "label": "IDOR / BOLA",
        "description": (
            "Object, account, user, and entity identifiers prone to access control flaws"
        ),
        "keywords": {
            "id", "user_id", "userid", "account_id", "accountid", "doc_id", "uuid",
            "org_id", "orgid", "profile_id", "order_id", "customer_id", "file_id",
            "item_id", "project_id", "uid", "member_id", "team_id", "tenant_id"
        }
    },
    "admin_bypass": {
        "label": "Admin / Privilege / Debug",
        "description": (
            "Flags, roles, and modes that may trigger administrative functionality or bypasses"
        ),
        "keywords": {
            "admin", "debug", "test", "internal", "dev", "role", "preview",
            "is_admin", "root", "view_as", "impersonate", "super", "bypass",
            "sandbox", "staging", "mode", "grant", "permission"
        }
    },
    "sqli_injection": {
        "label": "SQLi / Command / Injection",
        "description": (
            "Search, filter, ordering, and execution parameters susceptible to query injection"
        ),
        "keywords": {
            "query", "q", "search", "filter", "order", "sort", "column", "cmd",
            "exec", "sql", "select", "table", "group", "limit", "where", "expression",
            "match", "eval", "key"
        }
    },
    "path_traversal_lfi": {
        "label": "Path Traversal / LFI",
        "description": (
            "File system paths, templates, and view includes prone to arbitrary read/traversal"
        ),
        "keywords": {
            "file", "path", "template", "include", "page", "doc", "folder",
            "load", "view", "source", "filepath", "filename", "read", "layout"
        }
    }
}


def classify_parameter(param_name: str) -> List[str]:
    """Map a parameter name to matching vulnerability risk categories."""
    param_clean = param_name.strip().lower()
    matches = []
    for cat_key, cat_data in PARAM_CATEGORIES.items():
        if param_clean in cat_data["keywords"]:
            matches.append(cat_key)
        else:
            # Check prefix/suffix substrings for compound param names like user_id, redirect_url
            for kw in cat_data["keywords"]:
                is_compound = (
                    len(kw) > 3
                    and (param_clean.startswith(f"{kw}_") or param_clean.endswith(f"_{kw}"))
                )
                if is_compound:
                    matches.append(cat_key)
                    break
    return list(set(matches))


def analyze_parameters(
    params_list: List[str],
    urls_list: List[str],
    output_dir: Optional[Path] = None
) -> Dict[str, Any]:
    """Build the high-value attack surface matrix from gathered parameters and URLs."""
    # Harvest query params from URLs
    all_params: Set[str] = set(params_list)
    param_to_urls: Dict[str, List[str]] = {}

    for u in urls_list:
        try:
            parsed = urllib.parse.urlparse(u)
            qs = urllib.parse.parse_qs(parsed.query)
            for k in qs.keys():
                all_params.add(k)
                if k not in param_to_urls:
                    param_to_urls[k] = []
                if len(param_to_urls[k]) < 5:  # Sample up to 5 URLs per param
                    param_to_urls[k].append(u)
        except Exception:
            continue

    matrix: Dict[str, Dict[str, Any]] = {}
    for cat_key, cat_data in PARAM_CATEGORIES.items():
        matrix[cat_key] = {
            "label": cat_data["label"],
            "description": cat_data["description"],
            "matched_params": [],
            "params_count": 0,
        }

    unclassified: List[str] = []

    for p in sorted(all_params):
        cats = classify_parameter(p)
        if cats:
            for c in cats:
                matrix[c]["matched_params"].append({
                    "name": p,
                    "sample_urls": param_to_urls.get(p, [])
                })
        else:
            unclassified.append(p)

    total_high_value = sum(len(m["matched_params"]) for m in matrix.values())
    for cat_key in matrix:
        matrix[cat_key]["params_count"] = len(matrix[cat_key]["matched_params"])

    result = {
        "total_parameters_evaluated": len(all_params),
        "total_high_value_flagged": total_high_value,
        "unclassified_count": len(unclassified),
        "categories": matrix,
        "unclassified_parameters": unclassified,
    }

    if output_dir:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out_file = output_dir / "param_matrix.json"
        out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")

    return result
