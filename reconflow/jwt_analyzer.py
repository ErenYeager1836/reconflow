"""
reconflow.jwt_analyzer
------------------------
Performs security posture and vulnerability analysis on discovered JSON Web Tokens (JWTs).
Checks for:
1. 'alg: none' signature bypass vulnerability.
2. Weak / default HMAC secret key brute-force (HS256/384/512).
3. Missing or excessive expiration (exp) claims.
4. Sensitive data exposure in decoded payload (passwords, admin flags, keys).

100% standard library implementation (base64, json, hmac, hashlib, time).
"""

import base64
import hashlib
import hmac
import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

JWT_REGEX = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}(?:\.[a-zA-Z0-9_-]*)?")

DEFAULT_WEAK_SECRETS = [
    "secret", "password", "123456", "jwt", "admin", "app", "test",
    "root", "guest", "default", "development", "changeit", "token",
    "key", "api", "auth", "secret123", "secretkey", "supersecret",
    "12345678", "welcome", "master", "mysecret", "private",
]

SENSITIVE_KEY_PATTERNS = ["password", "passwd", "secret", "private_key", "api_key", "token"]
PRIVILEGE_KEY_PATTERNS = ["admin", "role", "superuser", "is_admin", "privilege", "perms"]


def _b64url_decode(s: str) -> bytes:
    """Safely decode base64url string with missing padding."""
    rem = len(s) % 4
    if rem:
        s += "=" * (4 - rem)
    return base64.urlsafe_b64decode(s.encode("ascii"))


def extract_jwts(content: str) -> List[str]:
    """Extract candidate JWT strings from arbitrary text."""
    if not content:
        return []
    return list(set(JWT_REGEX.findall(content)))


def decode_jwt(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
    """Decode header, payload, and signature from a JWT string."""
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT format (requires header.payload[.sig])")

    try:
        header_raw = _b64url_decode(parts[0]).decode("utf-8", errors="ignore")
        header = json.loads(header_raw)
    except Exception as e:
        raise ValueError(f"Failed to decode JWT header: {e}")

    try:
        payload_raw = _b64url_decode(parts[1]).decode("utf-8", errors="ignore")
        payload = json.loads(payload_raw)
    except Exception as e:
        raise ValueError(f"Failed to decode JWT payload: {e}")

    signature = parts[2] if len(parts) > 2 else ""
    return header, payload, signature


def _test_hmac_secret(header_b64: str, payload_b64: str, signature: str,
                      alg: str, candidate: str) -> bool:
    """Test if candidate secret matches the HMAC signature."""
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    if alg == "HS256":
        digest_mod = hashlib.sha256
    elif alg == "HS384":
        digest_mod = hashlib.sha384
    elif alg == "HS512":
        digest_mod = hashlib.sha512
    else:
        return False

    computed = hmac.new(candidate.encode("utf-8"), signing_input, digest_mod).digest()
    computed_b64 = base64.urlsafe_b64encode(computed).decode("ascii").rstrip("=")
    clean_target = signature.rstrip("=")
    return computed_b64 == clean_target


def analyze_jwt(token: str, domain: Optional[str] = None) -> Dict[str, Any]:
    """
    Performs full AppSec security inspection on a single JWT token.
    Returns analysis report dict with vulnerabilities and posture checks.
    """
    parts = token.strip().split(".")
    header, payload, signature = decode_jwt(token)

    vulnerabilities = []
    alg = str(header.get("alg", "")).strip()

    # 1. Check for 'alg: none' signature bypass
    if alg.lower() == "none" or not alg:
        vulnerabilities.append({
            "severity": "CRITICAL",
            "title": "Insecure Algorithm (alg: none / empty)",
            "description": "Token specifies 'none' or missing algorithm, allowing unsigned "
                           "arbitrary payload manipulation.",
        })

    # 2. Check for weak/default HMAC secret keys
    elif alg in ("HS256", "HS384", "HS512") and signature:
        candidates = list(DEFAULT_WEAK_SECRETS)
        if domain:
            candidates.append(domain)
            candidates.append(domain.split(".")[0])

        cracked_secret = None
        for secret in candidates:
            if _test_hmac_secret(parts[0], parts[1], signature, alg, secret):
                cracked_secret = secret
                break

        if cracked_secret:
            vulnerabilities.append({
                "severity": "CRITICAL",
                "title": "Weak / Default HMAC Secret Key",
                "description": f"Token signature was verified using common weak secret "
                               f"'{cracked_secret}'. Full signature forgery is possible.",
                "secret": cracked_secret,
            })

    # 3. Check expiration (exp) and validity claims
    now = int(time.time())
    exp = payload.get("exp")
    if exp is None:
        vulnerabilities.append({
            "severity": "MEDIUM",
            "title": "Missing Expiration Claim (exp)",
            "description": "Token contains no expiration timestamp, making it perpetual and "
                           "vulnerable to persistent session hijacking.",
        })
    else:
        try:
            exp_int = int(exp)
            if exp_int < now:
                vulnerabilities.append({
                    "severity": "INFO",
                    "title": "Expired Token",
                    "description": f"Token expired at UNIX timestamp {exp_int}.",
                })
            elif exp_int - now > 31536000:  # > 1 year
                vulnerabilities.append({
                    "severity": "LOW",
                    "title": "Excessive Token Lifetime (> 1 year)",
                    "description": "Token expiration is configured unusually far in the future.",
                })
        except (ValueError, TypeError):
            pass

    # 4. Check for sensitive keys in payload
    for key, val in payload.items():
        k_lower = key.lower()
        if any(pat in k_lower for pat in SENSITIVE_KEY_PATTERNS):
            vulnerabilities.append({
                "severity": "HIGH",
                "title": f"Sensitive Key '{key}' Exposed in Payload",
                "description": f"Payload directly contains potentially sensitive key: {key}",
            })
        elif any(pat in k_lower for pat in PRIVILEGE_KEY_PATTERNS):
            vulnerabilities.append({
                "severity": "INFO",
                "title": f"Privilege Attribute '{key}' Present",
                "description": f"Role / permission field found in payload: {key}={val}",
            })

    # Overall token risk score
    severities = [v["severity"] for v in vulnerabilities]
    if "CRITICAL" in severities:
        overall = "CRITICAL"
    elif "HIGH" in severities:
        overall = "HIGH"
    elif "MEDIUM" in severities:
        overall = "MEDIUM"
    elif "LOW" in severities:
        overall = "LOW"
    else:
        overall = "CLEAN"

    token_preview = f"{token[:25]}...{token[-10:]}" if len(token) > 40 else token
    return {
        "token_preview": token_preview,
        "algorithm": alg,
        "header": header,
        "payload": payload,
        "risk_level": overall,
        "vulnerabilities": vulnerabilities,
    }


def audit_jwts(tokens: List[str], output_dir: Optional[Path] = None,
               domain: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Audits a list of JWT token strings and optionally writes findings to jwt_analysis.json.
    """
    if not tokens:
        return []

    results = []
    for tok in tokens:
        try:
            report = analyze_jwt(tok, domain=domain)
            results.append(report)
        except Exception:
            continue

    if output_dir:
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        out_file = output_dir / "jwt_analysis.json"
        out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")

    return results
