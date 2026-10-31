"""reconflow.scope - Program scope parsing, validation, and enforcement."""

import ipaddress
import sys
from pathlib import Path
from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when scope loading or validation fails."""
    pass


def normalize_host(target: str) -> str:
    """Normalize hostnames and URLs.

    Lowercases, strips scheme, userinfo, port, path, query, fragment, and trailing dot.
    """
    if not target:
        return ""
    s = target.strip().lstrip("\ufeff").lower()

    # Strip scheme if present
    if "://" in s:
        parsed = urlparse(s)
        s = parsed.netloc or parsed.path
    else:
        # Strip path/query/fragment if scheme was omitted but slash exists
        s = s.split("/", 1)[0]
        s = s.split("?", 1)[0]
        s = s.split("#", 1)[0]

    # Strip userinfo (user:pass@host)
    if "@" in s:
        s = s.split("@", 1)[-1]

    # Handle port for IPv6 literals [::1]:8080 vs host:port
    if s.startswith("[") and "]" in s:
        # IPv6 literal
        ipv6_part = s[1:s.index("]")]
        rest = s[s.index("]") + 1:]
        if rest.startswith(":"):
            s = ipv6_part
        else:
            s = ipv6_part
    elif ":" in s:
        parts = s.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            s = parts[0]

    # Strip trailing dot
    s = s.rstrip(".")
    return s


class ScopeRule:
    """Represents a single in-scope or out-of-scope rule."""

    def __init__(self, raw: str, is_out_of_scope: bool):
        self.raw = raw
        self.is_out_of_scope = is_out_of_scope
        self.is_ip_network = False
        self.network = None
        self.is_wildcard = False
        self.wildcard_apex = None
        self.is_exact_domain = False
        self.exact_domain = None

        norm = normalize_host(raw)

        # Check for IP address or CIDR
        # Note: raw might contain CIDR like 192.168.1.0/24 which normalize_host might split on /
        # so check raw without whitespace/prefix first for CIDR
        clean_raw = raw.strip().lstrip("\ufeff")
        if clean_raw.startswith("!") or clean_raw.startswith("-"):
            clean_raw = clean_raw[1:].strip()
        elif clean_raw.lower().startswith("out:"):
            clean_raw = clean_raw[4:].strip()
        elif clean_raw.lower().startswith("in:"):
            clean_raw = clean_raw[3:].strip()
        elif clean_raw.startswith("+"):
            clean_raw = clean_raw[1:].strip()

        # Check CIDR / IP
        try:
            net = ipaddress.ip_network(clean_raw, strict=False)
            self.is_ip_network = True
            self.network = net
            return
        except ValueError:
            pass

        # Check wildcard domain (*.example.com)
        if clean_raw.startswith("*."):
            apex = clean_raw[2:].strip().rstrip(".").lower()
            if "://" in apex:
                apex = normalize_host(apex)
            self.is_wildcard = True
            self.wildcard_apex = apex
            return

        # Exact domain
        self.is_exact_domain = True
        self.exact_domain = norm

    def matches(self, host: str, resolved_ip: str = None) -> bool:
        """Check if a normalized host (or resolved IP) matches this rule."""
        # 1. IP / CIDR matching
        if self.is_ip_network:
            # Check if host itself is an IP
            try:
                ip_obj = ipaddress.ip_address(host)
                if ip_obj in self.network:
                    return True
            except ValueError:
                pass

            # Check if resolved IP is provided and matches
            if resolved_ip:
                try:
                    ip_obj = ipaddress.ip_address(resolved_ip)
                    if ip_obj in self.network:
                        return True
                except ValueError:
                    pass
            return False

        # 2. Wildcard domain matching: *.example.com
        # Matches subdomains only, NOT example.com itself and NOT notexample.com.
        if self.is_wildcard:
            # Must end with ".<apex>" and must not be equal to apex
            suffix = f".{self.wildcard_apex}"
            if host.endswith(suffix) and host != self.wildcard_apex:
                return True
            return False

        # 3. Exact domain matching: example.com
        if self.is_exact_domain:
            return host == self.exact_domain

        return False


def load_scope(scope_file_path: str or Path) -> dict:
    """Load and parse a scope file.

    Fails closed if the file is missing, unreadable, empty, or has no valid
    in-scope entries.

    Returns dict with 'in_scope' and 'out_of_scope' lists of ScopeRule objects.
    """
    path = Path(scope_file_path)
    if not path.exists():
        raise ScopeError(f"Scope file not found: {path}")

    try:
        content = path.read_text(encoding="utf-8-sig")
    except Exception as e:
        raise ScopeError(f"Scope file is unreadable: {path} ({e})")

    lines = [line.strip() for line in content.splitlines()]
    non_comment_lines = [
        line for line in lines
        if line and not line.startswith("#")
    ]

    if not non_comment_lines:
        raise ScopeError(f"Scope file is empty: {path}")

    in_scope_rules = []
    out_of_scope_rules = []

    for line in non_comment_lines:
        # Check out-of-scope prefix: !, -, or out:
        is_out = False
        clean = line
        if clean.startswith("!"):
            is_out = True
            clean = clean[1:].strip()
        elif clean.startswith("-"):
            is_out = True
            clean = clean[1:].strip()
        elif clean.lower().startswith("out:"):
            is_out = True
            clean = clean[4:].strip()
        elif clean.lower().startswith("in:"):
            clean = clean[3:].strip()
        elif clean.startswith("+"):
            clean = clean[1:].strip()

        if not clean:
            continue

        rule = ScopeRule(clean, is_out_of_scope=is_out)
        if is_out:
            out_of_scope_rules.append(rule)
        else:
            in_scope_rules.append(rule)

    if not in_scope_rules:
        raise ScopeError(
            f"Scope file contains no valid in-scope entries: {path}. "
            "Aborting to fail closed."
        )

    return {
        "path": str(path),
        "in_scope": in_scope_rules,
        "out_of_scope": out_of_scope_rules,
        "is_default": False,
    }


def make_default_scope(domain: str) -> dict:
    """Create a default scope restricting targets to domain and its subdomains (*.domain)."""
    norm = normalize_host(domain)
    return {
        "path": None,
        "in_scope": [
            ScopeRule(f"*.{norm}", is_out_of_scope=False),
            ScopeRule(norm, is_out_of_scope=False),
        ],
        "out_of_scope": [],
        "is_default": True,
    }


def is_in_scope(target: str, scope: dict, resolved_ip: str = None) -> bool:
    """Determine whether a target hostname or IP is in scope.

    Out-of-scope entries ALWAYS override in-scope entries.
    """
    norm = normalize_host(target)
    if not norm:
        return False

    # 1. Out-of-scope entries ALWAYS override in-scope
    for rule in scope.get("out_of_scope", []):
        if rule.matches(norm, resolved_ip=resolved_ip):
            return False

    # 2. Must match at least one in-scope rule
    for rule in scope.get("in_scope", []):
        if rule.matches(norm, resolved_ip=resolved_ip):
            return True

    return False


def run(args):
    """Execute scope check command for given targets."""
    scope_file = getattr(args, "scope_file", None)
    targets = getattr(args, "targets", [])

    if not scope_file:
        sys.exit("Error: Scope file is required.")
    if not targets:
        sys.exit("Error: At least one target is required.")

    try:
        scope = load_scope(scope_file)
    except ScopeError as e:
        sys.exit(f"Error: {e}")

    for target in targets:
        if is_in_scope(target, scope):
            print(f"[+] {target}: IN SCOPE")
        else:
            print(f"[-] {target}: OUT OF SCOPE")
