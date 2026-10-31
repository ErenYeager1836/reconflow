"""reconflow.leads - Extensible lead generation rules for new and changed recon targets.

Generates actionable hints ("worth checking") based on keywords, tech stacks,
page titles, and HTTP status code transitions.
"""

from urllib.parse import urlparse

KEYWORD_HINTS = {
    "dev": (
        "Worth checking: Development host may expose debug flags, stack traces, "
        "or test credentials."
    ),
    "development": (
        "Worth checking: Development host may expose debug flags, stack traces, "
        "or test credentials."
    ),
    "staging": (
        "Worth checking: Staging system often mirrors production with weaker auth "
        "or unpatched features."
    ),
    "stage": (
        "Worth checking: Staging system often mirrors production with weaker auth "
        "or unpatched features."
    ),
    "test": (
        "Worth checking: Test system may contain mock data or bypassed security controls."
    ),
    "qa": "Worth checking: QA environment may have permissive access controls or debug logs.",
    "uat": (
        "Worth checking: UAT system often contains pre-release features or unhardened interfaces."
    ),
    "admin": (
        "Worth checking: Administrative interface; test for panel access, auth bypass, "
        "or default credentials."
    ),
    "adm": (
        "Worth checking: Administrative interface; test for panel access, auth bypass, "
        "or default credentials."
    ),
    "internal": (
        "Worth checking: Internal portal may rely on network perimeter trust without auth."
    ),
    "intranet": (
        "Worth checking: Intranet service; check for missing access controls or exposed documents."
    ),
    "corp": (
        "Worth checking: Corporate interface; check for SSO bypass or unauthenticated directories."
    ),
    "api": (
        "Worth checking: API endpoint; test for IDOR, mass assignment, and unauthenticated routes."
    ),
    "rest": (
        "Worth checking: REST API service; explore API routes for missing authorization."
    ),
    "graphql": (
        "Worth checking: GraphQL endpoint; test for introspection and query batching."
    ),
    "beta": (
        "Worth checking: Prerelease beta environment; look for unhardened endpoints or debug flags."
    ),
    "old": (
        "Worth checking: Deprecated service; check for unpatched vulnerabilities and legacy CVEs."
    ),
    "legacy": "Worth checking: Legacy system may run outdated software with known CVEs.",
    "bak": (
        "Worth checking: Backup/archive host; check for exposed archives and sensitive dumps."
    ),
    "backup": (
        "Worth checking: Backup/archive host; check for exposed archives and sensitive dumps."
    ),
    "vpn": "Worth checking: VPN/gateway access; check for default logins or known appliance CVEs.",
    "remote": "Worth checking: Remote access portal; inspect login security and MFA enforcement.",
    "portal": (
        "Worth checking: Login/user portal; test for auth bypass, credential stuffing, "
        "or open redirect."
    ),
    "login": (
        "Worth checking: Login page; test for auth bypass, credential stuffing, or open redirect."
    ),
    "sso": (
        "Worth checking: Single sign-on gateway; inspect SAML/OAuth redirect URIs and tokens."
    ),
    "auth": "Worth checking: Authentication service; check token issuance and password resets.",
}

TECH_TITLE_HINTS = [
    (
        "jenkins",
        "Worth checking: Jenkins instance; check for unauthenticated access or /script console.",
    ),
    (
        "grafana",
        "Worth checking: Grafana dashboard; check for default credentials or snapshot leaks.",
    ),
    ("kibana", "Worth checking: Kibana interface; inspect for unprotected Elasticsearch indices."),
    ("phpmyadmin", "Worth checking: phpMyAdmin interface; check for default credentials."),
    (
        "swagger",
        "Worth checking: Swagger UI; explore documented API endpoints for unauthenticated access.",
    ),
    (
        "openapi",
        "Worth checking: OpenAPI documentation; explore documented API routes.",
    ),
    (
        "index of /",
        "Worth checking: Directory listing enabled; check exposed files and backups.",
    ),
    (
        "directory listing",
        "Worth checking: Directory listing enabled; check exposed files and backups.",
    ),
    (
        "gitlab",
        "Worth checking: GitLab instance; check for public repos, user signup, or snippets.",
    ),
    (
        "spring boot",
        "Worth checking: Spring Boot application; test for exposed /actuator endpoints.",
    ),
    (
        "actuator",
        "Worth checking: Spring Boot Actuator detected; check /env, /heapdump, and /beans.",
    ),
    ("laravel", "Worth checking: Laravel application; test for exposed .env or debug mode."),
    ("django", "Worth checking: Django application; test for debug tracebacks or admin panel."),
    ("airflow", "Worth checking: Apache Airflow; check for unauthenticated webserver / DAGs."),
    ("sonarqube", "Worth checking: SonarQube portal; check for public project code or API keys."),
    ("docker", "Worth checking: Docker registry or API; check for unauthenticated /v2/_catalog."),
    ("kubernetes", "Worth checking: Kubernetes dashboard or API; check for exposed API endpoints."),
]


def extract_hints_for_host(
    url: str,
    status_code: int = None,
    title: str = None,
    tech: list = None,
) -> list:
    """Analyze a single live host and return list of actionable lead hints."""
    hints = []
    seen = set()

    hostname = (urlparse(url).hostname or url).lower()
    labels = hostname.replace("-", ".").replace("_", ".").split(".")

    # 1. Hostname keyword hints
    for label in labels:
        if label in KEYWORD_HINTS:
            hint = KEYWORD_HINTS[label]
            if hint not in seen:
                seen.add(hint)
                hints.append(hint)

    # 2. Tech and title hints
    tech_str = " ".join(t.lower() for t in (tech or []))
    title_lower = (title or "").lower()
    combined_meta = f"{tech_str} {title_lower}"

    for trigger, hint in TECH_TITLE_HINTS:
        if trigger in combined_meta:
            if hint not in seen:
                seen.add(hint)
                hints.append(hint)

    # 3. Status code hints
    if status_code in (401, 403):
        hint = (
            "Worth checking: HTTP 401/403 barrier; test path normalization or header bypasses."
        )
        if hint not in seen:
            seen.add(hint)
            hints.append(hint)
    elif status_code == 500:
        hint = (
            "Worth checking: Internal server error (500); inspect response body for debug traces."
        )
        if hint not in seen:
            seen.add(hint)
            hints.append(hint)

    return hints


def extract_hints_for_change(url: str, diffs: dict, new_host_meta: dict = None) -> list:
    """Analyze a changed host transition and return lead hints."""
    hints = []
    seen = set()

    status_diff = diffs.get("status_code")
    if status_diff:
        old_status, new_status = status_diff
        if old_status in (401, 403) and new_status == 200:
            hint = (
                f"Worth checking: Status changed from {old_status} to 200; "
                "previously protected resource is now publicly accessible."
            )
            if hint not in seen:
                seen.add(hint)
                hints.append(hint)
        elif new_status in (401, 403) and old_status != new_status:
            hint = (
                f"Worth checking: Status changed to {new_status}; "
                "newly restricted endpoint may have bypassable auth controls."
            )
            if hint not in seen:
                seen.add(hint)
                hints.append(hint)

    title_diff = diffs.get("title")
    if title_diff:
        old_title, new_title = title_diff
        new_title_lower = (new_title or "").lower()
        if any(w in new_title_lower for w in ("login", "admin", "dashboard", "portal", "sign in")):
            hint = (
                f"Worth checking: Page title changed to '{new_title}'; "
                "inspect newly exposed auth interface."
            )
            if hint not in seen:
                seen.add(hint)
                hints.append(hint)

    tech_diff = diffs.get("technologies")
    if tech_diff:
        old_tech, new_tech = set(tech_diff[0]), set(tech_diff[1])
        added_tech = new_tech - old_tech
        added_str = " ".join(t.lower() for t in added_tech)
        for trigger, hint in TECH_TITLE_HINTS:
            if trigger in added_str:
                if hint not in seen:
                    seen.add(hint)
                    hints.append(hint)

    base_hints = extract_hints_for_host(
        url,
        status_code=(new_host_meta or {}).get("status_code"),
        title=(new_host_meta or {}).get("title"),
        tech=(new_host_meta or {}).get("technologies"),
    )
    for h in base_hints:
        if h not in seen:
            seen.add(h)
            hints.append(h)

    return hints


def score_lead(target: str, meta: dict = None) -> int:
    """Calculate an interest score (0 to 100) for a host or URL."""
    score = 0
    meta = meta or {}
    t_lower = target.lower()

    # High-value exposure patterns (+30)
    high_value_keywords = (
        ".env",
        ".git",
        "backup",
        "dump",
        ".sql",
        "heapdump",
        "actuator",
    )
    if any(k in t_lower for k in high_value_keywords):
        score += 30

    # API / documentation / debug (+25)
    api_keywords = ("swagger", "openapi", "graphql", "api/v", "debug", "trace")
    if any(k in t_lower for k in api_keywords):
        score += 25

    # Admin / internal / dev environment (+20)
    env_keywords = (
        "admin",
        "internal",
        "intranet",
        "corp",
        "dev.",
        "staging.",
        "test.",
    )
    if any(k in t_lower for k in env_keywords):
        score += 20

    # Auth / access portals (+15)
    auth_keywords = ("login", "signin", "sso", "oauth", "portal", "auth")
    if any(k in t_lower for k in auth_keywords):
        score += 15

    # Dangerous parameter indicators in URLs (+15)
    param_keywords = (
        "url=",
        "redirect=",
        "next=",
        "dest=",
        "target=",
        "file=",
        "path=",
    )
    if any(p in t_lower for p in param_keywords):
        score += 15

    # Status codes (+10)
    status_code = meta.get("status_code")
    if status_code in (401, 403, 500):
        score += 10

    return min(score, 100)


def rank_leads(targets: list) -> list:
    """Rank hosts or URLs by score in descending order."""
    ranked = []
    for item in targets:
        if isinstance(item, dict):
            url = item.get("url") or item.get("host") or ""
            meta = item
        else:
            url = str(item)
            meta = {}
        score = score_lead(url, meta)
        hints = extract_hints_for_host(
            url,
            status_code=meta.get("status_code"),
            title=meta.get("title"),
            tech=meta.get("technologies"),
        )
        ranked.append({
            "target": url,
            "score": score,
            "hints": hints,
            "meta": meta,
        })
    ranked.sort(key=lambda x: x["score"], reverse=True)
    return ranked
