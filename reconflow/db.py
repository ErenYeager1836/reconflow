"""reconflow.db - SQLite target storage and scan run ledger."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def _get_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_db(db_path: Path) -> sqlite3.Connection:
    """Connect to SQLite database with foreign keys and row factory enabled."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Path) -> sqlite3.Connection:
    """Initialize SQLite database tables and indices for target state."""
    conn = get_db(db_path)
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS runs (
            id TEXT PRIMARY KEY,
            domain TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            status TEXT NOT NULL DEFAULT 'running',
            stages_completed TEXT NOT NULL DEFAULT '[]'
        );

        CREATE TABLE IF NOT EXISTS subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            host TEXT NOT NULL,
            run_id TEXT NOT NULL,
            discovered_at TEXT NOT NULL,
            UNIQUE(domain, host, run_id)
        );

        CREATE TABLE IF NOT EXISTS dns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            host TEXT NOT NULL,
            ips TEXT NOT NULL DEFAULT '[]',
            cnames TEXT NOT NULL DEFAULT '[]',
            status_code TEXT,
            run_id TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(domain, host, run_id)
        );

        CREATE TABLE IF NOT EXISTS hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            host TEXT NOT NULL,
            url TEXT NOT NULL,
            status_code INTEGER DEFAULT 0,
            title TEXT DEFAULT '',
            technologies TEXT NOT NULL DEFAULT '[]',
            cname TEXT NOT NULL DEFAULT '[]',
            webserver TEXT DEFAULT '',
            run_id TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            UNIQUE(domain, url, run_id)
        );

        CREATE TABLE IF NOT EXISTS urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            url TEXT NOT NULL,
            source TEXT DEFAULT '',
            run_id TEXT NOT NULL,
            discovered_at TEXT NOT NULL,
            UNIQUE(domain, url, run_id)
        );

        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            host TEXT NOT NULL,
            ip TEXT DEFAULT '',
            port INTEGER NOT NULL,
            run_id TEXT NOT NULL,
            discovered_at TEXT NOT NULL,
            UNIQUE(domain, host, port, run_id)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            template_id TEXT NOT NULL,
            name TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            host TEXT NOT NULL,
            matched_at TEXT NOT NULL,
            matcher_name TEXT DEFAULT '',
            description TEXT DEFAULT '',
            run_id TEXT NOT NULL,
            discovered_at TEXT NOT NULL,
            UNIQUE(domain, template_id, host, matcher_name, run_id)
        );

        CREATE INDEX IF NOT EXISTS idx_runs_domain ON runs(domain);
        CREATE INDEX IF NOT EXISTS idx_subdomains_domain_host ON subdomains(domain, host);
        CREATE INDEX IF NOT EXISTS idx_subdomains_run_id ON subdomains(run_id);
        CREATE INDEX IF NOT EXISTS idx_hosts_domain_url ON hosts(domain, url);
        CREATE INDEX IF NOT EXISTS idx_hosts_run_id ON hosts(run_id);
        CREATE INDEX IF NOT EXISTS idx_urls_domain_url ON urls(domain, url);
        CREATE INDEX IF NOT EXISTS idx_urls_run_id ON urls(run_id);
        CREATE INDEX IF NOT EXISTS idx_ports_domain_host ON ports(domain, host);
        CREATE INDEX IF NOT EXISTS idx_ports_run_id ON ports(run_id);
        CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings(domain);
        CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id);
        """)
    return conn


def record_run_start(db_path: Path, run_id: str, domain: str) -> None:
    """Record a new scan run in the database."""
    conn = init_db(db_path)
    now = _get_utc_now()
    with conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO runs (id, domain, created_at, status, stages_completed)
            VALUES (?, ?, ?, 'running', '[]')
            """,
            (run_id, domain, now),
        )
    conn.close()


def record_stage_completed(db_path: Path, run_id: str, stage: str) -> None:
    """Append a completed stage to the run's completed stages list."""
    conn = init_db(db_path)
    with conn:
        cur = conn.execute("SELECT stages_completed FROM runs WHERE id = ?", (run_id,))
        row = cur.fetchone()
        if row:
            try:
                stages = json.loads(row["stages_completed"])
            except Exception:
                stages = []
            if stage not in stages:
                stages.append(stage)
                conn.execute(
                    "UPDATE runs SET stages_completed = ? WHERE id = ?",
                    (json.dumps(stages), run_id),
                )
    conn.close()


def record_run_complete(db_path: Path, run_id: str, status: str = "completed") -> None:
    """Mark a run as completed."""
    conn = init_db(db_path)
    now = _get_utc_now()
    with conn:
        conn.execute(
            "UPDATE runs SET completed_at = ?, status = ? WHERE id = ?",
            (now, status, run_id),
        )
    conn.close()


def get_completed_stages(db_path: Path, run_id: str) -> List[str]:
    """Return the list of completed stages for a run."""
    conn = init_db(db_path)
    cur = conn.execute("SELECT stages_completed FROM runs WHERE id = ?", (run_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        try:
            return json.loads(row["stages_completed"])
        except Exception:
            return []
    return []


def get_latest_runs(db_path: Path, domain: str, limit: int = 2) -> List[str]:
    """Return the IDs of the latest scan runs for a domain."""
    conn = init_db(db_path)
    cur = conn.execute(
        """
        SELECT id FROM runs
        WHERE domain = ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (domain, limit),
    )
    rows = cur.fetchall()
    conn.close()
    return [r["id"] for r in rows]


def get_last_run(db_path: Path, domain: str) -> Optional[Dict[str, Any]]:
    """Return metadata dict of the latest run for a domain."""
    conn = init_db(db_path)
    cur = conn.execute(
        """
        SELECT id, domain, created_at, completed_at, status, stages_completed
        FROM runs
        WHERE domain = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (domain,),
    )
    row = cur.fetchone()
    conn.close()
    if not row:
        return None
    try:
        stages = json.loads(row["stages_completed"])
    except Exception:
        stages = []
    return {
        "id": row["id"],
        "domain": row["domain"],
        "created_at": row["created_at"],
        "completed_at": row["completed_at"],
        "status": row["status"],
        "stages_completed": stages,
    }


def save_subdomains(db_path: Path, domain: str, run_id: str, subs: List[str]) -> None:
    """Persist discovered subdomains into the database."""
    conn = init_db(db_path)
    now = _get_utc_now()
    with conn:
        for s in subs:
            host = s.strip().lower()
            if host:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO subdomains (domain, host, run_id, discovered_at)
                    VALUES (?, ?, ?, ?)
                    """,
                    (domain, host, run_id, now),
                )
    conn.close()


def save_dns_records(
    db_path: Path, domain: str, run_id: str, records: List[Dict[str, Any]]
) -> None:
    """Persist resolved DNS records into the database."""
    conn = init_db(db_path)
    now = _get_utc_now()
    with conn:
        for r in records:
            host = (r.get("host") or "").strip().lower()
            if not host:
                continue
            ips = json.dumps(r.get("ips") or [])
            cnames = json.dumps(r.get("cnames") or [])
            status_code = str(r.get("status_code") or "")
            conn.execute(
                """
                INSERT OR REPLACE INTO dns
                (domain, host, ips, cnames, status_code, run_id, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (domain, host, ips, cnames, status_code, run_id, now),
            )
    conn.close()


def save_hosts(
    db_path: Path, domain: str, run_id: str, hosts_data: List[Dict[str, Any]]
) -> None:
    """Persist probed live HTTP hosts into the database."""
    conn = init_db(db_path)
    now = _get_utc_now()
    with conn:
        for h in hosts_data:
            url = (h.get("url") or "").strip()
            if not url:
                continue
            host = (h.get("host") or "").strip().lower()
            status_code = int(h.get("status_code", 0) or 0)
            title = h.get("title") or ""
            tech = json.dumps(h.get("technologies") or [])
            cname = json.dumps(h.get("cname") or [])
            webserver = h.get("webserver") or ""
            conn.execute(
                """
                INSERT OR REPLACE INTO hosts
                (domain, host, url, status_code, title, technologies, cname,
                 webserver, run_id, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (domain, host, url, status_code, title, tech, cname, webserver, run_id, now),
            )
    conn.close()


def save_urls(
    db_path: Path, domain: str, run_id: str, urls: List[Any]
) -> None:
    """Persist gathered endpoints/URLs into the database."""
    conn = init_db(db_path)
    now = _get_utc_now()
    with conn:
        for u in urls:
            if isinstance(u, dict):
                url_str = (u.get("url") or "").strip()
                source = u.get("source") or ""
            else:
                url_str = str(u).strip()
                source = ""
            if url_str:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO urls (domain, url, source, run_id, discovered_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (domain, url_str, source, run_id, now),
                )
    conn.close()


def save_ports(
    db_path: Path, domain: str, run_id: str, ports: List[Dict[str, Any]]
) -> None:
    """Persist discovered open ports into the database."""
    conn = init_db(db_path)
    now = _get_utc_now()
    with conn:
        for p in ports:
            host = (p.get("host") or "").strip().lower()
            ip = p.get("ip") or ""
            port = int(p.get("port") or 0)
            if host and port > 0:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO ports (domain, host, ip, port, run_id, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (domain, host, ip, port, run_id, now),
                )
    conn.close()


def save_findings(
    db_path: Path, domain: str, run_id: str, findings: List[Dict[str, Any]]
) -> None:
    """Persist nuclei vulnerability findings into the database."""
    conn = init_db(db_path)
    now = _get_utc_now()
    with conn:
        for f in findings:
            template_id = (f.get("template_id") or "").strip()
            name = (f.get("name") or "").strip()
            severity = (f.get("severity") or "info").strip().lower()
            host = (f.get("host") or "").strip().lower()
            matched_at = (f.get("matched_at") or "").strip()
            matcher_name = (f.get("matcher_name") or "").strip()
            description = (f.get("description") or "").strip()
            if template_id and host:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO findings
                    (domain, template_id, name, severity, host, matched_at,
                     matcher_name, description, run_id, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        domain,
                        template_id,
                        name,
                        severity,
                        host,
                        matched_at,
                        matcher_name,
                        description,
                        run_id,
                        now,
                    ),
                )
    conn.close()


def get_subdomains(
    db_path: Path, domain: str, run_id: Optional[str] = None
) -> List[str]:
    """Retrieve discovered subdomains for a domain, optionally filtered by run_id."""
    conn = get_db(db_path)
    if run_id:
        cur = conn.execute(
            "SELECT host FROM subdomains WHERE domain = ? AND run_id = ? ORDER BY host",
            (domain, run_id),
        )
    else:
        cur = conn.execute(
            "SELECT DISTINCT host FROM subdomains WHERE domain = ? ORDER BY host",
            (domain,),
        )
    subs = [r["host"] for r in cur.fetchall()]
    conn.close()
    return subs


def get_hosts(
    db_path: Path, domain: str, run_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieve probed hosts for a domain, optionally filtered by run_id."""
    conn = get_db(db_path)
    if run_id:
        cur = conn.execute(
            """
            SELECT host, url, status_code, title, technologies, cname, webserver
            FROM hosts
            WHERE domain = ? AND run_id = ?
            ORDER BY url
            """,
            (domain, run_id),
        )
    else:
        cur = conn.execute(
            """
            SELECT host, url, status_code, title, technologies, cname, webserver
            FROM hosts
            WHERE domain = ?
            ORDER BY url
            """,
            (domain,),
        )
    hosts = []
    for r in cur.fetchall():
        try:
            tech = json.loads(r["technologies"])
        except Exception:
            tech = []
        try:
            cname = json.loads(r["cname"])
        except Exception:
            cname = []
        hosts.append({
            "host": r["host"],
            "url": r["url"],
            "status_code": r["status_code"],
            "title": r["title"],
            "technologies": tech,
            "cname": cname,
            "webserver": r["webserver"],
        })
    conn.close()
    return hosts


def get_urls(
    db_path: Path, domain: str, run_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieve URLs for a domain, optionally filtered by run_id."""
    conn = get_db(db_path)
    if run_id:
        cur = conn.execute(
            "SELECT url, source FROM urls WHERE domain = ? AND run_id = ? ORDER BY url",
            (domain, run_id),
        )
    else:
        cur = conn.execute(
            "SELECT DISTINCT url, source FROM urls WHERE domain = ? ORDER BY url",
            (domain,),
        )
    urls = [{"url": r["url"], "source": r["source"]} for r in cur.fetchall()]
    conn.close()
    return urls


def get_ports(
    db_path: Path, domain: str, run_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieve open ports for a domain, optionally filtered by run_id."""
    conn = get_db(db_path)
    if run_id:
        cur = conn.execute(
            "SELECT host, ip, port FROM ports WHERE domain = ? AND run_id = ? ORDER BY port",
            (domain, run_id),
        )
    else:
        cur = conn.execute(
            "SELECT DISTINCT host, ip, port FROM ports WHERE domain = ? ORDER BY port",
            (domain,),
        )
    ports = [{"host": r["host"], "ip": r["ip"], "port": r["port"]} for r in cur.fetchall()]
    conn.close()
    return ports


def get_findings(
    db_path: Path, domain: str, run_id: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Retrieve findings for a domain, optionally filtered by run_id."""
    conn = get_db(db_path)
    if run_id:
        cur = conn.execute(
            """
            SELECT template_id, name, severity, host, matched_at, matcher_name, description
            FROM findings
            WHERE domain = ? AND run_id = ?
            ORDER BY severity DESC
            """,
            (domain, run_id),
        )
    else:
        cur = conn.execute(
            """
            SELECT template_id, name, severity, host, matched_at, matcher_name, description
            FROM findings
            WHERE domain = ?
            ORDER BY severity DESC
            """,
            (domain,),
        )
    findings = [
        {
            "template_id": r["template_id"],
            "name": r["name"],
            "severity": r["severity"],
            "host": r["host"],
            "matched_at": r["matched_at"],
            "matcher_name": r["matcher_name"],
            "description": r["description"],
        }
        for r in cur.fetchall()
    ]
    conn.close()
    return findings


def get_run_data(db_path: Path, run_id: str) -> Dict[str, Any]:
    """Retrieve all structured recon records for a specific scan run."""
    conn = init_db(db_path)

    # Subdomains
    cur = conn.execute("SELECT host FROM subdomains WHERE run_id = ?", (run_id,))
    subdomains = [r["host"] for r in cur.fetchall()]

    # DNS
    cur = conn.execute("SELECT host, ips, cnames, status_code FROM dns WHERE run_id = ?", (run_id,))
    dns_records = []
    for r in cur.fetchall():
        try:
            ips = json.loads(r["ips"])
        except Exception:
            ips = []
        try:
            cnames = json.loads(r["cnames"])
        except Exception:
            cnames = []
        dns_records.append({
            "host": r["host"],
            "ips": ips,
            "cnames": cnames,
            "status_code": r["status_code"],
        })

    # Hosts
    cur = conn.execute(
        """
        SELECT host, url, status_code, title, technologies, cname, webserver
        FROM hosts
        WHERE run_id = ?
        """,
        (run_id,),
    )
    hosts = []
    for r in cur.fetchall():
        try:
            tech = json.loads(r["technologies"])
        except Exception:
            tech = []
        try:
            cname = json.loads(r["cname"])
        except Exception:
            cname = []
        hosts.append({
            "host": r["host"],
            "url": r["url"],
            "status_code": r["status_code"],
            "title": r["title"],
            "technologies": tech,
            "cname": cname,
            "webserver": r["webserver"],
        })

    # URLs
    cur = conn.execute("SELECT url, source FROM urls WHERE run_id = ?", (run_id,))
    urls = [{"url": r["url"], "source": r["source"]} for r in cur.fetchall()]

    # Ports
    cur = conn.execute("SELECT host, ip, port FROM ports WHERE run_id = ?", (run_id,))
    ports = [{"host": r["host"], "ip": r["ip"], "port": r["port"]} for r in cur.fetchall()]

    # Findings
    cur = conn.execute(
        """
        SELECT template_id, name, severity, host, matched_at, matcher_name, description
        FROM findings
        WHERE run_id = ?
        """,
        (run_id,),
    )
    findings = [
        {
            "template_id": r["template_id"],
            "name": r["name"],
            "severity": r["severity"],
            "host": r["host"],
            "matched_at": r["matched_at"],
            "matcher_name": r["matcher_name"],
            "description": r["description"],
        }
        for r in cur.fetchall()
    ]

    conn.close()
    return {
        "run_id": run_id,
        "subdomains": subdomains,
        "dns": dns_records,
        "hosts": hosts,
        "urls": urls,
        "ports": ports,
        "findings": findings,
    }
