"""reconflow.history - Snapshot tracking and incremental scan history management."""

import json
from datetime import datetime
from pathlib import Path


def init_run(out_dir: Path, domain: str = ""):
    """Initialize a new scan run directory and mark it as incomplete initially."""
    base_id = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    run_id = base_id
    runs_dir = out_dir / "runs"
    runs_dir.mkdir(parents=True, exist_ok=True)

    counter = 1
    while (runs_dir / run_id).exists():
        run_id = f"{base_id}_{counter}"
        counter += 1

    run_dir = runs_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    metadata = {
        "run_id": run_id,
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "status": "incomplete",
        "incomplete": True,
        "subdomains": [],
        "hosts": [],
    }
    (run_dir / "snapshot.json").write_text(
        json.dumps(metadata, indent=2) + "\n", encoding="utf-8"
    )

    (run_dir / "scan.jsonl").touch(exist_ok=True)
    try:
        from . import db

        db_path = out_dir / "reconflow.db"
        db.record_run_start(db_path, run_id, domain)
    except Exception:
        pass
    return run_id, run_dir


def record_subdomain(run_dir: Path, subdomain: str):
    """Incrementally record a discovered subdomain into scan.jsonl and flush immediately."""
    jsonl_file = run_dir / "scan.jsonl"
    record = {"type": "subdomain", "subdomain": subdomain}
    with open(jsonl_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
        f.flush()


def record_host(run_dir: Path, host_data: dict):
    """Incrementally record a probed live host into scan.jsonl and flush immediately."""
    jsonl_file = run_dir / "scan.jsonl"
    record = {"type": "host", "host": host_data}
    with open(jsonl_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
        f.flush()


def finalize_run(
    run_dir: Path,
    subs,
    hosts,
    domain: str = "",
    urls=None,
    ports=None,
    findings=None,
    stages_completed=None,
):
    """Mark scan run as complete and write final snapshot.json and SQLite db."""
    snapshot_file = run_dir / "snapshot.json"
    run_id = run_dir.name
    timestamp = datetime.now().isoformat()
    if snapshot_file.exists():
        try:
            existing = json.loads(snapshot_file.read_text(encoding="utf-8"))
            run_id = existing.get("run_id", run_id)
            timestamp = existing.get("timestamp", timestamp)
            if not domain:
                domain = existing.get("domain", "")
        except Exception:
            pass

    data = {
        "run_id": run_id,
        "domain": domain,
        "timestamp": timestamp,
        "status": "complete",
        "incomplete": False,
        "subdomains": sorted(subs),
        "hosts": hosts or [],
        "urls": urls or [],
        "ports": ports or [],
        "findings": findings or [],
        "stages_completed": stages_completed or [],
    }
    snapshot_file.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    # Persist to target SQLite database
    try:
        from . import db

        out_dir = run_dir.parent.parent
        db_path = out_dir / "reconflow.db"
        db.save_subdomains(db_path, domain, run_id, subs)
        db.save_hosts(db_path, domain, run_id, hosts or [])
        if urls:
            db.save_urls(db_path, domain, run_id, urls)
        if ports:
            db.save_ports(db_path, domain, run_id, ports)
        if findings:
            db.save_findings(db_path, domain, run_id, findings)
        db.record_run_complete(db_path, run_id, status="completed")
    except Exception:
        pass

    return run_id


def save_snapshot(out_dir: Path, subs, hosts, domain: str = ""):
    """Save scan results as a timestamped snapshot under out_dir/runs/<run_id>/.

    Backward-compatible wrapper around init_run and finalize_run.
    """
    run_id, run_dir = init_run(out_dir, domain=domain)
    for s in subs:
        record_subdomain(run_dir, s)
    for h in (hosts or []):
        record_host(run_dir, h)
    finalize_run(run_dir, subs, hosts, domain=domain)
    return run_id


def list_runs(out_dir: Path):
    """Return a sorted list of run directories containing snapshot.json or scan.jsonl."""
    runs_dir = out_dir / "runs"
    if not runs_dir.exists() or not runs_dir.is_dir():
        return []
    valid_runs = [
        p for p in runs_dir.iterdir()
        if p.is_dir() and ((p / "snapshot.json").exists() or (p / "scan.jsonl").exists())
    ]
    return sorted(valid_runs, key=lambda p: p.name)


def load_snapshot(run_dir: Path):
    """Load and parse scan snapshot from the specified run directory.

    Handles incomplete scans and handles truncated last line in scan.jsonl.
    Backward-compatible with legacy snapshot.json formats.
    """
    snapshot_file = run_dir / "snapshot.json"
    jsonl_file = run_dir / "scan.jsonl"

    data = None
    if snapshot_file.exists():
        try:
            data = json.loads(snapshot_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            data = None

    if data is None:
        if not jsonl_file.exists():
            raise FileNotFoundError(f"No scan data found in {run_dir}")
        data = {
            "run_id": run_dir.name,
            "timestamp": datetime.now().isoformat(),
            "status": "incomplete",
            "incomplete": True,
            "subdomains": [],
            "hosts": [],
        }

    # Ensure status keys exist (legacy snapshots without status are complete)
    if "status" not in data:
        data["status"] = "complete"
        data["incomplete"] = False
    elif "incomplete" not in data:
        data["incomplete"] = (data.get("status") == "incomplete")

    # If scan was incomplete or jsonl exists, parse incremental records handling truncated lines
    if jsonl_file.exists():
        jsonl_subs = set()
        jsonl_hosts = []
        try:
            with open(jsonl_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        record = json.loads(stripped)
                    except json.JSONDecodeError:
                        # Handle truncated last line from abrupt exit / crash
                        continue
                    rec_type = record.get("type")
                    if rec_type == "subdomain":
                        sub = record.get("subdomain") or record.get("data")
                        if sub:
                            jsonl_subs.add(sub)
                    elif rec_type == "host":
                        h = record.get("host") or record.get("data")
                        if h:
                            jsonl_hosts.append(h)
        except OSError:
            pass

        # If data has empty subdomains/hosts (e.g. from an incomplete run), populate from jsonl
        if data.get("incomplete"):
            if jsonl_subs and not data.get("subdomains"):
                data["subdomains"] = sorted(jsonl_subs)
            if jsonl_hosts and not data.get("hosts"):
                data["hosts"] = jsonl_hosts

    # Ensure extended fields exist
    if "urls" not in data:
        data["urls"] = []
    if "ports" not in data:
        data["ports"] = []
    if "findings" not in data:
        data["findings"] = []

    # If missing extended fields, check SQLite db
    db_path = run_dir.parent.parent / "reconflow.db"
    if db_path.exists() and (not data["urls"] or not data["ports"] or not data["findings"]):
        try:
            from . import db

            db_data = db.get_run_data(db_path, data.get("run_id", run_dir.name))
            if not data["urls"] and db_data.get("urls"):
                data["urls"] = db_data["urls"]
            if not data["ports"] and db_data.get("ports"):
                data["ports"] = db_data["ports"]
            if not data["findings"] and db_data.get("findings"):
                data["findings"] = db_data["findings"]
        except Exception:
            pass

    return data
