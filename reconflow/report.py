"""reconflow.report - Regenerate reports from saved scan snapshots."""

import csv
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit
from . import history


CSV_COLUMNS = (
    "subdomain",
    "ip",
    "status_code",
    "title",
    "technologies",
    "cname",
    "takeover_risk",
)


def export_csv(target, live_hosts, output_dir):
    """Export live host records to report.csv using standard CSV quoting.

    Reconflow's probe snapshots identify hosts primarily by URL. Optional
    enrichment fields absent from a scan become empty cells rather than
    causing an error. The target provides a fallback for incomplete rows.
    """
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "report.csv"

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for host in live_hosts or []:
            if not isinstance(host, dict):
                continue
            url = str(host.get("url") or "")
            hostname = urlsplit(url).hostname if url else None
            technologies = host.get("technologies") or []
            if isinstance(technologies, (list, tuple)):
                technologies = "; ".join(str(item) for item in technologies)
            status_code = host.get("status_code")
            takeover_risk = host.get("takeover_risk")
            writer.writerow(
                {
                    "subdomain": host.get("subdomain") or hostname or target,
                    "ip": host.get("ip") or "",
                    "status_code": status_code if status_code is not None else "",
                    "title": host.get("title") or "",
                    "technologies": technologies,
                    "cname": host.get("cname") or "",
                    "takeover_risk": takeover_risk if takeover_risk is not None else "",
                }
            )
    return path


def export_sarif(domain: str, findings: list, output_dir) -> Path:
    """Export findings to report.sarif (SARIF v2.1.0)."""
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "report.sarif"
    sarif_data = build_sarif_report(domain, findings or [])
    path.write_text(json.dumps(sarif_data, indent=2) + "\n", encoding="utf-8")
    return path


def build_sarif_report(domain: str, findings: list) -> dict:
    """Construct structured SARIF v2.1.0 document from findings."""
    rules = []
    results = []
    seen_rules = set()

    level_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    for f in findings or []:
        if not isinstance(f, dict):
            continue
        tid = f.get("template_id") or f.get("template-id") or "reconflow-finding"
        name = f.get("name") or tid
        sev = (f.get("severity") or "info").lower()
        level = level_map.get(sev, "note")
        desc = f.get("description") or f.get("reason") or name
        host = f.get("host") or domain
        matched_at = f.get("matched_at") or f.get("url") or host

        if tid not in seen_rules:
            seen_rules.add(tid)
            rules.append({
                "id": tid,
                "name": name,
                "shortDescription": {"text": name},
                "fullDescription": {"text": desc},
                "defaultConfiguration": {"level": level},
            })

        results.append({
            "ruleId": tid,
            "level": level,
            "message": {"text": f"Finding on {host}: {name}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": matched_at,
                        }
                    }
                }
            ],
        })

    return {
        "$schema": (
            "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
            "sarif-schema-2.1.0.json"
        ),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "reconflow",
                        "version": "0.4.0",
                        "informationUri": "https://github.com/erenyeager/reconflow",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def format_host_display(host: dict) -> str:
    """Format a host dictionary into a human-readable summary line."""
    url = host.get("url", "")
    code = host.get("status_code", "")
    title = host.get("title", "")
    tech = host.get("technologies", [])

    parts = [url]
    if code:
        parts.append(f"[{code}]")
    if title:
        parts.append(f"[{title}]")
    if tech:
        tech_str = ", ".join(tech) if isinstance(tech, list) else str(tech)
        parts.append(f"[{tech_str}]")
    return " ".join(parts)


def build_markdown_report(domain, run_id, timestamp, subs, hosts, status="complete"):
    """Render a structured Markdown report from scan snapshot data."""
    lines = [
        f"# reconflow report: {domain}",
        "",
        f"- Run ID: `{run_id}`",
        f"- Generated: {timestamp}",
        f"- Status: {status}",
        f"- Subdomains found: {len(subs)}",
        f"- Live hosts: {len(hosts)}",
        "",
        "## Live hosts",
        "",
        "```",
    ]
    if hosts:
        for h in hosts:
            if isinstance(h, dict):
                lines.append(format_host_display(h))
            else:
                lines.append(str(h))
    else:
        lines.append("(No live hosts discovered)")
    lines.extend(["```", ""])
    return "\n".join(lines)


def build_json_report(domain, run_id, timestamp, subs, hosts, status="complete"):
    """Construct structured JSON report dictionary from scan snapshot data."""
    return {
        "domain": domain,
        "run_id": run_id,
        "generated": timestamp,
        "status": status,
        "subdomains_count": len(subs),
        "live_count": len(hosts),
        "subdomains": subs,
        "live_hosts": hosts,
    }


def run(args):
    """Execute report regeneration subcommand."""
    domain = getattr(args, "domain", None)
    if not domain:
        sys.exit("Error: Target domain is required.")

    output_dir = getattr(args, "output", "output") or "output"
    run_id_arg = getattr(args, "run_id", None)
    if not isinstance(run_id_arg, str):
        run_id_arg = getattr(args, "run", None)
    if not isinstance(run_id_arg, str):
        run_id_arg = None

    json_output = bool(getattr(args, "json_report", False) or getattr(args, "json", False))

    out_dir = Path(output_dir) / domain
    runs_dir = out_dir / "runs"

    if not out_dir.exists() or not runs_dir.exists():
        msg = f"[!] No scan history found for {domain} in {out_dir}. Run a scan first."
        if json_output:
            print(json.dumps({"domain": domain, "error": msg, "runs_count": 0}))
        else:
            print(msg)
        sys.exit(0)

    # Select specific run or latest run
    target_run_dir = None
    if run_id_arg:
        candidate = runs_dir / run_id_arg
        if candidate.exists() and candidate.is_dir():
            target_run_dir = candidate
        else:
            msg = f"[!] Scan run '{run_id_arg}' not found for {domain} in {out_dir}."
            if json_output:
                print(json.dumps({"domain": domain, "error": msg}))
            else:
                print(msg)
            sys.exit(1)
    else:
        runs = history.list_runs(out_dir)
        if not runs:
            msg = f"[!] No scan history found for {domain} in {out_dir}. Run a scan first."
            if json_output:
                print(json.dumps({"domain": domain, "error": msg, "runs_count": 0}))
            else:
                print(msg)
            sys.exit(0)
        target_run_dir = runs[-1]

    snapshot = history.load_snapshot(target_run_dir)
    run_id = snapshot.get("run_id", target_run_dir.name)
    timestamp = snapshot.get("timestamp", "")
    subs = snapshot.get("subdomains", [])
    hosts = snapshot.get("hosts", [])
    status = snapshot.get("status", "complete")

    findings = snapshot.get("findings", [])

    md_report = build_markdown_report(domain, run_id, timestamp, subs, hosts, status=status)
    json_data = build_json_report(domain, run_id, timestamp, subs, hosts, status=status)
    sarif_data = build_sarif_report(domain, findings)

    # Write regenerated reports to out_dir
    (out_dir / "report.md").write_text(md_report, encoding="utf-8")
    (out_dir / "report.json").write_text(
        json.dumps(json_data, indent=2) + "\n", encoding="utf-8"
    )
    export_csv(domain, hosts, out_dir)
    export_sarif(domain, findings, out_dir)

    raw_fmt = getattr(args, "format", None)
    fmt = str(raw_fmt).lower().strip() if isinstance(raw_fmt, str) and raw_fmt else None
    if not fmt:
        fmt = "json" if json_output else "md"

    if fmt == "sarif":
        print(json.dumps(sarif_data, indent=2))
    elif fmt == "csv":
        print((out_dir / "report.csv").read_text(encoding="utf-8"))
    elif fmt == "json":
        print(json.dumps(json_data, indent=2))
    else:
        print(md_report)
        print(f"[+] Regenerated reports saved to {out_dir / 'report.md'}")
