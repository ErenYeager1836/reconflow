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
            writer.writerow(
                {
                    "subdomain": host.get("subdomain") or hostname or target,
                    "ip": host.get("ip") or "",
                    "status_code": host.get("status_code") if host.get("status_code") is not None else "",
                    "title": host.get("title") or "",
                    "technologies": technologies,
                    "cname": host.get("cname") or "",
                    "takeover_risk": host.get("takeover_risk") if host.get("takeover_risk") is not None else "",
                }
            )
    return path


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

    md_report = build_markdown_report(domain, run_id, timestamp, subs, hosts, status=status)
    json_data = build_json_report(domain, run_id, timestamp, subs, hosts, status=status)

    # Write regenerated reports to out_dir
    (out_dir / "report.md").write_text(md_report, encoding="utf-8")
    (out_dir / "report.json").write_text(
        json.dumps(json_data, indent=2) + "\n", encoding="utf-8"
    )

    if json_output:
        print(json.dumps(json_data, indent=2))
    else:
        print(md_report)
        print(f"[+] Regenerated reports saved to {out_dir / 'report.md'}")
