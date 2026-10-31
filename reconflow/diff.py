"""reconflow.diff - Differential change detection between scan runs."""

import json
import sys
from pathlib import Path
from urllib.parse import urlparse
from . import history


# Tags that flip between runs because of CDN/transport behavior, not app changes
IGNORED_TECH = {"HTTP/2", "HTTP/3", "HSTS"}


def _hostname(url):
    return (urlparse(url).hostname or url).lower()


def _by_host(hosts):
    """Map hostname -> host record. If a host answers on both schemes, prefer https."""
    result = {}
    for h in hosts or []:
        if not isinstance(h, dict) or "url" not in h:
            continue
        name = _hostname(h["url"])
        current = result.get(name)
        if current is None or (
            h["url"].startswith("https://") and not current["url"].startswith("https://")
        ):
            result[name] = h
    return result


def _meaningful_tech(tech):
    return {t for t in (tech or []) if t not in IGNORED_TECH}


def compare(old, new, triage_hosts=None):
    """Compare two scan snapshots and return differences.

    Hosts are matched by hostname, so a scheme flip (http <-> https) is not
    reported as one host disappearing and another appearing.
    Tested or ignored hosts from triage_hosts are suppressed.
    """
    old_hosts = _by_host(old.get("hosts"))
    new_hosts = _by_host(new.get("hosts"))

    triage_map = {}
    if isinstance(triage_hosts, dict):
        for k, v in triage_hosts.items():
            if isinstance(v, dict):
                triage_map[k] = v.get("status", "tested")
            else:
                triage_map[k] = str(v)
    elif isinstance(triage_hosts, (set, list)):
        for k in triage_hosts:
            triage_map[k] = "tested"

    suppressed_triaged = []

    changed = {}
    for name in old_hosts.keys() & new_hosts.keys():
        triage_status = triage_map.get(name)
        if triage_status == "ignore":
            suppressed_triaged.append(new_hosts[name]["url"])
            continue
        o, n = old_hosts[name], new_hosts[name]
        diffs = {}
        if o.get("status_code") != n.get("status_code"):
            diffs["status_code"] = (o.get("status_code"), n.get("status_code"))
        if o.get("title") != n.get("title"):
            diffs["title"] = (o.get("title"), n.get("title"))
        if _meaningful_tech(o.get("technologies")) != _meaningful_tech(n.get("technologies")):
            diffs["technologies"] = (o.get("technologies") or [], n.get("technologies") or [])
        if diffs:
            changed[n["url"]] = diffs

    old_subs = set(old.get("subdomains") or [])
    new_subs = set(new.get("subdomains") or [])

    new_live_names = new_hosts.keys() - old_hosts.keys()
    new_live_urls = []
    for h in new_live_names:
        if h in triage_map:
            suppressed_triaged.append(new_hosts[h]["url"])
        else:
            new_live_urls.append(new_hosts[h]["url"])
    new_live_urls.sort()

    gone_live_urls = sorted(old_hosts[h]["url"] for h in old_hosts.keys() - new_hosts.keys())
    removed_subs = sorted(old_subs - new_subs)

    # Incomplete scan handling: never report missing hosts as gone if scan was incomplete
    incomplete_warning = None
    old_incomplete = bool(old.get("incomplete") or old.get("status") == "incomplete")
    new_incomplete = bool(new.get("incomplete") or new.get("status") == "incomplete")
    if old_incomplete or new_incomplete:
        gone_live_urls = []
        removed_subs = []
        incomplete_warning = (
            "Warning: Comparison involves an incomplete scan; "
            "missing hosts are not reported as gone."
        )

    # Generate lead hints
    from . import leads

    lead_hints = {}
    for url in new_live_urls:
        h_record = next(
            (h for h in (new.get("hosts") or []) if isinstance(h, dict) and h.get("url") == url),
            None,
        )
        hints = leads.extract_hints_for_host(
            url,
            status_code=h_record.get("status_code") if h_record else None,
            title=h_record.get("title") if h_record else None,
            tech=h_record.get("technologies") if h_record else None,
        )
        if hints:
            lead_hints[url] = hints

    for url, diffs in changed.items():
        h_record = next(
            (h for h in (new.get("hosts") or []) if isinstance(h, dict) and h.get("url") == url),
            None,
        )
        hints = leads.extract_hints_for_change(url, diffs, new_host_meta=h_record)
        if hints:
            lead_hints[url] = hints

    # 1. New open ports
    old_ports = {}
    for p in old.get("ports") or []:
        if isinstance(p, dict) and "host" in p and "port" in p:
            old_ports.setdefault(p["host"].lower(), set()).add(int(p["port"]))
    new_ports = {}
    for p in new.get("ports") or []:
        if isinstance(p, dict) and "host" in p and "port" in p:
            h = p["host"].lower()
            port = int(p["port"])
            if port not in old_ports.get(h, set()):
                new_ports.setdefault(h, []).append(port)
    for h in new_ports:
        new_ports[h].sort()

    # 2. New URLs / endpoints
    old_urls = set()
    for u in old.get("urls") or []:
        url_str = u.get("url") if isinstance(u, dict) else str(u)
        if url_str:
            old_urls.add(url_str.strip())
    new_urls_list = []
    for u in new.get("urls") or []:
        url_str = u.get("url") if isinstance(u, dict) else str(u)
        if url_str and url_str.strip() not in old_urls:
            new_urls_list.append(url_str.strip())
    new_urls = sorted(set(new_urls_list))

    # 3. New nuclei findings (deduped by template-id + host + matcher)
    def _finding_key(f):
        if not isinstance(f, dict):
            return str(f)
        return (
            (f.get("template_id") or f.get("template-id") or "").strip().lower(),
            (f.get("host") or "").strip().lower(),
            (f.get("matcher_name") or f.get("matcher-name") or "").strip().lower(),
        )

    old_findings_keys = {_finding_key(f) for f in old.get("findings") or []}
    new_findings = []
    seen_new_findings = set()
    for f in new.get("findings") or []:
        key = _finding_key(f)
        if key not in old_findings_keys and key not in seen_new_findings:
            seen_new_findings.add(key)
            new_findings.append(f)

    result = {
        "new_subdomains": sorted(new_subs - old_subs),
        "removed_subdomains": removed_subs,
        "new_live": new_live_urls,
        "gone_live": gone_live_urls,
        "changed": changed,
        "new_ports": new_ports,
        "new_urls": new_urls,
        "new_findings": new_findings,
        "lead_hints": lead_hints,
    }
    if suppressed_triaged:
        result["suppressed_triaged"] = sorted(set(suppressed_triaged))
    if incomplete_warning:
        result["incomplete_warning"] = incomplete_warning
    return result


def format_diff(diff_result, old_id, new_id, new_data=None):
    """Render a human-readable comparison summary between two runs."""
    lines = [
        f"[*] Recon diff: {old_id} -> {new_id}",
        "=" * 60,
    ]

    incomplete_warning = diff_result.get("incomplete_warning")
    if incomplete_warning:
        lines.append(f"[!] {incomplete_warning}\n")

    suppressed_triaged = diff_result.get("suppressed_triaged", [])
    if suppressed_triaged:
        lines.append(
            f"[*] Filtered out {len(suppressed_triaged)} triaged host(s) (tested/ignored)."
        )

    new_subs = diff_result.get("new_subdomains", [])
    new_live = diff_result.get("new_live", [])
    changed = diff_result.get("changed", {})
    removed_subs = diff_result.get("removed_subdomains", [])
    gone_live = diff_result.get("gone_live", [])
    new_ports = diff_result.get("new_ports", {})
    new_urls = diff_result.get("new_urls", [])
    new_findings = diff_result.get("new_findings", [])
    lead_hints = diff_result.get("lead_hints", {})

    has_changes = any([
        new_subs,
        new_live,
        changed,
        removed_subs,
        gone_live,
        new_ports,
        new_urls,
        new_findings,
    ])
    if not has_changes:
        lines.append("[+] No changes detected between scans.")
        return "\n".join(lines)

    if new_subs:
        lines.append(f"\n[+] NEW SUBDOMAINS ({len(new_subs)}):")
        for s in new_subs:
            lines.append(f"    + {s}")

    if new_live:
        lines.append(f"\n[+] NEWLY LIVE HOSTS ({len(new_live)}):")
        hosts_map = {}
        if new_data and isinstance(new_data, dict):
            hosts_map = {
                h["url"]: h
                for h in (new_data.get("hosts") or [])
                if isinstance(h, dict) and "url" in h
            }
        for h in new_live:
            meta = hosts_map.get(h)
            if meta:
                code = meta.get("status_code")
                title = meta.get("title")
                tech = meta.get("technologies") or []
                parts = []
                if code:
                    parts.append(f"[{code}]")
                if title:
                    parts.append(f"[{title}]")
                if tech:
                    tech_str = ", ".join(tech) if isinstance(tech, list) else str(tech)
                    parts.append(f"[{tech_str}]")
                detail = (" " + " ".join(parts)) if parts else ""
                lines.append(f"    + {h}{detail}")
            else:
                lines.append(f"    + {h}")
            if h in lead_hints:
                for hint in lead_hints[h]:
                    lines.append(f"        * {hint}")

    if changed:
        lines.append(f"\n[*] CHANGED HOSTS ({len(changed)}):")
        for url, diffs in changed.items():
            lines.append(f"    ~ {url}")
            if "status_code" in diffs:
                o, n = diffs["status_code"]
                lines.append(f"        status: {o} -> {n}")
            if "title" in diffs:
                o, n = diffs["title"]
                lines.append(f"        title: '{o}' -> '{n}'")
            if "technologies" in diffs:
                o, n = diffs["technologies"]
                lines.append(f"        tech: {o} -> {n}")
            if url in lead_hints:
                for hint in lead_hints[url]:
                    lines.append(f"        * {hint}")

    if new_ports:
        lines.append(f"\n[+] NEW OPEN PORTS ({len(new_ports)} hosts):")
        for h, ports in sorted(new_ports.items()):
            ports_str = ", ".join(str(p) for p in ports)
            lines.append(f"    + {h}: {ports_str}")

    if new_urls:
        lines.append(f"\n[+] NEW ENDPOINTS / URLS ({len(new_urls)}):")
        for u in new_urls:
            lines.append(f"    + {u}")

    if new_findings:
        lines.append(f"\n[!] NEW VULNERABILITY FINDINGS ({len(new_findings)}):")
        for f in new_findings:
            sev = (f.get("severity") or "info").upper()
            name = f.get("name") or f.get("template_id") or "Finding"
            host = f.get("host") or ""
            tid = f.get("template_id") or ""
            lines.append(f"    ! [{sev}] {name} ({tid}) on {host}")

    if removed_subs:
        lines.append(f"\n[-] Removed subdomains ({len(removed_subs)}) [informational]:")
        for s in removed_subs:
            lines.append(f"    - {s}")

    if gone_live:
        lines.append(f"\n[-] Inactive hosts ({len(gone_live)}) [informational]:")
        for h in gone_live:
            lines.append(f"    - {h}")

    lines.append("\n" + "=" * 60)
    return "\n".join(lines)


def run(args):
    """Execute diff comparison for a domain between its latest two scan runs."""
    domain = getattr(args, "domain", None)
    if not domain:
        sys.exit("Error: Target domain is required.")

    output_dir = getattr(args, "output", "output") or "output"
    json_output = bool(getattr(args, "json_report", False) or getattr(args, "json", False))
    out_dir = Path(output_dir) / domain

    runs = history.list_runs(out_dir)
    if len(runs) < 2:
        if not runs:
            msg = f"[!] No scan history found for {domain} in {out_dir}. Run a scan first."
        else:
            msg = (
                f"[!] Only 1 scan run found for {domain} ({runs[0].name}). "
                "Need at least 2 runs to compare."
            )
        if json_output:
            print(json.dumps({"domain": domain, "error": msg, "runs_count": len(runs)}))
        else:
            print(msg)
        sys.exit(0)

    old_run = runs[-2]
    new_run = runs[-1]
    old_data = history.load_snapshot(old_run)
    new_data = history.load_snapshot(new_run)

    # Load triage state if exists for this domain
    from . import triage

    triage_data = triage.load_triage(out_dir)
    triaged_hosts = triage_data.get("hosts", {})

    diff_result = compare(old_data, new_data, triage_hosts=triaged_hosts)
    has_changes = any([
        diff_result.get("new_subdomains"),
        diff_result.get("new_live"),
        diff_result.get("changed"),
        diff_result.get("removed_subdomains"),
        diff_result.get("gone_live"),
        diff_result.get("new_ports"),
        diff_result.get("new_urls"),
        diff_result.get("new_findings"),
    ])

    notify_enabled = bool(getattr(args, "notify", False))
    webhook_url_arg = getattr(args, "webhook_url", None)

    output_text = format_diff(
        diff_result,
        old_data.get("run_id", old_run.name),
        new_data.get("run_id", new_run.name),
        new_data=new_data,
    )

    if json_output:
        payload = {
            "domain": domain,
            "old_run": old_data.get("run_id", old_run.name),
            "new_run": new_data.get("run_id", new_run.name),
            "has_changes": has_changes,
            **diff_result,
        }
        print(json.dumps(payload, indent=2))
    else:
        print(output_text)

    if notify_enabled:
        if has_changes:
            from . import notify

            url = notify.resolve_webhook_url(webhook_url_arg)
            if not url:
                print(
                    "[!] --notify requested, but no webhook URL found in "
                    "RECONFLOW_WEBHOOK_URL or --webhook-url.",
                    file=sys.stderr,
                )
            else:
                notify.send_webhook(url, output_text)

    sys.exit(1 if has_changes else 0)
