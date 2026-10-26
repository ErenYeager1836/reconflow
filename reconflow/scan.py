"""reconflow.scan - subdomain discovery and live host probing pipeline."""

import argparse
import json
import random
import shutil
import socket
import string
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

RESOLVE_THREADS = 50


TOOL_DOWNLOAD_URLS = {
    "subfinder": "https://github.com/projectdiscovery/subfinder/releases",
    "httpx": "https://github.com/projectdiscovery/httpx/releases (ProjectDiscovery Go binary)",
    "gowitness": "https://github.com/sensepost/gowitness/releases",
}


def run_cmd(cmd):
    """Run an external command and return the completed process."""
    return subprocess.run(
        cmd,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


# Backwards compatibility alias
run_subprocess = run_cmd


def resolve_httpx_binary():
    """Find and verify ProjectDiscovery httpx binary (checking httpx-toolkit then httpx)."""
    for candidate in ["httpx-toolkit", "httpx"]:
        if shutil.which(candidate) is None:
            continue
        try:
            res = run_cmd([candidate, "-version"])
            out = (res.stdout + " " + res.stderr).lower()
            if "projectdiscovery" in out:
                return candidate
            if candidate == "httpx-toolkit":
                return candidate
        except Exception:
            pass

    if shutil.which("httpx"):
        try:
            res = run_cmd(["httpx", "-h"])
            out = (res.stdout + " " + res.stderr).lower()
            if "projectdiscovery" in out or "-status-code" in out:
                return "httpx"
        except Exception:
            pass
        return "httpx"
    return None


def check_tools(tools):
    """Check that required external binaries are available in PATH."""
    missing = []
    for t in tools:
        if t == "httpx":
            if not resolve_httpx_binary():
                missing.append("httpx")
        elif shutil.which(t) is None:
            missing.append(t)

    if missing:
        lines = [
            f"[!] Missing required tools: {', '.join(missing)}",
            "",
            "Installation links:",
        ]
        for t in missing:
            url = TOOL_DOWNLOAD_URLS.get(t, "See README for details")
            lines.append(f"  - {t}: {url}")
        lines.append("")
        lines.append(
            "Note: 'httpx' must be ProjectDiscovery's binary "
            "(https://github.com/projectdiscovery/httpx),"
        )
        lines.append("      not the Python 'httpx' library from PyPI.")
        sys.exit("\n".join(lines))


def resolve(host):
    """Return the set of IP addresses a hostname resolves to (empty set if none)."""
    try:
        return {info[4][0] for info in socket.getaddrinfo(host, None)}
    except (socket.gaierror, UnicodeError, OSError):
        return set()


def detect_wildcard(domain, min_samples=5, max_samples=20, stable_rounds=3, resolve_fn=None):
    """Resolve random nonexistent names to detect wildcard DNS and rotating IP pools.

    Returns the set of wildcard IPs (empty set means no wildcard detected).
    If a domain uses wildcard DNS with round-robin or rotating pools, continues
    sampling until the IP set stabilizes or max_samples is reached.
    """
    _resolve = resolve_fn or resolve
    first_label = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
    first_ips = _resolve(f"{first_label}.{domain}")
    if not first_ips:
        return set()

    ips = set(first_ips)
    consecutive_stable = 0

    for i in range(1, max_samples):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
        resolved_ips = _resolve(f"{label}.{domain}")
        new_ips = resolved_ips - ips
        if new_ips:
            ips |= new_ips
            consecutive_stable = 0
        else:
            consecutive_stable += 1
            if i >= min_samples and consecutive_stable >= stable_rounds:
                break

    return ips


def filter_wildcard(subs, wildcard_ips, resolve_fn=None, scope_data=None):
    """Drop subdomains whose IPs all fall inside wildcard IPs or resolve out of scope."""
    _resolve = resolve_fn or resolve
    with ThreadPoolExecutor(max_workers=RESOLVE_THREADS) as pool:
        resolved = list(pool.map(_resolve, subs))
    kept = []
    for s, ips in zip(subs, resolved):
        if not ips or ips <= wildcard_ips:
            continue
        if scope_data:
            from . import scope

            out_ip = False
            for ip_str in ips:
                if not scope.is_in_scope(s, scope_data, resolved_ip=ip_str):
                    out_ip = True
                    break
            if out_ip:
                print(f"[*] [scope] Skipped host resolving to out-of-scope IP: {s} ({ips})")
                continue
        kept.append(s)
    return kept


def find_subdomains(domain, out_file):
    """Discover subdomains using subfinder and write to out_file."""
    print(f"[*] Finding subdomains for {domain}...")
    result = run_cmd(["subfinder", "-d", domain, "-silent"])
    subs = set(result.stdout.split())
    subs.add(domain.strip().lower())
    subs_sorted = sorted(subs)
    out_file.write_text("\n".join(subs_sorted) + "\n", encoding="utf-8")
    print(f"[+] Found {len(subs_sorted)} subdomains")
    return subs_sorted


def probe_hosts(
    subs_file,
    out_file,
    threads=None,
    timeout=None,
    json_report=False,
    httpx_bin=None,
    scope_data=None,
    run_dir=None,
):
    """Probe subdomains for live HTTP/HTTPS services using httpx."""
    bin_name = httpx_bin or resolve_httpx_binary() or "httpx"
    print("[*] Probing for live hosts (this can take a while on big targets)...")
    cmd = [
        bin_name,
        "-l",
        str(subs_file),
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-location",
    ]
    if json_report:
        cmd.append("-json")
    if threads is not None:
        cmd.extend(["-threads", str(threads)])
    if timeout is not None:
        cmd.extend(["-timeout", str(int(timeout))])

    lines = []
    hosts_data = []
    error_lines = []

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("", encoding="utf-8")

    with open(out_file, "a", encoding="utf-8") as live_fh:
        with subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
        ) as proc:
            for line in proc.stdout:
                stripped = line.strip()
                if not stripped:
                    continue
                if json_report:
                    try:
                        data = json.loads(stripped)
                        url = data.get("url") or ""
                        final_url = data.get("final_url") or data.get("location")

                        if scope_data:
                            from . import scope

                            if not scope.is_in_scope(url, scope_data):
                                print(f"[*] [scope] Skipped out-of-scope probed host: {url}")
                                continue

                            if final_url:
                                if not scope.is_in_scope(final_url, scope_data):
                                    print(
                                        f"[*] [scope] Redirect target out of scope: "
                                        f"{final_url} (from {url})"
                                    )
                                    data["redirect_out_of_scope"] = final_url
                                    if data.get("url") == final_url:
                                        data["url"] = url
                                else:
                                    data["redirect_in_scope"] = final_url

                        code = data.get("status_code", data.get("status-code", 0))
                        title = data.get("title", "")
                        tech = data.get("tech") or data.get("technologies") or []
                        entry = {
                            "url": url,
                            "status_code": code,
                            "title": title,
                            "technologies": tech,
                        }
                        if "redirect_out_of_scope" in data:
                            entry["redirect_out_of_scope"] = data["redirect_out_of_scope"]
                        if "redirect_in_scope" in data:
                            entry["redirect_in_scope"] = data["redirect_in_scope"]
                        hosts_data.append(entry)
                        display = f"{url} [{code}]"
                        if title:
                            display += f" [{title}]"
                        if tech:
                            tech_str = ", ".join(tech) if isinstance(tech, list) else tech
                            display += f" [{tech_str}]"
                        if "redirect_out_of_scope" in data:
                            display += f" [redirect out of scope: {data['redirect_out_of_scope']}]"
                        lines.append(display)
                        live_fh.write(display + "\n")
                        live_fh.flush()

                        if run_dir:
                            from . import history

                            history.record_host(run_dir, entry)

                        print(f"[*] [{len(lines)} alive] {display}")
                    except json.JSONDecodeError:
                        error_lines.append(stripped)
                else:
                    if stripped.startswith("http://") or stripped.startswith("https://"):
                        tokens = stripped.split()
                        url = tokens[0]
                        if scope_data:
                            from . import scope

                            if not scope.is_in_scope(url, scope_data):
                                print(f"[*] [scope] Skipped out-of-scope probed host: {url}")
                                continue

                        import re

                        redirect_url = None
                        brackets = re.findall(r"\[(.*?)\]", stripped)
                        for b in brackets:
                            b_clean = b.strip()
                            for prefix in ("location:", "->", "to:"):
                                if b_clean.lower().startswith(prefix):
                                    b_clean = b_clean[len(prefix):].strip()
                            if (
                                b_clean.startswith("http://") or b_clean.startswith("https://")
                            ) and b_clean != url:
                                redirect_url = b_clean
                                break

                        has_oos_redirect = False
                        has_in_scope_redirect = False
                        if redirect_url and scope_data:
                            from . import scope

                            if not scope.is_in_scope(redirect_url, scope_data):
                                print(
                                    f"[*] [scope] Redirect target out of scope: "
                                    f"{redirect_url} (from {url})"
                                )
                                has_oos_redirect = True
                            else:
                                has_in_scope_redirect = True

                        display = stripped
                        if has_oos_redirect and "redirect out of scope:" not in display:
                            display += f" [redirect out of scope: {redirect_url}]"

                        entry = {"url": url}
                        if has_oos_redirect:
                            entry["redirect_out_of_scope"] = redirect_url
                        if has_in_scope_redirect:
                            entry["redirect_in_scope"] = redirect_url
                        hosts_data.append(entry)

                        lines.append(display)
                        live_fh.write(display + "\n")
                        live_fh.flush()
                        if run_dir:
                            from . import history

                            history.record_host(run_dir, entry)
                        print(f"[*] [{len(lines)} alive] {display}")
                    else:
                        error_lines.append(stripped)
            proc.wait()

    if proc.returncode != 0:
        if error_lines:
            err_msg = "\n".join(error_lines)
            print(f"[!] httpx probing error (exit code {proc.returncode}):\n{err_msg}")
        elif not lines:
            print(f"[!] httpx probing failed (exit code {proc.returncode})")

    print(f"[+] Probing complete: {len(lines)} hosts are alive")
    return lines, hosts_data


def capture_screenshots(live_hosts, screenshots_dir, scope_data=None, hosts_data=None):
    """Capture screenshots of live hosts using gowitness."""
    screenshots_dir.mkdir(parents=True, exist_ok=True)
    urls = [line.split()[0] for line in live_hosts if line.strip()]

    out_of_scope_redirects = {}
    verified_in_scope_redirects = set()
    unverified_3xx = set()

    if hosts_data:
        for h in hosts_data:
            if isinstance(h, dict):
                u = h.get("url")
                if h.get("redirect_out_of_scope"):
                    out_of_scope_redirects[u] = h["redirect_out_of_scope"]
                if h.get("redirect_in_scope"):
                    verified_in_scope_redirects.add(u)
                code = h.get("status_code", 0)
                if code in (301, 302, 303, 307, 308) and u not in verified_in_scope_redirects:
                    unverified_3xx.add(u)

    for line in live_hosts:
        first_token = line.split()[0]
        if "redirect out of scope:" in line:
            import re

            m = re.search(r"redirect out of scope:\s*([^\]\s]+)", line)
            if m:
                out_of_scope_redirects[first_token] = m.group(1)
        elif scope_data and any(f"[{code}]" in line for code in (301, 302, 303, 307, 308)):
            if first_token not in verified_in_scope_redirects:
                unverified_3xx.add(first_token)

    filtered_urls = []
    for u in urls:
        if scope_data:
            from . import scope

            if not scope.is_in_scope(u, scope_data):
                continue
        if u in out_of_scope_redirects:
            print(
                f"[*] [scope] Skipping screenshot for {u}: "
                f"redirects to out-of-scope target ({out_of_scope_redirects[u]})"
            )
            continue
        if scope_data and u in unverified_3xx:
            print(
                f"[*] [scope] Skipping screenshot for {u}: "
                "3xx redirect location could not be verified in scope"
            )
            continue
        filtered_urls.append(u)
    urls = filtered_urls

    if not urls:
        return []
    print("[*] Capturing screenshots of live hosts with gowitness...")
    urls_file = screenshots_dir / ".targets.txt"
    urls_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
    cmd = [
        "gowitness",
        "scan",
        "file",
        "-f",
        str(urls_file),
        "--screenshot-path",
        str(screenshots_dir),
    ]
    run_cmd(cmd)
    try:
        urls_file.unlink(missing_ok=True)
    except OSError:
        pass
    images = sorted(p.name for p in screenshots_dir.glob("*.png"))
    print(f"[+] Captured {len(images)} screenshots in {screenshots_dir}")
    return images


def write_report(
    domain,
    subs,
    live,
    out_dir,
    wildcard_ips=None,
    dropped=0,
    hosts_data=None,
    screenshots=None,
):
    """Write markdown and optional JSON reports to out_dir."""
    report = out_dir / "report.md"
    warning = ""
    if wildcard_ips:
        warning = (
            f"> **Wildcard DNS detected** (resolves to {', '.join(sorted(wildcard_ips))}). "
            f"{dropped} subdomains that only pointed there were filtered out.\n\n"
        )
    screenshot_section = ""
    if screenshots:
        screenshot_section = (
            f"## Screenshots\n\nCaptured {len(screenshots)} screenshot(s) in `screenshots/`.\n\n"
        )
    report.write_text(
        f"# reconflow report: {domain}\n\n"
        f"Generated: {datetime.now():%Y-%m-%d %H:%M}\n\n"
        f"{warning}"
        f"- Subdomains found: {len(subs)}\n"
        f"- Live hosts: {len(live)}\n\n"
        f"## Live hosts\n\n```\n" + "\n".join(live) + "\n```\n\n"
        f"{screenshot_section}",
        encoding="utf-8",
    )
    print(f"[+] Report saved to {report}")

    if hosts_data is not None:
        json_report_path = out_dir / "report.json"
        report_dict = {
            "domain": domain,
            "generated": datetime.now().isoformat(),
            "subdomains_count": len(subs),
            "live_count": len(live),
            "wildcard_detected": bool(wildcard_ips),
            "wildcard_ips": sorted(wildcard_ips) if wildcard_ips else [],
            "wildcard_filtered_count": dropped,
            "screenshots_count": len(screenshots) if screenshots else 0,
            "live_hosts": hosts_data,
        }
        json_report_path.write_text(json.dumps(report_dict, indent=2) + "\n", encoding="utf-8")
        print(f"[+] JSON report saved to {json_report_path}")


def run(args):
    """Run the core recon pipeline using provided arguments namespace."""
    domain = getattr(args, "domain", None)
    if not domain:
        sys.exit("Error: Target domain is required.")

    output_dir = getattr(args, "output", "output") or "output"
    threads = getattr(args, "threads", None)
    timeout = getattr(args, "timeout", None)
    keep_wildcard = getattr(args, "keep_wildcard", False)
    json_report = bool(getattr(args, "json_report", False) or getattr(args, "json", False))
    csv_report = bool(getattr(args, "csv", False))
    screenshots_enabled = getattr(args, "screenshots", False)
    scope_file = getattr(args, "scope", None)
    scope_data = None
    if scope_file and isinstance(scope_file, (str, Path)):
        from . import scope

        try:
            scope_data = scope.load_scope(scope_file)
        except scope.ScopeError as e:
            sys.exit(f"Error: {e}")

    required_tools = ["subfinder", "httpx"]
    if screenshots_enabled:
        required_tools.append("gowitness")
    check_tools(required_tools)

    out_dir = Path(output_dir) / domain
    out_dir.mkdir(parents=True, exist_ok=True)

    from . import history

    run_id, run_dir = history.init_run(out_dir, domain=domain)

    try:
        subs = find_subdomains(domain, out_dir / "subdomains.txt")

        if scope_data:
            from . import scope

            in_scope_subs = []
            for s in subs:
                if scope.is_in_scope(s, scope_data):
                    in_scope_subs.append(s)
                else:
                    print(f"[*] [scope] Skipped out-of-scope host: {s}")
            subs = in_scope_subs
            (out_dir / "subdomains.txt").write_text(
                "\n".join(subs) + ("\n" if subs else ""), encoding="utf-8"
            )

        for s in subs:
            history.record_subdomain(run_dir, s)

        screenshots = []
        if not subs:
            print("[!] No in-scope subdomains left to probe.")
            live = []
            hosts_data = []
            wildcard_ips = set()
            dropped = 0
        else:
            wildcard_ips = detect_wildcard(domain)
            dropped = 0
            if wildcard_ips:
                ips_str = ", ".join(sorted(wildcard_ips))
                print(f"[!] Wildcard DNS detected: random names resolve to {ips_str}")
                if keep_wildcard:
                    print("[!] --keep-wildcard set, results will not be filtered")
                else:
                    kept = filter_wildcard(subs, wildcard_ips, scope_data=scope_data)
                    dropped = len(subs) - len(kept)
                    print(
                        f"[*] Filtered out {dropped} wildcard-only subdomains, {len(kept)} remain"
                    )
                    subs = kept
                    (out_dir / "subdomains.txt").write_text(
                        "\n".join(subs) + ("\n" if subs else ""), encoding="utf-8"
                    )

            if not subs:
                print("[!] No subdomains left to probe.")
                live = []
                hosts_data = []
            else:
                httpx_bin = resolve_httpx_binary() or "httpx"
                live, hosts_data = probe_hosts(
                    out_dir / "subdomains.txt",
                    out_dir / "live.txt",
                    threads=threads,
                    timeout=timeout,
                    json_report=True,
                    httpx_bin=httpx_bin,
                    scope_data=scope_data,
                    run_dir=run_dir,
                )
                if screenshots_enabled and live:
                    screenshots = capture_screenshots(
                        live,
                        out_dir / "screenshots",
                        scope_data=scope_data,
                        hosts_data=hosts_data,
                    )

        write_report(
            domain,
            subs,
            live,
            out_dir,
            wildcard_ips=wildcard_ips,
            dropped=dropped,
            hosts_data=(hosts_data if json_report else None),
            screenshots=screenshots,
        )

        if csv_report:
            from .report import export_csv

            export_csv(domain, hosts_data, out_dir)

        history.finalize_run(run_dir, subs, hosts_data or [], domain=domain)
        print(f"[+] Saved scan snapshot ({run_id})")

        return {
            "domain": domain,
            "run_id": run_id,
            "subdomains": subs,
            "live": live,
            "hosts": hosts_data or [],
            "output_dir": str(out_dir),
        }
    except KeyboardInterrupt:
        sys.exit(f"\n[!] Interrupted. Partial results (if any) are in {out_dir}")


def main():
    """Standalone entry point for scan module."""
    parser = argparse.ArgumentParser(
        description="reconflow: subdomain discovery + live host probing in one command"
    )
    parser.add_argument("-d", "--domain", required=True, help="target domain (must be in scope!)")
    parser.add_argument("-o", "--output", default="output", help="output folder (default: output)")
    parser.add_argument(
        "--keep-wildcard",
        action="store_true",
        help="warn about wildcard DNS but don't filter wildcard results",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=None,
        help="number of threads for httpx probing (default: httpx default)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="timeout in seconds for httpx probing (default: 5)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_report",
        help="also write results to report.json",
    )
    parser.add_argument(
        "--csv",
        action="store_true",
        help="write live host data to report.csv",
    )
    parser.add_argument(
        "--screenshots",
        action="store_true",
        help="capture screenshots of live hosts using gowitness",
    )
    parser.add_argument(
        "--scope",
        default=None,
        help="path to scope file (enforces strict scope boundaries)",
    )
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
