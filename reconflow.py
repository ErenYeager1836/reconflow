#!/usr/bin/env python3
"""reconflow - chain subdomain discovery and live host probing."""

import argparse
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


def check_tools(tools):
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        sys.exit(f"Missing tools: {', '.join(missing)}. See README for install steps.")


def run(cmd):
    return subprocess.run(
        cmd, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )


def resolve(host):
    """Return the set of IP addresses a hostname resolves to (empty set if none)."""
    try:
        return {info[4][0] for info in socket.getaddrinfo(host, None)}
    except (socket.gaierror, UnicodeError, OSError):
        return set()


def detect_wildcard(domain, tries=3):
    """Resolve random nonexistent names. If they resolve, the domain uses wildcard DNS.

    Returns the set of wildcard IPs (empty set means no wildcard detected).
    """
    ips = set()
    for _ in range(tries):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
        ips |= resolve(f"{label}.{domain}")
    return ips


def filter_wildcard(subs, wildcard_ips):
    """Drop subdomains whose IPs all fall inside the wildcard IP set."""
    with ThreadPoolExecutor(max_workers=RESOLVE_THREADS) as pool:
        resolved = list(pool.map(resolve, subs))
    kept = [s for s, ips in zip(subs, resolved) if ips and not ips <= wildcard_ips]
    return kept


def find_subdomains(domain, out_file):
    print(f"[*] Finding subdomains for {domain}...")
    result = run(["subfinder", "-d", domain, "-silent"])
    subs = sorted(set(result.stdout.split()))
    out_file.write_text("\n".join(subs) + "\n", encoding="utf-8")
    print(f"[+] Found {len(subs)} subdomains")
    return subs


def probe_hosts(subs_file, out_file, threads=None, timeout=None):
    print("[*] Probing for live hosts (this can take a while on big targets)...")
    cmd = ["httpx", "-l", str(subs_file), "-silent",
           "-status-code", "-title", "-tech-detect"]
    if threads is not None:
        cmd.extend(["-threads", str(threads)])
    if timeout is not None:
        cmd.extend(["-timeout", str(timeout)])
    result = run(cmd)
    lines = [l for l in result.stdout.splitlines() if l.strip()]
    out_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[+] {len(lines)} hosts are alive")
    return lines


def write_report(domain, subs, live, out_dir, wildcard_ips=None, dropped=0):
    report = out_dir / "report.md"
    warning = ""
    if wildcard_ips:
        warning = (
            f"> **Wildcard DNS detected** (resolves to {', '.join(sorted(wildcard_ips))}). "
            f"{dropped} subdomains that only pointed there were filtered out.\n\n"
        )
    report.write_text(
        f"# reconflow report: {domain}\n\n"
        f"Generated: {datetime.now():%Y-%m-%d %H:%M}\n\n"
        f"{warning}"
        f"- Subdomains found: {len(subs)}\n"
        f"- Live hosts: {len(live)}\n\n"
        f"## Live hosts\n\n```\n" + "\n".join(live) + "\n```\n",
        encoding="utf-8",
    )
    print(f"[+] Report saved to {report}")


def main():
    parser = argparse.ArgumentParser(
        description="reconflow: subdomain discovery + live host probing in one command")
    parser.add_argument("-d", "--domain", required=True, help="target domain (must be in scope!)")
    parser.add_argument("-o", "--output", default="output", help="output folder (default: output)")
    parser.add_argument("--keep-wildcard", action="store_true",
                        help="warn about wildcard DNS but don't filter wildcard results")
    parser.add_argument("--threads", type=int, default=None,
                        help="number of threads for httpx probing (default: httpx default)")
    parser.add_argument("--timeout", type=int, default=None,
                        help="timeout in seconds for httpx probing (default: httpx default)")
    args = parser.parse_args()

    check_tools(["subfinder", "httpx"])

    out_dir = Path(args.output) / args.domain
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        subs = find_subdomains(args.domain, out_dir / "subdomains.txt")

        wildcard_ips = detect_wildcard(args.domain)
        dropped = 0
        if wildcard_ips:
            print(f"[!] Wildcard DNS detected: random names resolve to {', '.join(sorted(wildcard_ips))}")
            if args.keep_wildcard:
                print("[!] --keep-wildcard set, results will not be filtered")
            else:
                kept = filter_wildcard(subs, wildcard_ips)
                dropped = len(subs) - len(kept)
                print(f"[*] Filtered out {dropped} wildcard-only subdomains, {len(kept)} remain")
                subs = kept
                (out_dir / "subdomains.txt").write_text(
                    "\n".join(subs) + ("\n" if subs else ""), encoding="utf-8")

        if not subs:
            print("[!] No subdomains left to probe.")
            live = []
        else:
            live = probe_hosts(out_dir / "subdomains.txt", out_dir / "live.txt",
                               threads=args.threads, timeout=args.timeout)
        write_report(args.domain, subs, live, out_dir, wildcard_ips, dropped)
    except KeyboardInterrupt:
        sys.exit("\n[!] Interrupted. Partial results (if any) are in " + str(out_dir))


if __name__ == "__main__":
    main()
