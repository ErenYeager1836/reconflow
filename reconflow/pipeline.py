"""reconflow.pipeline - Stage-based recon pipeline orchestrator."""

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .plugins import (
    ToolPlugin,
    get_plugins_for_stage,
)

CANONICAL_STAGES = [
    "subdomains",
    "dns",
    "http",
    "urls",
    "ports",
    "vulns",
]

STAGE_ALIASES = {
    # All stages
    "all": "all",
    # Subdomain Enum
    "subdomains": "subdomains",
    "subdomain": "subdomains",
    "subdomain_enum": "subdomains",
    "subfinder": "subdomains",
    # DNS Resolve
    "dns": "dns",
    "dns_resolve": "dns",
    "dnsx": "dns",
    # HTTP Probe
    "http": "http",
    "http_probe": "http",
    "httpx": "http",
    # URL Collection
    "urls": "urls",
    "url": "urls",
    "url_collection": "urls",
    "katana": "urls",
    "gau": "urls",
    "waybackurls": "urls",
    # Port Scan
    "ports": "ports",
    "port": "ports",
    "port_scan": "ports",
    "naabu": "ports",
    # Vuln Scan
    "vulns": "vulns",
    "vuln": "vulns",
    "vuln_scan": "vulns",
    "nuclei": "vulns",
}


def normalize_stage_name(name: str) -> str:
    """Normalize a stage name or alias to its canonical form."""
    clean = name.strip().lower()
    if clean in STAGE_ALIASES:
        return STAGE_ALIASES[clean]
    raise ValueError(
        f"Unknown stage: '{name}'. Valid stages are: {', '.join(CANONICAL_STAGES)}"
    )


def resolve_stages(
    stages_arg: Optional[str] = None,
    skip_arg: Optional[str] = None,
) -> List[str]:
    """Resolve and order the active pipeline stages based on --stages and --skip.

    Preserves canonical pipeline order:
      subdomains -> dns -> http -> urls -> ports -> vulns
    """
    if stages_arg:
        requested: Set[str] = set()
        for item in stages_arg.split(","):
            item = item.strip()
            if not item:
                continue
            norm = normalize_stage_name(item)
            if norm == "all":
                requested.update(CANONICAL_STAGES)
            else:
                requested.add(norm)
        active = [s for s in CANONICAL_STAGES if s in requested]
    else:
        active = list(CANONICAL_STAGES)

    if skip_arg:
        skipped: Set[str] = set()
        for item in skip_arg.split(","):
            item = item.strip()
            if item:
                norm = normalize_stage_name(item)
                if norm == "all":
                    skipped.update(CANONICAL_STAGES)
                else:
                    skipped.add(norm)
        active = [s for s in active if s not in skipped]

    return active


def filter_in_scope_targets(
    targets: List[str],
    scope_data: Optional[Dict[str, Any]],
    log_fn=None,
) -> List[str]:
    """Hard gate: enforce program scope boundaries on targets before tool execution.

    Any host, URL, or IP outside the loaded scope is dropped BEFORE being passed
    to a tool, and logged as:
      [*] [scope] Skipped out-of-scope host: <target>
      [*] [scope] out of scope, skip <target>
    """
    if not scope_data:
        return list(targets)

    from . import scope

    in_scope = []
    for t in targets:
        if scope.is_in_scope(t, scope_data):
            in_scope.append(t)
        else:
            msg1 = f"[*] [scope] Skipped out-of-scope host: {t}"
            msg2 = f"[*] [scope] out of scope, skip {t}"
            if log_fn:
                log_fn(msg1)
                log_fn(msg2)
            else:
                print(msg1)
                print(msg2)
    return in_scope


def warn_intrusive() -> None:
    """Print high-visibility warning to stderr when intrusive scanning is enabled."""
    sys.stderr.write(
        "\n"
        + "=" * 80
        + "\n"
        "[WARNING] INTRUSIVE SCANNING ENABLED (--intrusive / --all-vulns)\n"
        "Aggressive and potentially disruptive vulnerability templates will be executed.\n"
        "Ensure you have explicit written authorization for intrusive testing on this target!\n"
        + "=" * 80
        + "\n\n"
    )
    sys.stderr.flush()


@dataclass
class PipelineContext:
    """State and artifacts passed between pipeline stages."""

    domain: str
    output_dir: Path
    stages: List[str] = field(default_factory=list)
    threads: int = 10
    rate: Optional[int] = 50
    timeout: Optional[int] = None
    silent: bool = False
    dry_run: bool = False
    intrusive: bool = False
    scope_data: Optional[Dict[str, Any]] = None
    subdomains: List[str] = field(default_factory=list)
    dns_records: List[Dict[str, Any]] = field(default_factory=list)
    live_hosts: List[Dict[str, Any]] = field(default_factory=list)
    urls: List[Dict[str, Any]] = field(default_factory=list)
    ports: List[Dict[str, Any]] = field(default_factory=list)
    vulns: List[Dict[str, Any]] = field(default_factory=list)
    stage_status: Dict[str, str] = field(default_factory=dict)

    def log(self, message: str) -> None:
        """Print progress or diagnostics to stderr if silent, else stdout."""
        target = sys.stderr if self.silent else sys.stdout
        print(message, file=target, flush=True)


class Pipeline:
    """Orchestrator for stage-based recon execution."""

    def __init__(
        self,
        domain: str,
        output_dir: Path,
        stages: Optional[List[str]] = None,
        threads: Optional[int] = None,
        rate: Optional[int] = None,
        timeout: Optional[int] = None,
        silent: bool = False,
        dry_run: bool = False,
        intrusive: bool = False,
        scope_data: Optional[Dict[str, Any]] = None,
    ):
        if rate is None:
            rate = 50

        if scope_data is None:
            from . import scope
            scope_data = scope.make_default_scope(domain)

        self.context = PipelineContext(
            domain=domain,
            output_dir=output_dir,
            stages=stages if stages is not None else list(CANONICAL_STAGES),
            threads=threads if threads is not None else 10,
            rate=rate,
            timeout=timeout,
            silent=silent,
            dry_run=dry_run,
            intrusive=intrusive,
            scope_data=scope_data,
        )

    def dry_run_plan(self) -> None:
        """Display the pipeline execution plan, active tools, and commands without running them."""
        domain = self.context.domain
        out_dir = self.context.output_dir
        stages = self.context.stages
        threads = self.context.threads or 10
        if self.context.rate == 0:
            rate_str = "unlimited"
        elif self.context.rate:
            rate_str = f"{self.context.rate} req/s"
        else:
            rate_str = "unlimited"
        intrusive_str = (
            "ENABLED (Aggressive)" if self.context.intrusive else "Disabled (Safe only)"
        )
        scope_path = (
            self.context.scope_data.get("path") if self.context.scope_data else None
        )
        scope_str = str(scope_path) if scope_path else "None"

        print("=" * 80)
        print("reconflow scan [DRY RUN]")
        print(f"Target Domain: {domain}")
        print(f"Scope File:    {scope_str}")
        if not scope_path:
            print(
                f"[!] No scope file loaded: limiting to {domain} and subdomains. "
                "Use --scope FILE for program-specific scope."
            )
        print(f"Rate Limit:    {rate_str} | Threads: {threads}")
        print(f"Intrusive:     {intrusive_str}")
        print("=" * 80)
        print(f"Active Stages ({len(stages)}):")

        for idx, stage in enumerate(stages, 1):
            plugins = get_plugins_for_stage(stage)
            plugin_names = ", ".join(p.name for p in plugins)
            print(f"  {idx}. {stage:<12} [tools: {plugin_names}]")
            for p in plugins:
                installed = p.is_installed()
                if installed:
                    ver = p.get_version()
                    ver_str = (
                        f" (version: {ver})"
                        if ver and ver not in ("not installed", "unknown")
                        else ""
                    )
                    status = f"[OK: {p.get_binary_path() or p.binary}{ver_str}]"
                else:
                    status = f"[MISSING: {p.get_missing_reason()}]"

                if stage == "subdomains":
                    target = domain
                elif stage in ("dns", "ports"):
                    target = str(out_dir / "subdomains.txt")
                elif stage in ("http", "vulns"):
                    target = str(out_dir / "live.txt")
                elif stage == "urls":
                    target = str(out_dir / "live.txt") if p.name == "katana" else domain
                else:
                    target = domain

                cmd = p.build_command(
                    target,
                    threads=self.context.threads,
                    rate=self.context.rate,
                    intrusive=self.context.intrusive,
                    timeout=self.context.timeout,
                )
                cmd_str = " ".join(cmd)
                print(f"     Tool {p.name:<11} {status}")
                print(f"     Command: {cmd_str}")

        print("=" * 80)
        print("[+] Dry run complete. No commands or network scans were executed.")

    def run_stage(self, stage: str) -> None:
        """Run all configured plugins for a specific stage."""
        plugins = get_plugins_for_stage(stage)
        if not plugins:
            self.context.stage_status[stage] = "no_plugins"
            return

        self.context.log(f"[*] Running stage: {stage}...")
        executed_any = False

        for plugin in plugins:
            if not plugin.is_installed():
                self.context.log(
                    f"[!] Tool '{plugin.name}' not found. "
                    f"Skipping {plugin.name} in {stage} stage.\n"
                    f"    Install: {plugin.install_hint}"
                )
                continue

            self._execute_plugin(plugin, stage)
            executed_any = True

        if not executed_any:
            self.context.stage_status[stage] = "skipped_tools_missing"
        else:
            self.context.stage_status[stage] = "completed"

    def _execute_plugin(self, plugin: ToolPlugin, stage: str) -> None:
        """Execute a single tool plugin within its stage with hard scope gates."""
        self.context.log(f"[*] Executing {plugin.name}...")
        out_dir = self.context.output_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        if stage == "subdomains":
            # Check domain against scope first
            if not filter_in_scope_targets(
                [self.context.domain], self.context.scope_data, log_fn=self.context.log
            ):
                self.context.log(f"[!] Target domain {self.context.domain} is out of scope.")
                return

            cmd = plugin.build_command(
                self.context.domain,
                threads=self.context.threads,
                rate=self.context.rate,
            )
            code, stdout, stderr = plugin.run_command_safe(
                cmd, timeout=self.context.timeout
            )
            records = plugin.parse_output(stdout, stderr)
            raw_hosts = [r["host"] for r in records if "host" in r]
            hosts = filter_in_scope_targets(
                raw_hosts, self.context.scope_data, log_fn=self.context.log
            )
            for h in hosts:
                if h not in self.context.subdomains:
                    self.context.subdomains.append(h)
            subs_file = out_dir / "subdomains.txt"
            subs_file.write_text(
                "\n".join(self.context.subdomains) + "\n" if self.context.subdomains else "",
                encoding="utf-8",
            )
            self.context.log(f"[+] Found {len(hosts)} in-scope subdomains via {plugin.name}")

        elif stage == "dns":
            subs_in_scope = filter_in_scope_targets(
                self.context.subdomains, self.context.scope_data, log_fn=self.context.log
            )
            if not subs_in_scope:
                self.context.log("[!] No in-scope subdomains available for DNS resolution.")
                return
            subs_file = out_dir / "subdomains.txt"
            subs_file.write_text(
                "\n".join(subs_in_scope) + "\n",
                encoding="utf-8",
            )
            cmd = plugin.build_command(
                str(subs_file),
                threads=self.context.threads,
                rate=self.context.rate,
            )
            code, stdout, stderr = plugin.run_command_safe(
                cmd, timeout=self.context.timeout
            )
            records = plugin.parse_output(stdout, stderr)
            self.context.dns_records.extend(records)
            self.context.log(f"[+] Resolved {len(records)} DNS records via {plugin.name}")

        elif stage == "http":
            subs_in_scope = filter_in_scope_targets(
                self.context.subdomains, self.context.scope_data, log_fn=self.context.log
            )
            if not subs_in_scope:
                self.context.log("[!] No in-scope subdomains available for HTTP probing.")
                return
            subs_file = out_dir / "subdomains.txt"
            subs_file.write_text(
                "\n".join(subs_in_scope) + "\n",
                encoding="utf-8",
            )
            cmd = plugin.build_command(
                str(subs_file),
                threads=self.context.threads,
                rate=self.context.rate,
                timeout=self.context.timeout,
            )
            code, stdout, stderr = plugin.run_command_safe(
                cmd, timeout=self.context.timeout
            )
            records = plugin.parse_output(stdout, stderr)
            # Filter live hosts by URL and hostname
            in_scope_records = []
            for r in records:
                target = r.get("url") or r.get("host")
                if filter_in_scope_targets(
                    [target], self.context.scope_data, log_fn=self.context.log
                ):
                    in_scope_records.append(r)
            self.context.live_hosts.extend(in_scope_records)
            live_urls = [r["url"] for r in in_scope_records if r.get("url")]
            live_file = out_dir / "live.txt"
            live_file.write_text(
                "\n".join(live_urls) + "\n" if live_urls else "",
                encoding="utf-8",
            )
            self.context.log(
                f"[+] Probed {len(in_scope_records)} in-scope live HTTP services via {plugin.name}"
            )

        elif stage == "urls":
            if plugin.name in ("gau", "waybackurls"):
                if not filter_in_scope_targets(
                    [self.context.domain], self.context.scope_data, log_fn=self.context.log
                ):
                    return
                cmd = plugin.build_command(self.context.domain, threads=self.context.threads)
            else:
                live_file = out_dir / "live.txt"
                target = str(live_file) if live_file.exists() else self.context.domain
                cmd = plugin.build_command(
                    target,
                    threads=self.context.threads,
                    rate=self.context.rate,
                )

            code, stdout, stderr = plugin.run_command_safe(
                cmd, timeout=self.context.timeout
            )
            raw_records = plugin.parse_output(stdout, stderr)
            # Hard scope gate on all collected URLs
            in_scope_records = []
            for r in raw_records:
                url_str = r.get("url", "")
                if filter_in_scope_targets(
                    [url_str], self.context.scope_data, log_fn=self.context.log
                ):
                    in_scope_records.append(r)
            self.context.urls.extend(in_scope_records)
            self.context.log(
                f"[+] Collected {len(in_scope_records)} in-scope URLs via {plugin.name}"
            )

        elif stage == "ports":
            subs_in_scope = filter_in_scope_targets(
                self.context.subdomains, self.context.scope_data, log_fn=self.context.log
            )
            if not subs_in_scope:
                self.context.log("[!] No in-scope targets for port scanning.")
                return
            subs_file = out_dir / "subdomains.txt"
            target = str(subs_file)
            cmd = plugin.build_command(
                target,
                threads=self.context.threads,
                rate=self.context.rate,
            )
            code, stdout, stderr = plugin.run_command_safe(
                cmd, timeout=self.context.timeout
            )
            raw_records = plugin.parse_output(stdout, stderr)
            in_scope_records = []
            for r in raw_records:
                target_host = r.get("host") or r.get("ip")
                if filter_in_scope_targets(
                    [target_host], self.context.scope_data, log_fn=self.context.log
                ):
                    in_scope_records.append(r)
            self.context.ports.extend(in_scope_records)
            self.context.log(
                f"[+] Found {len(in_scope_records)} in-scope open ports via {plugin.name}"
            )

        elif stage == "vulns":
            if self.context.intrusive:
                warn_intrusive()

            live_urls = [r["url"] for r in self.context.live_hosts if r.get("url")]
            urls_in_scope = filter_in_scope_targets(
                live_urls, self.context.scope_data, log_fn=self.context.log
            )
            if not urls_in_scope:
                self.context.log("[!] No in-scope live URLs for vulnerability scanning.")
                return
            live_file = out_dir / "live.txt"
            cmd = plugin.build_command(
                str(live_file),
                threads=self.context.threads,
                rate=self.context.rate,
                intrusive=self.context.intrusive,
            )
            code, stdout, stderr = plugin.run_command_safe(
                cmd, timeout=self.context.timeout
            )
            records = plugin.parse_output(stdout, stderr)
            self.context.vulns.extend(records)
            self.context.log(f"[+] Identified {len(records)} findings via {plugin.name}")

    def run(self) -> PipelineContext:
        """Execute the entire configured pipeline, or output dry-run plan."""
        if self.context.dry_run:
            self.dry_run_plan()
            return self.context

        if self.context.scope_data and self.context.scope_data.get("is_default"):
            self.context.log(
                f"[!] No scope file loaded: limiting to {self.context.domain} and subdomains. "
                "Use --scope FILE for program-specific scope."
            )

        for stage in self.context.stages:
            self.run_stage(stage)
        return self.context
