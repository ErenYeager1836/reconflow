"""reconflow.pipeline - Stage-based recon pipeline orchestrator."""

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
            if item:
                requested.add(normalize_stage_name(item))
        active = [s for s in CANONICAL_STAGES if s in requested]
    else:
        active = list(CANONICAL_STAGES)

    if skip_arg:
        skipped: Set[str] = set()
        for item in skip_arg.split(","):
            item = item.strip()
            if item:
                skipped.add(normalize_stage_name(item))
        active = [s for s in active if s not in skipped]

    return active


@dataclass
class PipelineContext:
    """State and artifacts passed between pipeline stages."""

    domain: str
    output_dir: Path
    stages: List[str] = field(default_factory=list)
    threads: Optional[int] = None
    timeout: Optional[int] = None
    silent: bool = False
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
        import sys

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
        timeout: Optional[int] = None,
        silent: bool = False,
        scope_data: Optional[Dict[str, Any]] = None,
    ):
        self.context = PipelineContext(
            domain=domain,
            output_dir=output_dir,
            stages=stages if stages is not None else list(CANONICAL_STAGES),
            threads=threads,
            timeout=timeout,
            silent=silent,
            scope_data=scope_data,
        )

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
        """Execute a single tool plugin within its stage."""
        self.context.log(f"[*] Executing {plugin.name}...")
        out_dir = self.context.output_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        if stage == "subdomains":
            cmd = plugin.build_command(self.context.domain)
            code, stdout, stderr = plugin.run_command_safe(
                cmd, timeout=self.context.timeout
            )
            records = plugin.parse_output(stdout, stderr)
            hosts = [r["host"] for r in records if "host" in r]
            for h in hosts:
                if h not in self.context.subdomains:
                    self.context.subdomains.append(h)
            subs_file = out_dir / "subdomains.txt"
            subs_file.write_text(
                "\n".join(self.context.subdomains) + "\n" if self.context.subdomains else "",
                encoding="utf-8",
            )
            self.context.log(f"[+] Found {len(hosts)} subdomains via {plugin.name}")

        elif stage == "dns":
            subs_file = out_dir / "subdomains.txt"
            if not subs_file.exists() or not self.context.subdomains:
                self.context.log("[!] No subdomains available for DNS resolution.")
                return
            cmd = plugin.build_command(str(subs_file), threads=self.context.threads)
            code, stdout, stderr = plugin.run_command_safe(
                cmd, timeout=self.context.timeout
            )
            records = plugin.parse_output(stdout, stderr)
            self.context.dns_records.extend(records)
            self.context.log(f"[+] Resolved {len(records)} DNS records via {plugin.name}")

        elif stage == "http":
            subs_file = out_dir / "subdomains.txt"
            if not subs_file.exists() or not self.context.subdomains:
                self.context.log("[!] No subdomains available for HTTP probing.")
                return
            cmd = plugin.build_command(
                str(subs_file),
                threads=self.context.threads,
                timeout=self.context.timeout,
            )
            code, stdout, stderr = plugin.run_command_safe(
                cmd, timeout=self.context.timeout
            )
            records = plugin.parse_output(stdout, stderr)
            self.context.live_hosts.extend(records)
            live_urls = [r["url"] for r in records if r.get("url")]
            live_file = out_dir / "live.txt"
            live_file.write_text(
                "\n".join(live_urls) + "\n" if live_urls else "",
                encoding="utf-8",
            )
            self.context.log(f"[+] Probed {len(records)} live HTTP services via {plugin.name}")

        elif stage == "urls":
            # Katana can crawl live URLs; gau and waybackurls query domain archives
            if plugin.name in ("gau", "waybackurls"):
                cmd = plugin.build_command(self.context.domain)
            else:
                live_file = out_dir / "live.txt"
                target = str(live_file) if live_file.exists() else self.context.domain
                cmd = plugin.build_command(target)

            code, stdout, stderr = plugin.run_command_safe(
                cmd, timeout=self.context.timeout
            )
            records = plugin.parse_output(stdout, stderr)
            self.context.urls.extend(records)
            self.context.log(f"[+] Collected {len(records)} URLs via {plugin.name}")

        elif stage == "ports":
            subs_file = out_dir / "subdomains.txt"
            target = str(subs_file) if subs_file.exists() else self.context.domain
            cmd = plugin.build_command(target)
            code, stdout, stderr = plugin.run_command_safe(
                cmd, timeout=self.context.timeout
            )
            records = plugin.parse_output(stdout, stderr)
            self.context.ports.extend(records)
            self.context.log(f"[+] Found {len(records)} open ports via {plugin.name}")

        elif stage == "vulns":
            live_file = out_dir / "live.txt"
            target = str(live_file) if live_file.exists() else self.context.domain
            cmd = plugin.build_command(target)
            code, stdout, stderr = plugin.run_command_safe(
                cmd, timeout=self.context.timeout
            )
            records = plugin.parse_output(stdout, stderr)
            self.context.vulns.extend(records)
            self.context.log(f"[+] Identified {len(records)} findings via {plugin.name}")

    def run(self) -> PipelineContext:
        """Execute the entire configured pipeline."""
        for stage in self.context.stages:
            self.run_stage(stage)
        return self.context
