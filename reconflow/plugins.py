"""reconflow.plugins - Tool plugins for external recon binaries."""

import json
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple


def _resolve_httpx_binary() -> Optional[str]:
    """Find and verify ProjectDiscovery httpx binary."""
    for candidate in ["httpx-toolkit", "httpx"]:
        if shutil.which(candidate) is None:
            continue
        try:
            res = subprocess.run(
                [candidate, "-version"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
            out = (res.stdout + " " + res.stderr).lower()
            if "projectdiscovery" in out or candidate == "httpx-toolkit":
                return candidate
        except Exception:
            pass

    if shutil.which("httpx"):
        try:
            res = subprocess.run(
                ["httpx", "-h"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
            out = (res.stdout + " " + res.stderr).lower()
            if "projectdiscovery" in out or "-status-code" in out:
                return "httpx"
        except Exception:
            pass
        return "httpx"
    return None


class ToolPlugin:
    """Base class for all external recon tool plugins."""

    name: str = ""
    stage: str = ""
    binary: str = ""
    install_hint: str = ""
    default_timeout: int = 300

    def is_installed(self) -> bool:
        """Check whether the required binary is available on PATH."""
        return shutil.which(self.binary) is not None

    def get_binary_path(self) -> Optional[str]:
        """Return the absolute path to the binary if installed, else None."""
        return shutil.which(self.binary)

    def get_version(self) -> str:
        """Query the tool version safely. Returns 'unknown' or 'not installed' on error."""
        if not self.is_installed():
            return "not installed"
        try:
            bin_path = self.get_binary_path() or self.binary
            res = subprocess.run(
                [bin_path, "-version"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
            combined = res.stdout + "\n" + res.stderr
            version_pattern = r"(?:Current Version:?|version:?|v)\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"
            match = re.search(version_pattern, combined, re.IGNORECASE)
            if match:
                return f"v{match.group(1)}"
            for line in combined.splitlines():
                line = line.strip()
                if line and ("version" in line.lower() or "current" in line.lower()):
                    return line
            return "installed"
        except Exception:
            return "installed"

    def run_command_safe(
        self,
        command: List[str],
        timeout: Optional[int] = None,
        input_data: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        """Execute a tool command safely using argument lists and timeouts.

        Never uses shell=True. Reads stdout and stderr to prevent deadlocks.
        """
        effective_timeout = timeout if timeout is not None else self.default_timeout
        try:
            proc = subprocess.Popen(
                command,
                stdin=subprocess.PIPE if input_data is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            stdout, stderr = proc.communicate(input=input_data, timeout=effective_timeout)
            return proc.returncode, stdout, stderr
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            return -1, stdout, f"{stderr}\n[!] Command timed out after {effective_timeout}s"
        except FileNotFoundError:
            return 127, "", f"[!] Binary not found: {command[0]}"
        except Exception as e:
            return 1, "", f"[!] Subprocess execution error: {e}"

    def build_command(self, target: Any, **kwargs) -> List[str]:
        """Construct the argument list for the tool."""
        raise NotImplementedError

    def parse_output(self, stdout: str, stderr: str = "", **kwargs) -> List[Dict[str, Any]]:
        """Parse raw stdout into normalized records."""
        raise NotImplementedError


class SubfinderPlugin(ToolPlugin):
    """Subdomain enumeration plugin using ProjectDiscovery's subfinder."""

    name = "subfinder"
    stage = "subdomains"
    binary = "subfinder"
    install_hint = "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    default_timeout = 300

    def build_command(self, target: Any, **kwargs) -> List[str]:
        cmd = [self.get_binary_path() or self.binary, "-d", str(target), "-silent"]
        all_sources = kwargs.get("all_sources", False)
        if all_sources:
            cmd.append("-all")
        return cmd

    def parse_output(self, stdout: str, stderr: str = "", **kwargs) -> List[Dict[str, Any]]:
        records = []
        for line in stdout.splitlines():
            host = line.strip().lower()
            if host and not host.startswith("["):
                records.append({
                    "host": host,
                    "source": "subfinder",
                })
        return records


class DnsxPlugin(ToolPlugin):
    """DNS resolution and reconnaissance plugin using ProjectDiscovery's dnsx."""

    name = "dnsx"
    stage = "dns"
    binary = "dnsx"
    install_hint = "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    default_timeout = 300

    def build_command(self, target: Any, **kwargs) -> List[str]:
        cmd = [self.get_binary_path() or self.binary, "-silent", "-json", "-recon"]
        threads = kwargs.get("threads")
        if threads:
            cmd.extend(["-t", str(threads)])
        if isinstance(target, str) and (target.endswith(".txt") or "\n" not in target):
            if shutil.which("test") is not None and target.endswith(".txt"):
                cmd.extend(["-l", target])
        return cmd

    def parse_output(self, stdout: str, stderr: str = "", **kwargs) -> List[Dict[str, Any]]:
        records = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = (data.get("host") or "").lower()
                ips = data.get("a") or []
                cnames = data.get("cname") or []
                status_code = data.get("status_code") or ""
                records.append({
                    "host": host,
                    "ips": ips if isinstance(ips, list) else [ips],
                    "cnames": cnames if isinstance(cnames, list) else [cnames],
                    "status_code": status_code,
                    "raw": data,
                })
            except json.JSONDecodeError:
                parts = line.split()
                if parts:
                    records.append({
                        "host": parts[0].lower(),
                        "ips": parts[1:] if len(parts) > 1 else [],
                        "cnames": [],
                        "status_code": "",
                        "raw": {"raw": line},
                    })
        return records


class HttpxPlugin(ToolPlugin):
    """HTTP probing and technology detection plugin using ProjectDiscovery's httpx."""

    name = "httpx"
    stage = "http"
    binary = "httpx"
    install_hint = "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    default_timeout = 600

    def is_installed(self) -> bool:
        return _resolve_httpx_binary() is not None

    def get_binary_path(self) -> Optional[str]:
        bin_name = _resolve_httpx_binary()
        if bin_name:
            return shutil.which(bin_name) or bin_name
        return None

    def build_command(self, target: Any, **kwargs) -> List[str]:
        bin_path = self.get_binary_path() or "httpx"
        cmd = [
            bin_path,
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-follow-redirects",
        ]
        threads = kwargs.get("threads")
        if threads:
            cmd.extend(["-threads", str(threads)])
        timeout = kwargs.get("timeout")
        if timeout:
            cmd.extend(["-timeout", str(timeout)])
        if isinstance(target, str) and target.endswith(".txt"):
            cmd.extend(["-l", target])
        return cmd

    def parse_output(self, stdout: str, stderr: str = "", **kwargs) -> List[Dict[str, Any]]:
        records = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                url = data.get("url") or ""
                host = data.get("input") or data.get("host") or ""
                status_code = data.get("status_code") or data.get("status-code") or 0
                title = data.get("title") or ""
                tech = data.get("tech") or data.get("technologies") or []
                cnames = data.get("cname") or data.get("cnames") or []
                records.append({
                    "url": url,
                    "host": host.lower(),
                    "status_code": int(status_code) if str(status_code).isdigit() else 0,
                    "title": title,
                    "technologies": tech if isinstance(tech, list) else [tech],
                    "cname": cnames if isinstance(cnames, list) else [cnames],
                    "webserver": data.get("webserver") or "",
                    "raw": data,
                })
            except json.JSONDecodeError:
                continue
        return records


class KatanaPlugin(ToolPlugin):
    """Web crawler and spider plugin using ProjectDiscovery's katana."""

    name = "katana"
    stage = "urls"
    binary = "katana"
    install_hint = "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
    default_timeout = 600

    def build_command(self, target: Any, **kwargs) -> List[str]:
        bin_path = self.get_binary_path() or self.binary
        cmd = [bin_path, "-silent", "-json", "-depth", "2", "-concurrency", "10"]
        if isinstance(target, str):
            if target.endswith(".txt"):
                cmd.extend(["-list", target])
            else:
                cmd.extend(["-u", target])
        return cmd

    def parse_output(self, stdout: str, stderr: str = "", **kwargs) -> List[Dict[str, Any]]:
        records = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                endpoint = data.get("request", {}).get("endpoint") or data.get("endpoint") or ""
                if endpoint:
                    records.append({
                        "url": endpoint,
                        "source": "katana",
                        "raw": data,
                    })
            except json.JSONDecodeError:
                if line.startswith(("http://", "https://")):
                    records.append({
                        "url": line,
                        "source": "katana",
                        "raw": {"url": line},
                    })
        return records


class GauPlugin(ToolPlugin):
    """Archived URL gathering plugin using gau (GetAllUrls)."""

    name = "gau"
    stage = "urls"
    binary = "gau"
    install_hint = "go install github.com/lc/gau/v2/cmd/gau@latest"
    default_timeout = 300

    def get_version(self) -> str:
        if not self.is_installed():
            return "not installed"
        try:
            res = subprocess.run(
                [self.get_binary_path() or self.binary, "--version"],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
            )
            combined = res.stdout + "\n" + res.stderr
            match = re.search(r"version:\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", combined, re.IGNORECASE)
            if match:
                return f"v{match.group(1)}"
            return "installed"
        except Exception:
            return "installed"

    def build_command(self, target: Any, **kwargs) -> List[str]:
        bin_path = self.get_binary_path() or self.binary
        cmd = [bin_path, "--threads", "5"]
        subs = kwargs.get("subs", True)
        if subs:
            cmd.append("--subs")
        cmd.append(str(target))
        return cmd

    def parse_output(self, stdout: str, stderr: str = "", **kwargs) -> List[Dict[str, Any]]:
        records = []
        for line in stdout.splitlines():
            url = line.strip()
            if url and url.startswith(("http://", "https://")):
                records.append({
                    "url": url,
                    "source": "gau",
                })
        return records


class WaybackurlsPlugin(ToolPlugin):
    """Wayback Machine URL collection plugin using waybackurls."""

    name = "waybackurls"
    stage = "urls"
    binary = "waybackurls"
    install_hint = "go install github.com/tomnomnom/waybackurls@latest"
    default_timeout = 300

    def get_version(self) -> str:
        if not self.is_installed():
            return "not installed"
        return "installed"

    def build_command(self, target: Any, **kwargs) -> List[str]:
        bin_path = self.get_binary_path() or self.binary
        return [bin_path, str(target)]

    def parse_output(self, stdout: str, stderr: str = "", **kwargs) -> List[Dict[str, Any]]:
        records = []
        for line in stdout.splitlines():
            url = line.strip()
            if url and url.startswith(("http://", "https://")):
                records.append({
                    "url": url,
                    "source": "waybackurls",
                })
        return records


class NaabuPlugin(ToolPlugin):
    """Fast port scanner plugin using ProjectDiscovery's naabu."""

    name = "naabu"
    stage = "ports"
    binary = "naabu"
    install_hint = "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    default_timeout = 600

    def build_command(self, target: Any, **kwargs) -> List[str]:
        bin_path = self.get_binary_path() or self.binary
        cmd = [bin_path, "-silent", "-json", "-top-ports", "100"]
        if isinstance(target, str) and target.endswith(".txt"):
            cmd.extend(["-list", target])
        elif isinstance(target, str):
            cmd.extend(["-host", target])
        return cmd

    def parse_output(self, stdout: str, stderr: str = "", **kwargs) -> List[Dict[str, Any]]:
        records = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                host = data.get("host") or ""
                ip = data.get("ip") or ""
                port = data.get("port") or 0
                records.append({
                    "host": host.lower(),
                    "ip": ip,
                    "port": int(port) if str(port).isdigit() else 0,
                    "raw": data,
                })
            except json.JSONDecodeError:
                continue
        return records


class NucleiPlugin(ToolPlugin):
    """Vulnerability scanner plugin using ProjectDiscovery's nuclei."""

    name = "nuclei"
    stage = "vulns"
    binary = "nuclei"
    install_hint = "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    default_timeout = 600

    def build_command(self, target: Any, **kwargs) -> List[str]:
        bin_path = self.get_binary_path() or self.binary
        cmd = [
            bin_path,
            "-silent",
            "-jsonl",
            "-severity",
            "info,low,medium,high,critical",
        ]
        tags = kwargs.get("tags")
        if tags:
            cmd.extend(["-tags", str(tags)])
        if isinstance(target, str) and target.endswith(".txt"):
            cmd.extend(["-list", target])
        elif isinstance(target, str):
            cmd.extend(["-u", target])
        return cmd

    def parse_output(self, stdout: str, stderr: str = "", **kwargs) -> List[Dict[str, Any]]:
        records = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                info = data.get("info") or {}
                records.append({
                    "template_id": data.get("template-id") or data.get("templateID") or "",
                    "name": info.get("name") or "",
                    "severity": info.get("severity") or "info",
                    "host": (data.get("host") or "").lower(),
                    "matched_at": data.get("matched-at") or data.get("matched") or "",
                    "matcher_name": data.get("matcher-name") or "",
                    "description": info.get("description") or "",
                    "raw": data,
                })
            except json.JSONDecodeError:
                continue
        return records


# Registry of supported plugins
ALL_PLUGINS: List[ToolPlugin] = [
    SubfinderPlugin(),
    DnsxPlugin(),
    HttpxPlugin(),
    KatanaPlugin(),
    GauPlugin(),
    WaybackurlsPlugin(),
    NaabuPlugin(),
    NucleiPlugin(),
]


def get_all_plugins() -> List[ToolPlugin]:
    """Return all registered plugins."""
    return list(ALL_PLUGINS)


def get_plugin(name: str) -> Optional[ToolPlugin]:
    """Retrieve a plugin by its canonical tool name."""
    name_norm = name.strip().lower()
    for p in ALL_PLUGINS:
        if p.name == name_norm:
            return p
    return None


def get_plugins_for_stage(stage: str) -> List[ToolPlugin]:
    """Return all plugins registered for a specific stage."""
    stage_norm = stage.strip().lower()
    return [p for p in ALL_PLUGINS if p.stage == stage_norm]
