"""reconflow.plugins - Tool plugins for external recon binaries."""

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple


def verify_projectdiscovery_binary(
    bin_path: str, timeout: int = 3
) -> Tuple[bool, Optional[str]]:
    """Verify that bin_path is a ProjectDiscovery binary via -version."""
    try:
        res = subprocess.run(
            [bin_path, "-version"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        combined = (res.stdout + "\n" + res.stderr)
        combined_lower = combined.lower()
        if "projectdiscovery" in combined_lower or "current version" in combined_lower:
            pattern = r"(?:Current Version:?|version:?|v)\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)"
            match = re.search(pattern, combined, re.IGNORECASE)
            version_str = f"v{match.group(1)}" if match else "installed"
            return True, version_str
        return False, None
    except Exception:
        return False, None


def _get_tool_override(tool_name: str) -> Optional[str]:
    """Check for explicit tool path in environment or reconflow.toml."""
    env_var = f"RECONFLOW_{tool_name.upper().replace('-', '_')}"
    val = os.environ.get(env_var)
    if val and val.strip():
        return val.strip()

    try:
        from .config import load_config
        cfg = load_config()
        tools_cfg = cfg.get("tools") or {}
        cfg_val = tools_cfg.get(tool_name)
        if cfg_val and str(cfg_val).strip():
            return str(cfg_val).strip()
    except Exception:
        pass

    return None


def _find_binary_candidates(
    tool_name: str, binary_names: List[str], include_override: bool = True
) -> List[str]:
    """Find all potential binary paths for a tool across overrides, PATH, and common dirs."""
    candidates: List[str] = []
    seen: set = set()

    def add_candidate(raw_path: Any) -> None:
        if not raw_path:
            return
        p_str = str(raw_path)
        norm = os.path.normcase(os.path.abspath(p_str))
        if norm in seen:
            return
        p = Path(p_str).expanduser()
        if p.is_file():
            seen.add(norm)
            candidates.append(p_str)
        elif not p.is_absolute() and len(p.parts) == 1:
            w = shutil.which(p_str)
            if w:
                w_norm = os.path.normcase(os.path.abspath(w))
                if w_norm not in seen:
                    seen.add(w_norm)
                    candidates.append(w)

    if include_override:
        override = _get_tool_override(tool_name)
        if override:
            add_candidate(override)

    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    extensions = [""]
    if sys.platform == "win32":
        pathext = os.environ.get("PATHEXT", ".COM;.EXE;.BAT;.CMD").split(";")
        extensions = [""] + [ext.lower() for ext in pathext if ext]

    for bname in binary_names:
        for d in path_dirs:
            if not d.strip():
                continue
            dir_path = Path(d).expanduser()
            if not dir_path.is_dir():
                continue
            for ext in extensions:
                target_file = dir_path / f"{bname}{ext}"
                try:
                    if target_file.is_file() and os.access(str(target_file), os.X_OK):
                        add_candidate(str(target_file))
                except OSError:
                    continue

    common_dirs: List[Path] = [
        Path.home() / "go" / "bin",
    ]
    gopath = os.environ.get("GOPATH")
    if gopath:
        common_dirs.append(Path(gopath) / "bin")

    if sys.platform == "win32":
        common_dirs.append(Path(r"C:\Tools\recon"))
        common_dirs.append(Path(r"C:\ProgramData\chocolatey\bin"))
    else:
        common_dirs.extend([
            Path("/usr/local/bin"),
            Path("/usr/bin"),
            Path.home() / ".local" / "bin",
        ])

    for bname in binary_names:
        for cdir in common_dirs:
            try:
                if not cdir.is_dir():
                    continue
                for ext in extensions:
                    target_file = cdir / f"{bname}{ext}"
                    if target_file.is_file() and os.access(str(target_file), os.X_OK):
                        add_candidate(str(target_file))
            except OSError:
                continue

    for bname in binary_names:
        w = shutil.which(bname)
        if w:
            add_candidate(w)

    return candidates


def resolve_tool_binary(
    tool_name: str,
    binary_names: List[str],
    validator: Optional[Callable[[str], Tuple[bool, Optional[str]]]] = None,
    hard_fail: bool = False,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Search candidates and return (verified_path, version, clashed_path)."""
    override = _get_tool_override(tool_name)
    if override:
        if validator:
            is_valid, version_str = validator(override)
            if is_valid:
                return override, version_str, None
            print(
                f"[!] Warning: couldn't verify identity of {override}",
                file=sys.stderr,
            )
            return override, "installed", None
        return override, "installed", None

    candidates = _find_binary_candidates(tool_name, binary_names, include_override=False)
    clashed_path: Optional[str] = None
    first_candidate: Optional[str] = None

    for cand in candidates:
        if first_candidate is None:
            first_candidate = cand
        if validator:
            is_valid, version_str = validator(cand)
            if is_valid:
                return cand, version_str, clashed_path
            else:
                if clashed_path is None:
                    clashed_path = cand
        else:
            return cand, "installed", None

    if hard_fail:
        return None, None, clashed_path

    if first_candidate:
        print(
            f"[!] Warning: couldn't verify identity of {first_candidate}",
            file=sys.stderr,
        )
        return first_candidate, "installed", None

    return None, None, None


def _resolve_httpx_binary() -> Optional[str]:
    """Find and verify ProjectDiscovery httpx binary."""
    p = get_plugin("httpx")
    if p:
        return p.get_binary_path()
    return None


class ToolPlugin:
    """Base class for all external recon tool plugins."""

    name: str = ""
    stage: str = ""
    binary: str = ""
    install_hint: str = ""
    default_timeout: int = 300
    hard_fail: bool = False

    def __init__(self) -> None:
        self._resolved_path: Optional[str] = None
        self._resolved_version: Optional[str] = None
        self._clashed_path: Optional[str] = None
        self._resolution_done: bool = False

    def reset_resolution(self) -> None:
        """Reset cached resolution state."""
        self._resolved_path = None
        self._resolved_version = None
        self._clashed_path = None
        self._resolution_done = False

    def get_binary_names(self) -> List[str]:
        """Return list of acceptable binary names to search."""
        return [self.binary]

    def verify_binary(self, bin_path: str) -> Tuple[bool, Optional[str]]:
        """Verify binary identity and extract version.

        Subclasses should override this with tool-specific checks.
        """
        if shutil.which(bin_path) is not None or Path(bin_path).is_file():
            return True, "installed"
        return False, None

    def resolve(self, force: bool = False) -> Optional[str]:
        """Resolve and verify binary path."""
        if self._resolution_done and not force:
            return self._resolved_path

        bin_path, version_str, clashed = resolve_tool_binary(
            self.name,
            self.get_binary_names(),
            validator=self.verify_binary,
            hard_fail=self.hard_fail,
        )
        self._resolved_path = bin_path
        self._resolved_version = version_str
        self._clashed_path = clashed
        self._resolution_done = True
        return self._resolved_path

    def is_installed(self) -> bool:
        """Check whether the verified binary is available."""
        return self.resolve() is not None

    def get_binary_path(self) -> Optional[str]:
        """Return the absolute path to the verified binary if installed, else None."""
        return self.resolve()

    def get_clashed_path(self) -> Optional[str]:
        """Return path of a shadowed or failed candidate, if one was found."""
        self.resolve()
        return self._clashed_path

    def get_missing_reason(self) -> str:
        """Return an informative message when binary is missing or failed verification."""
        clashed = self.get_clashed_path()
        if clashed:
            return (
                f"{self.name} found at {clashed} but failed verification check. "
                f"Install: {self.install_hint}, or set the path in reconflow.toml."
            )
        return f"Install: {self.install_hint}"

    def get_version(self) -> str:
        """Query the tool version safely. Returns 'unknown' or 'not installed' on error."""
        if not self.is_installed():
            return "not installed"
        if self._resolved_version and self._resolved_version != "installed":
            return self._resolved_version

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


class ProjectDiscoveryPlugin(ToolPlugin):
    """Base class for ProjectDiscovery suite plugins with -version identity verification."""

    hard_fail: bool = False

    def verify_binary(self, bin_path: str) -> Tuple[bool, Optional[str]]:
        return verify_projectdiscovery_binary(bin_path, timeout=3)

    def get_missing_reason(self) -> str:
        clashed = self.get_clashed_path()
        if clashed:
            return (
                f"{self.name} found at {clashed} but failed verification check. "
                f"Install: {self.install_hint}, or set the path in reconflow.toml."
            )
        return f"Install: {self.install_hint}"


class SubfinderPlugin(ProjectDiscoveryPlugin):
    """Subdomain enumeration plugin using ProjectDiscovery's subfinder."""

    name = "subfinder"
    stage = "subdomains"
    binary = "subfinder"
    install_hint = "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    default_timeout = 300

    def build_command(self, target: Any, **kwargs) -> List[str]:
        cmd = [self.get_binary_path() or self.binary, "-d", str(target), "-silent"]
        threads = kwargs.get("threads")
        if threads:
            cmd.extend(["-t", str(threads)])
        rate = kwargs.get("rate")
        if rate:
            cmd.extend(["-rl", str(rate)])
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


class DnsxPlugin(ProjectDiscoveryPlugin):
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
        rate = kwargs.get("rate")
        if rate:
            cmd.extend(["-rl", str(rate)])
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


class HttpxPlugin(ProjectDiscoveryPlugin):
    """HTTP probing and technology detection plugin using ProjectDiscovery's httpx."""

    name = "httpx"
    stage = "http"
    binary = "httpx"
    install_hint = "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    default_timeout = 600
    hard_fail: bool = True

    def get_binary_names(self) -> List[str]:
        return ["httpx-toolkit", "httpx"]

    def get_missing_reason(self) -> str:
        clashed = self.get_clashed_path()
        if clashed:
            return (
                f"httpx found at {clashed} but it is not ProjectDiscovery httpx "
                "(name clash with the Python httpx CLI). Install: go install -v "
                "github.com/projectdiscovery/httpx/cmd/httpx@latest, or set the path in "
                "reconflow.toml."
            )
        return f"Install: {self.install_hint}"

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
        rate = kwargs.get("rate")
        if rate:
            cmd.extend(["-rate-limit", str(rate)])
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


class KatanaPlugin(ProjectDiscoveryPlugin):
    """Web crawler and spider plugin using ProjectDiscovery's katana."""

    name = "katana"
    stage = "urls"
    binary = "katana"
    install_hint = "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
    default_timeout = 600

    def build_command(self, target: Any, **kwargs) -> List[str]:
        bin_path = self.get_binary_path() or self.binary
        cmd = [bin_path, "-silent", "-json", "-depth", "2"]
        threads = kwargs.get("threads")
        if threads:
            cmd.extend(["-concurrency", str(threads)])
        else:
            cmd.extend(["-concurrency", "10"])
        rate = kwargs.get("rate")
        if rate:
            cmd.extend(["-rate-limit", str(rate)])
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


class NaabuPlugin(ProjectDiscoveryPlugin):
    """Fast port scanner plugin using ProjectDiscovery's naabu."""

    name = "naabu"
    stage = "ports"
    binary = "naabu"
    install_hint = "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    default_timeout = 600

    def build_command(self, target: Any, **kwargs) -> List[str]:
        bin_path = self.get_binary_path() or self.binary
        cmd = [bin_path, "-silent", "-json", "-top-ports", "100"]
        threads = kwargs.get("threads")
        if threads:
            cmd.extend(["-c", str(threads)])
        rate = kwargs.get("rate")
        if rate:
            cmd.extend(["-rate", str(rate)])
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


class NucleiPlugin(ProjectDiscoveryPlugin):
    """Vulnerability scanner plugin using ProjectDiscovery's nuclei."""

    name = "nuclei"
    stage = "vulns"
    binary = "nuclei"
    install_hint = "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    default_timeout = 600

    def build_command(self, target: Any, **kwargs) -> List[str]:
        bin_path = self.get_binary_path() or self.binary
        cmd = [bin_path, "-silent", "-jsonl"]

        intrusive = kwargs.get("intrusive", False)
        tags = kwargs.get("tags")
        if not intrusive:
            safe_tags = str(tags) if tags else "technologies,exposure,misconfiguration,takeover"
            cmd.extend([
                "-tags",
                safe_tags,
                "-exclude-severity",
                "high,critical",
            ])
        else:
            cmd.extend(["-severity", "info,low,medium,high,critical"])
            if tags:
                cmd.extend(["-tags", str(tags)])

        threads = kwargs.get("threads")
        if threads:
            cmd.extend(["-c", str(threads)])
        rate = kwargs.get("rate")
        if rate:
            cmd.extend(["-rate-limit", str(rate)])
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


def reset_all_plugins() -> None:
    """Reset cached binary resolution across all registered plugins."""
    for p in ALL_PLUGINS:
        p.reset_resolution()
