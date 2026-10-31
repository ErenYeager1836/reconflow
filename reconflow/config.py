"""reconflow.config - Configuration file loader (reconflow.toml).

Supports loading project-level (./reconflow.toml) and user-level
(~/.config/reconflow/reconflow.toml) settings. CLI flags always override
configuration file settings.
"""

import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

# Attempt to load standard library tomllib (Python 3.11+) or tomli fallback
try:
    import tomllib  # type: ignore
except ImportError:
    try:
        import tomli as tomllib  # type: ignore
    except ImportError:
        tomllib = None


def find_config_file(explicit_path: Optional[str] = None) -> Optional[Path]:
    """Find reconflow.toml from explicit path, local directory, or user config home."""
    if explicit_path:
        p = Path(explicit_path)
        if p.exists() and p.is_file():
            return p

    # 1. Current working directory
    local = Path("reconflow.toml")
    if local.exists() and local.is_file():
        return local

    # 2. User config directory ~/.config/reconflow/reconflow.toml
    config_home = os.environ.get("XDG_CONFIG_HOME")
    if config_home:
        user_cfg = Path(config_home) / "reconflow" / "reconflow.toml"
    else:
        user_cfg = Path.home() / ".config" / "reconflow" / "reconflow.toml"

    if user_cfg.exists() and user_cfg.is_file():
        return user_cfg

    return None


def load_config(explicit_path: Optional[str] = None) -> Dict[str, Any]:
    """Load and parse reconflow.toml configuration."""
    cfg_file = find_config_file(explicit_path)
    if not cfg_file:
        return {}

    if tomllib is None:
        sys.exit("config files need Python 3.11+ or `pip install tomli`")

    try:
        content = cfg_file.read_text(encoding="utf-8")
        return tomllib.loads(content)
    except Exception as e:
        print(f"[!] Warning: Failed to parse config file {cfg_file}: {e}")
        return {}


def apply_config_to_args(args: Any, config: Dict[str, Any]) -> Any:
    """Populate unspecified CLI arguments with configuration defaults."""
    if not config:
        return args

    general = config.get("general") or {}
    pipeline = config.get("pipeline") or {}
    notify = config.get("notify") or {}

    # Threads
    if getattr(args, "threads", None) is None and "threads" in general:
        try:
            args.threads = int(general["threads"])
        except ValueError:
            pass

    # Timeout
    if getattr(args, "timeout", None) in (None, 5) and "timeout" in general:
        try:
            args.timeout = int(general["timeout"])
        except ValueError:
            pass

    # Rate
    if getattr(args, "rate", None) is None and "rate" in general:
        try:
            args.rate = int(general["rate"])
        except ValueError:
            pass

    # Output directory
    if getattr(args, "output", None) in (None, "output") and "output" in general:
        args.output = str(general["output"])

    # Stages and skip
    if getattr(args, "stages", None) is None and "stages" in pipeline:
        stages_val = pipeline["stages"]
        if isinstance(stages_val, list):
            args.stages = ",".join(str(s) for s in stages_val)
        else:
            args.stages = str(stages_val)

    if getattr(args, "skip", None) is None and "skip" in pipeline:
        skip_val = pipeline["skip"]
        if isinstance(skip_val, list):
            args.skip = ",".join(str(s) for s in skip_val)
        else:
            args.skip = str(skip_val)

    # Webhook URL
    if getattr(args, "webhook_url", None) is None and "webhook_url" in notify:
        args.webhook_url = str(notify["webhook_url"])

    return args
