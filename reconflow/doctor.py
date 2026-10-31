"""reconflow.doctor - Check installed toolchain and provide setup diagnostics."""

import sys
from typing import Any

from .plugins import get_all_plugins


def check_toolchain() -> int:
    """Audit all registered recon tools and print a diagnostic report.

    Returns the number of missing tools.
    """
    plugins = get_all_plugins()
    total = len(plugins)
    available_count = 0

    header = f"{'Tool':<13} {'Stage':<12} {'Status':<10} {'Version':<12} {'Path / Install Hint'}"
    separator = "-" * 88

    print("reconflow doctor - External Toolchain Diagnostic")
    print("=" * 88)
    print(header)
    print(separator)

    for p in plugins:
        installed = p.is_installed()
        if installed:
            available_count += 1
            status = "[OK]"
            version = p.get_version()
            info = p.get_binary_path() or p.binary
        else:
            status = "[MISSING]"
            version = "-"
            info = p.get_missing_reason()

        print(f"{p.name:<13} {p.stage:<12} {status:<10} {version:<12} {info}")

    print(separator)
    missing_count = total - available_count
    if missing_count == 0:
        print(f"[+] All {total}/{total} tools are installed and ready!")
    else:
        print(
            f"[*] {available_count}/{total} tools available. "
            f"Missing tools ({missing_count}) will be skipped gracefully during scans."
        )

    return missing_count


def run(args: Any = None) -> None:
    """CLI handler for `reconflow doctor` subcommand."""
    check_toolchain()
    sys.exit(0)
