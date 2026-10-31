"""reconflow.cli - Command-line interface and subcommand routing."""

import argparse
import sys
from . import __version__, scan


def build_parser():
    """Construct the main argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="reconflow",
        description="Recon pipeline for bug bounty hunters",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="subcommands",
        description="available operations",
    )

    # scan subcommand
    p_scan = subparsers.add_parser(
        "scan",
        help="Run recon on a domain",
        description="Discover subdomains, filter wildcard DNS, and probe live web services.",
    )
    p_scan.add_argument(
        "domain",
        help="Target domain (must be in scope!)",
    )
    p_scan.add_argument(
        "-o",
        "--output",
        default="output",
        help="Output folder (default: output)",
    )
    p_scan.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Number of threads for probing (default: 10)",
    )
    p_scan.add_argument(
        "--timeout",
        type=int,
        default=5,
        help="Timeout in seconds for probing (default: 5)",
    )
    p_scan.add_argument(
        "--keep-wildcard",
        action="store_true",
        help="Warn about wildcard DNS but don't filter wildcard results",
    )
    p_scan.add_argument(
        "--json",
        action="store_true",
        dest="json_report",
        help="Also write structured results to report.json",
    )
    p_scan.add_argument(
        "--csv",
        action="store_true",
        help="Export discovered live hosts to report.csv (no external dependencies)",
    )
    p_scan.add_argument(
        "-q", "--quiet", "--silent",
        action="store_true",
        dest="silent",
        help="Show only discovered targets/URLs on stdout; send progress to stderr",
    )
    p_scan.add_argument(
        "--screenshots",
        action="store_true",
        help="Capture screenshots of live hosts using gowitness",
    )
    p_scan.add_argument(
        "--scope",
        default=None,
        help="Path to scope file (enforces strict scope boundaries)",
    )
    p_scan.add_argument(
        "--stages",
        default=None,
        help="Comma-separated list of pipeline stages to run (e.g. subdomains,http,vulns)",
    )
    p_scan.add_argument(
        "--skip",
        default=None,
        help="Comma-separated list of pipeline stages to skip (e.g. ports,vulns)",
    )
    p_scan.add_argument(
        "--rate",
        type=int,
        default=None,
        help="Rate limit in req/s for supported tools (default: 50, use 0 for unlimited)",
    )
    p_scan.add_argument(
        "--dry-run",
        action="store_true",
        help="Display the pipeline stages and exact commands without executing them",
    )
    p_scan.add_argument(
        "--resume",
        action="store_true",
        help="Resume previous incomplete scan run, skipping completed stages",
    )
    p_scan.add_argument(
        "--intrusive",
        action="store_true",
        help="Enable aggressive/intrusive templates in vulnerability scanning (warns on stderr)",
    )
    p_scan.add_argument(
        "--all-vulns",
        action="store_true",
        help="Alias for --intrusive to run all vulnerability templates",
    )
    p_scan.add_argument(
        "-c", "--config",
        default=None,
        help="Path to custom reconflow.toml config file",
    )

    # diff subcommand
    p_diff = subparsers.add_parser(
        "diff",
        help="Compare the latest two scans for a domain",
        description=(
            "Compare the latest two scan snapshots to detect "
            "newly discovered subdomains and host changes."
        ),
    )
    p_diff.add_argument(
        "domain",
        help="Target domain to compare runs for",
    )
    p_diff.add_argument(
        "-o",
        "--output",
        default="output",
        help="Output folder (default: output)",
    )
    p_diff.add_argument(
        "--json",
        action="store_true",
        dest="json_report",
        help="Output diff comparison as JSON",
    )
    p_diff.add_argument(
        "--notify",
        action="store_true",
        help="Send diff notifications to Slack or Discord webhook",
    )
    p_diff.add_argument(
        "--webhook-url",
        default=None,
        help="Webhook URL (or set RECONFLOW_WEBHOOK_URL / DISCORD_WEBHOOK_URL / SLACK_WEBHOOK_URL)",
    )

    # scope subcommand
    p_scope = subparsers.add_parser(
        "scope",
        help="Check targets against program scope",
        description="Verify whether target hosts, IPs, or CIDRs are IN or OUT of scope.",
    )
    p_scope.add_argument(
        "scope_file",
        help="Path to scope file",
    )
    p_scope.add_argument(
        "targets",
        nargs="+",
        help="One or more target hostnames, URLs, or IPs to check",
    )

    # report subcommand
    p_report = subparsers.add_parser(
        "report",
        help="Regenerate reports from a saved scan",
        description=(
            "Regenerate Markdown and JSON reports from a saved scan without re-scanning."
        ),
    )
    p_report.add_argument(
        "domain",
        help="Target domain to generate report for",
    )
    p_report.add_argument(
        "-o",
        "--output",
        default="output",
        help="Output folder (default: output)",
    )
    p_report.add_argument(
        "--run",
        dest="run_id",
        default=None,
        help="Specific scan run ID (defaults to latest scan)",
    )
    p_report.add_argument(
        "--json",
        action="store_true",
        dest="json_report",
        help="Output regenerated report as JSON",
    )
    p_report.add_argument(
        "--format",
        choices=["md", "csv", "json", "sarif"],
        default=None,
        help="Report output format (md, csv, json, sarif)",
    )

    # mark subcommand
    p_mark = subparsers.add_parser(
        "mark",
        help="Mark a host triage state (--tested or --ignore)",
        description=(
            "Set triage state for a host so reviewed assets stop appearing in diffs."
        ),
    )
    p_mark.add_argument(
        "host",
        nargs="?",
        default=None,
        help="Target host or URL to mark",
    )
    p_mark.add_argument(
        "-d",
        "--domain",
        default=None,
        help="Target domain (inferred if omitted)",
    )
    p_mark.add_argument(
        "-o",
        "--output",
        default="output",
        help="Output folder (default: output)",
    )
    p_mark.add_argument(
        "--tested",
        action="store_true",
        help="Mark host as tested",
    )
    p_mark.add_argument(
        "--ignore",
        action="store_true",
        help="Mark host as ignored",
    )
    p_mark.add_argument(
        "--notes",
        default="",
        help="Optional triage notes",
    )
    p_mark.add_argument(
        "--list",
        action="store_true",
        help="List all triaged hosts for domain",
    )

    # doctor subcommand
    subparsers.add_parser(
        "doctor",
        help="Check external recon toolchain and dependencies",
        description=(
            "List installed external binaries, versions, and "
            "installation hints for missing tools."
        ),
    )

    return parser


def main(args=None):
    """Main entrypoint for CLI command dispatch."""
    parser = build_parser()
    parsed_args = parser.parse_args(args)

    from . import config

    cfg_path = getattr(parsed_args, "config", None)
    cfg = config.load_config(cfg_path)
    if cfg:
        parsed_args = config.apply_config_to_args(parsed_args, cfg)

    if parsed_args.command == "scan":
        scan.run(parsed_args)
    elif parsed_args.command == "diff":
        from . import diff

        diff.run(parsed_args)
    elif parsed_args.command == "scope":
        from . import scope

        scope.run(parsed_args)
    elif parsed_args.command == "report":
        from . import report

        report.run(parsed_args)
    elif parsed_args.command == "mark":
        from . import triage

        triage.run(parsed_args)
    elif parsed_args.command == "doctor":
        from . import doctor

        doctor.run(parsed_args)
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
