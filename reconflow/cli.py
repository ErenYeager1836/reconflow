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
        "--screenshots",
        action="store_true",
        help="Capture screenshots of live hosts using gowitness",
    )
    p_scan.add_argument(
        "--scope",
        default=None,
        help="Path to scope file (enforces strict scope boundaries)",
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

    return parser


def main(args=None):
    """Main entrypoint for CLI command dispatch."""
    parser = build_parser()
    parsed_args = parser.parse_args(args)

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
    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
