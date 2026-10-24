# reconflow

[![PyPI](https://img.shields.io/pypi/v/reconflow)](https://pypi.org/project/reconflow/)

Reconnaissance tool for bug bounty hunters that tracks **what changed** between scans. Chains [subfinder](https://github.com/projectdiscovery/subfinder) and [httpx](https://github.com/projectdiscovery/httpx) into a single automated pipeline, detects and filters out wildcard DNS noise, snapshots every target run, and highlights new subdomains, newly live hosts, and status changes with actionable lead hints.

```bash
pip install reconflow
reconflow scan example.com
reconflow diff example.com
```

> **Use responsibly.** Only scan domains you own or that are explicitly in scope for a bug bounty / pentest program you are authorized to test.

## Features

- **`scan`**: finds subdomains, drops wildcard DNS false positives (including rotating IP pools), probes live hosts for status code, title and technologies, and writes a Markdown report
- **`diff`**: compares your two most recent scans of a domain and highlights what's new
- **Scan history**: every scan saves a structured snapshot, so nothing is overwritten
- **Cron-friendly**: `diff` exits `1` when something changed and `0` when nothing did
- No Python dependencies beyond the standard library

## Requirements

- Python 3.8+
- [`subfinder`](https://github.com/projectdiscovery/subfinder/releases) and [`httpx`](https://github.com/projectdiscovery/httpx/releases) (ProjectDiscovery's Go versions) on your `PATH`
- [`gowitness`](https://github.com/sensepost/gowitness/releases) (optional, only for `--screenshots`; **gowitness v3+ required**, as v2 legacy flags do not support `gowitness scan file`)

> **Note:** `httpx` must be ProjectDiscovery's tool, not the Python `httpx` library. On Kali/Debian/Ubuntu it is often packaged as `httpx-toolkit`. reconflow checks for both names and verifies the binary.

Install Go tools directly with `go install`:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Check your tools:

```
subfinder -version
httpx -version
```

## Install

From PyPI:

```
pip install reconflow
```

From source:

```bash
git clone https://github.com/ErenYeager1836/reconflow.git
cd reconflow
pip install -e .
```

## Usage

```
reconflow scan example.com
reconflow scan example.com --scope scope.txt
reconflow diff example.com
reconflow scope scope.txt api.example.com notexample.com
```

You can also run it as a module: `python -m reconflow scan example.com`

### `scan`

| Option | Description |
| --- | --- |
| `domain` | Target domain (required, must be in scope) |
| `-o`, `--output` | Output folder (default: `output`) |
| `--threads` | Number of threads for probing (default: 10) |
| `--timeout` | Timeout in seconds for probing (default: 5) |
| `--keep-wildcard` | Warn about wildcard DNS but don't filter wildcard results |
| `--json` | Also write structured results to `report.json` |
| `--screenshots` | Capture screenshots of live hosts (requires gowitness) |
| `--scope` | Path to scope file (drops out-of-scope hosts before network activity) |

### `scope`

Verify whether targets are in or out of scope based on a program scope file:

```bash
reconflow scope scope.txt api.example.com admin.example.com 192.168.1.10
```

#### Scope file format & matching rules
- One entry per line; blank lines and `#` comments are ignored.
- **In-scope entries**: exact domains (`example.com`), wildcards (`*.example.com`), and IP/CIDR blocks (`192.168.1.0/24`).
- **Out-of-scope entries**: prefixed with `!`, `-`, or `out:` (e.g. `!admin.example.com`, `!10.0.0.0/8`).
- **Out-of-scope entries ALWAYS override in-scope entries**.
- **Wildcard matching**: `*.example.com` matches subdomains only (e.g. `api.example.com`, `dev.api.example.com`). It does **NOT** match the apex domain `example.com` itself and does **NOT** match `notexample.com`. The apex domain must be listed explicitly if in scope.
- **Normalization**: Hostnames are normalized first (lowercased; schemes, credentials, ports, paths, and trailing dots are stripped).
- **Fail closed**: If `--scope` is given and the file is missing, unreadable, empty, or contains no valid in-scope entries, reconflow aborts immediately. Out-of-scope hosts and redirect targets are never probed.

> **Browser Redirects & Scope**: `gowitness` captures screenshots in a real headless browser, which automatically follows HTTP redirects. `reconflow` protects your scope boundaries by capturing HTTP redirect targets (`Location` headers) via `httpx` in all modes and automatically skipping screenshots for any host that redirects to an out-of-scope destination. Note that client-side JavaScript redirects (e.g. `window.location`) or HTML `<meta http-equiv="refresh">` redirects execute inside the browser engine and cannot be detected beforehand.

### `diff`

| Option | Description |
| --- | --- |
| `domain` | Target domain to compare runs for (required) |
| `-o`, `--output` | Output folder (default: `output`) |
| `--json` | Print the comparison as JSON |
| `--notify` | Send webhook alert to Discord or Slack if changes are detected |
| `--webhook-url` | Webhook URL (or set `RECONFLOW_WEBHOOK_URL` / `DISCORD_WEBHOOK_URL` / `SLACK_WEBHOOK_URL`) |

`diff` needs at least two saved scans of the same domain. Run `scan` twice first.

### `mark`

Set triage state for a host on a per-domain basis so reviewed assets stop cluttering differential scans:

```bash
# Mark host as reviewed and tested
reconflow mark admin.example.com --tested

# Mark host to be ignored in subsequent diffs
reconflow mark dev-api.example.com --ignore --notes "Mock API for testing"

# List all triaged hosts for a domain
reconflow mark --list -d example.com
```

| Option | Description |
| --- | --- |
| `host` | Hostname or URL to mark |
| `-d`, `--domain` | Target domain (inferred if omitted) |
| `-o`, `--output` | Output folder (default: `output`) |
| `--tested` | Mark host as tested |
| `--ignore` | Mark host as ignored |
| `--notes` | Optional notes on the triage decision |
| `--list` | List all triaged hosts for domain |

> **Triage Behavior**:
> - `--ignore`: Permanently silences the host from appearing in `new_live` and `changed` sections in subsequent diffs.
> - `--tested`: Hides the host from `new_live` once reviewed, but if the host later undergoes a change (e.g. status code changes from 403 to 200, title changes, or new technology is detected), it automatically resurfaces under `changed` so you never miss critical updates.

### `report`

Regenerate Markdown (`report.md`) and JSON (`report.json`) reports from an existing scan snapshot without re-running any network discovery or probing:

```bash
# Regenerate report from the latest scan
reconflow report example.com

# Regenerate report for a specific historical scan run
reconflow report example.com --run 2026-10-18_185218

# Output structured report as JSON
reconflow report example.com --json
```

| Option | Description |
| --- | --- |
| `domain` | Target domain to generate report for (required) |
| `-o`, `--output` | Output folder (default: `output`) |
| `--run` | Specific scan run ID (defaults to latest scan) |
| `--json` | Print the regenerated report as JSON |

## Track changes with `diff`

Most recon tools tell you what exists. reconflow also tells you what changed. New subdomains, newly live hosts, and status transitions are annotated with actionable **lead hints** ("worth checking"):

> **Illustrative example output** (simulated demonstration, not from a real scan):
<!-- TODO: Replace illustrative sample diff output below with real output from an authorized scan run -->

```
[*] Recon diff: 2026-10-18_185218 -> 2026-10-18_190412
============================================================
[+] NEW SUBDOMAINS (2):
    + beta.example.com
    + staging-api.example.com
[+] NEWLY LIVE HOSTS (1):
    + https://beta.example.com [200] [Beta Portal] [Nginx, React]
        * Worth checking: Prerelease beta environment; look for unhardened endpoints or debug flags.
[*] CHANGED HOSTS (1):
    ~ https://admin.example.com
        status: 403 -> 200
        title: 'Forbidden' -> 'Admin Login'
        tech: ['Apache'] -> ['Apache', 'PHP']
        * Worth checking: Status changed from 403 to 200; previously protected resource is now publicly accessible.
        * Worth checking: Administrative interface; test for panel access, auth bypass, or default credentials.
[-] Removed subdomains (1) [informational]:
    - old.example.com
============================================================
```

> **Incomplete Scan Safeguards**: If a previous or current scan was interrupted (Ctrl+C), missing hosts are never reported as "gone" or removed, and a warning is displayed instead.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No changes found (or not enough history to compare) |
| `1` | Changes were detected |

### Webhook Alerts & Scheduled Automation

Send alerts to Discord or Slack only when new hosts or changes are detected:

```bash
# Set webhook in environment (recommended: avoids exposing secrets in shell history or ps)
export RECONFLOW_WEBHOOK_URL="https://discord.com/api/webhooks/..."

# Every 6 hours: rescan, diff, and notify on changes
0 */6 * * * reconflow scan example.com && reconflow diff example.com --notify >> ~/recon-changes.log
```

> **Security Note**: Using the `RECONFLOW_WEBHOOK_URL` (or `DISCORD_WEBHOOK_URL` / `SLACK_WEBHOOK_URL`) environment variable is strongly recommended over `--webhook-url` to prevent sensitive tokens from appearing in shell history (`.bash_history`) or process listings (`ps aux`).

## Output

Files are saved under `output/<domain>/`:

```
subdomains.txt      all discovered subdomains
live.txt            live hosts with status code, title, tech
report.md           summary report
report.json         structured report (with --json)
triage.json         triage records (with reconflow mark)
screenshots/        screenshots of live hosts (with --screenshots)
runs/<run_id>/      snapshot of each scan, used by diff
```

## Known limitations

- **Wildcard DNS domains** return many fake "live" hosts that all point to the same server. reconflow detects them and filters those hosts (use `--keep-wildcard` to disable).
- Discovery depends on subfinder's sources, so results can vary between runs.

## Roadmap

- [x] Subdomain discovery and live host probing
- [x] Wildcard DNS detection (including rotating IP pools)
- [x] `--threads` and `--timeout` options
- [x] JSON report output
- [x] Screenshots of live hosts
- [x] Scan history and `reconflow diff`
- [x] `reconflow scope`: check targets against program scope
- [x] `reconflow report`: regenerate reports from saved scans
- [x] Lead hints in `reconflow diff`
- [x] `--notify`: Discord/Slack webhook alerts for diff results
- [x] Triage state: `reconflow mark <host> --tested|--ignore`
- [x] Save results as they come in

## Contributing

Contributions are welcome. Look for issues labelled `good first issue`. Run the tests with:

```
python -m unittest discover tests -v
```

## License

MIT

<<<<<<< HEAD
## CSV reports

Use `--csv` on a scan to generate a spreadsheet-compatible `report.csv` alongside
`report.md` under `output/<domain>/`:

```sh
python -m reconflow scan example.com --csv
python -m reconflow scan example.com --csv --json --output my-results
```

The CSV contains `subdomain`, `ip`, `status_code`, `title`, `technologies`,
`cname`, and `takeover_risk` columns. Existing probe results primarily include
URLs, status, title and technology names. The exporter extracts the subdomain
from the URL, joins technology names with semicolons, and leaves fields blank
when the scanner did not collect them. An empty scan still writes the header.
All CSV quoting is handled by Python's standard `csv` module; no extra
packages are required.
=======
## Quiet output for UNIX pipelines

Pass `-q`, `--quiet`, or `--silent` to the `scan` command to keep stdout machine-readable:

```sh
python -m reconflow scan example.com --quiet | sort -u > targets.txt
```

Progress and scan diagnostics go to stderr, while stdout contains the discovered live HTTP(S) URLs (one per line); if no live hosts were found, the discovered subdomains are emitted instead. The ordinary Markdown report, run snapshots and optional `--json` report file are still written. Without the flag, the normal human-readable progress output is unchanged. This mode does not initiate any additional scanning beyond the regular `scan` command.
>>>>>>> 60a12bb (feat(scan): support quiet pipeline output (#14))
