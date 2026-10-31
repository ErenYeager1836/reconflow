# reconflow

[![PyPI](https://img.shields.io/pypi/v/reconflow)](https://pypi.org/project/reconflow/)

Reconnaissance orchestrator for bug bounty hunters that tracks **what changed** between scans. Orchestrates industry-standard external tools into a safe, automated pipeline, enforces strict program scope at every stage, records target state in SQLite, and highlights **new subdomains**, **new live hosts**, **new open ports**, **new endpoints**, and **new findings** with actionable lead hints.

```bash
pip install reconflow
reconflow doctor
reconflow scan example.com --scope scope.txt
reconflow diff example.com
```

> **Use responsibly.** Only scan domains you own or that are explicitly in scope for a bug bounty / pentest program you are authorized to test.

---

## Architecture

reconflow does not reinvent reconnaissance tools; it orchestrates them safely as external binaries, normalizes their outputs into SQLite, and detects changes over time:

```
+-------------------------------------------------------------------------+
|                                reconflow                                |
|                         Orchestration Pipeline                          |
+-------------------------------------------------------------------------+
       |
       +--> [1. subdomains] : subfinder (with strict scope filtering)
       |
       +--> [2. dns]        : dnsx / wildcard DNS detection
       |
       +--> [3. http]       : httpx (live status, tech, titles)
       |
       +--> [4. urls]       : katana / gau / waybackurls
       |
       +--> [5. ports]      : naabu (in-scope host port scanning)
       |
       +--> [6. vulns]      : nuclei (safe by default / --intrusive)
       |
       v
+-------------------------------------------------------------------------+
|  State Ledger (SQLite) & Snapshot History (output/<domain>/reconflow.db)|
+-------------------------------------------------------------------------+
       |
       +--> Analysis  : Takeover detection, JS endpoint & masked secret mining
       +--> Diffing   : What is NEW (ports, endpoints, findings, hosts)
       +--> Reporting : Markdown, CSV, JSON, and SARIF v2.1.0
       +--> Webhook   : Concise alert digest for Discord / Slack
```

---

## Features

- **Toolchain Diagnostics (`doctor`)**: Inspects installed external binaries, versions, paths, and provides installation hints for missing ones.
- **Modular Pipeline**: Six canonical stages (`subdomains -> dns -> http -> urls -> ports -> vulns`). Filter stages via `--stages` or `--skip`.
- **Hard Scope Enforcement**: Universal scope gate drops out-of-scope hosts and IPs before executing any tool. Fail-closed scope design.
- **Polite & Safe Scanning**: Rate limiting (`--rate`), thread limits (`--threads`), and safe vulnerability scanning defaults. Nuclei runs safe checks by default; aggressive templates require `--intrusive` or `--all-vulns`.
- **Dry Run & Resume**: Preview execution plans with `--dry-run`. Resume interrupted scans with `--resume` to skip already completed stages.
- **State & Differential Tracking (`diff`)**: Target SQLite database (`output/<domain>/reconflow.db`) tracks historical runs and surfaces what is NEW: subdomains, live hosts, open ports, endpoints, and vulnerability findings.
- **Analysis & Heuristics**: Subdomain takeover detection (marked conservatively as `"candidate, verify manually"`), JS endpoint and secret mining with **strictly masked previews** (`AKIA****************`), and lead scoring.
- **Multi-Format Reporting**: Export reports to Markdown, CSV, JSON, and SARIF v2.1.0 (`--format sarif`).
- **Configuration**: Global and local configuration via `reconflow.toml`.

---

## Toolchain & Requirements

- Python 3.8+
- Supported external tools (each optional; missing tools skip their stage gracefully):
  - [`subfinder`](https://github.com/projectdiscovery/subfinder): Subdomain enumeration
  - [`httpx`](https://github.com/projectdiscovery/httpx): Live HTTP probing & technology detection
  - [`dnsx`](https://github.com/projectdiscovery/dnsx): Fast multi-purpose DNS toolkit
  - [`naabu`](https://github.com/projectdiscovery/naabu): Fast port scanner
  - [`katana`](https://github.com/projectdiscovery/katana): Next-generation web crawler
  - [`gau`](https://github.com/lc/gau): Fetch known URLs from AlienVault, Wayback, Common Crawl
  - [`waybackurls`](https://github.com/tomnomnom/waybackurls): Fetch URLs from the Wayback Machine
  - [`nuclei`](https://github.com/projectdiscovery/nuclei): Fast vulnerability scanner
  - [`gowitness`](https://github.com/sensepost/gowitness): Screenshot generator (v3+ required)

Run the doctor command to verify your toolchain:

```bash
reconflow doctor
```

Install ProjectDiscovery tools via Go:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
```

---

## Installation

From PyPI:

```bash
pip install reconflow
```

From source:

```bash
git clone https://github.com/ErenYeager1836/reconflow.git
cd reconflow
pip install -e .
```

---

## Usage

### 1. Toolchain Check (`doctor`)

Check installed external binaries, their versions, and installation hints:

```bash
reconflow doctor
```

### 2. Scanning (`scan`)

Run a full or customized recon scan against an in-scope domain:

```bash
# Standard scan (subdomains -> dns -> http)
reconflow scan example.com --scope scope.txt

# Run specific pipeline stages
reconflow scan example.com --stages subdomains,http,urls

# Skip port scanning or intrusive vulnerability tests
reconflow scan example.com --skip ports,vulns

# Polite rate limiting and threads
reconflow scan example.com --rate 30 --threads 10

# Dry-run mode (prints execution plan without running external commands)
reconflow scan example.com --dry-run

# Resume an interrupted scan (skips completed stages)
reconflow scan example.com --resume

# Enable aggressive vulnerability templates (warns on stderr)
reconflow scan example.com --stages vulns --intrusive
```

#### `scan` Options

| Option | Description |
| --- | --- |
| `domain` | Target domain (required, must be in scope) |
| `-o`, `--output` | Output folder (default: `output`) |
| `--scope` | Path to scope file (drops out-of-scope targets before tool execution) |
| `--stages` | Comma-separated list of stages to run (`subdomains`, `dns`, `http`, `urls`, `ports`, `vulns`) |
| `--skip` | Comma-separated list of stages to skip |
| `--rate` | Rate limit in requests per second for supported tools |
| `--threads` | Concurrency / thread count for external tools |
| `--timeout` | HTTP timeout in seconds (default: 5) |
| `--dry-run` | Display pipeline stages and exact commands without executing them |
| `--resume` | Resume previous incomplete scan run, skipping completed stages |
| `--intrusive`, `--all-vulns` | Enable aggressive/intrusive templates in vulnerability scanning |
| `-c`, `--config` | Path to custom `reconflow.toml` config file |
| `-q`, `--quiet`, `--silent` | Show only discovered targets/URLs on stdout; send progress to stderr |
| `--screenshots` | Capture screenshots of live hosts using gowitness |
| `--keep-wildcard` | Warn about wildcard DNS but don't filter wildcard results |
| `--json` | Write structured results to `report.json` |
| `--csv` | Write live host data to `report.csv` |

#### Vulnerability Scanning & Nuclei Safe Mode

reconflow prioritizes target safety and politeness by default:

- **Default Safe Mode**: When the `vulns` stage runs, nuclei executes **ONLY** low-risk templates (`info`, `low`, `medium`) and **NEVER** runs `high` or `critical` severity templates out of the box. Disruptive tags like `dos`, `fuzz`, and `intrusive` are strictly excluded.
- **Subdomain Takeovers**: Takeover candidates are discovered via reconflow's dedicated CNAME inspection (checking dangling DNS pointers against recognized signatures like GitHub Pages, AWS S3, Heroku) and marked conservatively as `"candidate, verify manually"`, rather than executing high/critical nuclei templates.
- **Enabling Higher Severities**: To execute higher-severity (`high`, `critical`) or intrusive templates, you must explicitly pass `--intrusive` or `--all-vulns`. When enabled, reconflow emits a prominent warning banner to stderr reminding you to ensure written authorization.

---

### 3. Track Changes (`diff`)

Compare the two most recent scans for a domain to surface what is **NEW**:

```bash
reconflow diff example.com

# Emit JSON diff
reconflow diff example.com --json

# Send notification digest to Discord or Slack on changes
reconflow diff example.com --notify
```

`diff` reports:
- Newly discovered subdomains
- Newly live HTTP hosts with lead hints
- Newly opened ports
- Newly discovered endpoints and URLs
- Newly surfaced vulnerability findings

Exit code is `1` if changes were detected and `0` if no changes occurred, making it ideal for cron automation.

---

### 4. Scope Verification (`scope`)

Verify whether targets are in or out of scope based on a program scope file:

```bash
reconflow scope scope.txt api.example.com admin.example.com 192.168.1.10
```

#### Scope Rules
- Exact hosts (`example.com`), wildcards (`*.example.com`), and CIDR blocks (`10.0.0.0/8`).
- Out-of-scope lines prefixed with `!`, `-`, or `out:` (e.g. `!admin.example.com`).
- **Out-of-scope rules always take precedence** over in-scope rules.
- Out-of-scope targets are dropped before invoking external binaries.

---

### 5. Multi-Format Reporting (`report`)

Regenerate reports from saved scan snapshots in Markdown, CSV, JSON, or SARIF v2.1.0:

```bash
# Markdown report (default)
reconflow report example.com

# SARIF v2.1.0 format (for GitHub Security Code Scanning)
reconflow report example.com --format sarif

# CSV export
reconflow report example.com --format csv

# Specific run ID
reconflow report example.com --run 2026-10-31_153000 --format json
```

---

### 6. Host Triage (`mark`)

Mark hosts as tested or ignored so reviewed assets stop cluttering differential scans:

```bash
# Mark host as reviewed and tested
reconflow mark admin.example.com --tested

# Mark host to be ignored in subsequent diffs
reconflow mark dev-api.example.com --ignore --notes "Mock API for testing"

# List triaged hosts
reconflow mark --list -d example.com
```

---

## Configuration (`reconflow.toml`)

reconflow automatically checks `./reconflow.toml` and `~/.config/reconflow/reconflow.toml`. CLI flags always take precedence over configuration defaults.

```toml
[general]
output = "output"
threads = 20
timeout = 5
rate = 50

[pipeline]
stages = ["subdomains", "dns", "http", "urls"]
skip = ["ports"]

[templates]
exclude_tags = ["dos", "fuzz"]

[notify]
webhook_url = "https://discord.com/api/webhooks/..."
```

---

## Output Structure

Results are stored per target in `output/<domain>/`:

```
output/<domain>/
├── reconflow.db        # SQLite database tracking runs, hosts, ports, URLs, findings
├── subdomains.txt      # Discovered in-scope subdomains
├── live.txt            # Live probed HTTP services
├── urls.txt            # Crawled & archived endpoints
├── ports.json          # Open ports discovered by naabu
├── vulns.json          # Vulnerability findings from nuclei
├── report.md           # Markdown summary report
├── report.json         # JSON structured report
├── report.csv          # CSV host spreadsheet
├── report.sarif        # SARIF v2.1.0 finding report
├── triage.json         # Marked host triage states
├── screenshots/        # Live host screenshots (with --screenshots)
└── runs/<run_id>/      # Immutable snapshot for each scan run
```

---

## UNIX Pipelines (`--quiet`)

Pass `-q`, `--quiet`, or `--silent` to keep stdout clean and machine-readable:

```bash
reconflow scan example.com --quiet | sort -u > targets.txt
```

Progress and diagnostics go to stderr, while stdout outputs discovered live HTTP URLs (or subdomains).

---

## Contributing

Contributions are welcome! Run tests and linting with:

```bash
python -m unittest discover tests -v
flake8 reconflow tests --max-line-length=100 --ignore=E203,W503,W504
```

---

## License

MIT
