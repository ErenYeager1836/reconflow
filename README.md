# reconflow

**Recon that tells you what changed.**

Run it on a schedule against a bug bounty target and get told about new subdomains, newly live hosts, newly opened ports, and new endpoints since the last scan. It runs standard tools (subfinder, httpx, naabu, nuclei and others), keeps every run in SQLite, and refuses to touch anything outside your scope file.

[![CI](https://github.com/ErenYeager1836/reconflow/actions/workflows/ci.yml/badge.svg)](https://github.com/ErenYeager1836/reconflow/actions)
[![PyPI](https://img.shields.io/pypi/v/reconflow)](https://pypi.org/project/reconflow/)
[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

![demo](docs/demo.gif)  <!-- recorded from a domain I own, see docs/DEMO.md -->

## Who this is for

Solo bug bounty hunters who already use subfinder and httpx and want to know when something new shows up, without maintaining a pile of shell scripts and `anew` files.

## What it does

- Runs your toolchain in stages: subdomains, dns, http, urls, ports, vulns.
- Performs built-in zero-dependency security audits: DNSSEC/AXFR validation, JWT token analysis, Web Cache Deception detection, sensitive file audits, cloud bucket discovery, and CVE correlation.
- Drops anything outside your scope file before any tool runs, and refuses to scan an out-of-scope target at all.
- Stores each run so `reconflow diff` shows only what's new, and exits with code 1 when something changed, so it works in cron.
- Sends a short digest to Discord or Slack with `--notify`.
- Exports Markdown, CSV, JSON, and SARIF.

## What it doesn't do

- It doesn't replace subfinder, httpx, or nuclei. It calls them, so they must be installed (`reconflow doctor` checks).
- "Lead hints" are keyword heuristics ("staging", "admin"), not findings. Verify everything yourself.
- It runs on one machine. There's no distributed mode.
- Nuclei runs low-risk templates only unless you pass `--intrusive`.

## Quick start

```bash
pip install reconflow      # or: docker run ... (see Docker section)
reconflow doctor
reconflow scan example.com --scope scope.txt
reconflow scan example.com --full-audit  # run all audits, analysis, and discovery
reconflow diff example.com
```

## Example output

<!-- PASTE REAL OUTPUT from docs/DEMO.md here. State which domain it came from. -->

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
       +--> Audits    : DNSSEC, AXFR, JWT, Web Cache, Cloud Buckets, CVE correlation
       +--> Diffing   : What is NEW (ports, endpoints, findings, hosts)
       +--> Reporting : Markdown, CSV, JSON, and SARIF v2.1.0
       +--> Webhook   : Concise alert digest for Discord / Slack
```

---

## Features

- **Toolchain Diagnostics (`doctor`)**: Inspects installed external binaries, versions, paths, and provides installation hints for missing ones.
- **Modular Pipeline**: Six canonical stages (`subdomains -> dns -> http -> urls -> ports -> vulns`). Filter stages via `--stages` or `--skip`.
- **Advanced Defensive Audits (`--audits`, `--full-audit`)**: 15 built-in zero-dependency security audits including cloud storage bucket discovery (AWS S3, GCP, Azure), DNSSEC/CAA verification, AXFR zone transfer tests, exposed sensitive files (`.git`, `.env`), WAF fingerprinting, defensive HTTP security headers grading, and favicon hashing.
- **Web & API Intelligence (`--jwt`, `--params`, `--cache-audit`)**: Dissects JWT tokens, checks `alg: none` and weak HMAC secrets, categorizes URL parameters for SSRF/IDOR/SQLi, and tests for Web Cache Deception.
- **Vulnerability & OSINT Engines (`--cve-correlate`, `--github-leaks`)**: Correlates detected software versions with the NVD CVE API v2.0 and queries public GitHub code for leaked credentials or secrets referencing the domain.
- **Hard Scope Enforcement**: Universal scope gate drops out-of-scope hosts and IPs before executing any tool. Fail-closed scope design.
- **Polite & Safe Scanning**: Rate limiting (`--rate`, default: 50 req/s, use 0 for unlimited), thread limits (`--threads`), and safe vulnerability scanning defaults. Nuclei runs safe checks by default; aggressive templates require `--intrusive` or `--all-vulns`.
- **Dry Run & Resume**: Preview execution plans with `--dry-run`. Resume interrupted scans with `--resume` to skip already completed stages.
- **State & Differential Tracking (`diff`)**: Target SQLite database (`output/<domain>/reconflow.db`) tracks historical runs and surfaces what is NEW: subdomains, live hosts, open ports, endpoints, and vulnerability findings.
- **Analysis & Heuristics**: Subdomain takeover detection (marked conservatively as `"candidate, verify manually"`), JS endpoint and secret mining with **strictly masked previews** (`AKIA****************`), and lead scoring.
- **Multi-Format Reporting**: Export reports to Markdown, CSV, JSON, and SARIF v2.1.0 (`--format sarif`).
- **Configuration**: Global and local configuration via `reconflow.toml`.

---

## Toolchain & Requirements

- Python 3.10+
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
*(Release v0.5.0 brings built-in standard-library security audits, DNSSEC/AXFR tests, JWT analysis, and CVE correlation).*

From source:

```bash
git clone https://github.com/ErenYeager1836/reconflow.git
cd reconflow
pip install -e .
```

### Docker

A multi-stage container is provided with all supported external tools (`subfinder`, `httpx`, `dnsx`, `naabu`, `katana`, `nuclei`, `gau`, `waybackurls`) pre-installed under an unprivileged user:

Pre-built multi-architecture images (`linux/amd64`, `linux/arm64`) are published to GitHub Container Registry on every tagged release:

```bash
docker pull ghcr.io/erenyeager1836/reconflow:latest
```

```bash
# Build the container:
docker build -t reconflow .

# Verify toolchain availability:
docker run --rm reconflow doctor

# Run scan with mounted scope file and persistent output directory:
docker run --rm \
  -v $(pwd)/output:/app/output \
  -v $(pwd)/scope.txt:/app/scope.txt:ro \
  reconflow scan example.com --scope /app/scope.txt

# Inspect differential changes:
docker run --rm \
  -v $(pwd)/output:/app/output \
  reconflow diff example.com
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
| `--rate` | Rate limit in requests per second for supported tools (default: 50, use 0 for unlimited) |
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
| `--axfr` | Audit authoritative nameservers for unrestricted DNS Zone Transfers (AXFR) |
| `--dns-sec` | Audit DNSSEC, RFC 6844 CAA records, and check for dangling cloud nameservers |
| `--permute` | Generate scaled subdomain permutations with wildcard DNS filtering and HTTP verification |
| `--perm-wordlist` | Path to custom SecLists-style wordlist for subdomain permutations |
| `--params` | Categorize discovered URL query parameters for SSRF, IDOR, LFI, and SQLi |
| `--jwt` | Audit discovered JWT tokens for `alg: none` bypass, weak HMAC secrets, and missing `exp` |
| `--cache-audit` | Audit CDN cache headers and test for Web Cache Deception & unkeyed reflection |
| `--cve-correlate` | Correlate detected web technologies against the NVD CVE API v2.0 |
| `--github-leaks` | Search public GitHub code for leaked credentials and configurations |
| `--github-token` | GitHub Personal Access Token for code search (or via `GITHUB_TOKEN` env var) |
| `--audits` | Run comprehensive defensive audits (cloud assets, ASN, CORS, sensitive files, WAF, SSL, etc.) |
| `--full-audit` | Convenience flag: enable all analysis and audit modules across the scan |

#### Advanced Analysis & Security Audits

reconflow includes built-in standard-library security audits that run without external binaries:

- **DNS Infrastructure & AXFR (`--axfr`, `--dns-sec`)**: Tests nameservers for open zone transfers over TCP port 53, validates DNSSEC chain of trust (DS/DNSKEY records), inspects CAA issuance policies, and identifies dangling cloud nameservers (AWS Route53, Azure DNS, NS1) susceptible to zone hijacking.
- **Web & API Intelligence (`--jwt`, `--params`, `--cache-audit`)**: Dissects JWT tokens, attempts dictionary cracking of weak HMAC secrets, tests `alg: none` signature evasion, maps query parameters to vulnerability categories, and audits CDN caching rules for Web Cache Deception.
- **Vulnerability Correlation & OSINT (`--cve-correlate`, `--github-leaks`, `--audits`)**: Queries the NVD CVE API v2.0 for detected framework versions, searches public GitHub repositories for leaked credentials or `.env` files referencing the domain, extracts public cloud storage buckets (AWS S3, GCP Storage, Azure Blob), checks for exposed `.git` or sensitive dev files, and grades defensive HTTP response headers (A+ to F).
- **Automated Findings Persistence**: High-confidence vulnerabilities discovered during audits automatically populate `vulns.json`, SQLite `reconflow.db`, and scan reports, surfacing in `reconflow diff` comparisons across scan runs.

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

#### Example Output (Synthetic, Generated from Test Fixtures)

> [!NOTE]
> The following sample diff output is illustrative and was generated from synthetic test snapshots in `tests/test_diff.py` using `example.com` (RFC 2606 reserved documentation domain) rather than a live network scan. Zero external network requests were sent.

```text
[*] Recon diff: 2026-11-08_111610 -> 2026-11-08_111627
============================================================

[+] NEW SUBDOMAINS (2):
    + api.example.com
    + staging.example.com

[+] NEWLY LIVE HOSTS (2):
    + https://api.example.com [200] [API Gateway] [Express, Node.js]
        * Worth checking: API endpoint; test for IDOR, mass assignment, and unauthenticated routes.
    + https://staging.example.com [200] [Staging Portal] [React]
        * Worth checking: Staging system often mirrors production with weaker auth or unpatched features.

[*] CHANGED HOSTS (1):
    ~ https://admin.example.com
        status: 403 -> 200
        title: 'Access Denied' -> 'Admin Console'
        * Worth checking: Status changed from 403 to 200; previously protected resource is now publicly accessible.
        * Worth checking: Page title changed to 'Admin Console'; inspect newly exposed auth interface.
        * Worth checking: Administrative interface; test for panel access, auth bypass, or default credentials.

[+] NEW OPEN PORTS (1 hosts):
    + https://staging.example.com: 8443

[+] NEW ENDPOINTS / URLS (2):
    + https://api.example.com/v1/health
    + https://staging.example.com/login

============================================================
```

Exit code is `1` if changes were detected and `0` if no changes occurred, making it suitable for cron monitoring scripts.

---

### 4. Scope Verification (`scope`)

Verify whether targets are in or out of scope based on a program scope file:

```bash
reconflow scope scope.txt api.example.com admin.example.com 192.168.1.10
```

#### Scope Rules & Upfront Guard
- Exact hosts (`example.com`), wildcards (`*.example.com`), and CIDR blocks (`10.0.0.0/8`, `2001:db8::/32`).
- Out-of-scope lines prefixed with `!`, `-`, or `out:` (e.g. `!admin.example.com`).
- **Out-of-scope rules always take precedence** over in-scope rules.
- **Upfront Target Guard**: `reconflow scan <domain> --scope scope.txt` validates the target domain upfront. If the target domain or its parent wildcard is not permitted in the scope file, `reconflow` refuses to scan and aborts immediately before invoking external binaries or initiating network requests.
- **Wildcard vs. Apex Handling**: If a scope file contains only `*.example.com` and the scan target is the apex domain `example.com`, `reconflow` permits launching passive subdomain discovery (`subfinder -d example.com`) to locate in-scope subdomains. However, downstream HTTP probing and port scanning strictly drop `example.com` itself unless the apex is explicitly listed in the scope file.
- Downstream probe targets, redirected URLs, and discovered endpoints are filtered against the scope rules at every stage.

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

## Limitations

- **External Toolchain Dependencies**: reconflow is a pipeline orchestrator rather than a standalone network scanner. It delegates scanning to external Go binaries (`subfinder`, `httpx`, `dnsx`, `naabu`, `nuclei`, etc.). Missing tools result in skipped stages rather than native fallbacks.
- **Single-Node Execution**: Scanning and diffing run locally on a single machine; there is no distributed worker queue or multi-agent cluster scheduling.
- **SQLite Concurrency**: Scan states and snapshots are tracked in a local SQLite file (`output/<domain>/reconflow.db`). Running concurrent scans against the same target domain simultaneously may cause database lock contention.
- **Passive Enumeration Scope**: Subdomain discovery relies primarily on passive certificate and OSINT sources via `subfinder`; it does not perform active dictionary brute-forcing or DNS permutation scans by default.
- **WAF and Rate Throttling**: While `--rate` and `--threads` provide request pacing, scanning large targets without custom headers or low request rates can trigger upstream CDN rate limits (e.g. Cloudflare, Akamai).

---

## Contributing

The repository contains **176 automated tests** covering scope boundaries, differential comparison, and pipeline execution. Run tests and linting with:

```bash
python -m unittest discover tests -v
flake8 reconflow tests --max-line-length=100 --ignore=E203,W503,W504
```

---

## License

MIT
