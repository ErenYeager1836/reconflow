# Changelog

All notable changes to `reconflow` will be documented in this file.

## [0.5.0] - 2026-11-09

### Added
- **Wave 1: Web & API Intelligence Modules**:
  - `reconflow/jwt_analyzer.py`: Decode and audit JSON Web Tokens for `alg: none` signature evasion, missing expiration claims, and dictionary cracking against weak HMAC secrets.
  - `reconflow/params_analyzer.py`: Categorize URL query parameters for high-impact vulnerability surfaces (SSRF, IDOR, LFI/RFI, SQLi, and administrative privilege escalation).
  - `reconflow/cache_audit.py`: Web Cache Deception detection, CDN cacheability header analysis (`CF-Cache-Status`, `X-Cache`), and unkeyed header reflection audits.
- **Wave 2: DNS & Discovery Expansion Modules**:
  - `reconflow/zone_transfer.py`: RFC 1035 / RFC 5936 raw TCP socket AXFR query builder and response parser, with DoH authoritative nameserver discovery.
  - `reconflow/permute_scale.py`: Scaled subdomain permutation engine with SecLists wordlist support and `(status, content_length)` fingerprint clustering to eliminate wildcard DNS false positives.
  - `reconflow/dns_sec.py`: RFC 8484 DoH query engine for DNSSEC validation (DS/DNSKEY records), RFC 6844 CAA policy extraction, and dangling cloud nameserver detection (AWS Route53, Azure DNS, NS1).
- **Wave 3: Vulnerability & External OSINT Modules**:
  - `reconflow/cve_correlate.py`: Correlate detected web server and framework technologies against NVD CVE API v2.0 with rate limit throttling.
  - `reconflow/github_leaks.py`: Authenticated public GitHub code search for leaked credentials, API keys, and `.env` files referencing the target domain.
  - `reconflow/audits.py`: 15 built-in zero-dependency defensive audits:
    - Cloud asset bucket discovery across AWS S3, GCP Storage, Azure Blob, and DigitalOcean Spaces.
    - ASN & IP range mapping via RDAP.
    - CORS misconfiguration auditing (`null` origin, unvalidated reflections).
    - Dangling CNAME takeover verification.
    - crt.sh Certificate Transparency sub-issuer and SAN harvesting.
    - Exposed sensitive files and dev artifacts (`/.git/HEAD`, `/.env`, `/.DS_Store`).
    - Web Application Firewall (WAF) and reverse-proxy fingerprinting.
    - Crawl route harvesting (`/robots.txt`, `/sitemap.xml`).
    - Email security & anti-spoofing audit (SPF and DMARC enforcement).
    - SSL/TLS certificate security, cipher suite checks, and expiry warnings.
    - Favicon MD5/MurmurHash framework identification.
    - RFC 9116 `security.txt` discovery and disclosure policy verification.
    - Defensive HTTP security headers grading (A+ to F).
- **Scan CLI Integration & Findings Persistence**:
  - New scan flags: `--jwt`, `--params`, `--cache-audit`, `--axfr`, `--permute`, `--perm-wordlist`, `--dns-sec`, `--cve-correlate`, `--github-leaks`, `--github-token`, `--audits`, and convenience flag `--full-audit`.
  - Audits automatically record structured vulnerability findings into SQLite `reconflow.db` (`findings` table), `vulns.json`, and scan reports, participating in `reconflow diff` comparisons.
  - Shell completion scripts updated for Bash and Zsh (`tests/test_completions.py`).
  - Test suite expanded to 212 tests across unit, integration, and security audit suites.

## [0.4.2] - 2026-11-08

### Added
- **Upfront Target Scope Gate**:
  - `reconflow scan <domain> --scope scope.txt` validates the target domain upfront and refuses to scan if out of scope, exiting with code 1 without spawning subprocesses or initiating network calls.
  - Added dedicated scope matching tests for apex vs. wildcard boundaries, CIDR blocks, lookalike domain isolation (e.g., `notexample.com`), and precedence of exclusions.
  - Test suite expanded to 176 automated tests.

### Changed
- **Python Support**: Dropped end-of-life Python 3.9; set minimum runtime requirement to `requires-python >= 3.10`.
- **CI Modernization**: Returned GitHub Actions runners from `ubuntu-22.04` to `ubuntu-latest` testing Python 3.10, 3.11, 3.12, and 3.13.

## [0.4.1] - 2026-10-31

### Fixed
- **Resolved `httpx` Name Collision**:
  - Implemented multi-candidate binary resolution searching PATH, `RECONFLOW_HTTPX`, `reconflow.toml`, and common installation paths (`~/go/bin`, `$GOPATH/bin`, `C:\\Tools\\recon`).
  - Added `-version` identity verification checking for `"projectdiscovery"` or `"Current Version"` to prevent Python's `httpx` CLI from shadowing ProjectDiscovery's binary.
  - Added clear diagnostic warning in `reconflow doctor` and scans when only the clashing Python `httpx` CLI is detected.
  - Applied identity verification across ProjectDiscovery toolchain (`subfinder`, `dnsx`, `httpx`, `katana`, `naabu`, `nuclei`) and `gau`.
  - Enhanced `--dry-run` to display verified binary paths and detected version numbers.

## [0.4.0] - 2026-10-31

### Added
- **Stage-based Pipeline & Tool Plugins**:
  - Modular plugin architecture supporting standard external hunter binaries: `subfinder`, `dnsx`, `httpx`, `naabu`, `katana`, `gau`, `waybackurls`, `nuclei`.
  - Canonical execution pipeline: `subdomains -> dns -> http -> urls -> ports -> vulns`.
  - Fine-grained stage filtering via `--stages` and `--skip`.
  - `reconflow doctor` subcommand inspecting toolchain availability, versions, paths, and installation hints.
- **Safety, Strict Scope Gates & Politeness**:
  - Universal scope gate enforcing program boundaries across all stages. Out-of-scope targets are dropped before invoking external binaries.
  - Polite rate-limiting (`--rate <req/sec>`) and concurrency limits (`--threads <n>`).
  - Safe vulnerability scanning defaults: Nuclei executes safe informational/low checks by default; aggressive templates require `--intrusive` or `--all-vulns` with high-visibility warnings.
  - `--dry-run` mode displaying pipeline execution plan and exact shell commands without network activity or subprocess execution.
- **State Storage, Resume & Extended Diffing**:
  - Target SQLite database (`output/<domain>/reconflow.db`) tracking runs, subdomains, DNS, live hosts, endpoints, open ports, and findings.
  - Incremental scan resumption via `reconflow scan --resume`, skipping already completed stages on interrupted scans.
  - Extended differential tracking in `reconflow diff`: detecting new open ports, new endpoints/URLs, and deduplicated vulnerability findings.
- **Analysis & Heuristics**:
  - Subdomain takeover detection (`reconflow/takeover.py`) matching CNAME fingerprints and service signatures (GitHub Pages, AWS S3, Heroku, Azure, Shopify, Fastly, Pantheon, Ghost, etc.), conservatively flagged as `"candidate, verify manually"`.
  - JavaScript and endpoint mining (`reconflow/mining.py`) extracting endpoints, discovered subdomains, and exposed secrets with **strictly masked previews only** (e.g., `AKIA****************`).
  - Actionable lead scoring (`reconflow/leads.py`) prioritizing high-value administrative, documentation, debug, and credential interfaces.
- **Configuration, Reporting & Webhooks**:
  - Configuration support via `reconflow.toml` (`./reconflow.toml` and `~/.config/reconflow/reconflow.toml`).
  - Multiple report formats via `reconflow report --format md|csv|json|sarif`.
  - Export scan results to CSV format via `--csv` and `report --format csv` (closes #15).
  - Pipe-safe execution with `--silent` / `--quiet` / `-q` suppressing headers and diagnostic logs (closes #14).
  - Native Bash and Zsh shell auto-completion scripts in `scripts/completions/` (closes #16).
  - SARIF v2.1.0 exporter (`report.sarif`) for GitHub Code Scanning and IDE integration.
  - Concise webhook alert digests in `reconflow/notify.py` emitting summarized changes to Discord and Slack (closes #13).

## [0.3.0] - 2026-10-28
- Subdomain discovery and live host probing pipeline.
- Wildcard DNS detection and filtering.
- Differential change detection (`reconflow diff`) with lead hints.
- Triage state tracking (`reconflow mark`).
- Scope verification (`reconflow scope`).
- Markdown, CSV, and JSON report generation.
