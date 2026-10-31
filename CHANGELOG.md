# Changelog

All notable changes to `reconflow` will be documented in this file.

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
  - SARIF v2.1.0 exporter (`report.sarif`) for GitHub Code Scanning and IDE integration.
  - Concise webhook alert digests in `reconflow/notify.py` emitting summarized changes to Discord and Slack.

## [0.3.0] - 2026-10-28
- Subdomain discovery and live host probing pipeline.
- Wildcard DNS detection and filtering.
- Differential change detection (`reconflow diff`) with lead hints.
- Triage state tracking (`reconflow mark`).
- Scope verification (`reconflow scope`).
- Markdown, CSV, and JSON report generation.
