# reconflow Roadmap

This document outlines upcoming planned capabilities and improvements for `reconflow`.

## Planned Features

- [ ] **Custom HTTP Headers & User-Agent Pacing**: Allow setting custom authorization tokens, program identifier headers (e.g. `X-BugBounty-Hunter`), and randomized User-Agents directly in `reconflow.toml`.
- [ ] **Remote Snapshot Sync**: Optional S3/GCS sync command to push and pull `output/<domain>/reconflow.db` snapshots across machines for distributed hunters.
- [ ] **DNS Permutation & Alteration Support**: Native stage plugin for DNS word permutation (`altdns`/`shuffledns`) with strict in-scope filtering.
- [ ] **Automated Container Builds**: GitHub Actions workflow to build and push multi-arch Docker images to GitHub Container Registry (`ghcr.io/erenyeager1836/reconflow`) on version tags.
- [ ] **Custom Webhook Payload Templating**: Configurable Jinja-style notification templates for Slack and Discord alerts.
