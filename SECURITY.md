# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4.0 | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability or unexpected out-of-scope traffic generation in `reconflow`, please report it responsibly.

- **Private Reporting**: Open a private advisory report through GitHub's [Security Advisory Portal](https://github.com/ErenYeager1836/reconflow/security/advisories/new) or contact the project maintainer via email.
- **Please do not open a public issue** for potential security bugs or scope bypasses until they have been reviewed and addressed.
- When reporting, please include:
  - Reproduction steps and scope file configuration
  - Expected behavior vs. actual behavior observed
  - Operating system and toolchain versions (`reconflow doctor`)

We will acknowledge receipt within 48 hours and work on a fix or remediation promptly.

## Authorized Use Notice

`reconflow` is designed strictly for reconnaissance against infrastructure that you own or have explicit, documented authorization to test (such as approved targets in an active bug bounty program).

- Always provide an accurate scope file (`--scope`) to enforce target boundaries.
- `reconflow` refuses to target domains outside your scope file and operates under fail-closed scope semantics.
- By default, nuclei runs only informational/low-risk checks; intrusive scanning requires explicit `--intrusive` opt-in.
- Do not use this tool for unauthorized network scanning, denial of service, or harassment.
