# Demo Plan: Differential Recon on an Owned Domain

This guide outlines the reproducible steps to demonstrate `reconflow`'s differential change detection against a live target domain that you own.

## Prerequisites
1. A domain you own (e.g. `<yourdomain>`) with DNS hosted on a provider such as Cloudflare.
2. An initial web page configured on `www.<yourdomain>` (e.g. a free GitHub Pages site or simple HTTP server).

---

## Step 1: Baseline Scan
Create a scope file containing only your authorized target domain:
```bash
cat << 'EOF' > scope.txt
<yourdomain>
*.${yourdomain}
EOF
```

Run an initial baseline scan covering passive discovery, DNS resolution, and HTTP probing:
```bash
reconflow scan <yourdomain> --scope scope.txt --stages subdomains,dns,http
```
This stores the initial baseline target state in SQLite (`output/<yourdomain>/reconflow.db`).

---

## Step 2: Introduce an Observable Change
Introduce a genuine, observable change on your target:
- **Option A (New Subdomain)**: Add a new DNS A/CNAME record `staging.<yourdomain>` pointing to a test web page titled "Staging Portal". Wait for DNS to propagate. (If passive OSINT via subfinder takes time to index the new hostname, use `--stages dns,http` with the target directly or Option B).
- **Option B (Changed Status / Title)**: Modify an existing web endpoint (e.g., change HTTP response status from 403 to 200, or update the `<title>` tag to "Admin Console").
- **Option C (New Open Port)**: Open a test port (e.g., port 8443) on an in-scope host you control.

---

## Step 3: Run Second Scan & Differential Inspection
Run the scan again to capture the updated state:
```bash
reconflow scan <yourdomain> --scope scope.txt --stages subdomains,dns,http
```

Execute differential comparison:
```bash
reconflow diff <yourdomain>
```
`reconflow diff` compares the two runs, highlights what changed, and exits with code `1` when changes are detected.

---

## Step 4: Record Demo
Record the terminal session using `asciinema` or a terminal GIF recorder (e.g. `vhs`, `agg`), keeping the overall demo under 30 seconds.
Paste the verified raw terminal output into the README's **Example output** section.
