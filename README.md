# reconflow

Subdomain discovery and live host probing in **one command**.

`reconflow` chains [subfinder](https://github.com/projectdiscovery/subfinder) and [httpx](https://github.com/projectdiscovery/httpx) into a single workflow and writes a clean Markdown report, so you don't have to run each tool by hand and copy results between them.

> **Use responsibly.** Only scan domains you own or that are explicitly in scope for a bug bounty / pentest program you are authorized to test.

## What it does

1. Finds subdomains of a target (subfinder)
2. Probes which ones are alive and records status code, title and technologies (httpx)
3. Saves `subdomains.txt`, `live.txt` and a `report.md`

## Requirements

- Python 3.8+ (no extra Python packages needed)
- [`subfinder`](https://github.com/projectdiscovery/subfinder/releases) and [`httpx`](https://github.com/projectdiscovery/httpx/releases) (ProjectDiscovery's versions) available on your `PATH`

Check they work:

```
subfinder -version
httpx -version
```

## Install

```
git clone https://github.com/ErenYeager1836/reconflow.git
cd reconflow
```

## Usage

```
python reconflow.py -d example.com
```

| Option | Description |
| --- | --- |
| `-d`, `--domain` | Target domain (required) |
| `-o`, `--output` | Output folder (default: `output`) |
| `--threads` | Number of threads for httpx probing (default: httpx default) |
| `--timeout` | Timeout in seconds for httpx probing (default: httpx default) |

## Example output

```
[*] Finding subdomains for example.com...
[+] Found 8 subdomains
[*] Probing for live hosts...
[+] 8 hosts are alive
[+] Report saved to output\example.com\report.md
```

Files created in `output/<domain>/`:

```
subdomains.txt   all discovered subdomains
live.txt         live hosts with status code, title, tech
report.md        summary report
```

## Known limitations

- **Wildcard DNS domains** return many fake "live" hosts that all point to the same server. reconflow detects them and filters the fake hosts (use `--keep-wildcard` to disable).
- No progress display yet. Large targets can look frozen while httpx works.

## Roadmap

- [x] Wildcard DNS detection
- [ ] Live progress display
- [x] `--threads` and `--timeout` options
- [ ] Screenshots of live hosts
- [ ] JSON / HTML report output
- [ ] Save results as they come in

## Contributing

Contributions are welcome. Look for issues labelled `good first issue`.

## License

MIT
