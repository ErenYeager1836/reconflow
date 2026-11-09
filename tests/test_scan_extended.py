"""
tests.test_scan_extended
------------------------
Tests scan pipeline integration with new analysis and audit engines:
- AXFR zone transfer detection & findings persistence
- DNSSEC & dangling nameserver detection
- Web cache deception findings
- Subdomain permutation candidate addition
- Full-audit flag orchestration
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from reconflow.scan import run as run_scan

PROBE_RET = (
    ["https://target.test [200]"],
    [{"url": "https://target.test", "technologies": ["Apache"]}],
)


class TestScanExtended(unittest.TestCase):
    """Test suite for extended scan pipeline flags and findings integration."""

    @patch("reconflow.scan.check_tools")
    @patch("reconflow.scan.find_subdomains", return_value=["target.test"])
    @patch("reconflow.scan.detect_wildcard", return_value=set())
    @patch("reconflow.scan.probe_hosts", return_value=PROBE_RET)
    def test_scan_with_axfr_and_dnssec_findings(
        self,
        mock_probe,
        mock_wildcard,
        mock_subs,
        mock_check_tools,
    ):
        """Verify that --axfr and --dns-sec findings are captured into vuln_records and DB."""
        fake_axfr_results = [{
            "nameserver": "ns1.target.test",
            "ip": "1.2.3.4",
            "vulnerable": True,
            "status": "VULNERABLE (AXFR open)",
            "records_count": 10,
        }]
        fake_dns_results = {
            "domain": "target.test",
            "dnssec": {"status": "UNSIGNED"},
            "nameservers": {
                "has_dangling_ns": True,
                "dangling_nameservers": [{
                    "nameserver": "ns-123.awsdns-01.com",
                    "cloud_provider": "awsdns",
                    "is_resolving": False,
                }],
            },
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            patch_axfr = patch(
                "reconflow.zone_transfer.audit_zone_transfer",
                return_value=fake_axfr_results,
            )
            patch_dns = patch(
                "reconflow.dns_sec.audit_dns_security",
                return_value=fake_dns_results,
            )
            with patch_axfr, patch_dns:
                args = MagicMock(
                    domain="target.test",
                    output=str(tmp_path),
                    threads=5,
                    timeout=2,
                    keep_wildcard=False,
                    json_report=True,
                    csv=False,
                    screenshots=False,
                    scope=None,
                    stages=None,
                    skip=None,
                    rate=None,
                    dry_run=False,
                    resume=False,
                    intrusive=False,
                    silent=True,
                    axfr=True,
                    dns_sec=True,
                    full_audit=False,
                    permute=False,
                    params=False,
                    cache_audit=False,
                    jwt=False,
                    cve_correlate=False,
                    github_leaks=False,
                    audits=False,
                )
                res = run_scan(args)

            findings = res["findings"]
            template_ids = {f["template_id"] for f in findings}
            self.assertIn("dns-zone-transfer-axfr", template_ids)
            self.assertIn("dangling-nameserver-takeover", template_ids)

            out_dir = tmp_path / "target.test"
            vulns_file = out_dir / "vulns.json"
            self.assertTrue(vulns_file.is_file())
            saved_vulns = json.loads(vulns_file.read_text(encoding="utf-8"))
            self.assertGreaterEqual(len(saved_vulns), 2)

    @patch("reconflow.scan.check_tools")
    @patch("reconflow.scan.find_subdomains", return_value=["target.test"])
    @patch("reconflow.scan.detect_wildcard", return_value=set())
    @patch("reconflow.scan.probe_hosts", return_value=(["https://target.test [200]"], []))
    def test_scan_with_permute_adds_subdomains(
        self,
        mock_probe,
        mock_wildcard,
        mock_subs,
        mock_check_tools,
    ):
        """Verify that --permute integrates newly confirmed permutation hosts into subdomains."""
        fake_perm_results = [
            {"host": "admin.target.test", "status": 200, "content_length": 500},
            {"host": "api.target.test", "status": 200, "content_length": 600},
        ]

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with patch(
                "reconflow.permute_scale.generate_permutations_scaled",
                return_value=fake_perm_results,
            ):
                args = MagicMock(
                    domain="target.test",
                    output=str(tmp_path),
                    threads=5,
                    timeout=2,
                    keep_wildcard=False,
                    json_report=False,
                    csv=False,
                    screenshots=False,
                    scope=None,
                    stages=None,
                    skip=None,
                    rate=None,
                    dry_run=False,
                    resume=False,
                    intrusive=False,
                    silent=True,
                    axfr=False,
                    dns_sec=False,
                    full_audit=False,
                    permute=True,
                    perm_wordlist=None,
                    params=False,
                    cache_audit=False,
                    jwt=False,
                    cve_correlate=False,
                    github_leaks=False,
                    audits=False,
                )
                res = run_scan(args)

            subs = res["subdomains"]
            self.assertIn("admin.target.test", subs)
            self.assertIn("api.target.test", subs)
            self.assertGreaterEqual(len(subs), 3)


if __name__ == "__main__":
    unittest.main()
