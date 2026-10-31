"""Unit tests for pipeline stage resolution and orchestrator execution."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reconflow.pipeline import (
    CANONICAL_STAGES,
    Pipeline,
    normalize_stage_name,
    resolve_stages,
)


class TestPipelineResolution(unittest.TestCase):
    """Test resolution of active pipeline stages and flag parsing."""

    def test_default_stages(self):
        stages = resolve_stages()
        self.assertEqual(stages, CANONICAL_STAGES)

    def test_stages_flag_selection(self):
        stages = resolve_stages(stages_arg="subdomains,http,vulns")
        self.assertEqual(stages, ["subdomains", "http", "vulns"])

    def test_stages_preserves_canonical_order(self):
        # Order passed is vulns, then subdomains; should resolve in canonical pipeline order
        stages = resolve_stages(stages_arg="vulns,subdomains")
        self.assertEqual(stages, ["subdomains", "vulns"])

    def test_skip_flag_exclusion(self):
        stages = resolve_stages(skip_arg="ports,vulns")
        self.assertEqual(stages, ["subdomains", "dns", "http", "urls"])

    def test_stages_and_skip_combination(self):
        stages = resolve_stages(
            stages_arg="subdomains,dns,http,urls",
            skip_arg="dns",
        )
        self.assertEqual(stages, ["subdomains", "http", "urls"])

    def test_stage_aliases(self):
        self.assertEqual(normalize_stage_name("subdomain_enum"), "subdomains")
        self.assertEqual(normalize_stage_name("subfinder"), "subdomains")
        self.assertEqual(normalize_stage_name("dns_resolve"), "dns")
        self.assertEqual(normalize_stage_name("dnsx"), "dns")
        self.assertEqual(normalize_stage_name("http_probe"), "http")
        self.assertEqual(normalize_stage_name("httpx"), "http")
        self.assertEqual(normalize_stage_name("url_collection"), "urls")
        self.assertEqual(normalize_stage_name("katana"), "urls")
        self.assertEqual(normalize_stage_name("port_scan"), "ports")
        self.assertEqual(normalize_stage_name("naabu"), "ports")
        self.assertEqual(normalize_stage_name("vuln_scan"), "vulns")
        self.assertEqual(normalize_stage_name("nuclei"), "vulns")

    def test_invalid_stage_raises_error(self):
        with self.assertRaises(ValueError) as cm:
            resolve_stages(stages_arg="subdomains,invalid_xyz")
        self.assertIn("Unknown stage", str(cm.exception))


class TestPipelineOrchestration(unittest.TestCase):
    """Test pipeline run and missing tool handling."""

    def test_missing_tool_skips_gracefully(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            pipeline = Pipeline(
                domain="example.com",
                output_dir=out_dir,
                stages=["ports"],
                silent=True,
            )
            # Patch naabu is_installed to False
            with patch("reconflow.plugins.NaabuPlugin.is_installed", return_value=False):
                ctx = pipeline.run()
                self.assertEqual(ctx.stage_status["ports"], "skipped_tools_missing")
                self.assertEqual(ctx.ports, [])

    def test_pipeline_run_with_mocked_plugins(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir)
            pipeline = Pipeline(
                domain="example.com",
                output_dir=out_dir,
                stages=["subdomains"],
                silent=True,
            )
            with patch("reconflow.plugins.SubfinderPlugin.is_installed", return_value=True), \
                 patch("reconflow.plugins.SubfinderPlugin.run_command_safe",
                       return_value=(0, "sub.example.com\n", "")):
                ctx = pipeline.run()
                self.assertEqual(ctx.stage_status["subdomains"], "completed")
                self.assertIn("sub.example.com", ctx.subdomains)
                self.assertTrue((out_dir / "subdomains.txt").exists())


if __name__ == "__main__":
    unittest.main()
