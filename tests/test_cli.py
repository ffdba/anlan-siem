from __future__ import annotations

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from anlan.__main__ import main
from anlan.reporting import write_report
from anlan.triage import build_report, load_alerts, parse_time

ROOT = Path(__file__).resolve().parents[1]


class CLITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def test_demo_never_starts_processes_or_network_services(self):
        with patch("sys.argv", ["anlan", "demo", "-o", str(self.directory)]), \
             patch("subprocess.run", side_effect=AssertionError("No external tools")), \
             patch("socket.create_connection", side_effect=AssertionError("No network")), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(), 0)
        report = json.loads((self.directory / "incidents.json").read_text(encoding="utf-8"))
        self.assertTrue(report["demo"])
        self.assertEqual(report["summary"]["incidents"], 5)
        self.assertIn("SYNTHETIC DEMO", (self.directory / "triage.md").read_text(encoding="utf-8"))

    def test_triage_cli_exports_existing_alerts_without_tools(self):
        with patch("sys.argv", ["anlan", "triage", str(ROOT / "examples" / "alerts.jsonl"),
                               "--now", "2026-11-19T09:20:00+08:00", "-o", str(self.directory)]), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(), 0)
        report = json.loads((self.directory / "incidents.json").read_text(encoding="utf-8"))
        self.assertFalse(report["demo"])
        self.assertEqual(report["summary"]["suppressed_alerts"], 0)

    def test_validation_cli_returns_status_and_saves_inventory(self):
        output = self.directory / "validation.json"
        with patch("sys.argv", ["anlan", "validate", "-o", str(output)]), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(), 0)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8"))["summary"]["rules"], 34)

    def test_report_escapes_untrusted_metadata(self):
        alerts, _ = load_alerts(ROOT / "examples" / "alerts.jsonl")
        report = build_report(alerts, now=parse_time("2026-11-19T09:20:00+08:00"))
        report["incidents"][0]["agent_name"] = '<script>alert(1)</script> | [bad](javascript:x)'
        paths = write_report(report, self.directory / "nested")
        markdown = paths["markdown"].read_text(encoding="utf-8")
        self.assertNotIn("<script>", markdown)
        self.assertNotIn("[bad](javascript:x)", markdown)
        self.assertTrue(paths["json"].exists())

    def test_cli_handles_legacy_console_encoding(self):
        result = subprocess.run(
            [sys.executable, "-S", "-m", "anlan", "validate"],
            cwd=ROOT, env={**os.environ, "PYTHONIOENCODING": "cp1252"},
            capture_output=True, text=True, encoding="utf-8", timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "pass")


if __name__ == "__main__":
    unittest.main()
