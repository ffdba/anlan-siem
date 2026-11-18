from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from anlan.reporting import write_report
from anlan.triage import build_report, load_alerts, load_policies, parse_time
from anlan.validation import validate_rules

ROOT = Path(__file__).resolve().parents[1]


def main():
    # Redirected Windows streams may use a legacy code page despite UTF-8 input.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Anlan detection configuration and offline Wazuh triage.")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate", help="Validate XML and project contracts, without starting Wazuh.")
    validate.add_argument("--root", type=Path, default=ROOT)
    validate.add_argument("-o", "--output", type=Path)
    demo = commands.add_parser("demo", help="Replay synthetic Wazuh alerts locally.")
    demo.add_argument("-o", "--output-dir", type=Path, default=Path("output/demo"))
    triage = commands.add_parser("triage", help="Build a local incident queue from Wazuh alerts JSONL.")
    triage.add_argument("input", type=Path)
    triage.add_argument("--policies", type=Path)
    triage.add_argument("--window", type=int, default=300)
    triage.add_argument("--now", help="Explicit timezone-aware evaluation clock for reproducible replay.")
    triage.add_argument("--skip-invalid", action="store_true", help="Record invalid lines rather than stop.")
    triage.add_argument("-o", "--output-dir", type=Path, default=Path("output/triage"))
    args = parser.parse_args()
    try:
        if args.command == "validate":
            result = validate_rules(args.root)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            return 0 if result["status"] == "pass" else 1
        is_demo = args.command == "demo"
        source = ROOT / "examples" / "alerts.jsonl" if is_demo else args.input
        policy_path = ROOT / "config" / "demo-policies.json" if is_demo else args.policies
        alerts, errors = load_alerts(source, skip_invalid=False if is_demo else args.skip_invalid)
        now = parse_time("2026-11-19T09:20:00+08:00") if is_demo else (
            parse_time(args.now) if args.now else datetime.now(timezone.utc)
        )
        report = build_report(alerts, policies=load_policies(policy_path),
                              window_seconds=300 if is_demo else args.window, now=now, input_errors=errors)
        report["demo"] = is_demo
        paths = write_report(report, args.output_dir)
        print(json.dumps(report["summary"], ensure_ascii=False))
        for kind, path in paths.items():
            print(f"{kind}: {path.resolve()}")
        return 0
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
