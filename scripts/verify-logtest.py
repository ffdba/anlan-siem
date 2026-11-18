#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from anlan.validation import validate_rules


def parse_results(output: str) -> list[dict]:
    results, current, phase = [], {}, 0
    for line in output.splitlines():
        if "**Phase 2:" in line:
            if current:
                results.append(current)
            current, phase = {"fields": {}}, 2
        elif "**Phase 3:" in line:
            phase = 3
        match = re.match(r"^\s*([\w.]+):\s*'(.*)'\s*$", line)
        if not match:
            continue
        key, value = match.groups()
        if phase == 2:
            if key == "name":
                current["decoder"] = value
            else:
                current["fields"][key] = value
        elif phase == 3 and key in {"id", "level"}:
            current["rule_id" if key == "id" else "level"] = value
    if current:
        results.append(current)
    return results


def parse_result(output: str) -> dict:
    results = parse_results(output)
    return results[-1] if results else {}


def matches_case(case: dict, observations: list[dict]) -> bool:
    forbidden = {str(rule_id) for rule_id in case.get("forbidden_rule_ids", [])}
    if any(item.get("rule_id") in forbidden for item in observations):
        return False
    if case.get("match_scope", "last") not in {"last", "any"}:
        raise ValueError("match_scope must be last or any.")
    candidates = observations if case.get("match_scope") == "any" else observations[-1:]
    expected = case["expected"]
    return any(
        all(str(item.get(key, "")) == str(expected[key]) for key in ("rule_id", "level", "decoder"))
        and all(item.get("fields", {}).get(key) == value
                for key, value in expected.get("fields", {}).items())
        for item in candidates
    )


def case_logs(case: dict) -> list[str]:
    if not case.get("repeat"):
        return case["logs"]
    count = case["repeat"]
    if type(count) is not int or not 1 <= count <= 1000 or len(case["logs"]) != 1:
        raise ValueError("Invalid sequence repetition.")
    sources = case["source_ips"]
    if not isinstance(sources, list) or not sources or any(not isinstance(ip, str) for ip in sources):
        raise ValueError("Sequence needs explicit source IPs.")
    return [case["logs"][0].format(srcip=sources[index % len(sources)], sequence=index)
            for index in range(count)]


def main():
    parser = argparse.ArgumentParser(description="Assert expectations against an actual Wazuh logtest engine.")
    engine = parser.add_mutually_exclusive_group(required=True)
    engine.add_argument("--binary", help="Local wazuh-logtest executable path.")
    engine.add_argument("--container", help="Existing manager container name; no containers are started.")
    parser.add_argument("--cases", type=Path, default=ROOT / "tests" / "logtest-cases.json")
    parser.add_argument("-o", "--output", type=Path, default=ROOT / "output" / "logtest-results.json")
    args = parser.parse_args()
    try:
        validation = validate_rules(ROOT)
        if validation["errors"]:
            raise ValueError("Configuration validation failed: " + "; ".join(validation["errors"]))
        document = json.loads(args.cases.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or document.get("version") != 1:
            raise ValueError("Native case document must have version 1.")
        cases = document.get("cases", [])
        if not isinstance(cases, list) or not cases:
            raise ValueError("No valid native logtest cases.")
        command = [args.binary] if args.binary else [
            "docker", "exec", "-i", args.container, "/var/ossec/bin/wazuh-logtest",
        ]
        results = []
        for case in cases:
            # One process/session per case; all lines in a sequence retain correlation state.
            logs = case_logs(case)
            proc = subprocess.run(command, input="\n".join(logs) + "\n", capture_output=True,
                                  text=True, encoding="utf-8", timeout=60, check=False)
            output = proc.stdout + "\n" + proc.stderr
            observations = parse_results(output)
            observed = observations[-1] if observations else {}
            expected = case["expected"]
            matched = (proc.returncode == 0 and len(observations) == len(logs)
                       and matches_case(case, observations))
            results.append({"name": case["name"], "kind": case["kind"],
                            "passed": matched, "expected": expected, "observed": observed,
                            "forbidden_rule_ids": case.get("forbidden_rule_ids", []),
                            "expected_observations": len(logs),
                            "sequence_observations": observations,
                            "engine_returncode": proc.returncode, "engine_output": output})
            print(f"{'PASS' if matched else 'FAIL'} {case['name']}")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps({"engine": command, "cases": results}, indent=2) + "\n",
                               encoding="utf-8")
        return 0 if all(result["passed"] for result in results) else 1
    except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as exc:
        print(f"Native engine verification failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
