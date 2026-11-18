from __future__ import annotations

import json
import re
from pathlib import Path


def text(value) -> str:
    return re.sub(r"([\\`*_{}\[\]()<>|#!])", r"\\\1", re.sub(r"\s+", " ", str(value)))


def render_report(report: dict) -> str:
    summary = report["summary"]
    lines = [
        "# Anlan SIEM Triage", "", f"Generated: {text(report['generated_at'])}", "",
    ]
    if report.get("demo"):
        lines += ["> SYNTHETIC DEMO. No Wazuh service was started and no real attack was executed.", ""]
    lines += [
        "## Queue Summary", "",
        f"- Unique alerts: {summary['unique_alerts']}; duplicates: {summary['duplicates']}",
        f"- Review queue: {summary['queued_alerts']} alerts in {summary['incidents']} incidents",
        f"- Locally suppressed: {summary['suppressed_alerts']}; invalid lines: {summary['invalid_lines']}",
        "", "## Incident Priority", "",
        "| Manager | Host / Agent | Actor | Category | Priority | Events | Rule IDs |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for incident in report["incidents"]:
        lines.append(
            f"| {text(incident['manager'])} "
            f"| {text(incident['agent_name'] or incident['agent_id'])} / {text(incident['agent_id'])} "
            f"| {text(incident['actor'])} | {text(incident['category'])} "
            f"| {incident['priority']} ({incident['max_rule_level']}) "
            f"| {incident['event_count']} | {text(', '.join(incident['rule_ids']))} |"
        )
    if not report["incidents"]:
        lines += ["| No queued incidents | - | - | - | - | - | - |"]
    lines += ["", "## Evidence Review", ""]
    for incident in report["incidents"]:
        lines += [
            f"### {text(incident['category'])} / {text(incident['agent_name'] or incident['agent_id'])}", "",
            f"- ID: `{incident['id']}`",
            f"- Manager / Agent: {text(incident['manager'])} / {text(incident['agent_id'])}",
            f"- Window: {text(incident['first_seen'])} to {text(incident['last_seen'])}",
            f"- Rationale: {text(incident['rationale'])}",
            f"- ATT&CK: {text(', '.join(incident['mitre']) or 'Not supplied')}",
            f"- Evidence: {text(', '.join(incident['evidence']))}",
            f"- Next action: {text(incident['next_action'])}", "",
        ]
    lines += ["## Suppression Audit", ""]
    for policy in report["policy_audit"]:
        lines += [
            f"- {text(policy['id'])}: {policy['state']}; {policy['matched_alerts']} matches; "
            f"owner {text(policy['owner'])}; ticket {text(policy['ticket'])}",
            f"  - Reason: {text(policy['reason'])}; expires {text(policy['expires_at'])}",
        ]
    if not report["policy_audit"]:
        lines += ["No suppression policies configured."]
    lines += ["", "## Limitations", "", *[f"- {text(v)}" for v in report["limitations"]], ""]
    if report["input_errors"]:
        lines += ["## Invalid Input", ""]
        lines += [f"- {text(e['evidence'])}: {text(e['error'])}" for e in report["input_errors"]]
    return "\n".join(lines) + "\n"


def write_report(report: dict, directory: str | Path) -> dict[str, Path]:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    paths = {"json": directory / "incidents.json", "markdown": directory / "triage.md"}
    paths["json"].write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    paths["markdown"].write_text(render_report(report), encoding="utf-8")
    return paths
