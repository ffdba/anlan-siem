from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path


def stable_id(kind: str, *parts) -> str:
    value = json.dumps(parts, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return f"{kind}-{hashlib.sha256(value.encode()).hexdigest()[:20]}"


def parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("Timestamp must be an ISO-8601 string.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("Invalid ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a timezone.")
    return parsed.astimezone(timezone.utc)


def _string(value, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string.")
    return value


def _strings(value, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be a list of strings.")
    return value


@dataclass(frozen=True)
class Alert:
    id: str
    timestamp: datetime
    manager: str
    agent_id: str
    agent_name: str
    rule_id: str
    level: int
    description: str
    source_ip: str
    user: str
    url: str
    groups: tuple[str, ...]
    mitre: tuple[str, ...]
    evidence: str

    def to_dict(self) -> dict:
        row = asdict(self)
        row["timestamp"] = self.timestamp.isoformat()
        return row


def normalize_alert(row: dict, evidence: str = "") -> Alert:
    if not isinstance(row, dict):
        raise ValueError("Alert must be an object.")
    for key in ("rule", "agent", "manager", "data"):
        if not isinstance(row.get(key, {}), dict):
            raise ValueError(f"{key} must be an object.")
    rule, agent, data = row.get("rule", {}), row.get("agent", {}), row.get("data", {})
    rule_id = rule.get("id")
    if not isinstance(rule_id, (str, int)) or isinstance(rule_id, bool) or not str(rule_id).isdigit():
        raise ValueError("rule.id must be a numeric identifier.")
    level = rule.get("level")
    if type(level) is not int or not 0 <= level <= 15:
        raise ValueError("rule.level must be an integer between 0 and 15.")
    timestamp = parse_time(row.get("timestamp"))
    agent_id = _string(agent.get("id", ""), "agent.id")
    if not agent_id:
        raise ValueError("agent.id is required to isolate monitored hosts.")
    manager = _string(row.get("manager", {}).get("name", ""), "manager.name")
    if not manager:
        raise ValueError("manager.name is required to isolate Wazuh deployments.")
    source = _string(data.get("srcip", ""), "data.srcip")
    if source:
        try:
            source = ipaddress.ip_address(source).compressed
        except ValueError as exc:
            raise ValueError("data.srcip must be an IP address.") from exc
    groups = tuple(sorted(set(_strings(rule.get("groups", []), "rule.groups"))))
    mitre = rule.get("mitre", {})
    if not isinstance(mitre, dict):
        raise ValueError("rule.mitre must be an object.")
    techniques = tuple(sorted(set(_strings(mitre.get("id", []), "rule.mitre.id"))))
    user = _string(data.get("dstuser") or data.get("srcuser") or "", "user")
    url = _string(data.get("url", ""), "data.url")
    description = _string(rule.get("description", ""), "rule.description")
    agent_name = _string(agent.get("name", ""), "agent.name")
    native_id = row.get("id", "")
    if not isinstance(native_id, (str, int)) or isinstance(native_id, bool):
        raise ValueError("Alert id must be a string or integer.")
    if native_id:
        event_id = stable_id("event", manager, agent_id, str(native_id))
    else:
        event_id = stable_id("event", manager, agent_id, timestamp.isoformat(), str(rule_id),
                             level, source, user, url, groups, techniques, description)
    return Alert(event_id, timestamp, manager, agent_id, agent_name, str(rule_id), level,
                 description, source, user, url, groups, techniques, evidence)


def load_alerts(path: str | Path, *, skip_invalid: bool = False) -> tuple[list[Alert], list[dict]]:
    path = Path(path)
    alerts, errors = [], []
    with path.open(encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            evidence = f"{path.name}#L{line_number}"
            try:
                alerts.append(normalize_alert(json.loads(line), evidence))
            except (ValueError, TypeError) as exc:
                if not skip_invalid:
                    raise ValueError(f"{evidence}: {exc}") from exc
                errors.append({"evidence": evidence, "error": str(exc)})
    return alerts, errors


def load_policies(path: str | Path | None) -> list[dict]:
    if path is None:
        return []
    document = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(document, dict) or document.get("version") != 1:
        raise ValueError("Policy document must have version 1.")
    policies = document.get("suppressions", [])
    validate_policies(policies)
    return policies


def validate_policies(policies: list[dict]):
    if not isinstance(policies, list):
        raise ValueError("suppressions must be a list.")
    seen = set()
    for policy in policies:
        if not isinstance(policy, dict):
            raise ValueError("Suppression must be an object.")
        for field in ("id", "reason", "owner", "ticket"):
            if not _string(policy.get(field), field).strip():
                raise ValueError(f"Suppression {field} cannot be empty.")
        if policy["id"] in seen:
            raise ValueError("Suppression IDs must be unique.")
        seen.add(policy["id"])
        for field in ("rule_ids", "manager_names", "agent_ids", "source_cidrs"):
            values = _strings(policy.get(field), field)
            if not values or any(not value.strip() for value in values):
                raise ValueError(f"Suppression {field} must be nonempty and explicit.")
        if any(not value.isdigit() for value in policy["rule_ids"]):
            raise ValueError("Suppression rule_ids must be numeric.")
        if "*" in policy["agent_ids"] or "*" in policy["manager_names"]:
            raise ValueError("Wildcard manager or agent scope is not permitted.")
        for network in policy["source_cidrs"]:
            if ipaddress.ip_network(network).prefixlen == 0:
                raise ValueError("Catch-all networks are not permitted.")
        start, end = parse_time(policy.get("starts_at")), parse_time(policy.get("expires_at"))
        if not start < end or end - start > timedelta(days=30):
            raise ValueError("Suppression duration must be positive and at most 30 days.")


def category(alert: Alert) -> str:
    groups = set(alert.groups)
    for name in ("sql_injection", "xss", "path_traversal", "command_injection",
                 "file_upload", "rfi", "lfi", "brute_force", "account_creation",
                 "time_anomaly", "privileged_access", "reconnaissance"):
        if name in groups:
            return name
    return f"rule_{alert.rule_id}"


def priority(level: int) -> str:
    if level >= 14:
        return "critical"
    if level >= 11:
        return "high"
    if level >= 7:
        return "medium"
    return "low"


def build_report(alerts: list[Alert], *, policies: list[dict] | None = None,
                 window_seconds: int = 300, now: datetime | None = None,
                 input_errors: list[dict] | None = None) -> dict:
    if type(window_seconds) is not int or not 1 <= window_seconds <= 86400:
        raise ValueError("Incident window must be between 1 and 86400 seconds.")
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("Evaluation clock must include a timezone.")
    now = now.astimezone(timezone.utc)
    policies = [] if policies is None else policies
    validate_policies(policies)
    unique, evidence = {}, {}
    for alert in alerts:
        if alert.id in unique:
            previous = unique[alert.id].to_dict()
            current = alert.to_dict()
            previous.pop("evidence")
            current.pop("evidence")
            if previous != current:
                raise ValueError(f"Conflicting observations for alert identity {alert.id}.")
        else:
            unique[alert.id] = alert
        evidence.setdefault(alert.id, [])
        if alert.evidence and alert.evidence not in evidence[alert.id]:
            evidence[alert.id].append(alert.evidence)
    for refs in evidence.values():
        refs.sort()

    policy_states = []
    active_policies = []
    for policy in policies:
        start, end = parse_time(policy["starts_at"]), parse_time(policy["expires_at"])
        state = "expired" if now >= end else "pending" if now < start else "active"
        policy_states.append({**policy, "state": state, "matched_alerts": 0})
        if state == "active":
            active_policies.append((policy_states[-1],
                                    [ipaddress.ip_network(n) for n in policy["source_cidrs"]]))

    suppressed, candidates = [], []
    for alert in sorted(unique.values(), key=lambda a: (a.timestamp, a.id)):
        matches = []
        for policy, networks in active_policies:
            if (alert.rule_id in policy["rule_ids"] and alert.manager in policy["manager_names"]
                    and alert.agent_id in policy["agent_ids"]
                    and parse_time(policy["starts_at"]) <= alert.timestamp < parse_time(policy["expires_at"])
                    and alert.source_ip and any(ipaddress.ip_address(alert.source_ip) in n for n in networks)):
                policy["matched_alerts"] += 1
                matches.append(policy["id"])
        if matches:
            suppressed.append({"event_id": alert.id, "rule_id": alert.rule_id, "manager": alert.manager,
                               "timestamp": alert.timestamp.isoformat(),
                               "agent_id": alert.agent_id, "source_ip": alert.source_ip,
                               "policy_ids": matches, "evidence": evidence[alert.id]})
        else:
            candidates.append(alert)

    buckets: dict[tuple, list[list[Alert]]] = {}
    for alert in candidates:
        # Missing source identities are isolated rather than grouped as one "unknown" actor.
        actor = alert.source_ip or (f"user:{alert.user}" if alert.user else alert.id)
        key = (alert.manager, alert.agent_id, actor, category(alert))
        windows = buckets.setdefault(key, [])
        if not windows or (alert.timestamp - windows[-1][0].timestamp).total_seconds() >= window_seconds:
            windows.append([])
        windows[-1].append(alert)

    incidents = []
    for (manager, agent_id, actor, family), windows in buckets.items():
        for events in windows:
            first, last = events[0], events[-1]
            level = max(e.level for e in events)
            techniques = sorted({t for e in events for t in e.mitre})
            incidents.append({
                "id": stable_id("incident", manager, agent_id, actor, family, first.id),
                "category": family, "manager": manager, "agent_id": agent_id,
                "agent_name": first.agent_name, "actor": actor,
                "first_seen": first.timestamp.isoformat(), "last_seen": last.timestamp.isoformat(),
                "event_count": len(events), "max_rule_level": level, "priority": priority(level),
                "rule_ids": sorted({e.rule_id for e in events}),
                "users": sorted({e.user for e in events if e.user}),
                "mitre": techniques, "event_ids": [e.id for e in events],
                "evidence": [ref for e in events for ref in evidence[e.id]],
                "rationale": f"{len(events)} unique {'event' if len(events) == 1 else 'events'} "
                             f"on one monitored host within a "
                             f"{window_seconds}-second anchored window; highest rule level is {level}.",
                "next_action": "Review source evidence and authorized activity; an alert does not prove compromise.",
            })
    incidents.sort(key=lambda i: (-i["max_rule_level"], -i["event_count"], i["id"]))
    errors = input_errors or []
    return {
        "schema_version": "1.0", "generated_at": now.isoformat(),
        "window_seconds": window_seconds,
        "summary": {
            "input_alerts": len(alerts), "unique_alerts": len(unique),
            "duplicates": len(alerts) - len(unique), "invalid_lines": len(errors),
            "suppressed_alerts": len(suppressed), "queued_alerts": len(candidates),
            "incidents": len(incidents),
        },
        "incidents": incidents, "suppressed": suppressed, "policy_audit": policy_states,
        "events": [
            {**alert.to_dict(), "evidence": evidence[alert.id]}
            for alert in sorted(unique.values(), key=lambda a: (a.timestamp, a.id))
        ],
        "input_errors": errors,
        "limitations": [
            "This is offline triage of supplied Wazuh alerts, not a replacement detection engine.",
            "Priority derives from Wazuh rule levels, not confirmed exploitation or business impact.",
            "Suppression only changes this local review queue; source logs and Wazuh alerts are not deleted.",
            "Anchored windows use event timestamps; incident IDs can change when earlier evidence is added.",
            "No alerts or ATT&CK mappings do not demonstrate detection coverage or absence of attacks.",
            "URL and user metadata may be sensitive even though full_log and secret payloads are omitted.",
        ],
    }
