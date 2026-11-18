from __future__ import annotations

import copy
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from anlan.triage import build_report, load_alerts, load_policies, normalize_alert, parse_time

ROOT = Path(__file__).resolve().parents[1]
CLOCK = parse_time("2026-11-19T09:20:00+08:00")


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.alerts, _ = load_alerts(ROOT / "examples" / "alerts.jsonl")
        self.policies = load_policies(ROOT / "config" / "demo-policies.json")

    def test_demo_deduplicates_and_groups_without_losing_evidence(self):
        report = build_report(self.alerts, policies=self.policies, now=CLOCK)
        self.assertEqual(report["summary"], {
            "input_alerts": 10, "unique_alerts": 9, "duplicates": 1, "invalid_lines": 0,
            "suppressed_alerts": 1, "queued_alerts": 8, "incidents": 5,
        })
        incident = next(i for i in report["incidents"] if i["event_count"] == 3)
        self.assertEqual(incident["rule_ids"], ["100001", "100002", "100003"])
        self.assertEqual(len(incident["evidence"]), 4)
        self.assertEqual(incident["priority"], "high")
        self.assertEqual(incident["mitre"], ["T1190"])

    def test_same_actor_on_two_hosts_is_isolated(self):
        report = build_report(self.alerts, now=CLOCK)
        incidents = [i for i in report["incidents"] if i["actor"] == "203.0.113.10"]
        self.assertEqual({i["agent_id"] for i in incidents}, {"001", "002"})
        self.assertEqual(len(incidents), 3)

    def test_manager_scopes_are_isolated(self):
        original = self.alerts[0]
        other = replace(original, id="other", manager="another-manager")
        self.assertEqual(len(build_report([original, other], now=CLOCK)["incidents"]), 2)

    def test_anchored_window_does_not_chain_indefinitely(self):
        original = self.alerts[0]
        events = [replace(original, id=str(n), timestamp=original.timestamp + timedelta(seconds=n))
                  for n in (0, 240, 480)]
        report = build_report(events, now=CLOCK)
        self.assertEqual(sorted(i["event_count"] for i in report["incidents"]), [1, 2])

    def test_window_boundary_is_exclusive(self):
        original = self.alerts[0]
        later = replace(original, id="later", timestamp=original.timestamp + timedelta(seconds=300))
        self.assertEqual(len(build_report([original, later], now=CLOCK)["incidents"]), 2)

    def test_missing_actor_is_not_merged_into_one_unknown_identity(self):
        original = replace(self.alerts[0], source_ip="", user="")
        other = replace(original, id="other")
        self.assertEqual(len(build_report([original, other], now=CLOCK)["incidents"]), 2)

    def test_user_identity_can_group_system_events_without_ip(self):
        original = replace(self.alerts[0], source_ip="", user="demo")
        other = replace(original, id="other")
        report = build_report([original, other], now=CLOCK)
        self.assertEqual(len(report["incidents"]), 1)
        self.assertEqual(report["incidents"][0]["actor"], "user:demo")

    def test_duplicate_identity_with_changed_content_is_rejected(self):
        original = self.alerts[0]
        with self.assertRaises(ValueError):
            build_report([original, replace(original, level=15)], now=CLOCK)

    def test_input_order_does_not_change_report(self):
        first = build_report(self.alerts, policies=self.policies, now=CLOCK)
        second = build_report(list(reversed(self.alerts)), policies=self.policies, now=CLOCK)
        self.assertEqual(first, second)

    def test_event_ids_and_rule_levels_are_preserved(self):
        report = build_report(self.alerts, now=CLOCK)
        ids = {event["id"] for event in report["events"]}
        self.assertTrue(all(set(i["event_ids"]) <= ids for i in report["incidents"]))
        self.assertEqual(report["incidents"][0]["max_rule_level"], 12)

    def test_raw_payload_is_not_exported(self):
        self.assertNotIn("Synthetic raw payload", json.dumps(build_report(self.alerts, now=CLOCK)))

    def test_empty_input_does_not_claim_environment_is_clean(self):
        report = build_report([], now=CLOCK)
        self.assertEqual(report["summary"]["incidents"], 0)
        self.assertTrue(any("absence of attacks" in note for note in report["limitations"]))

    def test_invalid_window_rejected(self):
        for value in (0, -1, 86401, "300", True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                build_report(self.alerts, window_seconds=value)

    def test_timezone_normalization(self):
        self.assertEqual(parse_time("2026-11-19T09:20:00+08:00"),
                         parse_time("2026-11-19T01:20:00Z"))
        with self.assertRaises(ValueError):
            parse_time("2026-11-19T09:20:00")


class SuppressionTests(unittest.TestCase):
    def setUp(self):
        self.alerts, _ = load_alerts(ROOT / "examples" / "alerts.jsonl")
        self.policy = load_policies(ROOT / "config" / "demo-policies.json")[0]
        self.alert = next(a for a in self.alerts if a.rule_id == "100014")

    def report(self, event=None, policy=None, now=CLOCK):
        return build_report([event or self.alert], policies=[policy or self.policy], now=now)

    def test_active_policy_is_audited_not_deleted(self):
        report = self.report()
        self.assertEqual(report["summary"]["suppressed_alerts"], 1)
        self.assertEqual(len(report["events"]), 1)
        self.assertEqual(report["suppressed"][0]["policy_ids"], ["demo-approved-scanner"])
        self.assertEqual(report["policy_audit"][0]["matched_alerts"], 1)

    def test_expiry_boundary_and_future_policy_do_not_suppress(self):
        for now, state in ((parse_time(self.policy["expires_at"]), "expired"),
                           (parse_time(self.policy["starts_at"]) - timedelta(seconds=1), "pending")):
            with self.subTest(state=state):
                report = self.report(now=now)
                self.assertEqual(report["summary"]["suppressed_alerts"], 0)
                self.assertEqual(report["policy_audit"][0]["state"], state)

    def test_event_must_also_be_inside_approved_window(self):
        event = replace(self.alert, timestamp=parse_time(self.policy["starts_at"]) - timedelta(seconds=1))
        self.assertEqual(self.report(event=event)["summary"]["suppressed_alerts"], 0)

    def test_scope_requires_rule_host_cluster_and_source(self):
        for changes in ({"rule_id": "100001"}, {"agent_id": "002"},
                        {"manager": "another-manager"}, {"source_ip": "192.0.2.51"}, {"source_ip": ""}):
            with self.subTest(changes=changes):
                self.assertEqual(self.report(event=replace(self.alert, **changes))["summary"]["suppressed_alerts"], 0)

    def test_invalid_or_unbounded_policy_fails_closed(self):
        mutations = (
            ("reason", ""), ("owner", ""), ("ticket", ""), ("rule_ids", []),
            ("agent_ids", ["*"]), ("manager_names", ["*"]), ("source_cidrs", ["0.0.0.0/0"]),
            ("source_cidrs", ["::/0"]), ("expires_at", "2027-11-19T10:00:00+08:00"),
            ("expires_at", "2026-11-18T10:00:00+08:00"),
        )
        for field, value in mutations:
            policy = {**self.policy, field: value}
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.report(policy=policy)

    def test_policy_input_is_not_mutated(self):
        before = copy.deepcopy(self.policy)
        self.report()
        self.assertEqual(self.policy, before)

    def test_empty_non_list_policies_cannot_bypass_validation(self):
        for policies in ({}, "", False):
            with self.subTest(policies=policies), self.assertRaises(ValueError):
                build_report([self.alert], policies=policies, now=CLOCK)


class InputTests(unittest.TestCase):
    def setUp(self):
        self.row = json.loads((ROOT / "examples" / "alerts.jsonl").read_text().splitlines()[0])

    def test_semantic_identity_without_native_id_is_stable(self):
        self.row.pop("id")
        first = normalize_alert(self.row)
        self.row["full_log"] = "private new payload"
        self.assertEqual(first.id, normalize_alert(self.row).id)

    def test_same_native_id_on_different_hosts_is_distinct(self):
        first = normalize_alert(self.row)
        self.row["agent"]["id"] = "002"
        self.assertNotEqual(first.id, normalize_alert(self.row).id)

    def test_invalid_schema_rejected(self):
        for field, value in (("timestamp", "yesterday"), ("rule", []), ("agent", None),
                             ("id", True), ("manager", {"name": ""})):
            with self.subTest(field=field), self.assertRaises(ValueError):
                normalize_alert({**self.row, field: value})
        for level in (-1, 16, True, "12"):
            with self.subTest(level=level), self.assertRaises(ValueError):
                normalize_alert({**self.row, "rule": {**self.row["rule"], "level": level}})

    def test_invalid_ip_rejected(self):
        self.row["data"]["srcip"] = "not-an-ip"
        with self.assertRaises(ValueError):
            normalize_alert(self.row)

    def test_invalid_lines_require_explicit_opt_in(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            path = Path(directory) / "alerts.jsonl"
            path.write_text(json.dumps(self.row) + "\ninvalid\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_alerts(path)
            alerts, errors = load_alerts(path, skip_invalid=True)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(errors[0]["evidence"], "alerts.jsonl#L2")


if __name__ == "__main__":
    unittest.main()
