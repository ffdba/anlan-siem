from __future__ import annotations

import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path

from anlan.triage import category, normalize_alert
from anlan.validation import read_xml, validate_rules

ROOT = Path(__file__).resolve().parents[1]


class ValidationTests(unittest.TestCase):
    def test_repository_has_valid_xml_and_contracts(self):
        result = validate_rules(ROOT)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["summary"]["rules"], 34)
        self.assertEqual(result["summary"]["decoders"], 10)
        self.assertNotEqual(result["summary"]["mapped_rules"], 34)

    def test_all_access_decoders_share_core_field_contract(self):
        rows = validate_rules(ROOT)["decoders"]
        for name in ("web-access-log-detail", "apache-access-log", "nginx-access-log"):
            fields = next(row["fields"] for row in rows if row["name"] == name)
            self.assertTrue({"srcip", "http_method", "url", "status_code"} <= set(fields))

    def test_empty_project_fails_not_passes(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            result = validate_rules(directory)
        self.assertEqual(result["status"], "fail")

    def test_broken_xml_duplicate_ids_and_unscoped_frequency_fail(self):
        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            rules = Path(directory) / "wazuh_config" / "rules"
            rules.mkdir(parents=True)
            (rules / "a.xml").write_text(
                '<group name="test,"><rule id="100001" level="12" frequency="8" timeframe="120">'
                '<if_matched_sid>100999</if_matched_sid></rule>'
                '<rule id="100001" level="16"/></group>', encoding="utf-8")
            result = validate_rules(directory)
            self.assertTrue(any("duplicated" in e for e in result["errors"]))
            self.assertTrue(any("source IP" in e for e in result["errors"]))
            self.assertTrue(any("missing custom rule" in e for e in result["errors"]))
            (rules / "broken.xml").write_text("<rule><script", encoding="utf-8")
            self.assertTrue(any("broken.xml" in e for e in validate_rules(directory)["errors"]))

    def test_benign_patterns_in_python_compatible_pcre_subset(self):
        # Pattern sanity only. Native decoder precedence and correlation are not emulated here.
        rule = read_xml(ROOT / "wazuh_config" / "rules" / "005-web-attacks.xml")
        command = rule.find(".//rule[@id='100043']/field").text
        upload = rule.find(".//rule[@id='100044']/field[@name='url']").text
        self.assertIsNone(re.search(command, "/app?cmd=help"))
        self.assertIsNone(re.search(command, "/docs?q=a;b"))
        self.assertIsNone(re.search(upload, "/index.php"))
        self.assertIsNotNone(re.search(upload, "/uploads/demo.php"))

    def test_native_cases_are_explicit_and_refer_to_actual_rules(self):
        cases = json.loads((ROOT / "tests" / "logtest-cases.json").read_text(encoding="utf-8"))["cases"]
        ids = {rule["id"] for rule in validate_rules(ROOT)["rules"]}
        self.assertTrue(all(case["expected"]["rule_id"] in ids for case in cases))
        self.assertTrue(all(case["logs"] for case in cases))
        self.assertIn("negative", {case["kind"] for case in cases})

    def test_effective_web_groups_keep_independent_categories(self):
        document = read_xml(ROOT / "wazuh_config" / "rules" / "005-web-attacks.xml")
        group = document.find("group")
        inherited = group.get("name", "").split(",")
        families = {"100040": "xss", "100041": "rfi", "100042": "lfi",
                    "100043": "command_injection", "100044": "file_upload",
                    "100045": "reconnaissance"}
        for rule in group.findall("rule"):
            groups = inherited + (rule.findtext("group") or "").split(",")
            row = {"timestamp": "2026-11-19T01:00:00Z", "manager": {"name": "test"},
                   "agent": {"id": "001"}, "rule": {"id": rule.get("id"),
                   "level": int(rule.get("level")), "groups": [g.strip() for g in groups if g.strip()]}}
            with self.subTest(rule=rule.get("id")):
                self.assertEqual(category(normalize_alert(row)), families[rule.get("id")])


class LogtestParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("verify_logtest", ROOT / "scripts" / "verify-logtest.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_final_result_and_decoded_fields_are_parsed(self):
        result = self.module.parse_result(
            "**Phase 2: Completed decoding.\n name: 'web-access-log'\n url: '/first'\n"
            "**Phase 3: Completed filtering.\n id: '100000'\n level: '1'\n"
            "**Phase 2: Completed decoding.\n name: 'web-access-log'\n url: '/last'\n"
            "**Phase 3: Completed filtering.\n id: '100001'\n level: '12'\n"
        )
        self.assertEqual(result, {"decoder": "web-access-log", "fields": {"url": "/last"},
                                  "rule_id": "100001", "level": "12"})

    def test_no_engine_output_cannot_pass_as_a_match(self):
        self.assertEqual(self.module.parse_result("tool not found"), {})

    def test_native_sequences_preserve_source_isolation(self):
        cases = json.loads((ROOT / "tests" / "logtest-cases.json").read_text(encoding="utf-8"))["cases"]
        positive = next(c for c in cases if c["name"] == "same-source-404-correlation")
        negative = next(c for c in cases if c["name"] == "distributed-404-not-one-actor")
        same = self.module.case_logs(positive)
        distributed = self.module.case_logs(negative)
        self.assertEqual(len(same), 26)
        self.assertEqual(len({line.split()[1] for line in same}), 1)
        self.assertEqual(len({line.split()[1] for line in distributed}), 26)

    def test_forbidden_rule_in_middle_of_sequence_cannot_pass(self):
        case = {"expected": {"rule_id": "100046", "level": 1, "decoder": "web-access-log"},
                "forbidden_rule_ids": ["100045"]}
        normal = {"rule_id": "100046", "level": "1", "decoder": "web-access-log"}
        bad = {**normal, "rule_id": "100045", "level": "7"}
        self.assertTrue(self.module.matches_case(case, [normal, normal]))
        self.assertFalse(self.module.matches_case(case, [normal, bad, normal]))
        self.assertFalse(self.module.matches_case(case, []))

    def test_any_match_does_not_override_forbidden_rule(self):
        case = {"expected": {"rule_id": "100045", "level": 7, "decoder": "web-access-log"},
                "match_scope": "any", "forbidden_rule_ids": ["100043"]}
        expected = {"rule_id": "100045", "level": "7", "decoder": "web-access-log"}
        normal = {**expected, "rule_id": "100046", "level": "1"}
        self.assertTrue(self.module.matches_case(case, [expected, normal]))
        self.assertFalse(self.module.matches_case(case, [expected, {**normal, "rule_id": "100043"}]))


if __name__ == "__main__":
    unittest.main()
