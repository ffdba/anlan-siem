from __future__ import annotations

import re
from pathlib import Path
from xml.etree import ElementTree as ET


def read_xml(path: Path) -> ET.Element:
    # Wazuh accepts sibling decoder elements rather than a single XML document root.
    return ET.fromstring("<anlan_config>" + path.read_text(encoding="utf-8-sig") + "</anlan_config>")


def validate_rules(root: str | Path) -> dict:
    root = Path(root)
    errors, warnings, rules, decoders = [], [], [], []
    decoder_names = set()
    decoder_fields = set()
    for path in sorted((root / "wazuh_config" / "decoders").glob("*.xml")):
        try:
            document = read_xml(path)
        except (ET.ParseError, OSError) as exc:
            errors.append(f"{path.name}: {exc}")
            continue
        for element in document.findall("decoder"):
            name = element.get("name", "")
            if not name or name in decoder_names:
                errors.append(f"{path.name}: missing or duplicated decoder name {name!r}")
            decoder_names.add(name)
            fields = [v.strip() for v in (element.findtext("order") or "").split(",") if v.strip()]
            decoder_fields.update(fields)
            pattern = element.find("regex")
            if pattern is not None:
                if pattern.get("type") != "pcre2":
                    errors.append(f"{name}: extraction regex must explicitly select pcre2.")
                try:
                    captures = re.compile(pattern.text or "").groups
                    if captures != len(fields):
                        errors.append(f"{name}: {captures} capture groups but {len(fields)} order fields.")
                except re.error:
                    warnings.append(f"{name}: capture-count check requires native PCRE2 validation.")
            decoders.append({"name": name, "parent": element.findtext("parent") or "",
                             "fields": fields, "file": path.name})
    if not decoders:
        errors.append("No decoder XML files found.")
    for decoder in decoders:
        if decoder["parent"] and decoder["parent"] not in decoder_names:
            errors.append(f"{decoder['name']}: unknown decoder parent {decoder['parent']}")

    ids = set()
    for path in sorted((root / "wazuh_config" / "rules").glob("*.xml")):
        try:
            document = read_xml(path)
        except (ET.ParseError, OSError) as exc:
            errors.append(f"{path.name}: {exc}")
            continue
        for element in document.findall(".//rule"):
            rule_id = element.get("id", "")
            if not rule_id.isdigit() or not 100000 <= int(rule_id) <= 120000 or rule_id in ids:
                errors.append(f"{path.name}: invalid or duplicated custom rule ID {rule_id!r}")
            ids.add(rule_id)
            try:
                level = int(element.get("level", "-1"))
                if not 0 <= level <= 15:
                    raise ValueError
            except ValueError:
                level = -1
                errors.append(f"{rule_id}: rule level must be between 0 and 15.")
            frequency = element.get("frequency")
            historical = element.find("if_matched_sid") is not None or element.find("if_matched_group") is not None
            if frequency:
                try:
                    if int(frequency) < 1 or int(element.get("timeframe", "0")) < 1:
                        raise ValueError
                except ValueError:
                    errors.append(f"{rule_id}: invalid frequency/timeframe.")
                if not historical:
                    errors.append(f"{rule_id}: frequency needs an explicit history selector.")
                if element.find("same_srcip") is None and element.find("same_source_ip") is None:
                    errors.append(f"{rule_id}: correlation must isolate source IP.")
            elif historical:
                errors.append(f"{rule_id}: historical selector without a frequency window.")
            for field in element.findall("field"):
                name = field.get("name", "")
                if name not in decoder_fields | {"srcuser", "dstuser"}:
                    errors.append(f"{rule_id}: field {name!r} is absent from the decoder contract.")
                if field.get("type") != "pcre2":
                    errors.append(f"{rule_id}: field regex must explicitly select pcre2.")
            selector = element.findtext("decoded_as")
            if selector and selector not in decoder_names:
                errors.append(f"{rule_id}: unknown decoder {selector!r}; decoded_as is not an alternation.")
            mappings = [e.text or "" for e in element.findall("mitre/id")]
            for technique in mappings:
                if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
                    errors.append(f"{rule_id}: invalid ATT&CK identifier {technique!r}.")
            if level >= 7 and not mappings:
                warnings.append(f"{rule_id}: alerting rule has no ATT&CK mapping.")
            rules.append({
                "id": rule_id, "level": level, "file": path.name,
                "description": element.findtext("description") or "", "mitre": mappings,
                "frequency": int(frequency) if frequency and frequency.isdigit() else None,
                "references": [
                    v.strip() for tag in ("if_sid", "if_matched_sid")
                    for value in element.findall(tag) for v in (value.text or "").split(",")
                ],
            })
    if not rules:
        errors.append("No rule XML files found.")
    for rule in rules:
        for reference in rule["references"]:
            if not reference.isdigit():
                errors.append(f"{rule['id']}: invalid reference {reference!r}")
            elif int(reference) >= 100000 and reference not in ids:
                errors.append(f"{rule['id']}: missing custom rule reference {reference}")
    return {
        "status": "pass" if not errors else "fail",
        "validation": "Static XML and project contracts only; not native Wazuh rule execution.",
        "summary": {"rules": len(rules), "decoders": len(decoders),
                    "mapped_rules": sum(bool(r["mitre"]) for r in rules),
                    "techniques": sorted({t for r in rules for t in r["mitre"]})},
        "errors": errors, "warnings": warnings, "rules": rules, "decoders": decoders,
    }
