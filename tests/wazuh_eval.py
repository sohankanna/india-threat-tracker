"""Emulates Wazuh's field matching for the rules in detections/wazuh/local_rules.xml.

What it models: a rule fires when its parent rule (<if_sid>) fired and every
<field> condition matches the decoded event. type="pcre2" fields are evaluated
with the `regex` package, which follows PCRE semantics for the constructs used
here (lookahead, alternation, (?i)); fields without a type are OS_Regex and are
restricted to simple anchored literals, which this module enforces.

What it does not model: decoding raw logs. Events are given already decoded,
with the field names verified against the Wazuh 4.14 ruleset. This is a check
of the rule logic, not a substitute for running wazuh-logtest on a manager.
"""
import xml.etree.ElementTree as ET

import regex

SIMPLE_OSREGEX = regex.compile(r"^\^?[A-Za-z0-9_.-]+\$?$")
ALLOWED_TAGS = {"if_sid", "field", "description", "mitre", "options", "group"}


class Unsupported(Exception):
    pass


def load_rules(path):
    with open(path) as f:
        root = ET.fromstring("<root>" + f.read() + "</root>")
    rules = {}
    for rule in root.iter("rule"):
        tags = {child.tag for child in rule}
        if tags - ALLOWED_TAGS:
            raise Unsupported(f"rule {rule.get('id')}: unmodelled elements {tags - ALLOWED_TAGS}")
        fields = []
        for fe in rule.findall("field"):
            if fe.get("negate"):
                raise Unsupported(f"rule {rule.get('id')}: negate is not modelled")
            pattern, kind = fe.text or "", fe.get("type", "osregex")
            if kind == "osregex" and not SIMPLE_OSREGEX.match(pattern):
                raise Unsupported(f"rule {rule.get('id')}: OS_Regex {pattern!r} is beyond the emulator")
            if kind not in ("osregex", "pcre2"):
                raise Unsupported(f"rule {rule.get('id')}: field type {kind}")
            fields.append((fe.get("name"), regex.compile(pattern)))
        rules[rule.get("id")] = {"if_sid": rule.findtext("if_sid"), "fields": fields}
    return rules


def fires(rule, parent_sid, event) -> bool:
    if rule["if_sid"] != parent_sid:
        return False
    for name, pattern in rule["fields"]:
        value = event.get(name)
        if value is None or pattern.search(str(value)) is None:
            return False
    return True


# ── Fixture (Sigma field names) -> decoded Wazuh event ────────────────────
SYSMON = {
    "ParentImage": "win.eventdata.parentImage",
    "Image": "win.eventdata.image",
    "CommandLine": "win.eventdata.commandLine",
    "TargetObject": "win.eventdata.targetObject",
    "Details": "win.eventdata.details",
}
SYSMON_PARENT = {1: "61603", 13: "61615"}


def decode(kind, fixture):
    """Return (parent_sid, decoded_event) for a fixture event."""
    if kind == "sysmon":
        ev = {SYSMON[k]: v for k, v in fixture.items() if k in SYSMON}
        return SYSMON_PARENT[fixture["EventID"]], ev
    if kind == "paloalto":
        return "64500", {
            "type": fixture.get("type"),
            "content_threat_type": fixture.get("subtype"),
            "event_id": fixture.get("event"),
            "description": fixture.get("description"),
        }
    if kind == "graph":
        return "87802", {
            "riskLevelAggregated": fixture.get("RiskLevelAggregated"),
            "status.errorCode": str(fixture.get("ResultType")),
        }
    raise ValueError(kind)
