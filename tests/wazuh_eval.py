"""Emulates Wazuh's field matching for the rules in detections/wazuh/local_rules.xml.

What it models: a rule fires when its parent rule (<if_sid>) fired and every
<field> condition matches the decoded event. type="pcre2" fields are evaluated
with the `regex` package, which follows PCRE semantics for the constructs used
here (lookahead, alternation, (?i)); fields without a type are OS_Regex and are
restricted to simple anchored literals, which this module enforces.

Decoding: fixtures are first turned into the raw logs a manager receives
(tests/wazuh_logs.py) and decoded from those. JSON sources (Windows
eventchannel, Azure Graph) are flattened as Wazuh's JSON decoder does. PAN-OS
SYSTEM logs are decoded with the regexes copied from Wazuh 4.14.9
ruleset/decoders/0505-paloalto_decoders.xml, which capture each field as
[^,]*: a quoted description that contains commas is cut at the first comma,
exactly as on a real manager.

This is still an emulation. detections/tests/wazuh_logtest.py replays the same
raw logs through a real wazuh-logtest in CI.
"""
import json
import xml.etree.ElementTree as ET

import regex

import wazuh_logs

SIMPLE_OSREGEX = regex.compile(r"^\^?[A-Za-z0-9_.-]+\$?$")
ALLOWED_TAGS = {"if_sid", "field", "regex", "description", "mitre", "options", "group"}


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
        full_log = []
        for re_el in rule.findall("regex"):
            if re_el.get("type") != "pcre2":
                raise Unsupported(f"rule {rule.get('id')}: only pcre2 <regex> is modelled")
            full_log.append(regex.compile(re_el.text or ""))
        rules[rule.get("id")] = {"if_sid": rule.findtext("if_sid"), "fields": fields, "regex": full_log}
    return rules


def fires(rule, parent_sid, event) -> bool:
    if rule["if_sid"] != parent_sid:
        return False
    for name, pattern in rule["fields"]:
        value = event.get(name)
        if value is None or pattern.search(str(value)) is None:
            return False
    for pattern in rule.get("regex", []):  # <regex> runs against the full log
        if pattern.search(event.get("full_log", "")) is None:
            return False
    return True


# ── Decoding raw logs ─────────────────────────────────────────────────────
def flatten(obj, prefix=""):
    """Wazuh's JSON decoder: nested keys become dotted field names."""
    out = {}
    for k, v in obj.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flatten(v, key + "."))
        else:
            out[key] = "" if v is None else (str(v).lower() if isinstance(v, bool) else str(v))
    return out


# Wazuh 4.14.9 ruleset/decoders/0505-paloalto_decoders.xml (paloalto-system-fields).
PAN_PREMATCH = regex.compile(r"^[^,]*,\d+\/\d+\/\d+\s\d+:\d+:\d+,\d+,SYSTEM,")
PAN_SYSTEM_1 = regex.compile(r"^[^,]*,(\d+\/\d+\/\d+\s\d+:\d+:\d+),(\d+),(SYSTEM)")
PAN_SYSTEM_2 = regex.compile(
    r"^,([^,]*),[^,]*,([^,]*),([^,]*),([^,]*),([^,]*),[^,]*,[^,]*,([^,]*),([^,]*),([^,]*),([^,]*),([^,]*),"
    r"([^,]*),([^,]*),([^,]*),([^,]*),([^,]*),([^,]*)")
PAN_ORDER_2 = ["content_threat_type", "generated_time", "virtual_system", "event_id", "object", "module",
               "severity", "description", "sequence_number", "action_flags", "device_group_hierarchy_level_1",
               "device_group_hierarchy_level_2", "device_group_hierarchy_level_3",
               "device_group_hierarchy_level_4", "virtual_system_name", "device_name"]
SYSLOG_HEADER = regex.compile(r"^[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \S+ ")


def decode_raw(kind, raw):
    """Return (parent_sid, decoded_fields) for a raw log, as the manager would."""
    if kind == "sysmon":
        ev = flatten(json.loads(raw))
        if ev.get("win.system.channel") != wazuh_logs.SYSMON_CHANNEL:
            return None, ev
        return {"1": "61603", "13": "61615"}.get(ev.get("win.system.eventID")), ev
    if kind == "graph":
        ev = flatten(json.loads(raw))
        return ("87802" if ev.get("azure_tag") == "azure-ad-graph" else None), ev
    if kind == "paloalto":
        log = SYSLOG_HEADER.sub("", raw, count=1)
        ev = {"full_log": log}
        if not PAN_PREMATCH.search(log):
            return None, ev
        m1 = PAN_SYSTEM_1.search(log)
        ev.update(zip(["receive_time", "serial_number", "type"], m1.groups()))
        m2 = PAN_SYSTEM_2.search(log[m1.end():])
        if m2:
            ev.update(zip(PAN_ORDER_2, m2.groups()))
        return "64500", ev
    raise ValueError(kind)


def decode(kind, fixture):
    """Fixture -> raw log -> (parent_sid, decoded_event)."""
    return decode_raw(kind, wazuh_logs.RAW[kind](fixture))
