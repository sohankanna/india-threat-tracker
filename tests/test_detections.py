"""Executable tests for the detection pack.

Three levels, and the docs say which is which (detections/TESTING.md):

1. Sigma (canonical): every fixture event is evaluated against the rule.
2. Wazuh: every fixture event is evaluated against local_rules.xml with an
   emulation of Wazuh field matching (tests/wazuh_eval.py), using decoder field
   names verified against the Wazuh 4.14 ruleset.
3. Splunk and Elastic: no SIEM runs in CI. The two rules whose semantics went
   wrong before (DNS, PAN-OS) are emulated from their query text: the split
   pattern, extraction pattern and CIDR ranges are read out of the shipped query
   and applied to the fixtures. The other rules get assertions on the exact
   semantics that matter, and every backend is checked to use the same process
   lists and the same trusted ranges as the Sigma rule.
"""
import ipaddress
import json
import os
import random
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
import sigma_eval  # noqa: E402
import wazuh_eval  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..", "detections")
TRUSTED = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
ADMIN_ALLOW = [ipaddress.ip_network("10.0.0.0/8")]

# rule file stem -> (Wazuh decoder kind, Wazuh rule id)
RULES = {
    "office_document_spawns_script_interpreter": ("sysmon", "100210"),
    "office_archive_lnk_spawns_lolbin": ("sysmon", "100211"),
    "windows_suspicious_dns_server_change": ("sysmon", "100212"),
    "pan_os_mgmt_auth_from_unexpected_source": ("paloalto", "100220"),
    "entra_aitm_risky_signin_token_replay": ("graph", "100230"),
}


def read(*parts):
    with open(os.path.join(ROOT, *parts)) as f:
        return f.read()


def fixtures(stem):
    d = json.loads(read("tests", f"{stem}.events.json"))
    return [(e, True) for e in d["should_match"]] + [(e, False) for e in d["should_not_match"]]


def code(text, comment):
    """Query text with comment lines and Splunk ``` comments ``` removed."""
    text = re.sub(r"```.*?```", "", text, flags=re.S)
    return "\n".join(line for line in text.splitlines() if not line.strip().startswith(comment))


def in_nets(ip, nets):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def label(event):
    return event.get("_case") or event.get("_why") or json.dumps(event)[:80]


# ── 1. Sigma ──────────────────────────────────────────────────────────────
class SigmaFixtures(unittest.TestCase):
    def test_every_fixture_against_the_canonical_rule(self):
        for stem in RULES:
            rule = sigma_eval.load_rule(os.path.join(ROOT, "sigma", f"{stem}.yml"))
            cases = fixtures(stem)
            self.assertTrue(any(m for _, m in cases) and any(not m for _, m in cases), f"{stem}: needs both kinds")
            for event, expected in cases:
                with self.subTest(rule=stem, case=label(event)):
                    self.assertEqual(sigma_eval.matches(rule, event), expected)


# ── 2. Wazuh ──────────────────────────────────────────────────────────────
class WazuhFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = wazuh_eval.load_rules(os.path.join(ROOT, "wazuh", "local_rules.xml"))

    def test_every_fixture_against_the_wazuh_rule(self):
        for stem, (kind, rule_id) in RULES.items():
            for event, expected in fixtures(stem):
                with self.subTest(rule=f"{stem} -> {rule_id}", case=label(event)):
                    parent, decoded = wazuh_eval.decode(kind, event)
                    self.assertEqual(wazuh_eval.fires(self.rules[rule_id], parent, decoded), expected)

    def test_kmsi_interrupt_goes_to_the_context_rule_only(self):
        event = {"RiskLevelAggregated": "high", "ResultType": 50140}
        parent, decoded = wazuh_eval.decode("graph", event)
        self.assertFalse(wazuh_eval.fires(self.rules["100230"], parent, decoded))
        self.assertTrue(wazuh_eval.fires(self.rules["100231"], parent, decoded))


# ── 3a. Splunk / Elastic: emulated from the query text ────────────────────
def splunk_dns_alerts(spl, event):
    pats = re.findall(r'TargetObject="([^"]+)"', spl)
    assert len(pats) == 3, "expected one required TargetObject pattern and two alternatives"
    def wild(p, v):
        p = p.replace("\\\\", "\\")
        rx = "^" + ".*".join(re.escape(x) for x in p.split("*")) + "$"
        return re.match(rx, v, re.I) is not None
    target = event.get("TargetObject", "")
    if not (wild(pats[0], target) and (wild(pats[1], target) or wild(pats[2], target))):
        return False
    split_re = re.search(r'replace\(Details,\s*"([^"]+)",\s*","\)', spl).group(1)
    cidrs = [ipaddress.ip_network(c) for c in re.findall(r'cidrmatch\("([^"]+)",\s*resolver\)', spl)]
    parts = re.sub(split_re, ",", event.get("Details", "")).strip(",").split(",")
    return any(p != "" and not in_nets(p, cidrs) for p in parts)


def esql_dns_alerts(esql, event):
    target = event.get("TargetObject", "")
    values = re.search(r"registry\.value IN \(([^)]*)\)", esql).group(1)
    allowed = re.findall(r'"([^"]+)"', values)
    path_re = re.search(r'registry\.path RLIKE "([^"]+)"', esql).group(1)
    if target.rsplit("\\", 1)[-1] not in allowed or re.fullmatch(path_re, target) is None:
        return False
    split_re = re.search(r'REPLACE\(raw,\s*"([^"]+)",\s*","\)', esql).group(1)
    cidr_call = re.search(r"CIDR_MATCH\(TO_IP\(resolver\),([^)]*)\)", esql).group(1)
    cidrs = [ipaddress.ip_network(c) for c in re.findall(r'"([^"]+)"', cidr_call)]
    parts = re.sub(split_re, ",", event.get("Details", "")).split(",")
    return any(p != "" and in_nets(p, [ipaddress.ip_network("0.0.0.0/0")]) and not in_nets(p, cidrs) for p in parts)


def pan_raw(event):
    """A SYSTEM log line in PAN-OS syslog CSV shape, carrying the fixture's fields."""
    return (f"1,2026/10/20 10:00:00,012801000001,{event['type']},{event['subtype']},0,2026/10/20 10:00:00,,"
            f"{event['event']},,0,0,general,informational,\"{event['description']}\",1,0x0")


def splunk_pan_alerts(spl, event):
    raw = pan_raw(event)
    spl = code(spl, "#")
    search = spl.strip().splitlines()[0]
    terms = re.findall(r'"([^"]+)"', search)
    if not all(t.lower() in raw.lower() for t in terms):
        return False
    rex = re.search(r'rex field=_raw "([^"]+)"', spl).group(1).replace("(?<", "(?P<")
    m = re.search(rex, raw)
    if not m:
        return False
    cidrs = [ipaddress.ip_network(c) for c in re.findall(r'cidrmatch\("([^"]+)",\s*admin_source\)', spl)]
    return not in_nets(m.group("admin_source"), cidrs)


def esql_pan_alerts(esql, event):
    conds = dict(re.findall(r'(panw\.panos\.[\w.]+) == "([^"]+)"', esql))
    decoded = {"panw.panos.type": event["type"], "panw.panos.sub_type": event["subtype"],
               "panw.panos.event.id": event["event"]}
    if any(decoded.get(k) != v for k, v in conds.items()):
        return False
    grok = re.search(r'GROK panw\.panos\.description "([^"]+)"', esql).group(1)
    rx = grok.replace("%{IP:admin_source}", r"(?P<admin_source>\d{1,3}(?:\.\d{1,3}){3})")
    m = re.search(rx, event["description"])
    if not m:
        return False
    cidr_call = re.search(r"CIDR_MATCH\(TO_IP\(admin_source\),([^)]*)\)", esql).group(1)
    cidrs = [ipaddress.ip_network(c) for c in re.findall(r'"([^"]+)"', cidr_call)]
    return not in_nets(m.group("admin_source"), cidrs)


class QueryEmulation(unittest.TestCase):
    def check(self, stem, fn, text):
        for event, expected in fixtures(stem):
            with self.subTest(rule=stem, case=label(event)):
                self.assertEqual(fn(text, event), expected)

    def test_splunk_dns(self):
        self.check("windows_suspicious_dns_server_change", splunk_dns_alerts,
                   code(read("splunk", "windows_suspicious_dns_server_change.spl"), "#"))

    def test_elastic_dns(self):
        self.check("windows_suspicious_dns_server_change", esql_dns_alerts,
                   code(read("elastic", "windows_suspicious_dns_server_change.esql"), "//"))

    def test_splunk_pan(self):
        self.check("pan_os_mgmt_auth_from_unexpected_source", splunk_pan_alerts,
                   read("splunk", "pan_os_mgmt_auth_from_unexpected_source.spl"))

    def test_elastic_pan(self):
        self.check("pan_os_mgmt_auth_from_unexpected_source", esql_pan_alerts,
                   code(read("elastic", "pan_os_mgmt_auth_from_unexpected_source.esql"), "//"))


# ── 3b. Semantics every backend must share ────────────────────────────────
def sigma_list(stem, key):
    rule = sigma_eval.load_rule(os.path.join(ROOT, "sigma", f"{stem}.yml"))
    for block in rule["detection"].values():
        if isinstance(block, dict) and key in block:
            return {v.lower().lstrip("\\") for v in block[key]}
    raise KeyError(key)


def splunk_list(stem, field):
    spl = code(read("splunk", f"{stem}.spl"), "#")
    return {m.lower() for m in re.findall(rf'(?<![A-Za-z]){field}="\*\\\\([^"\\]+)"', spl)}


def elastic_list(stem, field):
    eql = code(read("elastic", f"{stem}.eql"), "//")
    m = re.search(rf"{re.escape(field)} : \(([^)]*)\)", eql)
    return {v.lower() for v in re.findall(r'"([^"]+)"', m.group(1))}


def wazuh_list(rule_id, field):
    rules = wazuh_eval.load_rules(os.path.join(ROOT, "wazuh", "local_rules.xml"))
    pattern = dict(rules[rule_id]["fields"])[field].pattern
    alts = re.search(r"\(([^()]+)\)\\\.exe", pattern).group(1)
    return {f"{a.lower()}.exe" for a in alts.split("|")}


class Equivalence(unittest.TestCase):
    def test_process_lists_identical_in_every_backend(self):
        for stem, rule_id in (("office_document_spawns_script_interpreter", "100210"),
                              ("office_archive_lnk_spawns_lolbin", "100211")):
            for sigma_key, spl, ecs, wz in (("ParentImage|endswith", "ParentImage", "process.parent.name", "win.eventdata.parentImage"),
                                            ("Image|endswith", "Image", "process.name", "win.eventdata.image")):
                with self.subTest(rule=stem, field=spl):
                    canonical = sigma_list(stem, sigma_key)
                    self.assertEqual(splunk_list(stem, spl), canonical, "Splunk")
                    self.assertEqual(elastic_list(stem, ecs), canonical, "Elastic")
                    self.assertEqual(wazuh_list(rule_id, wz), canonical, "Wazuh")

    def test_archive_rule_has_no_lnk_shortcut_anywhere(self):
        self.assertNotIn("CommandLine=", code(read("splunk", "office_archive_lnk_spawns_lolbin.spl"), "#").split("|")[0])
        self.assertNotIn("command_line", code(read("elastic", "office_archive_lnk_spawns_lolbin.eql"), "//"))
        rule = sigma_eval.load_rule(os.path.join(ROOT, "sigma", "office_archive_lnk_spawns_lolbin.yml"))
        self.assertEqual(rule["detection"]["condition"], "selection_parent and selection_child")

    def test_entra_primary_is_success_only(self):
        spl = code(read("splunk", "entra_aitm_risky_signin_token_replay.spl"), "#")
        kql = code(read("elastic", "entra_aitm_risky_signin_token_replay.kql"), "//")
        self.assertIn("errorCode=0", spl)
        self.assertNotIn("50140", spl)
        self.assertIn("error_code:0", kql)
        self.assertNotIn("50140", kql)

    def test_trusted_resolver_policy_is_identical(self):
        """Sigma and Wazuh express the policy as a regex; Splunk and Elastic as
        CIDRs. Check all four agree on boundary addresses and 3,000 random ones,
        alone and in mixed lists in both orders."""
        sigma_re = sigma_eval.load_rule(os.path.join(ROOT, "sigma", "windows_suspicious_dns_server_change.yml"))[
            "detection"]["untrusted_resolver"]["Details|re"]
        wazuh_re = dict(wazuh_eval.load_rules(os.path.join(ROOT, "wazuh", "local_rules.xml"))["100212"]["fields"])[
            "win.eventdata.details"].pattern
        spl = code(read("splunk", "windows_suspicious_dns_server_change.spl"), "#")
        esql = code(read("elastic", "windows_suspicious_dns_server_change.esql"), "//")
        self.assertEqual({ipaddress.ip_network(c) for c in re.findall(r'cidrmatch\("([^"]+)"', spl)}, set(TRUSTED))
        self.assertEqual({ipaddress.ip_network(c) for c in re.findall(r'"(\d+\.\d+\.\d+\.\d+/\d+)"', esql)}, set(TRUSTED))
        rng = random.Random(1918)
        boundary = ["9.255.255.255", "10.0.0.0", "10.255.255.255", "11.0.0.0", "110.0.0.1", "100.10.0.1",
                    "172.15.255.255", "172.16.0.0", "172.31.255.255", "172.32.0.0",
                    "192.167.255.255", "192.168.0.0", "192.168.255.255", "192.169.0.0"]
        ips = boundary + [str(ipaddress.IPv4Address(rng.getrandbits(32))) for _ in range(3000)]
        ips += [str(rng.choice(TRUSTED)[rng.randrange(1, 60000)]) for _ in range(1000)]
        for ip in ips:
            expected = not in_nets(ip, TRUSTED)
            for name, rx in (("sigma", sigma_re), ("wazuh", wazuh_re)):
                for value in (ip, f"10.0.0.53,{ip}", f"{ip},10.0.0.53", f"10.0.0.53 {ip}"):
                    self.assertEqual(re.search(rx, value) is not None, expected, f"{name}: {value!r}")

    def test_admin_allowlist_is_identical(self):
        wazuh_re = dict(wazuh_eval.load_rules(os.path.join(ROOT, "wazuh", "local_rules.xml"))["100220"]["fields"])["description"].pattern
        spl = read("splunk", "pan_os_mgmt_auth_from_unexpected_source.spl")
        esql = code(read("elastic", "pan_os_mgmt_auth_from_unexpected_source.esql"), "//")
        sigma = sigma_eval.load_rule(os.path.join(ROOT, "sigma", "pan_os_mgmt_auth_from_unexpected_source.yml"))
        self.assertEqual({ipaddress.ip_network(c) for c in sigma["detection"]["filter_admin_sources"]["src_ip|cidr"]}, set(ADMIN_ALLOW))
        self.assertEqual({ipaddress.ip_network(c) for c in re.findall(r'cidrmatch\("([^"]+)"', code(spl, "#"))}, set(ADMIN_ALLOW))
        self.assertEqual({ipaddress.ip_network(c) for c in re.findall(r'"(\d+\.\d+\.\d+\.\d+/\d+)"', esql)}, set(ADMIN_ALLOW))
        rng = random.Random(64500)
        for _ in range(3000):
            ip = str(ipaddress.IPv4Address(rng.getrandbits(32)))
            fired = re.search(wazuh_re, f"authenticated for user 'admin'. From: {ip}.") is not None
            self.assertEqual(fired, not in_nets(ip, ADMIN_ALLOW), ip)


if __name__ == "__main__":
    unittest.main()
