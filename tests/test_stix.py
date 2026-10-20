"""Tests for the STIX 2.1 export (scripts/build_stix.py).

* the committed bundle is current, valid against the OASIS schemas, and every
  indicator pattern is a valid STIX pattern;
* referential integrity: every reference resolves, no duplicate ids;
* ids are stable and history (created/modified) is preserved across builds;
* each mapping rule, including records with optional fields missing.
"""
import copy
import json
import os
import sys
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import build_stix as bs  # noqa: E402
from stix2patterns.validator import validate as validate_pattern  # noqa: E402
from stix2validator import ValidationOptions, validate_parsed_json  # noqa: E402

BUNDLE_PATH = os.path.join(ROOT, "data", "india-threat-tracker-stix.json")
# SHOULD-level warnings accepted, with the reason documented in STIX-GUIDE.md.
ACCEPTED_WARNINGS = {"302"}  # external reference URL without a hash (web pages change)


def load_bundle():
    with open(BUNDLE_PATH, encoding="utf-8") as f:
        return json.load(f)


def refs_of(obj):
    out = []
    for k, v in obj.items():
        if k.endswith("_ref") and isinstance(v, str):
            out.append(v)
        elif k.endswith("_refs") and isinstance(v, list):
            out += v
    return out


def feeds():
    return {n: bs.load(f"{n}.json") for n in ("smishing-apk", "apt-campaigns", "assessment", "exploited-cve")}


def minimal_data():
    """Synthetic records with as few optional fields as possible."""
    return {
        "smishing-apk": {"items": [
            {"id": "sm-x-1", "title": "Bare campaign", "date_added": "2026-01-01", "confidence": "low"},
            {"id": "sm-x-2", "title": "Indicator campaign", "date_added": "2026-01-02", "confidence": "medium",
             "category": "Android banking malware", "first_seen": "2025-12",
             "iocs": {"domains": ["bad[.]example"], "urls": ["hxxps://bad[.]example/a.apk"],
                      "sha256": ["A" * 64], "package_names": ["com.bad.app"], "telegram_bots": ["bad_bot"]},
             "infrastructure": {"abused_platforms": ["github.com"]},
             "attack": [{"id": "T1660", "name": "Phishing"}],
             "sources": [{"title": "Vendor report", "url": "https://vendor.example/report"}]},
            {"id": "sm-x-3", "title": "Lure themes", "date_added": "2026-01-03", "confidence": "high",
             "category": "Reference: lure themes"},
        ]},
        "apt-campaigns": {"items": [
            {"id": "apt-x", "actor": "Example Group", "date_added": "2026-01-01", "confidence": "high",
             "suspected_origin": "Example-nexus", "attribution_note": "As reported by vendors.",
             "known_tools": ["ExampleRAT", "Backdoor loaders"],
             "attack": [{"id": "T1566.001", "name": "Phishing: Spearphishing Attachment"}]},
        ]},
        "assessment": {"period": "January 2026", "updated": "2026-01-31", "analyst": "Tester",
                       "summary": "Summary of the month for testing.", "items": [
                           {"rank": 1, "title": "Edge", "severity": "high", "category": "exploited-vulns",
                            "why": "Because it is tested.",
                            "evidence": [{"type": "cve", "id": "CVE-2026-0001"},
                                         {"type": "campaign", "id": "sm-x-2"},
                                         {"type": "source", "title": "Advisory", "url": "https://adv.example"}]}]},
        "exploited-cve": {"items": [{"cve": "CVE-2026-0001", "name": "Example flaw", "description": "Bad.",
                                     "date_added": "2026-01-05", "known_ransomware": False}]},
    }


def build_min(data=None, previous=None, registry=None):
    reg = registry if registry is not None else bs.IdRegistry()
    return bs.build(previous, reg, data or minimal_data()), reg


def by_type(bundle, t):
    return [o for o in bundle["objects"] if o["type"] == t]


class CommittedBundle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = load_bundle()

    def test_is_current(self):
        registry = bs.IdRegistry.load(allow_new=False)
        rebuilt = bs.render(bs.build(self.bundle, registry))
        with open(BUNDLE_PATH, encoding="utf-8") as f:
            self.assertEqual(rebuilt, f.read(), "run python scripts/build_stix.py")

    def test_valid_against_oasis_schemas(self):
        results = validate_parsed_json(self.bundle, ValidationOptions(version="2.1", strict=False))
        self.assertTrue(results.is_valid, [str(e) for e in results.errors])
        strict = validate_parsed_json(self.bundle, ValidationOptions(version="2.1", strict=True))
        codes = {str(e).split("{")[1].split("}")[0] for e in strict.errors}
        self.assertLessEqual(codes, ACCEPTED_WARNINGS, f"unexpected SHOULD violations: {codes}")

    def test_every_pattern_is_valid(self):
        for ind in by_type(self.bundle, "indicator"):
            ok, errors = validate_pattern(ind["pattern"], ret_errs=True)
            self.assertTrue(ok, f"{ind['pattern']}: {errors}")

    def test_referential_integrity_and_unique_ids(self):
        ids = [o["id"] for o in self.bundle["objects"]]
        self.assertEqual(len(ids), len(set(ids)), "duplicate ids")
        present = set(ids)
        for o in self.bundle["objects"]:
            for ref in refs_of(o):
                self.assertIn(ref, present, f"{o['id']} -> {ref}")

    def test_every_indicator_value_comes_from_a_campaign_ioc(self):
        iocs = set()
        for c in feeds()["smishing-apk"]["items"]:
            for kind in ("domains", "urls", "sha256"):
                iocs |= {bs.refang(v).lower() for v in (c.get("iocs") or {}).get(kind, [])}
        for ind in by_type(self.bundle, "indicator"):
            value = ind["pattern"].split("= '")[1].rstrip("']").lower()
            self.assertIn(value, iocs)

    def test_infrastructure_context_never_becomes_an_indicator(self):
        patterns = " ".join(i["pattern"] for i in by_type(self.bundle, "indicator")).lower()
        for c in feeds()["smishing-apk"]["items"]:
            for values in (c.get("infrastructure") or {}).values():
                for v in values:
                    host = v.split(" ")[0].lower()
                    self.assertNotIn(host, patterns, f"{v} must not be an indicator")

    def test_registry_covers_every_object(self):
        registry = bs.IdRegistry.load(allow_new=False)
        known = set(registry.ids.values())
        for o in self.bundle["objects"]:
            if o["type"] != "marking-definition":
                self.assertIn(o["id"], known)


class Mapping(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle, cls.registry = build_min()

    def test_reference_records_are_not_campaigns(self):
        names = {c["name"] for c in by_type(self.bundle, "campaign")}
        self.assertEqual(names, {"Bare campaign", "Indicator campaign"})

    def test_campaign_with_no_optional_fields(self):
        c = next(c for c in by_type(self.bundle, "campaign") if c["name"] == "Bare campaign")
        self.assertEqual(c["confidence"], 15)
        self.assertEqual(c["created"], "2026-01-01T00:00:00.000Z")
        self.assertNotIn("first_seen", c)

    def test_month_precision_dates_stay_in_the_description(self):
        c = next(c for c in by_type(self.bundle, "campaign") if c["name"] == "Indicator campaign")
        self.assertNotIn("first_seen", c)
        self.assertIn("First reported: 2025-12", c["description"])

    def test_indicators_are_refanged_typed_and_linked(self):
        inds = {i["pattern"] for i in by_type(self.bundle, "indicator")}
        self.assertEqual(inds, {
            "[domain-name:value = 'bad.example']",
            "[url:value = 'https://bad.example/a.apk']",
            "[file:hashes.'SHA-256' = '" + "a" * 64 + "']",
        })
        camp = next(c for c in by_type(self.bundle, "campaign") if c["name"] == "Indicator campaign")
        for i in by_type(self.bundle, "indicator"):
            self.assertEqual(i["valid_from"], "2026-01-02T00:00:00.000Z")
            rel = [r for r in by_type(self.bundle, "relationship") if r["source_ref"] == i["id"]]
            self.assertEqual([(r["relationship_type"], r["target_ref"]) for r in rel], [("indicates", camp["id"])])

    def test_non_pattern_iocs_and_infrastructure_go_to_the_description(self):
        c = next(c for c in by_type(self.bundle, "campaign") if c["name"] == "Indicator campaign")
        self.assertIn("Android package com.bad.app", c["description"])
        self.assertIn("Telegram bot bad_bot", c["description"])
        self.assertIn("do not block", c["description"])
        patterns = " ".join(i["pattern"] for i in by_type(self.bundle, "indicator"))
        for v in ("com.bad.app", "bad_bot", "github.com"):
            self.assertNotIn(v, patterns)

    def test_intrusion_sets_carry_attribution_without_asserting_it(self):
        self.assertEqual(by_type(self.bundle, "threat-actor"), [])
        iset = by_type(self.bundle, "intrusion-set")[0]
        self.assertIn("Reported attribution: Example-nexus", iset["description"])
        kinds = {r["relationship_type"] for r in by_type(self.bundle, "relationship")}
        self.assertNotIn("attributed-to", kinds)

    def test_generic_tool_names_are_not_malware(self):
        self.assertEqual({m["name"] for m in by_type(self.bundle, "malware")}, {"ExampleRAT"})

    def test_report_references_resolve_and_cve_outside_kev_is_labelled(self):
        report = by_type(self.bundle, "report")[0]
        present = {o["id"] for o in self.bundle["objects"]}
        self.assertTrue(report["object_refs"])
        self.assertLessEqual(set(report["object_refs"]), present)
        self.assertIn("not source-reported fact", report["description"])
        data = minimal_data()
        data["assessment"]["items"][0]["evidence"].append({"type": "cve", "id": "CVE-2099-9999"})
        bundle, _ = build_min(data)
        v = next(v for v in by_type(bundle, "vulnerability") if v["name"] == "CVE-2099-9999")
        self.assertIn("Not in the current CISA KEV catalog", v["description"])

    def test_malformed_ioc_values_are_rejected_not_injected(self):
        for kind, value in (("domains", "bad'] OR [x:y = 'z"), ("domains", "not a domain"),
                            ("sha256", "abc123"), ("urls", "https://x.example/a' OR '1")):
            bad = minimal_data()
            bad["smishing-apk"]["items"][1]["iocs"] = {kind: [value]}
            with self.subTest(kind=kind, value=value), self.assertRaises(ValueError):
                build_min(bad)

    def test_string_literals_are_escaped(self):
        self.assertEqual(bs.stix_string("a'b\\c"), "'a\\'b\\\\c'")


class Stability(unittest.TestCase):
    def test_unchanged_data_rebuilds_identically(self):
        first, reg = build_min()
        second, _ = build_min(previous=first, registry=reg)
        self.assertEqual(bs.render(first), bs.render(second))

    def test_changed_record_keeps_id_and_created_and_bumps_modified(self):
        first, reg = build_min()
        data = minimal_data()
        data["smishing-apk"]["items"][0]["summary"] = "New information."
        second, _ = build_min(data, previous=first, registry=reg)
        old = {o["id"]: o for o in first["objects"]}
        new = {o["id"]: o for o in second["objects"]}
        self.assertEqual(old.keys(), new.keys(), "ids must not change")
        changed = [i for i in new if new[i] != old[i]]
        self.assertEqual([new[i]["name"] for i in changed if new[i]["type"] != "report"], ["Bare campaign"])
        c = new[changed[0]] if new[changed[0]]["type"] == "campaign" else next(new[i] for i in changed if new[i]["type"] == "campaign")
        o = old[c["id"]]
        self.assertEqual(c["created"], o["created"])
        self.assertGreater(c["modified"], o["modified"])
        self.assertNotEqual(first["id"], second["id"], "a changed bundle gets a new bundle id")

    def test_check_mode_refuses_unregistered_objects(self):
        _, reg = build_min()
        data = minimal_data()
        data["smishing-apk"]["items"].append({"id": "sm-x-new", "title": "New", "date_added": "2026-02-01",
                                              "confidence": "low"})
        with self.assertRaises(bs.StaleRegistry):
            build_min(data, registry=bs.IdRegistry(reg.ids, allow_new=False))


if __name__ == "__main__":
    unittest.main()
