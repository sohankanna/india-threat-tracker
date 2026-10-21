"""Interoperability: what MISP makes of the STIX bundle.

Runs the bundle through misp-stix, the library MISP itself uses to import
STIX 2.1 (MISP's /events/upload_stix/2 endpoint calls it), and checks what
survives. This is a library-level test, not an import into a running MISP
instance; that is .github/workflows/interop-misp.yml.

Known, accepted losses (documented in STIX-GUIDE.md), deliberately not asserted
so an improvement in misp-stix does not fail the build:
* "uses" relationships (campaign/intrusion set -> technique/malware) are not
  kept: MISP puts every cluster on the event without cluster relations;
* intrusion-set aliases survive in the description, not as MISP synonyms.
"""
import json
import os
import re
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BUNDLE = os.path.join(ROOT, "data", "india-threat-tracker-stix.json")

try:
    from misp_stix_converter import stix_2_to_misp
except ImportError:  # pragma: no cover - optional dependency
    stix_2_to_misp = None


@unittest.skipIf(stix_2_to_misp is None, "misp-stix not installed (pip install -r requirements-ci.txt)")
class MispImport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(BUNDLE, encoding="utf-8") as f:
            cls.bundle = json.load(f)
        cls.tmp = tempfile.TemporaryDirectory()
        result = stix_2_to_misp(BUNDLE, single_event=True, output_dir=cls.tmp.name, overwrite=True, debug=True)
        cls.result = result
        outputs = [os.path.join(cls.tmp.name, f) for f in os.listdir(cls.tmp.name)]
        cls.events = [json.load(open(p, encoding="utf-8")) for p in outputs]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def of_type(self, t):
        return [o for o in self.bundle["objects"] if o["type"] == t]

    def test_conversion_succeeds_without_errors(self):
        self.assertEqual(self.result.get("errors", []), [])
        self.assertEqual(self.result.get("success"), 1)
        self.assertEqual(len(self.events), 1)

    def test_every_indicator_becomes_an_ids_attribute_linked_to_its_campaign(self):
        event = self.events[0]
        values = {re.findall(r"'([^']*)'\]$", i["pattern"])[0] for i in self.of_type("indicator")}
        attrs = {a["value"]: a for a in event.get("Attribute", [])}
        self.assertEqual(set(attrs), values)
        for a in attrs.values():
            self.assertTrue(a["to_ids"], a["value"])
            self.assertTrue(any(g["type"] == "stix-2.1-campaign" for g in a.get("Galaxy", [])), a["value"])
            self.assertIn("not re-validated", a.get("comment", ""))

    def test_every_sdo_survives(self):
        text = json.dumps(self.events[0])
        for t in ("campaign", "intrusion-set", "malware", "attack-pattern", "vulnerability"):
            for o in self.of_type(t):
                self.assertIn(o["name"], text, f"{t} {o['name']}")

    def test_report_marking_and_producer(self):
        event = self.events[0]
        report = self.of_type("report")[0]
        self.assertEqual(event["info"], report["name"])
        self.assertEqual(len(event.get("EventReport", [])), 1)
        tags = {t["name"] for t in event.get("Tag", [])}
        self.assertIn("tlp:white", tags)
        self.assertTrue(any("India Threat Tracker" in t for t in tags))

    def test_infrastructure_context_is_not_an_attribute(self):
        values = " ".join(a["value"] for a in self.events[0].get("Attribute", []))
        for host in ("github.com", "raw.githubusercontent.com", "firebase"):
            self.assertNotIn(host, values.lower())


if __name__ == "__main__":
    unittest.main()
