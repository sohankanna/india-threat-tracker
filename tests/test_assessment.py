"""Every reference in the analyst assessment must resolve to something real."""
import json
import os
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")


def load(name):
    with open(os.path.join(ROOT, "data", name)) as f:
        return json.load(f)


class AssessmentEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.items = load("assessment.json")["items"]
        cls.kev = {i["cve"]: i for i in load("exploited-cve.json")["items"]}
        cls.ids = {
            "campaign": {i["id"] for i in load("smishing-apk.json")["items"]},
            "actor": {i["id"] for i in load("apt-campaigns.json")["items"]},
            "detection": {f[:-4] for f in os.listdir(os.path.join(ROOT, "detections", "sigma")) if f.endswith(".yml")},
        }

    def test_every_item_has_evidence(self):
        for it in self.items:
            self.assertTrue(it.get("evidence"), f"rank {it['rank']} has no evidence")

    def test_record_references_resolve(self):
        for it in self.items:
            for ev in it["evidence"]:
                if ev["type"] == "cve":
                    self.assertIn(ev["id"], self.kev, f"rank {it['rank']}: {ev['id']} is not in KEV")
                elif ev["type"] in self.ids:
                    self.assertIn(ev["id"], self.ids[ev["type"]], f"rank {it['rank']}: unknown {ev['type']} {ev['id']}")

    def test_ransomware_claims_match_kev(self):
        """Evidence that says 'known ransomware use' must be true in the KEV feed."""
        for it in self.items:
            for ev in it["evidence"]:
                if ev["type"] == "cve" and "ransomware" in ev.get("supports", ""):
                    self.assertTrue(self.kev[ev["id"]]["known_ransomware"], ev["id"])

    def test_items_that_cite_feed_records_also_cite_a_primary_source_or_record(self):
        for it in self.items:
            kinds = {ev["type"] for ev in it["evidence"]}
            self.assertTrue(kinds & {"source", "campaign", "actor", "cve"}, f"rank {it['rank']}")


if __name__ == "__main__":
    unittest.main()
