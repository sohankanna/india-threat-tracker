"""The ransomware feed must stay honest about what is confirmed."""
import json
import os
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")


def load(name):
    with open(os.path.join(ROOT, "data", name)) as f:
        return json.load(f)


class RansomwareFeed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.feed = load("ransomware.json")
        cls.kev = {i["cve"]: i for i in load("exploited-cve.json")["items"]}
        cls.ids = {g["id"] for g in cls.feed["items"]}

    def test_count_matches(self):
        self.assertEqual(self.feed["count"], len(self.feed["items"]))

    def test_kev_links_are_real_and_ransomware_linked(self):
        """A CVE tied to a ransomware group must be in KEV with known ransomware use."""
        for g in self.feed["items"]:
            for cve in g.get("kev", []):
                with self.subTest(group=g["id"], cve=cve):
                    self.assertIn(cve, self.kev)
                    self.assertTrue(self.kev[cve]["known_ransomware"])

    def test_incident_groups_resolve(self):
        for inc in self.feed["incidents"]:
            if "group" in inc:
                self.assertIn(inc["group"], self.ids, inc["organisation"])

    def test_claimed_incidents_say_so(self):
        """A claim the victim has not confirmed must carry its basis, never read as confirmed."""
        for inc in self.feed["incidents"]:
            if inc["status"] == "claimed":
                with self.subTest(org=inc["organisation"]):
                    self.assertIn("claim", inc.get("attribution_basis", "").lower())
                    self.assertTrue(any(w in inc["summary"].lower() for w in ("not confirm", "did not confirm")))

    def test_confirmed_victim_evidence_has_a_confirmed_incident(self):
        confirmed = {i.get("group") for i in self.feed["incidents"] if i["status"] == "confirmed"}
        for g in self.feed["items"]:
            if g["india_evidence"] == "confirmed-victim":
                self.assertIn(g["id"], confirmed, g["id"])

    def test_every_landscape_figure_has_a_source(self):
        for f in self.feed["landscape"]:
            self.assertTrue(f["source"]["url"].startswith("https://"), f["label"])


if __name__ == "__main__":
    unittest.main()
