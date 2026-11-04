"""misp-feed/: a MISP feed that matches the data and that MISP can load."""
import copy
import hashlib
import json
import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import build_misp_feed as feed  # noqa: E402

try:
    from pymisp import MISPEvent
except ImportError:  # pymisp is optional locally; CI installs it
    MISPEvent = None


class MispFeed(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = feed.build()
        cls.manifest = json.loads(cls.files["manifest.json"])
        cls.events = {n[:-5]: json.loads(t)["Event"] for n, t in cls.files.items()
                      if n.endswith(".json") and n != "manifest.json"}

    def test_committed_feed_is_current(self):
        self.assertEqual(feed.main(["--check"]), 0)

    def test_rebuild_is_deterministic(self):
        self.assertEqual(feed.build(), self.files)

    def test_manifest_lists_every_event_with_matching_summary(self):
        self.assertEqual(set(self.manifest), set(self.events))
        for uid, summary in self.manifest.items():
            e = self.events[uid]
            self.assertEqual(e["uuid"], uid)
            for k in ("info", "date", "timestamp", "threat_level_id", "analysis", "Orgc", "Tag"):
                self.assertEqual(summary[k], e[k], (uid, k))

    def test_hashes_cover_every_attribute(self):
        lines = set(self.files["hashes.csv"].strip().split("\n"))
        expected = {f"{hashlib.md5(a['value'].encode()).hexdigest()},{uid}"
                    for uid, e in self.events.items() for a in e["Attribute"]}
        self.assertEqual(lines, expected)

    def test_every_campaign_indicator_is_exported_refanged(self):
        smishing = feed.load("smishing-apk.json")
        values = {a["value"] for e in self.events.values() for a in e["Attribute"]}
        for c in smishing["items"]:
            for kind in feed.ATTR:
                for raw in (c.get("iocs") or {}).get(kind, []):
                    self.assertIn(feed.value_for(kind, raw), values, (c["id"], raw))
        self.assertFalse([v for v in values if "[.]" in v or v.startswith("hxxp")])

    def test_infrastructure_context_never_exported(self):
        smishing = feed.load("smishing-apk.json")
        values = {a["value"].lower() for e in self.events.values() for a in e["Attribute"]}
        for c in smishing["items"]:
            for vals in (c.get("infrastructure") or {}).values():
                for v in vals if isinstance(vals, list) else [vals]:
                    if isinstance(v, str):
                        self.assertNotIn(feed.refang(v).lower(), values, (c["id"], v))

    def test_only_blockable_types_are_marked_for_ids(self):
        for e in self.events.values():
            for a in e["Attribute"]:
                self.assertEqual(a["to_ids"], a["type"] in ("domain", "url", "sha256"), a)

    def test_uuids_are_unique(self):
        uuids = [a["uuid"] for e in self.events.values() for a in e["Attribute"]] + list(self.events)
        self.assertEqual(len(uuids), len(set(uuids)))

    def test_watchlist_event_has_every_high_relevance_cve(self):
        high = {i["cve"] for i in feed.load("watchlist.json")["items"] if i["india_relevance"] == "high"}
        vulns = {a["value"] for e in self.events.values() for a in e["Attribute"] if a["type"] == "vulnerability"}
        self.assertEqual(vulns, high)

    def test_bad_indicator_values_are_rejected(self):
        for kind, raw in (("domains", "not a domain"), ("sha256", "abc"), ("package_names", "../etc")):
            with self.assertRaises(ValueError):
                feed.value_for(kind, raw)

    @unittest.skipIf(MISPEvent is None, "pymisp not installed")
    def test_pymisp_loads_every_event(self):
        for uid, e in self.events.items():
            m = MISPEvent()
            m.load(copy.deepcopy({"Event": e}))  # load() consumes the dict
            self.assertEqual(str(m.uuid), uid)
            self.assertEqual(len(m.attributes), len(e["Attribute"]))


if __name__ == "__main__":
    unittest.main()
