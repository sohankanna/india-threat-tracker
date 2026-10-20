"""Regression tests for the KEV pipeline (scripts/fetch_exploited.py).

The core case: a hand-set India-relevance tier must survive repeated
regeneration. Before the fix, the pipeline read `_manual_relevance` flags from
the previous feed but never wrote them back, so an override vanished on the
second run.
"""
import datetime as dt
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import fetch_exploited as fe  # noqa: E402

TODAY = dt.date(2026, 10, 20)
STAMP = "2026-10-20T02:33:00Z"


def kev(cve, vendor, product, added, ransom=False):
    return {
        "cveID": cve, "vendorProject": vendor, "product": product,
        "vulnerabilityName": f"{vendor} {product} flaw", "shortDescription": "test",
        "dateAdded": added, "dueDate": added, "requiredAction": "Patch.",
        "knownRansomwareCampaignUse": "Known" if ransom else "Unknown", "cwes": [],
    }


# A: edge product, recent       -> high by heuristic, on watchlist
# B: unknown vendor, 2020       -> global by heuristic, off watchlist
# C: Windows, recent            -> medium by heuristic, on watchlist
KEV = [
    kev("CVE-2026-0001", "Fortinet", "FortiOS", "2026-10-01"),
    kev("CVE-2020-0002", "Acme", "Widget Server", "2020-01-15"),
    kev("CVE-2026-0003", "Microsoft", "Windows", "2026-09-30"),
]
EPSS = {"CVE-2026-0001": (0.91, 0.99, "2026-10-19")}


class Workspace:
    """Temp data dir with the three files the pipeline reads and writes."""

    def __init__(self, test, overrides=None):
        self.dir = tempfile.TemporaryDirectory()
        test.addCleanup(self.dir.cleanup)
        self.out = os.path.join(self.dir.name, "exploited-cve.json")
        self.watch = os.path.join(self.dir.name, "watchlist.json")
        self.ovr = os.path.join(self.dir.name, "relevance-overrides.json")
        if overrides is not None:
            with open(self.ovr, "w") as f:
                json.dump({"feed": "relevance-overrides", "overrides": overrides}, f)

    def run(self, kev_list=KEV):
        return fe.run(kev_list, EPSS, TODAY, STAMP, out=self.out, watch_out=self.watch, overrides_path=self.ovr)

    @staticmethod
    def item(feed, cve):
        return next((i for i in feed["items"] if i["cve"] == cve), None)


class ManualOverridePersistence(unittest.TestCase):
    def test_override_survives_two_regenerations(self):
        ws = Workspace(self, {"CVE-2020-0002": {"tier": "high", "reason": "Widely deployed in Indian banks", "reviewed": "2026-10-20"}})
        for run in (1, 2):
            full, _ = ws.run()
            b = ws.item(full, "CVE-2020-0002")
            self.assertEqual(b["india_relevance"], "high", f"run {run}")
            self.assertTrue(b["_manual_relevance"], f"run {run}")
            self.assertEqual(b["relevance_match"], "manual review", f"run {run}")
            self.assertEqual(b["relevance_reason"], "Widely deployed in Indian banks", f"run {run}")
            self.assertEqual(full["manual_overrides"]["applied"], 1, f"run {run}")

    def test_legacy_flag_in_previous_feed_survives_two_regenerations(self):
        """The original bug: an override stored only as a flag in the feed."""
        ws = Workspace(self)  # no overrides file at all
        full, _ = ws.run()
        self.assertEqual(ws.item(full, "CVE-2026-0003")["india_relevance"], "medium")
        # An editor hand-sets C to global directly in the generated feed (old workflow).
        for it in full["items"]:
            if it["cve"] == "CVE-2026-0003":
                it["india_relevance"], it["_manual_relevance"] = "global", True
        fe.write_json(ws.out, full)
        for run in (1, 2):
            full, slim = ws.run()
            c = ws.item(full, "CVE-2026-0003")
            self.assertEqual(c["india_relevance"], "global", f"run {run}")
            self.assertTrue(c.get("_manual_relevance"), f"run {run}: flag must be written back")
            self.assertIsNone(ws.item(slim, "CVE-2026-0003"), f"run {run}: global is never on the watchlist")

    def test_overrides_file_wins_over_legacy_flag(self):
        ws = Workspace(self, {"CVE-2026-0003": {"tier": "high", "reason": "Editor decision in the overrides file", "reviewed": "2026-10-20"}})
        full, _ = ws.run()
        for it in full["items"]:
            if it["cve"] == "CVE-2026-0003":
                it["india_relevance"], it["_manual_relevance"] = "global", True
        fe.write_json(ws.out, full)
        full, _ = ws.run()
        self.assertEqual(ws.item(full, "CVE-2026-0003")["india_relevance"], "high")

    def test_override_for_cve_that_left_kev_is_kept_and_reported(self):
        ovr = {"CVE-2020-0002": {"tier": "high", "reason": "Widely deployed in Indian banks", "reviewed": "2026-10-20"}}
        ws = Workspace(self, ovr)
        ws.run()
        full, slim = ws.run([KEV[0], KEV[2]])  # CISA drops B
        self.assertIsNone(ws.item(full, "CVE-2020-0002"))
        self.assertEqual(full["manual_overrides"]["orphaned"], ["CVE-2020-0002"])
        with open(ws.ovr) as f:
            self.assertEqual(json.load(f)["overrides"], ovr, "the pipeline must never edit the overrides file")
        full, _ = ws.run()  # B comes back: override applies again
        self.assertEqual(ws.item(full, "CVE-2020-0002")["india_relevance"], "high")
        self.assertEqual(full["manual_overrides"]["orphaned"], [])


class WatchlistRules(unittest.TestCase):
    def test_heuristic_tiers_and_watchlist(self):
        full, slim = Workspace(self).run()
        self.assertEqual(Workspace.item(full, "CVE-2026-0001")["india_relevance"], "high")
        self.assertEqual(Workspace.item(full, "CVE-2026-0001")["relevance_match"], "fortinet")
        self.assertEqual(Workspace.item(full, "CVE-2020-0002")["india_relevance"], "global")
        self.assertEqual({i["cve"] for i in slim["items"]}, {"CVE-2026-0001", "CVE-2026-0003"})
        self.assertEqual(slim["total_kev"], 3)

    def test_override_to_high_on_old_cve_follows_normal_watchlist_rule(self):
        """Explicit: an old, non-ransomware CVE overridden to high stays OFF the
        watchlist, because the recency rule still applies."""
        ws = Workspace(self, {"CVE-2020-0002": {"tier": "high", "reason": "Widely deployed in Indian banks", "reviewed": "2026-10-20"}})
        full, slim = ws.run()
        self.assertFalse(ws.item(full, "CVE-2020-0002")["watchlist"])
        self.assertIsNone(ws.item(slim, "CVE-2020-0002"))

    def test_override_can_force_watchlist(self):
        ws = Workspace(self, {"CVE-2020-0002": {"tier": "high", "reason": "Still exploited against Indian banks", "reviewed": "2026-10-20", "watchlist": True}})
        _, slim = ws.run()
        self.assertIsNotNone(ws.item(slim, "CVE-2020-0002"))

    def test_override_to_global_removes_from_watchlist(self):
        ws = Workspace(self, {"CVE-2026-0001": {"tier": "global", "reason": "Product not sold in India", "reviewed": "2026-10-20"}})
        _, slim = ws.run()
        self.assertIsNone(ws.item(slim, "CVE-2026-0001"))

    def test_missing_epss_is_null_not_zero(self):
        full, _ = Workspace(self).run()
        c = Workspace.item(full, "CVE-2026-0003")
        self.assertIsNone(c["epss"])
        self.assertIsNone(c["epss_date"])
        self.assertEqual(Workspace.item(full, "CVE-2026-0001")["epss_date"], "2026-10-19")

    def test_invalid_override_tier_is_rejected(self):
        ws = Workspace(self, {"CVE-2026-0001": {"tier": "critical", "reason": "Not a real tier", "reviewed": "2026-10-20"}})
        with self.assertRaises(ValueError):
            ws.run()

    def test_output_is_deterministic(self):
        a, _ = Workspace(self).run()
        b, _ = Workspace(self).run()
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))


if __name__ == "__main__":
    unittest.main()
