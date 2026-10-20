"""The example client in examples/ must keep working against the real feeds."""
import datetime as dt
import json
import os
import sys
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "examples"))
import consume_feeds as cf  # noqa: E402

DATA = os.path.join(ROOT, "data")


class ExampleClient(unittest.TestCase):
    def test_watchlist_filters(self):
        high = cf.watchlist(DATA, relevance="high")
        self.assertTrue(high and all(c["india_relevance"] == "high" for c in high))
        hot = cf.watchlist(DATA, min_epss=0.5)
        self.assertTrue(all(c["epss"] is not None and c["epss"] >= 0.5 for c in hot))

    def test_missing_epss_never_passes_a_threshold(self):
        unknown = [c for c in cf.watchlist(DATA) if c.get("epss") is None]
        self.assertFalse({c["cve"] for c in unknown} & {c["cve"] for c in cf.watchlist(DATA, min_epss=0.0)})

    def test_iocs_stay_defanged_unless_asked(self):
        domains = cf.iocs(DATA, "domains")
        self.assertTrue(domains and all("[.]" in d for d in domains))
        self.assertTrue(all("[.]" not in d for d in cf.iocs(DATA, "domains", do_refang=True)))

    def test_iocs_never_include_infrastructure(self):
        everything = " ".join(cf.iocs(DATA)).lower()
        for shared in ("githubusercontent", "github.com", "firebase", "hostinger"):
            self.assertNotIn(shared, everything)

    def test_health_flags_a_stale_feed(self):
        generated = json.load(open(os.path.join(DATA, "watchlist.json")))["generated_at"]
        ts = dt.datetime.fromisoformat(generated.replace("Z", "+00:00"))
        self.assertFalse(cf.health(DATA, now=ts + dt.timedelta(hours=12))["stale"])
        self.assertTrue(cf.health(DATA, now=ts + dt.timedelta(hours=40))["stale"])


if __name__ == "__main__":
    unittest.main()
