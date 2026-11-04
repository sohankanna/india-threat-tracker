"""scripts/make_tweet_draft.py: what gets drafted, and that every draft fits one post."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))
import make_tweet_draft as mtd  # noqa: E402


def kev(cve, added, relevance="high", vendor="Ivanti", product="Connect Secure", epss=0.01, ransomware=False):
    return {"cve": cve, "vendor": vendor, "product": product, "name": f"{vendor} {product} test bug",
            "date_added": added, "due_date": "2026-12-01", "india_relevance": relevance,
            "epss": epss, "known_ransomware": ransomware}


class TweetDraft(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.drafts = os.path.join(self.dir, "drafts")
        os.makedirs(self.drafts)

    def run_script(self, items, date, *extra):
        data = os.path.join(self.dir, "kev.json")
        with open(data, "w") as f:
            json.dump({"items": items}, f)
        with contextlib.redirect_stdout(io.StringIO()):
            mtd.main(["--data", data, "--drafts", self.drafts, "--date", date, *extra])
        return sorted(os.listdir(self.drafts))

    def read(self, name):
        with open(os.path.join(self.drafts, name)) as f:
            return f.read()

    def tweet(self, name):
        text = self.read(name)
        return text.split("```text\n", 1)[1].split("\n```", 1)[0]

    def test_selects_india_relevant_recent_entries(self):
        items = [
            kev("CVE-2026-0001", "2026-11-04"),                                      # high, today
            kev("CVE-2026-0002", "2026-11-02", vendor="Cisco", product="ASA"),      # high, inside lookback
            kev("CVE-2026-0003", "2026-11-04", "medium", "PHP Group", "PHP", 0.9),  # medium, high EPSS
            kev("CVE-2026-0004", "2026-11-04", "medium", "Acme", "Widget", 0.01),   # medium, low EPSS
            kev("CVE-2026-0005", "2026-11-04", "medium", "Acme", "Gadget", 0.01, ransomware=True),
            kev("CVE-2026-0006", "2026-11-04", "global", "Acme", "Thing", 0.99),    # not India-relevant
            kev("CVE-2026-0007", "2026-10-31"),                                      # outside lookback
        ]
        self.assertEqual(self.run_script(items, "2026-11-04"), ["2026-11-04.md"])
        text = self.read("2026-11-04.md")
        for cve in ("0001", "0002", "0003", "0005"):
            self.assertIn(f"CVE-2026-{cve}", text)
        for cve in ("0004", "0006", "0007"):
            self.assertNotIn(f"CVE-2026-{cve}", text)

    def test_nothing_new_writes_nothing(self):
        self.assertEqual(self.run_script([kev("CVE-2026-0006", "2026-11-04", "global")], "2026-11-04"), [])

    def test_never_drafts_a_cve_twice_and_reruns_are_stable(self):
        self.run_script([kev("CVE-2026-0001", "2026-11-03")], "2026-11-03")
        # Next day: the same entry is still inside the lookback but was already drafted.
        self.assertEqual(self.run_script([kev("CVE-2026-0001", "2026-11-03")], "2026-11-04"), ["2026-11-03.md"])
        # Same day again: today's own draft does not count as "already drafted".
        first = self.read("2026-11-03.md")
        self.run_script([kev("CVE-2026-0001", "2026-11-03")], "2026-11-03")
        self.assertEqual(self.read("2026-11-03.md"), first)

    def test_every_draft_fits_one_post_and_links_the_tracker(self):
        many = [kev(f"CVE-2026-{n:04d}", "2026-11-04", vendor=f"Vendor{n}",
                    product="Some Very Long Product Name Server Edition", ransomware=n % 2 == 0)
                for n in range(1, 15)]
        cases = {
            "single": [kev("CVE-2026-111357", "2026-11-04"), kev("CVE-2026-118527", "2026-11-04")],
            "ransomware": [kev("CVE-2026-0001", "2026-11-04", epss=0.97, ransomware=True)],
            "many": many,
        }
        for label, items in cases.items():
            with self.subTest(label):
                for f in os.listdir(self.drafts):
                    os.remove(os.path.join(self.drafts, f))
                self.run_script(items, "2026-11-04")
                tweet = self.tweet("2026-11-04.md")
                self.assertLessEqual(mtd.tweet_length(tweet), mtd.TWEET_LIMIT, tweet)
                self.assertIn("https://www.sohankanna.com/tracker", tweet)
                self.assertIn("DRAFT", self.read("2026-11-04.md"))

    def test_weekly_draft_on_mondays(self):
        items = [kev("CVE-2026-0001", "2026-10-27"), kev("CVE-2026-0002", "2026-11-01", vendor="Cisco", product="ASA"),
                 kev("CVE-2026-0003", "2026-11-02")]  # 2026-11-02 is the Monday itself: not last week
        names = self.run_script(items, "2026-11-02", "--lookback", "1")
        self.assertIn("week-2026-W44.md", names)
        week = self.read("week-2026-W44.md")
        self.assertIn("CVE-2026-0001", week)
        self.assertIn("CVE-2026-0002", week)
        self.assertNotIn("CVE-2026-0003", week)
        self.assertLessEqual(mtd.tweet_length(self.tweet("week-2026-W44.md")), mtd.TWEET_LIMIT)

    def test_monday_rerun_keeps_the_daily_draft(self):
        items = [kev("CVE-2026-0001", "2026-11-01")]  # Sunday: in both the Monday daily and the weekly
        self.run_script(items, "2026-11-02")
        first = self.read("2026-11-02.md")
        self.run_script(items, "2026-11-02")
        self.assertEqual(self.read("2026-11-02.md"), first)
        self.assertIn("CVE-2026-0001", self.read("week-2026-W44.md"))

    def test_length_counts_links_and_emoji_like_x(self):
        self.assertEqual(mtd.tweet_length("https://www.sohankanna.com/tracker#vulnerabilities"), 23)
        self.assertEqual(mtd.tweet_length("ab👇"), 4)

    def test_product_labels(self):
        self.assertEqual(mtd.product_label(kev("x", "", vendor="WordPress", product="WordPress Core")), "WordPress Core")
        self.assertEqual(mtd.product_label(kev("x", "", vendor="PHP Group", product="PHP")), "PHP")
        self.assertEqual(mtd.product_label(kev("x", "", vendor="Cisco",
                         product="Secure Firewall ASA Software and Cisco Secure FTD Software")),
                         "Cisco Secure Firewall ASA")


if __name__ == "__main__":
    unittest.main()
