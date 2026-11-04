"""CERT-In notes: parsing, the polite incremental scan, and the KEV gap."""
import datetime as dt
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import build_certin_gap as gap  # noqa: E402
import fetch_certin as fc  # noqa: E402

# Synthetic pages laid out like CERT-In's (navigation tables, header line, bold
# title, labels, bulleted software, CVE links). Not real CERT-In content.
NOTE = """<html><head><script>var x = "CVE-1999-0001";</script></head><body>
<table><tr><td><a href="/">Home</a></td><td>Vulnerability Notes</td></tr></table>
<table><tr><td class="contentTD">
<span>CERT-In Vulnerability Note {code}</span><br>
<b>Remote Code Execution Vulnerability in Example&nbsp;Server</b><br>
<b>Original Issue Date:</b>October 27, 2026<br>
<b>Severity Rating:</b> CRITICAL<br>
<b>Software Affected</b>
<ul><li>Example Server 8.2 versions prior to 8.2.35</li><li>Example Server 8.3 versions prior to 8.3.36</li></ul>
<b>Overview</b><p>A vulnerability has been reported.</p>
<b>References</b><br>
<b>CVE Name</b><br>
<a href="https://www.cve.org/CVERecord?id=CVE-2026-109619">CVE-2026-109619</a><br>
<a href="https://www.cve.org/CVERecord?id=CVE-2026-109618">CVE-2026-109618</a><br>
<a href="https://www.cve.org/CVERecord?id=CVE-2026-109619">CVE-2026-109619</a>
</td></tr></table>
<div>Last Updated On November 04, 2026</div></body></html>"""
MISSING = "<html><body><table><tr><td>Page Requested Currently Not available.</td></tr></table></body></html>"
LISTING = """<html><body><table>
<tr><td><a href="s2cMainServlet?pageid=PUBVLNOTES01&VLCODE=CIVN-{y}-{top:04d}">CERT-In Vulnerability Note CIVN-{y}-{top:04d}</a></td></tr>
<tr><td>(November 03, {y})</td></tr><tr><td>Something</td></tr>
<tr><td><a href="s2cMainServlet?pageid=PUBVLNOTES01&VLCODE=CIVN-{y}-0002">CERT-In Vulnerability Note CIVN-{y}-0002</a></td></tr>
</table></body></html>"""


class FakeSite:
    def __init__(self, tops, missing=(), broken=(), down=False, layout_changed=False):
        self.tops, self.missing, self.broken, self.down, self.layout_changed = tops, set(missing), set(broken), down, layout_changed
        self.requests = []

    def __call__(self, url):
        self.requests.append(url)
        if self.down:
            raise OSError("connection refused")
        if "VLNLIST02" in url:
            year = int(url.rsplit("=", 1)[1])
            return LISTING.format(y=year, top=self.tops.get(year, 2))
        code = url.rsplit("=", 1)[1]
        if code in self.broken:
            raise TimeoutError("timed out")
        if code in self.missing:
            return MISSING
        if self.layout_changed:
            return "<html><body>New site design</body></html>"
        return NOTE.format(code=code)


def run_fetch(feed, site, max_notes=500, today=dt.date(2026, 11, 4)):
    return fc.fetch(feed, today, max_notes, 0, fetcher=site, sleep=lambda s: None)


class Parse(unittest.TestCase):
    def test_reads_a_note(self):
        n = fc.parse_note(NOTE.format(code="CIVN-2026-0528"), "CIVN-2026-0528")
        self.assertEqual(n["issued"], "2026-10-27")
        self.assertEqual(n["severity"], "CRITICAL")
        self.assertEqual(n["title"], "Remote Code Execution Vulnerability in Example Server")
        self.assertEqual(n["cves"], ["CVE-2026-109619", "CVE-2026-109618"])  # deduplicated, script ignored
        self.assertEqual(n["software"], ["Example Server 8.2 versions prior to 8.2.35",
                                         "Example Server 8.3 versions prior to 8.3.36"])
        self.assertTrue(n["url"].endswith("VLCODE=CIVN-2026-0528"))

    def test_missing_code_is_none(self):
        self.assertIsNone(fc.parse_note(MISSING, "CIVN-2026-0272"))

    def test_wrong_or_unreadable_page_is_an_error(self):
        with self.assertRaises(ValueError):
            fc.parse_note(NOTE.format(code="CIVN-2026-0001"), "CIVN-2026-0002")
        with self.assertRaises(ValueError):
            fc.parse_note("<html>New site design</html>", "CIVN-2026-0002")

    def test_highest_code_from_listing(self):
        self.assertEqual(fc.highest_code(LISTING.format(y=2026, top=535), 2026), 535)
        self.assertIsNone(fc.highest_code("<html></html>", 2026))


class Scan(unittest.TestCase):
    def test_backfills_current_year_first_within_budget(self):
        site = FakeSite({2026: 6, 2025: 4})
        change = run_fetch({"scan": {}}, site, max_notes=4)
        self.assertEqual([n["code"] for n in change["notes"]],
                         ["CIVN-2026-0001", "CIVN-2026-0002", "CIVN-2026-0003", "CIVN-2026-0004"])
        self.assertEqual(change["scan"]["2026"]["next"], 5)
        # the next run picks up where this one stopped
        feed = fc.merge({"scan": {}, "items": []}, change, dt.date(2026, 11, 4))
        change2 = run_fetch(feed, FakeSite({2026: 6, 2025: 4}), max_notes=10)
        self.assertEqual(change2["notes"][0]["code"], "CIVN-2026-0005")
        self.assertEqual(change2["scan"]["2025"]["next"], 5)
        done = fc.merge(feed, change2, dt.date(2026, 11, 4))
        self.assertTrue(done["scan"]["2026"]["complete"] and done["scan"]["2025"]["complete"])
        self.assertEqual(done["count"], 10)

    def test_missing_codes_are_skipped_not_retried(self):
        change = run_fetch({"scan": {}}, FakeSite({2026: 3, 2025: 0}, missing={"CIVN-2026-0002"}))
        self.assertEqual([n["code"] for n in change["notes"] if n["code"].startswith("CIVN-2026")],
                         ["CIVN-2026-0001", "CIVN-2026-0003"])
        self.assertEqual(change["scan"]["2026"]["next"], 4)

    def test_network_error_stops_without_advancing(self):
        change = run_fetch({"scan": {}}, FakeSite({2026: 5}, broken={"CIVN-2026-0003"}))
        self.assertEqual(change["scan"]["2026"]["next"], 3)  # 0003 retried next run
        self.assertEqual(len(change["notes"]), 2)

    def test_site_down_changes_nothing(self):
        feed = {"scan": {"2026": {"next": 7, "highest_listed": 9, "complete": False}}, "items": []}
        change = run_fetch(feed, FakeSite({}, down=True))
        self.assertEqual(change["notes"], [])
        self.assertEqual(change["scan"]["2026"]["next"], 7)

    def test_layout_change_stops_at_the_first_unreadable_note(self):
        site = FakeSite({2026: 50}, layout_changed=True)
        change = run_fetch({"scan": {}}, site)
        self.assertEqual(change["scan"]["2026"]["next"], 1)  # nothing skipped
        self.assertIn("CIVN-2026-0001", change["scan"]["2026"]["stalled"])
        self.assertEqual(len(site.requests), 2)  # listing + one note
        # once the page reads again, the stall clears
        later = run_fetch({"scan": change["scan"]}, FakeSite({2026: 2}))
        self.assertNotIn("stalled", later["scan"]["2026"])

    def test_merge_is_stable_and_from_cache_round_trips(self):
        change = run_fetch({"scan": {}}, FakeSite({2026: 2, 2025: 1}))
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "notes.json")
            fc.write({"feed": "certin-notes", "scan": {}, "items": []}, out)
            os.makedirs(os.path.join(tmp, "cache"))
            with open(os.path.join(tmp, "cache", "certin.json"), "w") as f:
                json.dump(change, f)
            for _ in range(2):  # applying the same cached fetch twice gives the same file
                fc.main(["--from-cache", os.path.join(tmp, "cache"), "--out", out, "--date", "2026-11-04"])
                with open(out) as f:
                    text = f.read()
            self.assertEqual(json.loads(text)["count"], 4)  # 2 per year (listing tops at 2)


def kev_item(cve, added, relevance="high"):
    return {"cve": cve, "vendor": "V", "product": "P", "india_relevance": relevance, "date_added": added,
            "known_ransomware": False, "epss": 0.5}


def note(code, issued, cves):
    return {"code": code, "title": "t", "issued": issued, "severity": "HIGH", "cves": cves, "software": [],
            "url": fc.NOTE_URL.format(code=code)}


class Gap(unittest.TestCase):
    KEV = {"generated_at": "2026-11-04T00:00:00Z", "items": [
        kev_item("CVE-2026-0001", "2026-10-26"),
        kev_item("CVE-2026-0002", "2026-10-20"),
        kev_item("CVE-2026-0003", "2026-10-01", "medium"),
        kev_item("CVE-2026-0004", "2026-10-01", "global"),   # not India-relevant: ignored
        kev_item("CVE-2024-0005", "2024-06-01"),             # before the window: ignored
    ]}

    def notes(self, complete):
        return {"generated_at": "2026-11-04",
                "scan": {"2025": {"next": 9, "highest_listed": 8, "complete": complete},
                         "2026": {"next": 9, "highest_listed": 8, "complete": True}},
                "items": [note("CIVN-2026-0008", "2026-10-27", ["CVE-2026-0001"]),
                          note("CIVN-2026-0005", "2026-10-15", ["CVE-2026-0002"]),
                          note("CIVN-2026-0006", "2026-10-22", ["CVE-2026-0002"])]}

    def test_statuses_and_lag(self):
        g = gap.build(self.notes(complete=True), self.KEV)
        rows = {r["cve"]: r for r in g["items"]}
        self.assertEqual(set(rows), {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"})
        self.assertEqual(rows["CVE-2026-0001"]["lag_days"], 1)            # CERT-In a day after KEV
        self.assertEqual(rows["CVE-2026-0002"]["lag_days"], -5)           # CERT-In first; earliest note used
        self.assertEqual([n["code"] for n in rows["CVE-2026-0002"]["certin"]], ["CIVN-2026-0005", "CIVN-2026-0006"])
        self.assertEqual(rows["CVE-2026-0003"]["status"], "no-note")
        s = g["summary"]
        self.assertEqual((s["covered"], s["no_note"], s["certin_first"], s["kev_first"]), (2, 1, 1, 1))
        self.assertEqual(g["window_start"], "2025-01-01")

    def test_no_note_is_never_claimed_before_the_scan_is_complete(self):
        g = gap.build(self.notes(complete=False), self.KEV)
        self.assertEqual({r["status"] for r in g["items"] if not r["certin"]}, {"pending"})
        self.assertFalse(g["scan_complete"])

    def test_deterministic(self):
        a = gap.render(gap.build(self.notes(True), self.KEV))
        self.assertEqual(a, gap.render(gap.build(self.notes(True), self.KEV)))

    def test_committed_gap_file_is_current(self):
        self.assertEqual(gap.main(["--check"]), 0)


if __name__ == "__main__":
    unittest.main()
