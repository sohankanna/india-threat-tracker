"""IOC export guarantees: infrastructure context never becomes an indicator,
the exports are deterministic, and the committed files are up to date."""
import copy
import csv
import io
import json
import os
import sys
import unittest

from jsonschema import Draft7Validator

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import build_iocs  # noqa: E402

# Shared services that must never appear as an exported indicator.
SHARED = ("github.com", "githubusercontent.com", "firebase", "googleapis.com",
          "telegram.org", "api.telegram", "hostinger", "amazonaws.com", "cloudflare")


def load(name):
    with open(os.path.join(ROOT, name)) as f:
        return json.load(f)


def indicators(txt, csv_text):
    """Every exported indicator, from both files."""
    from_txt = {l for l in txt.splitlines() if l and not l.startswith("#")}
    from_csv = {r["indicator"] for r in csv.DictReader(io.StringIO(csv_text))}
    return from_txt, from_csv


class IocExports(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.feed = load("data/smishing-apk.json")
        cls.txt, cls.csv = build_iocs.build(cls.feed)

    def test_committed_exports_are_current(self):
        for path, expected in (("data/iocs.txt", self.txt), ("data/iocs.csv", self.csv)):
            with open(os.path.join(ROOT, path), newline="") as f:
                self.assertEqual(f.read().replace("\r\n", "\n"), expected,
                                 f"{path} is stale: run python scripts/build_iocs.py")

    def test_txt_and_csv_carry_the_same_indicators(self):
        t, c = indicators(self.txt, self.csv)
        self.assertEqual(t, c)
        expected = {v for it in self.feed["items"] for vals in (it.get("iocs") or {}).values() for v in vals}
        self.assertEqual(t, expected)

    def test_infrastructure_context_is_never_exported(self):
        t, c = indicators(self.txt, self.csv)
        infra = {v for it in self.feed["items"] for vals in (it.get("infrastructure") or {}).values() for v in vals}
        self.assertTrue(infra, "fixture data should contain infrastructure context to make this test meaningful")
        for value in infra:
            self.assertNotIn(value, t | c)
        for value in t | c:
            for shared in SHARED:
                self.assertNotIn(shared, value.lower(), f"{value} looks like a shared service")

    def test_infrastructure_stays_out_even_when_it_looks_like_an_indicator(self):
        feed = {"items": [{
            "id": "sm-test-1", "title": "synthetic", "confidence": "high", "last_verified": "2026-10-20",
            "sources": [{"title": "t", "url": "https://example.org"}],
            "iocs": {"domains": ["evil-challan[.]xyz"]},
            "infrastructure": {"abused_platforms": ["raw.githubusercontent.com", "github.com (releases)"],
                               "hosting_providers": ["Hostinger (web hosting)"], "c2_technology": ["Firebase"]},
        }]}
        t, c = indicators(*build_iocs.build(feed))
        self.assertEqual(t, {"evil-challan[.]xyz"})
        self.assertEqual(c, {"evil-challan[.]xyz"})

    def test_hosting_inside_iocs_is_rejected(self):
        """The old feed format put hosting in `iocs`; both the builder and the schema refuse it."""
        bad = copy.deepcopy(self.feed)
        bad["items"][0]["iocs"] = {"hosting": ["raw.githubusercontent.com"]}
        with self.assertRaises(ValueError):
            build_iocs.build(bad)
        schema = load("schema/smishing-apk.schema.json")
        self.assertTrue(list(Draft7Validator(schema).iter_errors(bad)))

    def test_output_is_deterministic_and_clock_free(self):
        self.assertEqual(build_iocs.build(self.feed), build_iocs.build(copy.deepcopy(self.feed)))
        self.assertIn(f"Data as of {build_iocs.data_date(self.feed)}", self.txt)

    def test_domains_and_urls_are_defanged(self):
        rows = list(csv.DictReader(io.StringIO(self.csv)))
        for r in rows:
            if r["type"] in ("domains", "urls"):
                v = r["indicator"]
                self.assertTrue("[.]" in v or v.startswith("hxxp"), f"{v} is not defanged")
        # And the schema refuses a live (un-defanged) domain or a malformed hash.
        schema = load("schema/smishing-apk.schema.json")
        for bad_iocs in ({"domains": ["evil.example"]}, {"urls": ["https://evil.example/a.apk"]}, {"sha256": ["not-a-hash"]}):
            bad = copy.deepcopy(self.feed)
            bad["items"][0]["iocs"] = bad_iocs
            self.assertTrue(list(Draft7Validator(schema).iter_errors(bad)), bad_iocs)

if __name__ == "__main__":
    unittest.main()
