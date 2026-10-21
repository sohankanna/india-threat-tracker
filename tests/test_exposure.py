"""Exposure Matcher: the data it relies on, and its output contract.

The matching logic itself is tested in TypeScript (matcher/test/), because
that is the code the website runs. These tests check, from Python:

* data/kev-affected.json covers exactly the KEV CVEs in exploited-cve.json;
* build_affected.py keeps previous entries and records failures instead of
  stopping, and normalises CVE 5 records faithfully;
* the engine's JSON export (via the CLI) validates against
  schema/exposure-report.schema.json and is deterministic.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from jsonschema import Draft7Validator

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import build_affected as ba  # noqa: E402


def load(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return json.load(f)


def node_ok():
    node = shutil.which("node")
    if not node:
        return False
    out = subprocess.run([node, "--version"], capture_output=True, text=True).stdout.strip().lstrip("v")
    major, minor = (int(x) for x in out.split(".")[:2])
    return (major, minor) >= (22, 6)


class AffectedData(unittest.TestCase):
    def test_covers_exactly_the_kev_cves(self):
        kev = {i["cve"] for i in load("data", "exploited-cve.json")["items"]}
        aff = [i["cve"] for i in load("data", "kev-affected.json")["items"]]
        self.assertEqual(len(aff), len(set(aff)), "duplicate CVEs")
        self.assertEqual(set(aff), kev, "run python scripts/build_affected.py --offline")

    def test_failed_fetch_keeps_previous_entry_and_is_counted(self):
        kev = [{"cve": "CVE-2026-0001"}, {"cve": "CVE-2026-0002"}]
        prev = {"items": [{"cve": "CVE-2026-0001", "record_state": "PUBLISHED", "record_updated": "x", "products": [{"source": "cna"}]}]}

        def getter(cve):
            raise OSError("network down")
        out = ba.build(kev, prev, getter, "all", __import__("datetime").date(2026, 10, 21))
        by = {e["cve"]: e for e in out["items"]}
        self.assertEqual(by["CVE-2026-0001"]["products"], [{"source": "cna"}])
        self.assertEqual(by["CVE-2026-0002"]["record_state"], "unavailable")
        self.assertEqual(out["coverage"]["fetch_failures_this_run"], 2)

    def test_normalise_keeps_cna_and_adp_entries_verbatim(self):
        record = {
            "cveMetadata": {"state": "PUBLISHED", "dateUpdated": "2026-01-02T00:00:00Z"},
            "containers": {
                "cna": {"affected": [{"vendor": "Acme", "product": "Gateway", "defaultStatus": "unaffected",
                                      "versions": [{"version": "1.0", "lessThan": "1.4", "status": "affected", "versionType": "semver",
                                                    "changes": [{"at": "1.2", "status": "unaffected"}]}]}]},
                "adp": [{"providerMetadata": {"shortName": "CISA-ADP"},
                         "affected": [{"vendor": "acme", "product": "gateway", "cpes": ["cpe:2.3:a:acme:gateway:*:*:*:*:*:*:*:*"],
                                       "versions": [{"version": "0", "lessThanOrEqual": "1.3", "status": "affected"}]}]}],
            },
        }
        e = ba.normalise("CVE-2026-0003", record)
        self.assertEqual(e["record_updated"], "2026-01-02T00:00:00Z")
        cna, adp = e["products"]
        self.assertEqual((cna["source"], cna["default_status"]), ("cna", "unaffected"))
        self.assertEqual(cna["versions"][0], {"version": "1.0", "less_than": "1.4", "status": "affected", "version_type": "semver",
                                              "changes": [{"at": "1.2", "status": "unaffected"}]})
        self.assertEqual(adp["source"], "adp:CISA-ADP")
        self.assertEqual(adp["versions"][0]["less_than_or_equal"], "1.3")
        rejected = ba.normalise("CVE-2026-0004", {"cveMetadata": {"state": "REJECTED"}})
        self.assertEqual(rejected["products"], [])

    def test_rotation_refreshes_every_cve_within_a_week(self):
        import datetime as dt
        cves = [f"CVE-2026-{n:04d}" for n in range(1, 300)]
        seen = set()
        for d in range(7):
            day = dt.date(2026, 10, 1) + dt.timedelta(days=d)
            seen |= {c for c in cves if ba.due_for_refresh(c, day)}
        self.assertEqual(seen, set(cves))


@unittest.skipUnless(node_ok(), "needs Node.js 22.6+")
class ReportContract(unittest.TestCase):
    def run_cli(self, out):
        r = subprocess.run(["node", "--experimental-strip-types", "--no-warnings", "matcher/cli.ts",
                            "matcher/sample-inventory.csv", "--json", out], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out, encoding="utf-8") as f:
            return f.read()

    def test_export_matches_schema_and_is_deterministic(self):
        with tempfile.TemporaryDirectory() as d:
            first = self.run_cli(os.path.join(d, "a.json"))
            second = self.run_cli(os.path.join(d, "b.json"))
        self.assertEqual(first, second)
        report = json.loads(first)
        errors = list(Draft7Validator(load("schema", "exposure-report.schema.json")).iter_errors(report))
        self.assertEqual(errors, [], [e.message for e in errors[:5]])
        kev = {i["cve"] for i in load("data", "exploited-cve.json")["items"]}
        self.assertTrue(all(f["cve"] in kev for f in report["findings"]))

    def test_template_header_is_what_the_engine_expects(self):
        with open(os.path.join(ROOT, "matcher", "inventory-template.csv"), encoding="utf-8") as f:
            header = f.readline().strip().split(",")
        src = open(os.path.join(ROOT, "matcher", "exposure.ts"), encoding="utf-8").read()
        cols = src.split("export const COLUMNS = [")[1].split("]")[0]
        self.assertEqual(header, [c.strip().strip("'") for c in cols.split(",")])


if __name__ == "__main__":
    unittest.main()
