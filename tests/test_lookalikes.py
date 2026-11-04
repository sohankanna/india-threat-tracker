"""scripts/scan_lookalikes.py: candidates, baseline, new leads, and the stored feed."""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import scan_lookalikes as sl  # noqa: E402

CONFIG = {
    "seed_tlds": ["com"],
    "short_label_length": 5,
    "fuzzers": ["omission", "dictionary"],
    "short_fuzzers": ["dictionary"],
    "dictionary": ["kyc"],
    "tlds": ["com"],
    "brands": [
        {"id": "sbi", "name": "State Bank of India", "sector": "banking", "labels": ["sbi"], "official": ["sbi.co.in"]},
        {"id": "hdfc-bank", "name": "HDFC Bank", "sector": "banking", "labels": ["hdfcbank"],
         "official": ["hdfcbank.com", "hdfckyc.com"]},
    ],
}


class FakeFuzzer:
    """Stands in for dnstwist.Fuzzer: a fixed permutation set per seed."""
    TABLE = {
        "sbi.com": [("dictionary", "sbikyc.com"), ("dictionary", "sbi-kyc.com"), ("dictionary", "xn--sbi-kyc.com")],
        "hdfcbank.com": [("omission", "hdfcbnk.com"), ("dictionary", "hdfckyc.com"), ("dictionary", "hdfcbank-kyc.com")],
    }

    def __init__(self, domain, dictionary=(), tld_dictionary=()):
        self.seed, self.domains = domain, set()

    def generate(self, fuzzers=()):
        self.fuzzers = fuzzers
        self.domains = [{"fuzzer": f, "domain": d} for f, d in self.TABLE[self.seed] if f in fuzzers]


def scan(found, certs=None):
    cands = {d: list(v) for d, v in sl.candidates(CONFIG, FakeFuzzer).items()}
    return {"candidates": cands, "found": {d: {"a": ["192.0.2.1"], "ns": ["ns1.example.net"], "mx": False}
                                            for d in found}, "certs": certs or {}}


class Candidates(unittest.TestCase):
    def test_official_domains_and_idn_are_excluded(self):
        c = sl.candidates(CONFIG, FakeFuzzer)
        self.assertNotIn("hdfckyc.com", c)          # listed as official
        self.assertNotIn("xn--sbi-kyc.com", c)      # IDN homographs left out on purpose
        self.assertEqual(c["hdfcbnk.com"], ("hdfc-bank", "hdfcbank", "omission"))

    def test_short_labels_only_get_short_fuzzers(self):
        seen = []

        class Spy(FakeFuzzer):
            def generate(self, fuzzers=()):
                seen.append((self.seed, tuple(fuzzers)))
                super().generate(fuzzers)
        sl.candidates(CONFIG, Spy)
        self.assertIn(("sbi.com", ("dictionary",)), seen)
        self.assertIn(("hdfcbank.com", ("omission", "dictionary")), seen)

    def test_real_dnstwist_with_the_real_config(self):
        try:
            import dnstwist  # noqa: F401
        except ImportError:
            self.skipTest("dnstwist not installed (only the lookalike workflow needs it)")
        with open(sl.CONFIG) as f:
            cfg = json.load(f)
        c = sl.candidates(cfg)
        self.assertGreater(len(c), 1000)
        self.assertIn("sbi-kyc.com", c)
        self.assertIn("parivahan-challan.in", c)
        for b in cfg["brands"]:
            for o in b["official"]:
                self.assertNotIn(o, c)

    def test_real_config_is_sane(self):
        with open(sl.CONFIG) as f:
            cfg = json.load(f)
        ids = [b["id"] for b in cfg["brands"]]
        self.assertEqual(len(ids), len(set(ids)))
        for b in cfg["brands"]:
            self.assertTrue(b["labels"] and b["official"], b["id"])
            self.assertIn(b["sector"], ("banking", "payments", "government"))
        self.assertNotIn("homoglyph", cfg["fuzzers"])  # see the config description


class Merge(unittest.TestCase):
    def test_first_scan_is_the_baseline(self):
        f = sl.merge({"scans": 0, "items": []}, scan(["sbikyc.com", "hdfcbnk.com"]), CONFIG, "2026-11-04")
        self.assertTrue(all(i["baseline"] for i in f["items"]))
        self.assertEqual(f["summary"]["new_last_30_days"], 0)
        self.assertEqual(f["baseline_date"], "2026-11-04")
        self.assertEqual({i["domain"] for i in f["items"]}, {"sbikyc[.]com", "hdfcbnk[.]com"})  # defanged

    def test_later_registrations_are_new_leads_and_listed_first(self):
        base = sl.merge({"scans": 0, "items": []}, scan(["sbikyc.com"]), CONFIG, "2026-11-01")
        f = sl.merge(base, scan(["sbikyc.com", "hdfcbank-kyc.com"], certs={"hdfcbank-kyc.com": "2026-11-03"}),
                     CONFIG, "2026-11-04")
        first = f["items"][0]
        self.assertEqual(first["domain"], "hdfcbank-kyc[.]com")
        self.assertFalse(first["baseline"])
        self.assertEqual(first["first_seen"], "2026-11-04")
        self.assertEqual(first["first_cert"], "2026-11-03")
        self.assertEqual(f["summary"]["new_with_certificate_last_30_days"], 1)
        self.assertEqual(f["summary"]["by_brand_new_last_30_days"], {"hdfc-bank": 1})
        old = next(i for i in f["items"] if i["domain"] == "sbikyc[.]com")
        self.assertEqual(old["first_seen"], "2026-11-01")
        self.assertEqual(f["baseline_date"], "2026-11-01")

    def test_vanished_domains_go_inactive_then_drop_after_90_days(self):
        base = sl.merge({"scans": 0, "items": []}, scan(["sbikyc.com"]), CONFIG, "2026-08-01")
        f = sl.merge(base, scan([]), CONFIG, "2026-08-02")
        self.assertFalse(f["items"][0]["active"])
        self.assertEqual(f["summary"]["registered"], 0)
        later = sl.merge(f, scan([]), CONFIG, "2026-11-04")
        self.assertEqual(later["items"], [])

    def test_feed_validates_against_its_schema(self):
        from jsonschema import Draft7Validator
        with open(os.path.join(ROOT, "schema", "lookalike-domains.schema.json")) as fh:
            schema = json.load(fh)
        base = sl.merge({"scans": 0, "items": []}, scan(["sbikyc.com"]), CONFIG, "2026-11-01")
        f = sl.merge(base, scan(["sbikyc.com", "hdfcbnk.com"]), CONFIG, "2026-11-04")
        self.assertEqual(list(Draft7Validator(schema).iter_errors(f)), [])


class Lookups(unittest.TestCase):
    def test_resolve_all_keeps_registered_and_survives_errors(self):
        def lookup(name):
            if name == "boom.com":
                raise RuntimeError("resolver blew up")
            return {"a": ["192.0.2.1"], "ns": [], "mx": False} if name.startswith("reg") else None
        found = sl.resolve_all(["reg1.com", "nx.com", "boom.com", "reg2.com"], lookup=lookup, threads=2)
        self.assertEqual(sorted(found), ["reg1.com", "reg2.com"])

    def test_dns_lookup_logic(self):
        try:
            import dns.resolver
        except ImportError:
            self.skipTest("dnspython not installed (only the lookalike workflow needs it)")

        class R:
            def __init__(self, answers):
                self.answers = answers

            def resolve(self, name, rtype):
                v = self.answers.get(rtype)
                if isinstance(v, Exception):
                    raise v
                if v is None:
                    raise dns.resolver.NoAnswer()
                return v
        self.assertIsNone(sl.dns_lookup("nx.com", R({"A": dns.resolver.NXDOMAIN()})))
        self.assertIsNone(sl.dns_lookup("empty.com", R({})))  # no A, no NS: not registered
        got = sl.dns_lookup("parked.com", R({"A": ["192.0.2.9."], "NS": ["ns2.host.", "ns1.host."], "MX": ["10 mx."]}))
        self.assertEqual(got, {"a": ["192.0.2.9"], "ns": ["ns1.host", "ns2.host"], "mx": True})
        got = sl.dns_lookup("nsonly.com", R({"NS": ["ns1.host."]}))
        self.assertEqual(got, {"a": [], "ns": ["ns1.host"], "mx": False})

    def test_first_cert_reads_crt_sh_json_and_fails_soft(self):
        body = json.dumps([{"not_before": "2026-11-03T10:00:00"}, {"not_before": "2026-10-30T00:00:00"}])
        self.assertEqual(sl.first_cert("x.com", fetch=lambda u: body), "2026-10-30")
        self.assertIsNone(sl.first_cert("x.com", fetch=lambda u: "<html>busy</html>"))
        self.assertIsNone(sl.first_cert("x.com", fetch=lambda u: "[]"))

    def test_from_cache_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "l.json")
            with open(out, "w") as f:
                json.dump({"scans": 0, "items": []}, f)
            os.makedirs(os.path.join(tmp, "c"))
            with open(os.path.join(tmp, "c", "lookalikes.json"), "w") as f:
                json.dump(scan(["sbikyc.com"]), f)
            original = sl.CONFIG
            cfg = os.path.join(tmp, "cfg.json")
            with open(cfg, "w") as f:
                json.dump(CONFIG, f)
            sl.CONFIG = cfg
            try:
                sl.main(["--from-cache", os.path.join(tmp, "c"), "--out", out, "--date", "2026-11-04"])
            finally:
                sl.CONFIG = original
            with open(out) as f:
                self.assertEqual(json.load(f)["count"], 1)


if __name__ == "__main__":
    unittest.main()
