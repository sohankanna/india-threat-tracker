"""scripts/build_release.py: reproducible release zips with everything a SOC needs."""
import hashlib
import os
import sys
import tempfile
import unittest
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "scripts"))
import build_release as rel  # noqa: E402


class Release(unittest.TestCase):
    def build(self, version="v9.9.9"):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        rel.build(version, tmp.name)
        return tmp.name

    def names(self, out, bundle, version="v9.9.9"):
        with zipfile.ZipFile(os.path.join(out, f"india-threat-tracker-{bundle}-{version}.zip")) as z:
            return z.namelist()

    def test_reproducible(self):
        a, b = self.build(), self.build()
        with open(os.path.join(a, "SHA256SUMS")) as f1, open(os.path.join(b, "SHA256SUMS")) as f2:
            self.assertEqual(f1.read(), f2.read())

    def test_checksums_match_the_files(self):
        out = self.build()
        with open(os.path.join(out, "SHA256SUMS")) as f:
            for line in f.read().strip().split("\n"):
                digest, name = line.split("  ")
                with open(os.path.join(out, name), "rb") as z:
                    self.assertEqual(hashlib.sha256(z.read()).hexdigest(), digest)

    def test_detection_pack_has_every_rule_in_every_format(self):
        names = self.names(self.build(), "detections")
        stems = [f[:-4] for f in os.listdir(os.path.join(ROOT, "detections", "sigma")) if f.endswith(".yml")]
        prefix = "india-threat-tracker-detections-v9.9.9/detections/"
        for stem in stems:
            self.assertIn(f"{prefix}sigma/{stem}.yml", names)
            self.assertIn(f"{prefix}splunk/{stem}.spl", names)
            self.assertIn(f"{prefix}tests/{stem}.events.json", names)
            self.assertTrue(any(n.startswith(f"{prefix}elastic/{stem}.") for n in names), stem)
        self.assertIn(f"{prefix}wazuh/local_rules.xml", names)
        self.assertIn("india-threat-tracker-detections-v9.9.9/LICENSE", names)

    def test_data_bundle_has_feeds_schemas_and_misp_feed(self):
        names = self.names(self.build(), "data")
        p = "india-threat-tracker-data-v9.9.9/"
        for f in os.listdir(os.path.join(ROOT, "data")):
            self.assertIn(f"{p}data/{f}", names)
        self.assertIn(f"{p}misp-feed/manifest.json", names)
        self.assertIn(f"{p}schema/exploited-cve.schema.json", names)

    def test_no_build_junk(self):
        for bundle in ("detections", "data"):
            for n in self.names(self.build(), bundle):
                self.assertNotIn("__pycache__", n)
                self.assertFalse(n.endswith(".pyc"), n)

    def test_rejects_bad_versions(self):
        with self.assertRaises(SystemExit):
            rel.build("1.0", tempfile.gettempdir())


if __name__ == "__main__":
    unittest.main()
