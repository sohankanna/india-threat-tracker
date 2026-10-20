"""data/meta.json must describe the repository as it actually is."""
import json
import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..")


def load(path):
    with open(os.path.join(ROOT, path)) as f:
        return json.load(f) if path.endswith(".json") else f.read()


class Manifest(unittest.TestCase):
    def setUp(self):
        self.meta = load("data/meta.json")["resources"]

    def test_every_data_file_is_listed_and_every_listed_file_exists(self):
        on_disk = {f"data/{f}" for f in os.listdir(os.path.join(ROOT, "data"))}
        listed = {r["file"] for r in self.meta.values()}
        self.assertEqual(listed, on_disk)
        for r in self.meta.values():
            if "schema" in r:
                self.assertTrue(os.path.exists(os.path.join(ROOT, r["schema"])), r["schema"])

    def test_every_schema_is_used_by_the_validator(self):
        validated = dict(re.findall(r'\("(data/[^"]+)", "(schema/[^"]+)"\)', load("scripts/validate.py")))
        for r in self.meta.values():
            if "schema" in r:
                self.assertEqual(validated.get(r["file"]), r["schema"], r["file"])

    def test_automated_cadence_matches_the_workflow_schedule(self):
        crons = re.findall(r'cron:\s*"([^"]+)"', load(".github/workflows/update.yml"))
        expected = {1: "daily", 2: "twice-daily"}[len(crons)]
        for name, r in self.meta.items():
            if r["updated_by"] == "automation":
                self.assertEqual(r["cadence"], expected, name)


if __name__ == "__main__":
    unittest.main()
