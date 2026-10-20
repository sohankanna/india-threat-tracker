#!/usr/bin/env python3
"""Validate each data file against its schema. Exit non-zero on any failure."""
import json
import os
import sys

from jsonschema import Draft7Validator

ROOT = os.path.join(os.path.dirname(__file__), "..")
PAIRS = [
    ("data/exploited-cve.json", "schema/exploited-cve.schema.json"),
    ("data/smishing-apk.json", "schema/smishing-apk.schema.json"),
    ("data/apt-campaigns.json", "schema/apt-campaign.schema.json"),
    ("data/watchlist.json", "schema/watchlist.schema.json"),
    ("data/assessment.json", "schema/assessment.schema.json"),
    ("data/relevance-overrides.json", "schema/relevance-overrides.schema.json"),
    ("data/meta.json", "schema/meta.schema.json"),
]


def main():
    ok = True
    for data_path, schema_path in PAIRS:
        with open(os.path.join(ROOT, schema_path)) as f:
            schema = json.load(f)
        with open(os.path.join(ROOT, data_path)) as f:
            data = json.load(f)
        errors = sorted(Draft7Validator(schema).iter_errors(data), key=lambda e: e.path)
        if errors:
            ok = False
            print(f"FAIL {data_path}")
            for e in errors[:20]:
                loc = "/".join(str(p) for p in e.path)
                print(f"  - {loc}: {e.message}")
        else:
            n = data.get("count")
            if n is None and isinstance(data.get("items"), list):
                n = len(data["items"])
            if n is None and isinstance(data.get("overrides"), dict):
                n = len(data["overrides"])
            if n is None and isinstance(data.get("resources"), dict):
                n = len(data["resources"])
            print(f"OK   {data_path} ({n} items)")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
