#!/usr/bin/env python3
"""Aggregate the indicators from the curated feeds into data/iocs.txt, a
plain-text list practitioners can curl. Defanged, defensive use only."""
import datetime as dt
import json
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")
OUT = os.path.join(ROOT, "data", "iocs.txt")
FIELDS = ["domains", "urls", "sha256", "package_names", "telegram_bots", "hosting"]
LABELS = {
    "domains": "domains",
    "urls": "urls",
    "sha256": "sha256",
    "package_names": "package_names",
    "telegram_bots": "telegram_bots",
    "hosting": "hosting",
}


def main():
    with open(os.path.join(ROOT, "data", "smishing-apk.json")) as f:
        sm = json.load(f)

    buckets = {k: [] for k in FIELDS}
    for item in sm.get("items", []):
        for k in FIELDS:
            for v in (item.get("iocs") or {}).get(k, []):
                if v not in buckets[k]:
                    buckets[k].append(v)

    lines = [
        "# India Threat Tracker - aggregated indicators",
        "# Defensive and research use only. No malware samples are hosted.",
        "# Indicators are defanged (example[.]com); re-fang at your own risk.",
        f"# Generated {dt.date.today().isoformat()} - https://github.com/sohankanna/india-threat-tracker",
        "",
    ]
    total = 0
    for k in FIELDS:
        if buckets[k]:
            lines.append(f"## {LABELS[k]}")
            lines.extend(buckets[k])
            lines.append("")
            total += len(buckets[k])

    with open(OUT, "w") as f:
        f.write("\n".join(lines).rstrip() + "\n")
    print(f"Wrote {total} indicators -> {OUT}")


if __name__ == "__main__":
    main()
