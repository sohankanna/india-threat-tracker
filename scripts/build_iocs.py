#!/usr/bin/env python3
"""Aggregate the indicators from the curated feeds into data/iocs.txt, a
plain-text list practitioners can curl. Defanged, defensive use only.

Only specific, campaign-associated indicators (the `iocs` object) go in here.
Infrastructure context - legitimate platforms a campaign abused, hosting
providers, C2 technology (the `infrastructure` object) - is deliberately left
out: those are shared, legitimate services and must never become blocklist
entries.
"""
import csv
import datetime as dt
import json
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")
OUT = os.path.join(ROOT, "data", "iocs.txt")
CSV_OUT = os.path.join(ROOT, "data", "iocs.csv")
FIELDS = ["domains", "urls", "sha256", "package_names", "telegram_bots"]
LABELS = {
    "domains": "Domains",
    "urls": "URLs",
    "sha256": "SHA-256 file hashes",
    "package_names": "Android package names",
    "telegram_bots": "Telegram bot handles",
}


def main():
    with open(os.path.join(ROOT, "data", "smishing-apk.json")) as f:
        sm = json.load(f)

    # type -> campaign id -> [values]; each value listed once, under the first
    # campaign that reported it
    titles = {it["id"]: it.get("title", "") for it in sm.get("items", [])}
    buckets = {k: {} for k in FIELDS}
    seen = {k: set() for k in FIELDS}
    for item in sm.get("items", []):
        for k in FIELDS:
            for v in (item.get("iocs") or {}).get(k, []):
                if v in seen[k]:
                    continue
                seen[k].add(v)
                buckets[k].setdefault(item["id"], []).append(v)

    total = sum(len(s) for s in seen.values())
    lines = [
        "# India Threat Tracker - campaign indicators",
        "# Defensive and research use only. No malware samples are hosted.",
        "# Indicators are defanged (example[.]com); re-fang at your own risk.",
        "# Every non-comment line is one bare indicator (safe for grep -v '^#').",
        "# Campaign ids map to data/smishing-apk.json for source, confidence and the",
        "# date the source was last checked.",
        "# Excluded on purpose: infrastructure context (abused legitimate platforms,",
        "# hosting providers, C2 technology). Do not block shared services.",
        "# Listing is not proof an indicator is still active - last-seen dates are",
        "# not tracked.",
        f"# Generated {dt.date.today().isoformat()} - {total} indicators - "
        "https://github.com/sohankanna/india-threat-tracker",
        "",
    ]
    for k in FIELDS:
        if buckets[k]:
            lines.append(f"## {LABELS[k]}")
            for cid, vals in buckets[k].items():
                lines.append(f"# {cid}: {titles.get(cid, '')}")
                lines.extend(vals)
            lines.append("")

    with open(OUT, "w") as f:
        f.write("\n".join(lines).rstrip() + "\n")

    # One row per indicator, with the provenance a reviewer needs next to it.
    by_id = {it["id"]: it for it in sm.get("items", [])}
    with open(CSV_OUT, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["indicator", "type", "campaign_id", "campaign", "confidence",
                    "source", "source_url", "source_checked", "status"])
        for k in FIELDS:
            for cid, vals in buckets[k].items():
                it = by_id[cid]
                src = (it.get("sources") or [{}])[0]
                for v in vals:
                    w.writerow([v, k, cid, it.get("title", ""), it.get("confidence", ""),
                                src.get("title", ""), src.get("url", ""),
                                it.get("last_verified", ""),
                                "as reported; not re-validated; last seen not tracked"])
    print(f"Wrote {total} indicators -> {OUT} and {CSV_OUT}")


if __name__ == "__main__":
    main()
