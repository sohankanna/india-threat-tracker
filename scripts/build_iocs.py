#!/usr/bin/env python3
"""Build data/iocs.txt and data/iocs.csv from data/smishing-apk.json.

Only specific, campaign-associated indicators (each campaign's `iocs` object)
are exported. Infrastructure context - legitimate platforms a campaign abused,
hosting providers, C2 technology (the `infrastructure` object) - is never
exported: those are shared services and must not become blocklist entries.

The output is deterministic: it depends only on the campaign data (its date
comes from the data, not the clock), so regenerating unchanged data produces
byte-identical files.

    python scripts/build_iocs.py           # write both files
    python scripts/build_iocs.py --check   # exit 1 if the committed files are stale
"""
import csv
import io
import json
import os
import sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SOURCE = os.path.join(ROOT, "data", "smishing-apk.json")
TXT_OUT = os.path.join(ROOT, "data", "iocs.txt")
CSV_OUT = os.path.join(ROOT, "data", "iocs.csv")
FIELDS = ["domains", "urls", "sha256", "package_names", "telegram_bots"]
LABELS = {
    "domains": "Domains",
    "urls": "URLs",
    "sha256": "SHA-256 file hashes",
    "package_names": "Android package names",
    "telegram_bots": "Telegram bot handles",
}
STATUS = "as reported; not re-validated; last seen not tracked"


def data_date(feed):
    """Latest review or update date in the data itself."""
    dates = [d for it in feed.get("items", []) for d in (it.get("last_verified"), it.get("last_updated")) if d]
    return max(dates) if dates else (feed.get("generated_at") or "unknown")


def collect(feed):
    """type -> campaign id -> [values], each value listed once (first campaign wins)."""
    buckets = {k: {} for k in FIELDS}
    seen = {k: set() for k in FIELDS}
    for item in feed.get("items", []):
        iocs = item.get("iocs") or {}
        unknown = set(iocs) - set(FIELDS)
        if unknown:
            raise ValueError(f"{item['id']}: unexpected indicator types {sorted(unknown)} "
                             "(infrastructure context belongs in `infrastructure`)")
        for k in FIELDS:
            for v in iocs.get(k, []):
                if v not in seen[k]:
                    seen[k].add(v)
                    buckets[k].setdefault(item["id"], []).append(v)
    return buckets


def build(feed):
    """Return (txt, csv) export text for a campaign feed."""
    buckets = collect(feed)
    by_id = {it["id"]: it for it in feed.get("items", [])}
    total = sum(len(v) for b in buckets.values() for v in b.values())

    lines = [
        "# India Threat Tracker - campaign indicators",
        "# Defensive and research use only. No malware samples are hosted.",
        "# Indicators are defanged (example[.]com); re-fang at your own risk.",
        "# Every non-comment line is one bare indicator (safe for grep -v '^#').",
        "# Campaign ids map to data/smishing-apk.json for source, confidence and the",
        "# date the source was last checked. data/iocs.csv has the same rows with that",
        "# provenance inline.",
        "# Excluded on purpose: infrastructure context (abused legitimate platforms,",
        "# hosting providers, C2 technology). Do not block shared services.",
        "# Listing is not proof an indicator is still active - last-seen dates are",
        "# not tracked.",
        f"# Data as of {data_date(feed)} - {total} indicators - "
        "https://github.com/sohankanna/india-threat-tracker",
        "",
    ]
    for k in FIELDS:
        if buckets[k]:
            lines.append(f"## {LABELS[k]}")
            for cid, vals in buckets[k].items():
                lines.append(f"# {cid}: {by_id[cid].get('title', '')}")
                lines.extend(vals)
            lines.append("")
    txt = "\n".join(lines).rstrip() + "\n"

    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(["indicator", "type", "campaign_id", "campaign", "confidence",
                "source", "source_url", "source_checked", "status"])
    for k in FIELDS:
        for cid, vals in buckets[k].items():
            it = by_id[cid]
            src = (it.get("sources") or [{}])[0]
            for v in vals:
                w.writerow([v, k, cid, it.get("title", ""), it.get("confidence", ""),
                            src.get("title", ""), src.get("url", ""), it.get("last_verified", ""), STATUS])
    return txt, out.getvalue()


def main(argv):
    with open(SOURCE) as f:
        txt, csv_text = build(json.load(f))
    if "--check" in argv:
        stale = []
        for path, expected in ((TXT_OUT, txt), (CSV_OUT, csv_text)):
            try:
                with open(path, newline="") as f:
                    current = f.read().replace("\r\n", "\n")
            except OSError:
                current = None
            if current != expected:
                stale.append(os.path.relpath(path, ROOT))
        if stale:
            print(f"FAIL stale IOC export(s): {', '.join(stale)}. Run: python scripts/build_iocs.py")
            return 1
        print("OK   IOC exports match data/smishing-apk.json")
        return 0
    for path, text in ((TXT_OUT, txt), (CSV_OUT, csv_text)):
        with open(path, "w", newline="") as f:
            f.write(text)
    n = len(csv_text.splitlines()) - 1
    print(f"Wrote {n} indicators -> data/iocs.txt and data/iocs.csv")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
