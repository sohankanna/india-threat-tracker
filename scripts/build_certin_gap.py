#!/usr/bin/env python3
"""Line up CERT-In's vulnerability notes against what is actually exploited.

Reads data/certin-notes.json (scripts/fetch_certin.py) and
data/exploited-cve.json, writes data/certin-gap.json. Offline and
deterministic: no network, and unchanged inputs give a byte-identical file.

For every India-relevant (high or medium) KEV entry added since the start of
the scanned window, it records:

  covered   CERT-In has a note naming the CVE: which note(s), and how many days
            the first note came before (negative) or after the KEV listing;
  no-note   every CERT-In note in the window has been checked and none names
            the CVE (a note from before the window may still exist);
  pending   the window has not been fully scanned yet, so "no note" can't be
            claimed.

    python scripts/build_certin_gap.py
    python scripts/build_certin_gap.py --check   # exit 1 if the file is stale
"""
import datetime as dt
import json
import os
import statistics
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
NOTES = os.path.join(ROOT, "data", "certin-notes.json")
KEV = os.path.join(ROOT, "data", "exploited-cve.json")
OUT = os.path.join(ROOT, "data", "certin-gap.json")
RELEVANT = ("high", "medium")


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def build(notes_feed, kev_feed):
    scan = notes_feed.get("scan", {})
    years = sorted(int(y) for y in scan) or [int(notes_feed.get("generated_at", "2026")[:4]) - 1]
    window_start = f"{years[0]}-01-01"
    complete = bool(scan) and all(s.get("complete") for s in scan.values())

    by_cve = {}
    for n in notes_feed.get("items", []):
        for cve in n.get("cves", []):
            by_cve.setdefault(cve, []).append(n)

    items = []
    for k in kev_feed.get("items", []):
        if k.get("india_relevance") not in RELEVANT or k.get("date_added", "") < window_start:
            continue
        notes = sorted(by_cve.get(k["cve"], []), key=lambda n: (n["issued"], n["code"]))
        row = {
            "cve": k["cve"],
            "vendor": k["vendor"],
            "product": k["product"],
            "india_relevance": k["india_relevance"],
            "kev_added": k["date_added"],
            "known_ransomware": bool(k.get("known_ransomware")),
            "epss": k.get("epss"),
        }
        if notes:
            first = notes[0]
            row.update(status="covered",
                       certin=[{"code": n["code"], "issued": n["issued"], "severity": n["severity"], "url": n["url"]}
                               for n in notes],
                       lag_days=(dt.date.fromisoformat(first["issued"]) - dt.date.fromisoformat(k["date_added"])).days)
        else:
            row.update(status="no-note" if complete else "pending", certin=[], lag_days=None)
        items.append(row)
    items.sort(key=lambda r: (r["kev_added"], r["cve"]), reverse=True)

    covered = [r for r in items if r["status"] == "covered"]
    lags = [r["lag_days"] for r in covered]
    summary = {
        "kev_considered": len(items),
        "covered": len(covered),
        "no_note": sum(r["status"] == "no-note" for r in items),
        "pending": sum(r["status"] == "pending" for r in items),
        "certin_first": sum(1 for x in lags if x < 0),
        "same_day": sum(1 for x in lags if x == 0),
        "kev_first": sum(1 for x in lags if x > 0),
        "median_lag_days": statistics.median(lags) if lags else None,
        "high_relevance_without_note": sum(1 for r in items if r["status"] == "no-note" and r["india_relevance"] == "high"),
    }
    dates = [notes_feed.get("generated_at", ""), kev_feed.get("generated_at", "")[:10]]
    return {
        "feed": "certin-gap",
        "generated_at": max(d for d in dates if d) if any(dates) else window_start,
        "window_start": window_start,
        "scan_complete": complete,
        "scanned": {y: {"checked_through": s.get("next", 1) - 1, "highest_listed": s.get("highest_listed", 0),
                        **({"stalled": s["stalled"]} if s.get("stalled") else {})}
                    for y, s in sorted(scan.items())},
        "method": "India-relevant (high/medium) CISA KEV entries added since window_start, matched by CVE ID "
                  "against CERT-In vulnerability notes (CIVN). lag_days = first CERT-In note date minus KEV date; "
                  "negative means CERT-In published first. 'no-note' is only used once every note in the window "
                  "has been checked.",
        "summary": summary,
        "count": len(items),
        "items": items,
    }


def render(feed):
    return json.dumps(feed, indent=2, ensure_ascii=False) + "\n"


def main(argv):
    text = render(build(load(NOTES), load(KEV)))
    if "--check" in argv:
        try:
            with open(OUT, encoding="utf-8") as f:
                current = f.read()
        except OSError:
            current = None
        if current != text:
            print("FAIL data/certin-gap.json is stale. Run: python scripts/build_certin_gap.py")
            return 1
        print("OK   data/certin-gap.json matches its inputs")
        return 0
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    s = json.loads(text)["summary"]
    print(f"CERT-In gap: {s['covered']} covered, {s['no_note']} no note, {s['pending']} pending "
          f"of {s['kev_considered']} India-relevant KEV entries")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
