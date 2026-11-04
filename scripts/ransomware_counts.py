#!/usr/bin/env python3
"""Monthly count of ransomware leak-site claims against India (counts only).

Runs in GitHub Actions (.github/workflows/ransomware-counts.yml) once a month
and writes a markdown summary to the job page. It does not change any data
file: the landscape figures in data/ransomware.json cite published reports, and
whether to update them stays a human call. This is the prompt to make it.

Source: the free ransomware.live API (victims by country). Its response format
is not formally documented, so the parser accepts the field names seen in the
wild ("attackdate" / "discovered" / "published", "group" / "group_name") and
fails soft: if the API is down or the shape changes, the job logs a warning and
exits 0 instead of breaking anything.

Privacy rule (same as the tracker): organisations that appear only on leak
sites are never named. Victim names are not read, stored or printed; only dates
and group names are used.

    python scripts/ransomware_counts.py                # fetch and print
    python scripts/ransomware_counts.py --from-file f  # parse a saved response
"""
import argparse
import datetime as dt
import json
import os
import sys
import urllib.request
from collections import Counter

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
API = "https://api.ransomware.live/v2/countryvictims/IN"
LANDSCAPE = os.path.join(ROOT, "data", "ransomware.json")
DATE_FIELDS = ("attackdate", "discovered", "published", "date")
GROUP_FIELDS = ("group", "group_name")
MONTHS = 12
STALE_DAYS = 45


def warn(msg):
    print(f"::warning::{msg}", file=sys.stderr)


def fetch(url, timeout=60):
    req = urllib.request.Request(url, headers={"User-Agent": "india-threat-tracker (monthly count)",
                                               "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)


def records(payload):
    """The list of victim records, whatever wrapper the API used."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("victims", "data", "items", "results"):
            if isinstance(payload.get(key), list):
                return payload[key]
    return []


def parse(rec):
    """(date, group) from one record, or None. Never touches the victim name."""
    if not isinstance(rec, dict):
        return None
    day = None
    for field in DATE_FIELDS:
        value = rec.get(field)
        if isinstance(value, str) and len(value) >= 10:
            try:
                day = dt.date.fromisoformat(value[:10])
                break
            except ValueError:
                continue
    if day is None:
        return None
    group = next((rec[f] for f in GROUP_FIELDS if isinstance(rec.get(f), str) and rec[f].strip()), "unknown")
    return day, group.strip()


def month_add(d, n):
    m = d.year * 12 + d.month - 1 + n
    return dt.date(m // 12, m % 12 + 1, 1)


def summarise(payload, today):
    parsed = [p for p in map(parse, records(payload)) if p]
    if not parsed:
        return None
    this_month = today.replace(day=1)
    first = month_add(this_month, -MONTHS)
    window = [(d, g) for d, g in parsed if first <= d < this_month]
    by_month = Counter(d.replace(day=1) for d, _ in window)
    recent = Counter(g for d, g in parsed if month_add(this_month, -3) <= d < this_month)

    lines = [
        f"# Ransomware leak-site claims against India - {today.isoformat()}",
        "",
        "Counts of **claims** posted on leak sites, from ransomware.live. A claim is not a",
        "confirmed incident, and victim names are deliberately left out.",
        "",
        "| Month | Claims |",
        "|---|---|",
    ]
    for i in range(MONTHS):
        m = month_add(first, i)
        lines.append(f"| {m:%b %Y} | {by_month.get(m, 0)} |")
    lines += ["", f"**Last {MONTHS} full months:** {len(window)} claims "
              f"({first:%b %Y} to {month_add(this_month, -1):%b %Y})", ""]
    if recent:
        lines += ["**Most active groups, last 3 full months:** "
                  + ", ".join(f"{g} ({n})" for g, n in recent.most_common(5)), ""]
    lines += landscape_note(today)
    return "\n".join(lines) + "\n"


def landscape_note(today):
    try:
        with open(LANDSCAPE, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    updated = data.get("generated_at", "")[:10]
    out = ["## Tracker landscape figures now", ""]
    for item in data.get("landscape", []):
        out.append(f"- {item.get('label')}: **{item.get('value')}** ({item.get('period')}) - "
                   f"{item.get('source', {}).get('title', 'no source')}")
    try:
        age = (today - dt.date.fromisoformat(updated)).days
    except ValueError:
        age = None
    if age is not None and age > STALE_DAYS:
        out += ["", f"The ransomware feed was last updated {age} days ago. If a newer published "
                "report has India figures, update `landscape` in data/ransomware.json "
                "(cite the report, not this count)."]
    return out + [""]


def main(argv=None):
    ap = argparse.ArgumentParser(description="Monthly count of ransomware leak-site claims against India.")
    ap.add_argument("--from-file", help="parse a saved API response instead of fetching")
    ap.add_argument("--date", help="treat this date (YYYY-MM-DD) as today")
    ap.add_argument("--out", help="also write the summary here")
    args = ap.parse_args(argv)
    today = dt.date.fromisoformat(args.date) if args.date else dt.datetime.now(dt.timezone.utc).date()

    try:
        if args.from_file:
            with open(args.from_file, encoding="utf-8") as f:
                payload = json.load(f)
        else:
            payload = fetch(API)
    except Exception as exc:  # network, HTTP or JSON errors: never fail the job
        warn(f"Could not read ransomware.live ({exc.__class__.__name__}: {exc}). No summary this month.")
        return 0

    text = summarise(payload, today)
    if text is None:
        warn("ransomware.live returned no records with a recognisable date field. "
             "The API format may have changed; check scripts/ransomware_counts.py.")
        return 0

    print(text)
    targets = [args.out, os.environ.get("GITHUB_STEP_SUMMARY")]
    for path in filter(None, targets):
        with open(path, "a", encoding="utf-8") as f:
            f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
