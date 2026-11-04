#!/usr/bin/env python3
"""Collect CERT-In vulnerability notes into data/certin-notes.json.

CERT-In (India's national CERT) publishes a vulnerability note (CIVN-YYYY-NNNN)
for most vendor security releases that matter in India. This script reads them
so the tracker can line them up against what is actually being exploited
(scripts/build_certin_gap.py).

How it walks the notes: codes are sequential within a year. For each year it
reads the year's listing page to learn the highest code published, then fetches
each note from where the last run stopped (`scan.<year>.next`), at most --max
notes per run, politely (one request every --delay seconds). Missing codes
(CERT-In skips or withdraws some) are recorded as checked and skipped. So the
first runs backfill the year a batch at a time and later runs only fetch the
few new notes.

It fails soft: if the site is unreachable, or a published note does not parse
(a layout change), it logs a warning, keeps what it has, records where it
stopped (`scan.<year>.stalled`) and does not advance past anything it could not
read. The update job never fails because of CERT-In.

    python scripts/fetch_certin.py                    # fetch and update the file
    python scripts/fetch_certin.py --cache DIR        # also save what was fetched
    python scripts/fetch_certin.py --from-cache DIR   # re-apply a saved fetch, no network
    python scripts/fetch_certin.py --parse page.html  # print what the parser reads
"""
import argparse
import datetime as dt
import html
import json
import os
import re
import sys
import time
import urllib.request
from html.parser import HTMLParser

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "data", "certin-notes.json")
BASE = "https://www.cert-in.org.in/s2cMainServlet"
NOTE_URL = BASE + "?pageid=PUBVLNOTES01&VLCODE={code}"
LIST_URL = BASE + "?pageid=VLNLIST02&year={year}"
CODE_RE = re.compile(r"CIVN-(\d{4})-(\d{4})")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
MISSING_MARK = "Currently Not available"
BLOCK = {"p", "div", "br", "tr", "td", "th", "li", "ul", "ol", "table", "h1", "h2", "h3", "h4", "h5", "b", "strong"}
SECTION_END = ("Overview", "Description", "Target Audience", "Risk Assessment", "Impact Assessment", "Solution")


class _Text(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts, self.skip = [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1
        if tag in BLOCK:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.skip = max(0, self.skip - 1)
        if tag in BLOCK:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.parts.append(data)


def page_lines(page):
    p = _Text()
    p.feed(page)
    text = html.unescape("".join(p.parts)).replace("\xa0", " ")
    return [re.sub(r"\s+", " ", ln).strip() for ln in text.split("\n") if ln.strip()]


def parse_note(page, code):
    """The note as a dict, None if the code is not published, ValueError if unreadable."""
    lines = page_lines(page)
    text = "\n".join(lines)
    if MISSING_MARK in text and "Original Issue Date" not in text:
        return None
    header = re.search(r"CERT-In Vulnerability Note\s*(CIVN-\d{4}-\d{4})", text)
    if not header or header.group(1) != code:
        raise ValueError(f"{code}: note header not found")
    m = re.search(r"Original Issue Date:?\s*([A-Z][a-z]+ \d{1,2},? \d{4})", text)
    if not m:
        raise ValueError(f"{code}: no issue date")
    issued = dt.datetime.strptime(m.group(1).replace(",", ""), "%B %d %Y").date().isoformat()
    sev = re.search(r"Severity Rating:?\s*([A-Za-z]+)", text)

    # Title: the first line after the header that is not a label.
    title = ""
    idx = next(i for i, ln in enumerate(lines) if code in ln and "Vulnerability Note" in ln)
    for ln in lines[idx + 1:]:
        rest = ln.replace(f"CERT-In Vulnerability Note {code}", "").strip()
        if rest and not rest.startswith(("Original Issue Date", "Severity Rating")):
            title = rest
            break

    software = []
    for i, ln in enumerate(lines):
        if ln.rstrip(":").strip() == "Software Affected":
            for s in lines[i + 1:]:
                if s.rstrip(":").strip().startswith(SECTION_END):
                    break
                software.append(s.lstrip("•-*· ").strip())
            break

    cves = list(dict.fromkeys(CVE_RE.findall(text)))
    return {
        "code": code,
        "title": title,
        "issued": issued,
        "severity": sev.group(1).upper() if sev else "UNKNOWN",
        "cves": cves,
        "software": [s for s in software if s][:20],
        "url": NOTE_URL.format(code=code),
    }


def highest_code(listing, year):
    codes = [int(n) for y, n in CODE_RE.findall(listing) if int(y) == year]
    return max(codes) if codes else None


def get(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "india-threat-tracker (open-source; daily, rate-limited)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def warn(msg):
    print(f"::warning::CERT-In: {msg}", file=sys.stderr)


def load_feed(path=OUT):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"feed": "certin-notes", "scan": {}, "items": []}


def years_to_scan(today):
    """Current year first, so new notes are never stuck behind last year's backfill."""
    return [today.year, today.year - 1]


def fetch(feed, today, max_notes, delay, fetcher=get, sleep=time.sleep):
    """Fetch new notes. Returns {"notes": [...], "scan": {...}} (what changed)."""
    scan = {y: dict(v) for y, v in feed.get("scan", {}).items()}
    notes, budget = [], max_notes
    for year in years_to_scan(today):
        state = scan.setdefault(str(year), {"next": 1, "highest_listed": 0})
        try:
            top = highest_code(fetcher(LIST_URL.format(year=year)), year)
        except Exception as e:
            warn(f"listing for {year} unreachable ({e.__class__.__name__}); stopping this run")
            break
        if top is None:
            warn(f"listing for {year} has no note codes; the page layout may have changed")
            continue
        state["highest_listed"] = max(state.get("highest_listed", 0), top)
        while state["next"] <= state["highest_listed"] and budget > 0:
            code = f"CIVN-{year}-{state['next']:04d}"
            sleep(delay)
            budget -= 1
            try:
                page = fetcher(NOTE_URL.format(code=code))
            except Exception as e:
                warn(f"{code} unreachable ({e.__class__.__name__}); will retry next run")
                return {"notes": notes, "scan": scan}
            try:
                note = parse_note(page, code)
            except ValueError as e:
                # Never skip a published note we could not read: stop here, say so
                # in the file, and retry from the same code next run.
                state["stalled"] = f"{code}: {e}"
                warn(f"{code} did not parse ({e}). Stopping at it; the page layout may have changed. "
                     "Check with: python scripts/fetch_certin.py --parse <saved page>")
                return {"notes": notes, "scan": scan}
            state.pop("stalled", None)
            if note:
                notes.append(note)
            state["next"] += 1
        if budget <= 0:
            break
    return {"notes": notes, "scan": scan}


def merge(feed, change, today):
    old_scan = json.loads(json.dumps(feed.get("scan", {})))
    by_code = {n["code"]: n for n in feed.get("items", [])}
    for n in change["notes"]:
        by_code[n["code"]] = n
    items = sorted(by_code.values(), key=lambda n: n["code"], reverse=True)
    scan = json.loads(json.dumps(old_scan))
    scan.update(change["scan"])
    complete = {y: s.get("next", 1) > s.get("highest_listed", 0) > 0 for y, s in scan.items()}
    return {
        "feed": "certin-notes",
        "generated_at": today.isoformat() if change["notes"] or scan != old_scan else
        feed.get("generated_at", today.isoformat()),
        "source": {"title": "CERT-In Vulnerability Notes", "url": BASE + "?pageid=VLNLIST"},
        "note": "Vulnerability notes (CIVN) only, not advisories (CIAD). A year is complete when every code up to "
                "the highest listed one has been checked; until then, a CVE missing here may still have a note.",
        "scan": {y: {**s, "complete": complete[y]} for y, s in sorted(scan.items())},
        "count": len(items),
        "items": items,
    }


def write(feed, path=OUT):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(feed, f, indent=2, ensure_ascii=False)
        f.write("\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Collect CERT-In vulnerability notes.")
    ap.add_argument("--cache")
    ap.add_argument("--from-cache")
    ap.add_argument("--max", type=int, default=150)
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--date")
    ap.add_argument("--parse", help="parse one saved note page and print the result")
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args(argv)

    if a.parse:
        with open(a.parse, encoding="utf-8") as f:
            page = f.read()
        code = (CODE_RE.search(page) or [None])[0]
        print(json.dumps(parse_note(page, code), indent=2))
        return 0

    today = dt.date.fromisoformat(a.date) if a.date else dt.datetime.now(dt.timezone.utc).date()
    feed = load_feed(a.out)
    cache_file = os.path.join(a.from_cache or a.cache or "", "certin.json")
    if a.from_cache:
        if not os.path.exists(cache_file):
            print("No cached CERT-In fetch; leaving data/certin-notes.json as it is.")
            return 0
        with open(cache_file, encoding="utf-8") as f:
            change = json.load(f)
    else:
        change = fetch(feed, today, a.max, a.delay)
        if a.cache:
            os.makedirs(a.cache, exist_ok=True)
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(change, f)
    merged = merge(feed, change, today)
    write(merged, a.out)
    done = ", ".join(f"{y}: {s['next'] - 1}/{s['highest_listed']}" for y, s in merged["scan"].items())
    print(f"CERT-In notes: {merged['count']} stored, {len(change['notes'])} new this run (checked {done})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
