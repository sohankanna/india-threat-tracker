#!/usr/bin/env python3
"""Minimal, dependency-free client for the India Threat Tracker feeds.

It shows the safe way to consume the data:

* check how old the feed is before trusting it
* treat a missing EPSS score as unknown, never as zero
* take indicators only from iocs.csv, which never contains infrastructure
  context (GitHub, Firebase, hosting providers)
* keep indicators defanged unless you explicitly ask to re-fang them

    python examples/consume_feeds.py health
    python examples/consume_feeds.py watchlist --relevance high --min-epss 0.5
    python examples/consume_feeds.py iocs --type domains
    python examples/consume_feeds.py iocs --type domains --refang   # for a blocklist you control

Use --source DIR to read a local checkout (e.g. --source data) instead of GitHub.
"""
import argparse
import csv
import datetime as dt
import io
import json
import sys
import urllib.request

RAW = "https://raw.githubusercontent.com/sohankanna/india-threat-tracker/main/data"
STALE_AFTER_HOURS = 36  # the feed is regenerated twice a day


def fetch(source, name):
    if source.startswith("http"):
        with urllib.request.urlopen(f"{source}/{name}", timeout=30) as r:
            return r.read().decode("utf-8")
    with open(f"{source}/{name}", encoding="utf-8") as f:
        return f.read()


def feed_age_hours(generated_at, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    ts = dt.datetime.fromisoformat(generated_at.replace("Z", "+00:00"))
    return (now - ts).total_seconds() / 3600


def health(source, now=None):
    w = json.loads(fetch(source, "watchlist.json"))
    age = feed_age_hours(w["generated_at"], now)
    stale = age > STALE_AFTER_HOURS
    return {"generated_at": w["generated_at"], "age_hours": round(age, 1), "stale": stale,
            "watchlist": w["count"], "total_kev": w.get("total_kev")}


def watchlist(source, relevance=None, min_epss=None):
    items = json.loads(fetch(source, "watchlist.json"))["items"]
    out = []
    for c in items:
        if relevance and c["india_relevance"] != relevance:
            continue
        if min_epss is not None and (c.get("epss") is None or c["epss"] < min_epss):
            continue  # no score is unknown, not low: it never passes a threshold
        out.append(c)
    return out


def refang(value):
    return value.replace("[.]", ".").replace("hxxp", "http")


def iocs(source, ioc_type=None, do_refang=False):
    rows = list(csv.DictReader(io.StringIO(fetch(source, "iocs.csv"))))
    if ioc_type:
        rows = [r for r in rows if r["type"] == ioc_type]
    return [refang(r["indicator"]) if do_refang else r["indicator"] for r in rows]


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--source", default=RAW, help="base URL or local data directory")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("health")
    w = sub.add_parser("watchlist")
    w.add_argument("--relevance", choices=["high", "medium"])
    w.add_argument("--min-epss", type=float)
    i = sub.add_parser("iocs")
    i.add_argument("--type", dest="ioc_type", choices=["domains", "urls", "sha256", "package_names", "telegram_bots"])
    i.add_argument("--refang", action="store_true", help="only for blocklists you control")
    a = p.parse_args(argv)

    if a.cmd == "health":
        h = health(a.source)
        print(json.dumps(h, indent=2))
        if h["stale"]:
            print(f"WARNING: feed is {h['age_hours']}h old; the update job may have failed", file=sys.stderr)
            return 2
    elif a.cmd == "watchlist":
        for c in watchlist(a.source, a.relevance, a.min_epss):
            epss = "unknown" if c.get("epss") is None else f"{c['epss']:.2%}"
            print(f"{c['cve']}\t{c['vendor']} {c['product']}\tEPSS {epss}\tdue {c.get('due_date') or '-'}")
    else:
        print("\n".join(iocs(a.source, a.ioc_type, a.refang)))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:  # e.g. piped into `head`
        sys.exit(0)
