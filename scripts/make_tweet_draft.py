#!/usr/bin/env python3
"""Write a *draft* post about new India-relevant KEV additions.

This is NOT post-ready. It puts the facts and a rough first draft in one place
so the maintainer can rewrite it in their own voice before posting. Nothing is
ever posted automatically.

Daily draft (drafts/<date>.md), written when there is something new:
  * KEV entries added in the last LOOKBACK days (default 3, because CISA adds
    entries in US hours and the twice-daily job can miss a same-day window),
  * that are India-relevant: `india_relevance` "high", or "medium" with known
    ransomware use or an EPSS score of at least MEDIUM_EPSS,
  * and that no earlier draft already mentions (so nothing is drafted twice).

Weekly draft (drafts/week-<ISO year>-W<week>.md), written on Mondays or with
--weekly: every India-relevant addition from the previous seven days.

Re-running on the same day rebuilds the same files, so the update job can call
it on every run (scripts/publish_update.sh).
"""
import argparse
import datetime as dt
import glob
import json
import os
import re
from collections import OrderedDict

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA = os.path.join(ROOT, "data", "exploited-cve.json")
ASSESSMENT = os.path.join(ROOT, "data", "assessment.json")
RANSOMWARE = os.path.join(ROOT, "data", "ransomware.json")
CERTIN = os.path.join(ROOT, "data", "certin-notes.json")
DRAFTS = os.path.join(ROOT, "drafts")

TRACKER_URL = "https://www.sohankanna.com/tracker#vulnerabilities"
HASHTAGS = "#CyberSecurity #India"
LOOKBACK = 3
MEDIUM_EPSS = 0.1
TWEET_LIMIT = 280
URL_WEIGHT = 23  # X counts every link as 23 characters
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def relevant(item):
    rel = item.get("india_relevance")
    if rel == "high":
        return True
    if rel == "medium":
        return bool(item.get("known_ransomware")) or (item.get("epss") or 0) >= MEDIUM_EPSS
    return False


def tweet_length(text):
    """Length roughly as X counts it: a URL is 23, an emoji or CJK character is 2."""
    text = re.sub(r"https?://\S+", "x" * URL_WEIGHT, text)
    return sum(2 if ord(c) > 0x10FF else 1 for c in text)


def fmt_epss(epss):
    if epss is None:
        return "no EPSS score yet"
    pct = epss * 100
    return f"EPSS {int(pct)}%" if pct >= 10 else f"EPSS {pct:.1f}%"


def product_label(item):
    vendor, product = item["vendor"].strip(), item["product"].strip()
    # "WordPress WordPress Core" -> "WordPress Core"
    first = product.split()[0].lower() if product else ""
    # "PHP Group PHP" -> "PHP"
    label = product if first and first in vendor.lower().split() else f"{vendor} {product}"
    # "Cisco Secure Firewall ASA Software and Cisco Secure FTD Software" -> "Cisco Secure Firewall ASA"
    if len(label) > 28 and " and " in label:
        label = label.split(" and ")[0]
    return re.sub(r" Software$", "", label)


def tracker_context():
    """CVE -> short note on where the tracker already mentions it."""
    notes = {}
    for g in (load(RANSOMWARE, {}) or {}).get("items", []):
        for cve in CVE_RE.findall(json.dumps(g.get("kev", []))):
            notes.setdefault(cve, []).append(f"linked to {g['name']} in the tracker")
    for n in (load(CERTIN, {}) or {}).get("items", []):
        for cve in n.get("cves", []):
            notes.setdefault(cve, []).append(f"CERT-In {n['code']} ({n['issued']})")
    assessment = load(ASSESSMENT, {}) or {}
    for cve in set(CVE_RE.findall(json.dumps(assessment))):
        notes.setdefault(cve, []).append(f"in the {assessment.get('period', 'current')} assessment")
    return notes


def already_drafted(drafts_dir, skip):
    seen = set()
    for path in glob.glob(os.path.join(drafts_dir, "*.md")):
        if os.path.basename(path) in skip:
            continue
        with open(path, encoding="utf-8") as f:
            seen.update(CVE_RE.findall(f.read()))
    return seen


def by_product(items):
    groups = OrderedDict()
    for i in sorted(items, key=lambda i: (not i.get("known_ransomware"),
                                          i.get("india_relevance") != "high",
                                          -(i.get("epss") or 0))):
        groups.setdefault(product_label(i), []).append(i)
    return groups


def compose(items, intro):
    """A rough casual first draft, trimmed to fit one post."""
    groups = by_product(items)
    tail = f"\n\ntracking the india-relevant ones here 👇\n{TRACKER_URL}\n\n{HASHTAGS}"

    if len(groups) == 1:
        label, its = next(iter(groups.items()))
        bug = "a new actively exploited bug" if len(its) == 1 else f"{len(its)} new actively exploited bugs"
        parts = [f"{label} has {bug} on CISA's KEV list",
                 "(" + ", ".join(i["cve"] for i in its) + ")"]
        extra = []
        if any(i.get("known_ransomware") for i in its):
            extra.append("ransomware crews are already using it")
        top = max((i.get("epss") or 0) for i in its)
        if top >= 0.5:
            extra.append(f"EPSS has it at {int(top * 100)}%, so expect mass scanning")
        advice = "if yours is internet facing, patch now and check it wasn't hit before you did"
        # Drop the optional bits, least useful first, until it fits one post.
        for keep_cves, keep_extra in ((True, True), (False, True), (False, False)):
            text = parts[0] + (" " + parts[1] if keep_cves else "")
            if keep_extra and extra:
                text += "\n\n" + ", and ".join(extra)
            text += "\n\n" + advice + tail
            if tweet_length(text) <= TWEET_LIMIT:
                return text
        return text

    head = f"{intro}\n"
    bullets = []
    for label, its in groups.items():
        note = f" (x{len(its)})" if len(its) > 1 else ""
        if any(i.get("known_ransomware") for i in its):
            note += " - used in ransomware"
        bullets.append(f"• {label}{note}")
    shown = bullets
    while len(shown) > 1:
        more = len(bullets) - len(shown)
        body = "\n".join(shown) + (f"\n• +{more} more" if more else "")
        text = head + "\n" + body + "\n\nif you run any of these, patch them first" + tail
        if tweet_length(text) <= TWEET_LIMIT:
            return text
        shown = shown[:-1]
    more = len(bullets) - 1
    return head + "\n" + bullets[0] + (f"\n• +{more} more" if more else "") + tail


def fact_lines(items, notes):
    out = []
    for i in sorted(items, key=lambda i: (i["date_added"], i["cve"])):
        flags = [fmt_epss(i.get("epss")), f"relevance {i['india_relevance']}"]
        if i.get("known_ransomware"):
            flags.append("known ransomware use")
        flags += notes.get(i["cve"], [])
        out.append(f"- {i['cve']} - {product_label(i)} | added {i['date_added']} | " + " | ".join(flags))
        out.append(f"  {i['name']} (CISA due date {i.get('due_date', '-')})")
    return out


def write(path, title, items, notes, intro):
    tweet = compose(items, intro)
    lines = [
        f"# {title} (DRAFT - rewrite in your own voice before posting)",
        "",
        "## Facts",
        "",
        *fact_lines(items, notes),
        "",
        f"## Rough draft ({tweet_length(tweet)}/{TWEET_LIMIT})",
        "",
        "```text",
        tweet,
        "```",
        "",
        "--",
        "Before posting: open each KEV entry and the vendor advisory, pick the one or",
        "two a defender here should care about and say why. Cut the rest.",
    ]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote draft -> {os.path.relpath(path, ROOT) if path.startswith(ROOT) else path}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--date", help="treat this date (YYYY-MM-DD) as today")
    ap.add_argument("--data", default=DATA)
    ap.add_argument("--drafts", default=DRAFTS)
    ap.add_argument("--lookback", type=int, default=LOOKBACK)
    ap.add_argument("--weekly", action="store_true", help="also write the weekly draft today")
    args = ap.parse_args(argv)

    today = dt.date.fromisoformat(args.date) if args.date else dt.datetime.now(dt.timezone.utc).date()
    items = [i for i in (load(args.data, {}) or {}).get("items", []) if relevant(i)]
    notes = tracker_context()

    daily_name = f"{today.isoformat()}.md"
    since = (today - dt.timedelta(days=args.lookback - 1)).isoformat()
    week_start = today - dt.timedelta(days=7)
    year, wk, _ = week_start.isocalendar()
    weekly_name = f"week-{year}-W{wk:02d}.md"
    # Files this run (re)writes do not count as earlier drafts.
    seen = already_drafted(args.drafts, skip={daily_name, weekly_name})
    new = [i for i in items if since <= i.get("date_added", "") <= today.isoformat() and i["cve"] not in seen]
    if new:
        n = len(new)
        intro = f"{n} new actively exploited bugs on CISA's KEV list that matter for indian orgs:"
        write(os.path.join(args.drafts, daily_name), f"KEV additions - {today.isoformat()}", new, notes, intro)
    else:
        print("No new India-relevant KEV entries; no daily draft written.")

    if args.weekly or today.weekday() == 0:
        start = week_start
        week = [i for i in items if start.isoformat() <= i.get("date_added", "") < today.isoformat()]
        if week:
            intro = f"last week's india-relevant adds to CISA's exploited list ({len(week)}):"
            write(os.path.join(args.drafts, weekly_name),
                  f"KEV week {year}-W{wk:02d} ({start.isoformat()} to {(today - dt.timedelta(days=1)).isoformat()})",
                  week, notes, intro)
        else:
            print("No India-relevant KEV entries last week; no weekly draft written.")


if __name__ == "__main__":
    main()
