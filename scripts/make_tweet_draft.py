#!/usr/bin/env python3
"""Generate a factual *draft* summary of today's notable KEV additions.

This is NOT post-ready. It assembles the facts so the maintainer can rewrite
them in their own voice before posting. Writes drafts/<date>.md only if there is
something India-relevant and new today.
"""
import datetime as dt
import json
import os

ROOT = os.path.join(os.path.dirname(__file__), "..")
DATA = os.path.join(ROOT, "data", "exploited-cve.json")
DRAFTS = os.path.join(ROOT, "drafts")


def main():
    with open(DATA) as f:
        data = json.load(f)
    today = dt.date.today().isoformat()

    new_hi = [i for i in data.get("items", [])
              if i.get("date_added") == today and i.get("india_relevance") == "high"]
    if not new_hi:
        print("No new high-relevance KEV entries today; no draft written.")
        return

    lines = [
        f"# Draft - {today} (REWRITE IN YOUR OWN VOICE before posting)",
        "",
        f"{len(new_hi)} new actively-exploited CVE(s) added to CISA KEV today that",
        "matter for Indian orgs:",
        "",
    ]
    for i in new_hi:
        ep = f" | EPSS {i['epss']:.0%}" if i.get("epss") else ""
        ransom = " | ransomware" if i.get("known_ransomware") else ""
        lines.append(f"- {i['cve']} - {i['vendor']} {i['product']}{ep}{ransom}")
        lines.append(f"  due {i.get('due_date','-')} | {i['name']}")
    lines += [
        "",
        "Full tracker: https://www.sohankanna.com/research  (#threatintel #India #CVE)",
        "",
        "--",
        "Notes for you: pick the 1-2 that actually matter, say why a defender here",
        "should care, and cut the rest. Keep it human.",
    ]

    os.makedirs(DRAFTS, exist_ok=True)
    path = os.path.join(DRAFTS, f"{today}.md")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote draft -> {path}")


if __name__ == "__main__":
    main()
