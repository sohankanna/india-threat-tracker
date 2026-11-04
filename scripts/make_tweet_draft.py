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
<<<<<<< ours
DRAFTS = os.path.join(ROOT, "drafts")

=======
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

>>>>>>> theirs

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
