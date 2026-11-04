#!/usr/bin/env python3
"""Build misp-feed/: the tracker as a native MISP feed.

A MISP instance can subscribe to it directly (Sync Actions -> Feeds -> Add
Feed, source format "MISP Feed", URL below) and pull updates on its own
schedule, instead of importing the STIX bundle by hand.

    https://raw.githubusercontent.com/sohankanna/india-threat-tracker/main/misp-feed

Layout (the format MISP's own feed generator writes):
    misp-feed/manifest.json     event uuid -> summary (MISP reads this first)
    misp-feed/hashes.csv        md5(attribute value),event uuid (for caching)
    misp-feed/<uuid>.json       one {"Event": {...}} per event

Events:
  * one per fraud campaign in data/smishing-apk.json that has indicators;
    only the campaign's own `iocs` are exported, never `infrastructure`
    context (same rule as data/iocs.txt);
  * one for the India-relevant KEV watchlist (high relevance): vulnerability
    attributes, not for blocking (to_ids false);
  * one for new lookalike-domain leads (data/lookalike-domains.json, last 30
    days): domain attributes with to_ids false, because they are unverified.

Values are re-fanged, as in the STIX bundle: MISP has to correlate real
values. The human-readable exports (data/iocs.txt, iocs.csv) stay defanged.

Deterministic: uuids are derived from the tracker's own ids (uuid5) and
timestamps from the dates in the data, so unchanged data rebuilds
byte-identically.

    python scripts/build_misp_feed.py           # write misp-feed/
    python scripts/build_misp_feed.py --check   # exit 1 if misp-feed/ is stale
"""
import calendar
import datetime as dt
import hashlib
import json
import os
import re
import sys
import uuid

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "misp-feed")
NS = uuid.UUID("6f1b3c2e-9d4a-5b7e-8c1f-2a3d4e5f6a7b")  # fixed namespace for this project
ORG = {"name": "India Threat Tracker", "uuid": str(uuid.uuid5(NS, "org"))}
REPO = "https://github.com/sohankanna/india-threat-tracker"

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PACKAGE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")

# iocs key -> (MISP type, category, to_ids, comment)
ATTR = {
    "domains": ("domain", "Network activity", True, ""),
    "urls": ("url", "Network activity", True, ""),
    "sha256": ("sha256", "Payload delivery", True, "Malicious APK"),
    "package_names": ("text", "Payload delivery", False, "Android package name"),
    "telegram_bots": ("text", "Network activity", False, "Telegram bot handle used by the campaign"),
}
THREAT = {"high": "2", "medium": "2", "low": "3"}  # MISP: 1 high, 2 medium, 3 low, 4 undefined


def load(name):
    with open(os.path.join(ROOT, "data", name), encoding="utf-8") as f:
        return json.load(f)


def refang(v):
    return v.replace("[.]", ".").replace("hxxps://", "https://").replace("hxxp://", "http://")


def epoch(day):
    """'2026-10-20' or '2026-10' -> epoch seconds (UTC midnight), as a string like MISP."""
    parts = [int(p) for p in day.split("-")] + [1, 1]
    return str(calendar.timegm(dt.date(parts[0], parts[1], parts[2]).timetuple()))


def full_date(*candidates):
    """First usable candidate, in order; a month ('2025-09') becomes its 1st."""
    for c in candidates:
        if c and re.fullmatch(r"\d{4}-\d{2}-\d{2}", c):
            return c
        if c and re.fullmatch(r"\d{4}-\d{2}", c):
            return c + "-01"
    raise ValueError(f"no usable date in {candidates}")


def value_for(kind, raw):
    v = refang(raw).strip()
    if kind == "domains":
        v = v.lower()
        if not DOMAIN_RE.match(v):
            raise ValueError(f"not a domain: {raw!r}")
    elif kind == "sha256":
        v = v.lower()
        if not SHA256_RE.match(v):
            raise ValueError(f"not a SHA-256: {raw!r}")
    elif kind == "package_names" and not PACKAGE_RE.match(v):
        raise ValueError(f"not an Android package name: {raw!r}")
    return v


def attribute(event_key, kind, value, ts, comment=None):
    mtype, category, to_ids, default_comment = ATTR[kind] if kind in ATTR else kind
    return {
        "uuid": str(uuid.uuid5(NS, f"{event_key}/{mtype}/{value}")),
        "type": mtype,
        "category": category,
        "value": value,
        "to_ids": to_ids,
        "comment": comment if comment is not None else default_comment,
        "timestamp": ts,
        "distribution": "5",
        "disable_correlation": False,
    }


def event(key, info, date, ts, threat, tags, attributes):
    return {
        "uuid": str(uuid.uuid5(NS, key)),
        "info": info,
        "date": date,
        "threat_level_id": threat,
        "analysis": "2",
        "timestamp": ts,
        "publish_timestamp": ts,
        "published": True,
        "Orgc": ORG,
        "Tag": [{"name": t} for t in tags],
        "Attribute": attributes,
    }


def campaign_events(smishing):
    out = []
    for c in smishing.get("items", []):
        iocs = c.get("iocs") or {}
        if not any(iocs.get(k) for k in ATTR):
            continue
        key = f"campaign/{c['id']}"
        ts = epoch(full_date(c.get("last_verified"), c.get("last_updated"), c.get("date_added")))
        src = (c.get("sources") or [{}])[0]
        attrs = []
        for kind in ATTR:
            for raw in iocs.get(kind, []):
                attrs.append(attribute(key, kind, value_for(kind, raw), ts))
        for s in c.get("sources") or []:
            attrs.append(attribute(key, ("link", "External analysis", False, "Source"), s["url"], ts, s["title"]))
        attrs.append(attribute(key, ("link", "External analysis", False, ""),
                               f"https://www.sohankanna.com/tracker#campaign-{c['id']}", ts,
                               "India Threat Tracker entry"))
        tags = ["tlp:clear", f'india-threat-tracker:id="{c["id"]}"',
                f'india-threat-tracker:confidence="{c.get("confidence", "unknown")}"']
        tags += [f'india-threat-tracker:tag="{t}"' for t in c.get("tags", [])]
        info = f"India Threat Tracker: {c['title']}"
        if src.get("title"):
            info += f" (source: {src['title'].split(' - ')[0]})"
        out.append(event(key, info, full_date(c.get("first_seen"), c.get("date_added")), ts,
                         THREAT.get(c.get("confidence"), "4"), tags, attrs))
    return out


def watchlist_event(watchlist):
    high = sorted((i for i in watchlist.get("items", []) if i.get("india_relevance") == "high"),
                  key=lambda i: (i["date_added"], i["cve"]))
    if not high:
        return []
    key = "watchlist/high"
    latest = max(i["date_added"] for i in high)
    ts = epoch(latest)
    attrs = []
    for i in high:
        bits = [f"{i['vendor']} {i['product']}", f"KEV {i['date_added']}"]
        if i.get("epss") is not None:
            bits.append(f"EPSS {i['epss']:.3f}")
        if i.get("known_ransomware"):
            bits.append("known ransomware use")
        attrs.append(attribute(key, ("vulnerability", "External analysis", False, ""), i["cve"],
                               epoch(i["date_added"]), "; ".join(bits)))
    tags = ["tlp:clear", 'india-threat-tracker:id="watchlist-high"']
    return [event(key, "India Threat Tracker: actively exploited vulnerabilities, high India relevance "
                       "(CISA KEV + EPSS)", latest, ts, "2", tags, attrs)]


def lookalike_event(feed):
    """New lookalike-domain leads (last 30 days, still registered). Context only: to_ids off."""
    if not feed or not feed.get("items"):
        return []
    since = (dt.date.fromisoformat(feed["generated_at"]) - dt.timedelta(days=30)).isoformat()
    leads = [i for i in feed["items"] if i["active"] and not i["baseline"] and i["first_seen"] >= since]
    if not leads:
        return []
    key = "lookalikes/new"
    latest = max(i["first_seen"] for i in leads)
    attrs = []
    for i in sorted(leads, key=lambda i: (i["first_seen"], i["domain"])):
        note = f"Lookalike of {i['brand_name']} ({i['fuzzer']}), first seen {i['first_seen']}"
        if i.get("first_cert"):
            note += f", first TLS certificate {i['first_cert']}"
        attrs.append(attribute(key, ("domain", "Network activity", False, ""), refang(i["domain"]),
                               epoch(i["first_seen"]), note + ". Lead, not verified."))
    tags = ["tlp:clear", 'india-threat-tracker:id="lookalike-leads"']
    return [event(key, "India Threat Tracker: new lookalike domains of Indian banks, payment apps and "
                       "government sites (leads, not verified)", latest, epoch(latest), "3", tags, attrs)]


def build():
    lookalikes = None
    if os.path.exists(os.path.join(ROOT, "data", "lookalike-domains.json")):
        lookalikes = load("lookalike-domains.json")
    events = (campaign_events(load("smishing-apk.json")) + watchlist_event(load("watchlist.json"))
              + lookalike_event(lookalikes))
    files = {}
    manifest = {}
    hashes = []
    for e in sorted(events, key=lambda e: e["uuid"]):
        files[f"{e['uuid']}.json"] = json.dumps({"Event": e}, indent=1, ensure_ascii=False) + "\n"
        manifest[e["uuid"]] = {k: e[k] for k in ("info", "date", "analysis", "threat_level_id", "timestamp",
                                                  "publish_timestamp", "Orgc", "Tag")}
        for a in e["Attribute"]:
            hashes.append(f"{hashlib.md5(a['value'].encode()).hexdigest()},{e['uuid']}")
    files["manifest.json"] = json.dumps(manifest, indent=1, ensure_ascii=False, sort_keys=True) + "\n"
    files["hashes.csv"] = "\n".join(sorted(hashes)) + "\n"
    return files


def main(argv):
    files = build()
    if "--check" in argv:
        on_disk = set(os.listdir(OUT)) if os.path.isdir(OUT) else set()
        on_disk.discard("README.md")
        stale = sorted(set(files) ^ on_disk)
        for name, text in files.items():
            path = os.path.join(OUT, name)
            if os.path.exists(path):
                with open(path, encoding="utf-8", newline="") as f:
                    if f.read().replace("\r\n", "\n") != text:
                        stale.append(name)
        if stale:
            print(f"FAIL misp-feed/ is stale ({', '.join(sorted(set(stale))[:5])}). Run: python scripts/build_misp_feed.py")
            return 1
        print(f"OK   misp-feed/ matches the data ({len(files) - 2} events)")
        return 0
    os.makedirs(OUT, exist_ok=True)
    for name in os.listdir(OUT):
        if name not in files and name != "README.md":
            os.remove(os.path.join(OUT, name))
    for name, text in files.items():
        with open(os.path.join(OUT, name), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    print(f"Wrote misp-feed/ ({len(files) - 2} events)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
