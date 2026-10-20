#!/usr/bin/env python3
"""Build data/india-threat-tracker-stix.json, a STIX 2.1 Bundle, from the
tracker's canonical feeds. The mapping is documented in STIX-GUIDE.md.

    python scripts/build_stix.py           # (re)write the bundle
    python scripts/build_stix.py --check   # exit 1 if the committed bundle is stale

Stable and reproducible
-----------------------
* Object ids are random UUIDv4 values, as STIX 2.1 recommends for domain and
  relationship objects, generated once per tracker key (a campaign id, a
  technique id, a relationship triple) and committed in stix/id-registry.json.
  Every later build reuses them, so the same record always has the same id.
  --check fails if a new object would need an id that is not committed yet.
* No wall-clock time is used. `created` comes from the record's own date
  (date_added, the assessment date), and the previous bundle is read back: an
  object whose content is unchanged keeps its `created` and `modified`; an
  object whose content changed keeps `created` and gets a later `modified`.
  Rebuilding unchanged data therefore produces a byte-identical file.

What is deliberately not exported
---------------------------------
* Infrastructure context (GitHub, Firebase, hosting providers): never an
  indicator.
* Android package names and Telegram bot handles: STIX has no well-fitting
  standard pattern for them; they are listed in the campaign description.
* Reference records that are not campaigns (category "Reference: ...").
* Timestamps the sources do not give: first_seen/last_seen are not set, and
  month-precision "first reported" dates stay in the description.
* Attribution relationships: intrusion sets carry reported attribution in
  their description; no attributed-to relationships are asserted.
"""
import hashlib
import json
import os
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone

import stix2
from stix2patterns.validator import validate as validate_pattern

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
OUT = os.path.join(ROOT, "data", "india-threat-tracker-stix.json")
REGISTRY = os.path.join(ROOT, "stix", "id-registry.json")


class StaleRegistry(Exception):
    pass


class IdRegistry:
    """tracker key -> STIX id, generated once (UUIDv4) and then reused."""

    def __init__(self, ids=None, allow_new=True):
        self.ids = dict(ids or {})
        self.allow_new = allow_new
        self.added = []

    def get(self, kind, key):
        k = f"{kind}:{key}"
        if k not in self.ids:
            if not self.allow_new:
                raise StaleRegistry(k)
            self.ids[k] = f"{kind}--{uuid.uuid4()}"
            self.added.append(k)
        return self.ids[k]

    @classmethod
    def load(cls, path=REGISTRY, allow_new=True):
        try:
            with open(path, encoding="utf-8") as f:
                return cls(json.load(f)["ids"], allow_new)
        except FileNotFoundError:
            return cls({}, allow_new)

    def save(self, path=REGISTRY):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"description": "STIX ids for India Threat Tracker objects. Generated once "
                                      "(UUIDv4) by scripts/build_stix.py and never changed; do not edit.",
                       "ids": dict(sorted(self.ids.items()))}, f, indent=2)
            f.write("\n")


IDS = IdRegistry()

# STIX 2.1 Appendix A, "High, Medium, Low" scale.
CONFIDENCE = {"high": 85, "medium": 50, "low": 15}

IOC_LABEL = {"domains": "Domain", "urls": "URL", "sha256": "SHA-256"}

# Names in known_tools that describe a capability rather than a specific family.
GENERIC_TOOLS = {"backdoor loaders"}



def sid(kind, key):
    return IDS.get(kind, key)


def day(value):
    """'2026-10-15' -> 2026-10-15T00:00:00Z (the date the tracker recorded it)."""
    return datetime.strptime(value[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)


def stamp(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$", re.I)
SHA256_RE = re.compile(r"^[a-f0-9]{64}$", re.I)
URL_RE = re.compile(r"^https?://[^\s'\\]+$", re.I)


def stix_string(value):
    """Quote a value as a STIX pattern string literal (escape \\ and ')."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def ioc_pattern(kind, raw):
    """(value, pattern) for an indicator, or ValueError if the value is not a
    well-formed value of that type. Values are checked before they are put in
    a pattern, so a malformed IOC can never change the pattern's logic."""
    if kind == "domains":
        value = refang(raw).lower()
        if not DOMAIN_RE.match(value):
            raise ValueError(f"not a domain name: {raw!r}")
        return value, f"[domain-name:value = {stix_string(value)}]"
    if kind == "urls":
        value = refang(raw)
        if not URL_RE.match(value):
            raise ValueError(f"not a URL: {raw!r}")
        return value, f"[url:value = {stix_string(value)}]"
    if kind == "sha256":
        value = raw.lower()
        if not SHA256_RE.match(value):
            raise ValueError(f"not a SHA-256 hash: {raw!r}")
        return value, f"[file:hashes.'SHA-256' = {stix_string(value)}]"
    return None


def refang(value):
    return value.replace("[.]", ".").replace("hxxps://", "https://").replace("hxxp://", "http://")


def load(name):
    with open(os.path.join(ROOT, "data", name), encoding="utf-8") as f:
        return json.load(f)


def sources_refs(sources):
    return [{"source_name": s["title"], "url": s["url"]} for s in sources or []]


def technique_ref(t):
    tid = t["id"]
    return {
        "source_name": "mitre-attack",
        "external_id": tid,
        "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
    }


class Builder:
    def __init__(self):
        self.objects = {}   # id -> dict (without created/modified)
        self.created = {}   # id -> earliest datetime the tracker asserted it
        self.updated = {}   # id -> date of the latest substantive record change

    def add(self, obj, created, updated=None):
        oid = obj["id"]
        if oid in self.objects and self.objects[oid] != obj:
            raise ValueError(f"conflicting definitions for {oid}")
        self.objects[oid] = obj
        self.created[oid] = min(created, self.created.get(oid, created))
        upd = max(updated or created, created)
        self.updated[oid] = max(upd, self.updated.get(oid, upd))
        return oid

    def relate(self, src, rel, dst, created, updated=None):
        return self.add({
            "type": "relationship",
            "id": sid("relationship", f"{src}|{rel}|{dst}"),
            "relationship_type": rel,
            "source_ref": src,
            "target_ref": dst,
        }, created, updated)


def build_objects(smishing, apt, assessment, kev):
    b = Builder()
    first = min(day(i["date_added"]) for i in smishing["items"] + apt["items"])

    identity = b.add({
        "type": "identity",
        "id": sid("identity", "india-threat-tracker"),
        "name": "India Threat Tracker",
        "identity_class": "system",
        "description": ("Open threat intelligence on threats to India, maintained by Sohan Kanna. "
                        "Data licensed CC BY 4.0. https://www.sohankanna.com/tracker"),
        "contact_information": "https://github.com/sohankanna/india-threat-tracker",
    }, first)

    def attack_pattern(t, created, updated):
        return b.add({
            "type": "attack-pattern",
            "id": sid("attack-pattern", t["id"]),
            "name": t["name"],
            "external_references": [technique_ref(t)],
        }, created, updated)

    def malware(name, created, updated, mitre=None):
        refs = [{"source_name": "mitre-attack", "external_id": mitre["id"], "url": mitre["url"]}] if mitre else None
        obj = {"type": "malware", "id": sid("malware", name.lower()), "name": name, "is_family": True}
        if refs:
            obj["external_references"] = refs
        return b.add(obj, created, updated)

    record_ids = {}

    # ── Campaigns ──
    for c in smishing["items"]:
        if c.get("category", "").lower().startswith("reference"):
            continue
        created, updated = day(c["date_added"]), day(c.get("last_updated") or c["date_added"])
        lines = [c.get("summary", "")]
        lines.append(f"Status in the tracker: {c.get('status', 'unknown')} (describes the reporting, "
                     "not whether infrastructure is live).")
        if c.get("first_seen"):
            lines.append(f"First reported: {c['first_seen']} (precision as given by the source).")
        if c.get("attribution"):
            lines.append(f"Attribution as reported: {c['attribution']}.")
        other = []
        for kind, label in (("package_names", "Android package"), ("telegram_bots", "Telegram bot")):
            other += [f"{label} {v}" for v in (c.get("iocs") or {}).get(kind, [])]
        if other:
            lines.append("Also reported, not expressed as STIX patterns: " + "; ".join(other) + ".")
        infra = [v for vals in (c.get("infrastructure") or {}).values() for v in vals]
        if infra:
            lines.append("Infrastructure context, not indicators (legitimate or shared services the "
                         "campaign abused; do not block): " + "; ".join(infra) + ".")
        if c.get("key_findings"):
            lines.append("Key findings: " + " ".join(c["key_findings"]))
        cid = b.add({
            "type": "campaign",
            "id": sid("campaign", c["id"]),
            "name": c["title"],
            "description": "\n\n".join(l for l in lines if l),
            "confidence": CONFIDENCE[c["confidence"]],
            "external_references": [{"source_name": "india-threat-tracker", "external_id": c["id"],
                                     "url": f"https://www.sohankanna.com/tracker#campaign-{c['id']}"}]
                                   + sources_refs(c.get("sources")),
        }, created, updated)
        record_ids[("campaign", c["id"])] = cid
        for t in c.get("attack") or []:
            b.relate(cid, "uses", attack_pattern(t, created, updated), created, updated)
        if "ghostbat" in c["title"].lower():
            b.relate(cid, "uses", malware("GhostBat RAT", created, updated), created, updated)

        # Indicators: only types with an unambiguous standard pattern.
        for kind, values in (c.get("iocs") or {}).items():
            for v in values:
                built = ioc_pattern(kind, v)
                if built is None:
                    continue
                value, pattern = built
                ok, errors = validate_pattern(pattern, ret_errs=True)
                if not ok:
                    raise ValueError(f"invalid pattern {pattern}: {errors}")
                iid = b.add({
                    "type": "indicator",
                    "id": sid("indicator", f"{kind}:{value}"),
                    "name": f"{IOC_LABEL[kind]} {v}",
                    "description": (f"Reported by {', '.join(s['title'] for s in c.get('sources', []))} "
                                    f"for the campaign '{c['title']}'. As reported; not re-validated. "
                                    "valid_from is the date the tracker began publishing it, not an "
                                    "observation date."),
                    "indicator_types": ["malicious-activity"],
                    "pattern": pattern,
                    "pattern_type": "stix",
                    "pattern_version": "2.1",
                    "valid_from": stamp(created),
                    "confidence": CONFIDENCE[c["confidence"]],
                    "external_references": sources_refs(c.get("sources")),
                }, created, updated)
                b.relate(iid, "indicates", cid, created, updated)

    # ── Intrusion sets ──
    for a in apt["items"]:
        created, updated = day(a["date_added"]), day(a.get("last_updated") or a["date_added"])
        desc = [a.get("summary", "")]
        if a.get("suspected_origin"):
            desc.append(f"Reported attribution: {a['suspected_origin']}. {a.get('attribution_note', '')}".strip())
        if a.get("key_findings"):
            desc.append("Key findings: " + " ".join(a["key_findings"]))
        refs = [{"source_name": "india-threat-tracker", "external_id": a["id"],
                 "url": f"https://www.sohankanna.com/tracker#actor-{a['id']}"}]
        if a.get("mitre_group"):
            refs.append({"source_name": "mitre-attack", "external_id": a["mitre_group"]["id"],
                         "url": a["mitre_group"]["url"]})
        obj = {
            "type": "intrusion-set",
            "id": sid("intrusion-set", a["id"]),
            "name": a["actor"],
            "description": "\n\n".join(d for d in desc if d),
            "confidence": CONFIDENCE[a["confidence"]],
            "external_references": refs + sources_refs(a.get("sources")),
        }
        if a.get("aliases"):
            obj["aliases"] = list(a["aliases"])
        iset = b.add(obj, created, updated)
        record_ids[("actor", a["id"])] = iset
        for t in a.get("attack") or []:
            b.relate(iset, "uses", attack_pattern(t, created, updated), created, updated)
        mitre_sw = {s["name"].lower(): s for s in a.get("software") or []}
        for name in a.get("known_tools") or []:
            if name.lower() in GENERIC_TOOLS:
                continue
            m = malware(name, created, updated, mitre_sw.get(name.lower()))
            b.relate(iset, "uses", m, created, updated)

    # ── Vulnerabilities referenced by the assessment ──
    kev_by_id = {i["cve"]: i for i in kev["items"]}
    a_date = day(assessment["updated"])
    for item in assessment["items"]:
        for ev in item.get("evidence") or []:
            if ev["type"] != "cve":
                continue
            k = kev_by_id.get(ev["id"])
            if k is None:
                # Never block the feed update over this; tests/test_assessment.py
                # fails the PR check so the assessment gets corrected.
                print(f"::warning::assessment cites {ev['id']}, which is not in the current KEV catalog")
                description = "Cited by the analyst assessment. Not in the current CISA KEV catalog."
            else:
                description = (f"{k.get('name', '')}. {k.get('description', '')} "
                               f"In CISA KEV since {k['date_added']}"
                               + (", with known ransomware use." if k.get("known_ransomware") else ".")).strip()
            obj = {
                "type": "vulnerability",
                "id": sid("vulnerability", ev["id"]),
                "name": ev["id"],
                "description": description,
                "external_references": [
                    {"source_name": "cve", "external_id": ev["id"]},
                    {"source_name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{ev['id']}"},
                    {"source_name": "CISA KEV", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
                ],
            }
            record_ids[("cve", ev["id"])] = b.add(obj, a_date)

    # ── The monthly assessment as a Report ──
    refs, ext = [], []
    body = [assessment["summary"]]
    for item in sorted(assessment["items"], key=lambda i: i["rank"]):
        body.append(f"{item['rank']}. {item['title']} ({item['severity']}): {item['why']}")
        for ev in item.get("evidence") or []:
            key = (ev["type"], ev.get("id"))
            if key in record_ids:
                refs.append(record_ids[key])
            elif ev["type"] == "source":
                ext.append({"source_name": ev["title"], "url": ev["url"]})
            elif ev["type"] == "detection":
                ext.append({"source_name": f"India Threat Tracker detection {ev['id']}",
                            "url": f"https://github.com/sohankanna/india-threat-tracker/blob/main/detections/sigma/{ev['id']}.yml"})
        for link in item.get("links") or []:
            ext.append({"source_name": link["title"], "url": link["url"]})
    seen, uniq_ext = set(), []
    for e in ext:
        if e["url"] not in seen:
            seen.add(e["url"])
            uniq_ext.append(e)
    b.add({
        "type": "report",
        "id": sid("report", f"assessment:{assessment['period']}"),
        "name": f"India threat assessment, {assessment['period']}",
        "description": ("Analyst assessment by " + assessment["analyst"] + ": judgement over the tracker's "
                        "feeds, not source-reported fact.\n\n" + "\n\n".join(body)),
        "report_types": ["threat-report"],
        "published": stamp(a_date),
        "object_refs": sorted(set(refs)),
        "external_references": uniq_ext,
    }, a_date)
    return b


def content_hash(obj):
    core = {k: v for k, v in obj.items() if k not in ("created", "modified")}
    return hashlib.sha256(json.dumps(core, sort_keys=True).encode()).hexdigest()


def parse_ts(value):
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


def finalise(b, previous):
    """Attach created/modified, reusing the previous bundle's history."""
    prev = {o["id"]: o for o in (previous or {}).get("objects", [])}
    identity = sid("identity", "india-threat-tracker")
    out = []
    for oid, core in b.objects.items():
        obj = dict(core)
        obj["spec_version"] = "2.1"
        if obj["type"] != "identity":
            obj["created_by_ref"] = identity
        obj["object_marking_refs"] = [stix2.TLP_WHITE.id]
        old = prev.get(oid)
        if old and content_hash(old) == content_hash(obj):
            obj["created"], obj["modified"] = old["created"], old["modified"]
        elif old:
            bumped = max(b.updated[oid], parse_ts(old["modified"]) + timedelta(milliseconds=1))
            obj["created"], obj["modified"] = old["created"], stamp(bumped)
        else:
            obj["created"] = stamp(b.created[oid])
            obj["modified"] = stamp(max(b.updated[oid], b.created[oid]))
        stix2.parse(obj, allow_custom=False)  # property and vocabulary checks
        out.append(obj)
    out.append(json.loads(stix2.TLP_WHITE.serialize()))
    out.sort(key=lambda o: (o["type"], o["id"]))
    # Same objects as before: keep the bundle id. Different: a new UUIDv4.
    unchanged = previous and previous.get("objects") == out
    bundle_id = previous["id"] if unchanged else f"bundle--{uuid.uuid4()}"
    return {"type": "bundle", "id": bundle_id, "objects": out}


def build(previous=None, registry=None, data=None):
    """Build the bundle. `data` overrides the feeds (tests); `registry` the ids."""
    global IDS
    IDS = registry if registry is not None else IdRegistry.load()
    d = data or {n: load(f"{n}.json") for n in ("smishing-apk", "apt-campaigns", "assessment", "exploited-cve")}
    b = build_objects(d["smishing-apk"], d["apt-campaigns"], d["assessment"], d["exploited-cve"])
    return finalise(b, previous)


def render(bundle):
    return json.dumps(bundle, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv):
    try:
        with open(OUT, encoding="utf-8") as f:
            current_text = f.read()
        previous = json.loads(current_text)
    except FileNotFoundError:
        current_text, previous = None, None
    check = "--check" in argv
    registry = IdRegistry.load(allow_new=not check)
    try:
        text = render(build(previous, registry))
    except StaleRegistry as e:
        print(f"::error::No committed STIX id for {e}: run python scripts/build_stix.py and commit stix/id-registry.json")
        return 1
    if check:
        if text != current_text:
            print("::error::data/india-threat-tracker-stix.json is stale: run python scripts/build_stix.py")
            return 1
        print("OK   STIX bundle matches the canonical feeds")
        return 0
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    if registry.added:
        registry.save()
        print(f"Registered {len(registry.added)} new STIX id(s) in stix/id-registry.json")
    counts = {}
    for o in json.loads(text)["objects"]:
        counts[o["type"]] = counts.get(o["type"], 0) + 1
    print("Wrote data/india-threat-tracker-stix.json: " + ", ".join(f"{v} {k}" for k, v in sorted(counts.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
