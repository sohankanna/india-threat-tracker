#!/usr/bin/env python3
"""Refresh config/attack-techniques.json from MITRE's ATT&CK STIX data.

A small, committed reference (technique id -> name, tactics) for the
Enterprise and Mobile domains, so the layer builder and CI can check every
technique the tracker uses without downloading ATT&CK on every run. Run it by
hand when MITRE publishes a new ATT&CK version, then rebuild the layers.

    python scripts/update_attack_ref.py            # latest version
    python scripts/update_attack_ref.py 20.0       # a specific version
"""
import json
import os
import sys
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUT = os.path.join(ROOT, "config", "attack-techniques.json")
BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
DOMAINS = {"enterprise": "enterprise-attack", "mobile": "mobile-attack"}


def get_json(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return json.load(r)


def technique_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("T"):
            return ref["external_id"]
    return None


def extract(bundle):
    objs = bundle["objects"]
    by_stix = {o["id"]: o for o in objs}
    current, retired = {}, {}
    revoked_by = {r["source_ref"]: r["target_ref"] for r in objs
                  if r.get("type") == "relationship" and r.get("relationship_type") == "revoked-by"}
    for o in objs:
        if o.get("type") != "attack-pattern":
            continue
        tid = technique_id(o)
        if not tid:
            continue
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            target = by_stix.get(revoked_by.get(o["id"], ""))
            retired[tid] = technique_id(target) if target else None
            continue
        current[tid] = {"name": o["name"],
                        "tactics": sorted(p["phase_name"] for p in o.get("kill_chain_phases", []))}
    return dict(sorted(current.items())), dict(sorted(retired.items()))


def main(argv):
    index = get_json(f"{BASE}/index.json")
    out = {"source": "MITRE ATT&CK STIX data (github.com/mitre-attack/attack-stix-data)", "domains": {}}
    for key, coll in DOMAINS.items():
        c = next(c for c in index["collections"] if c["versions"][0]["url"].split("/")[-2] == coll)
        v = next((x for x in c["versions"] if x["version"] == argv[0]), None) if argv else c["versions"][0]
        if v is None:
            raise SystemExit(f"{coll}: version {argv[0]} not found")
        current, retired = extract(get_json(v["url"]))
        out["domains"][key] = {"version": v["version"], "modified": v["modified"][:10],
                               "techniques": current, "retired": retired}
        print(f"{coll} {v['version']}: {len(current)} techniques, {len(retired)} retired")
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1, ensure_ascii=False, sort_keys=False)
        f.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
