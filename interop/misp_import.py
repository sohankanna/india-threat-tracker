#!/usr/bin/env python3
"""Import the STIX bundle into a running MISP instance and record what MISP stored.

Used by .github/workflows/interop-misp.yml against a disposable MISP started from
the official MISP/misp-docker images. Uploads through MISP's own STIX 2 import
(PyMISP upload_stix -> /events/upload_stix/2), then reads the created event back
through the API and compares it with the bundle.

    python interop/misp_import.py --url https://localhost --key KEY \
        --bundle data/india-threat-tracker-stix.json --out misp-import-results

Writes <out>.json and <out>.md. Exits 1 if the upload fails or any indicator or
domain object is missing from what MISP stored. Known, accepted losses (see
STIX-GUIDE.md) are reported, not failed.
"""
import argparse
import collections
import json
import re
import sys
import time
import warnings

from pymisp import PyMISP

warnings.filterwarnings("ignore")  # self-signed certificate on the disposable instance


def wait_for(url, key, timeout=900):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            misp = PyMISP(url, key, ssl=False, timeout=30)
            version = misp.misp_instance_version
            if isinstance(version, dict) and version.get("version"):
                return misp, version["version"]
            last = version
        except Exception as e:  # not up yet
            last = e
        time.sleep(10)
    raise SystemExit(f"MISP did not become ready: {last}")


def compare(bundle, events):
    """What MISP stored (events as plain dicts) against the bundle."""
    by_type = collections.defaultdict(list)
    for o in bundle["objects"]:
        by_type[o["type"]].append(o)
    stored_text = json.dumps(events)
    attrs = [at for e in events for at in e.get("Attribute", [])]
    galaxies = [g for e in events for g in e.get("Galaxy", [])]
    clusters = collections.Counter()
    for g in galaxies:
        clusters[g["type"]] += len(g.get("GalaxyCluster", []))
    indicator_values = {re.findall(r"'([^']*)'\]$", i["pattern"])[0] for i in by_type["indicator"]}
    missing_sdos = {
        t: [o["name"] for o in by_type[t] if o["name"] not in stored_text]
        for t in ("campaign", "intrusion-set", "malware", "attack-pattern", "vulnerability")
    }
    return {
        "bundle_objects": {t: len(v) for t, v in sorted(by_type.items())},
        "events_created": len(events),
        "attributes": dict(collections.Counter(at["type"] for at in attrs)),
        "attributes_to_ids": sum(1 for at in attrs if at.get("to_ids")),
        "attributes_linked_to_campaign": sum(1 for at in attrs if any(g.get("type") == "stix-2.1-campaign" for g in at.get("Galaxy", []))),
        "galaxy_clusters": dict(clusters),
        "event_reports": sum(len(e.get("EventReport", [])) for e in events),
        "tags": sorted({t["name"] for e in events for t in e.get("Tag", [])}),
        "missing_indicators": sorted(indicator_values - {at["value"] for at in attrs}),
        "missing_objects": {k: v for k, v in missing_sdos.items() if v},
        "cluster_relations": sum(len(c.get("GalaxyClusterRelation", [])) for g in galaxies for c in g.get("GalaxyCluster", [])),
        "uses_relationships_in_bundle": sum(1 for r in by_type["relationship"] if r["relationship_type"] == "uses"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--bundle", required=True)
    ap.add_argument("--out", default="misp-import-results")
    a = ap.parse_args()

    misp, version = wait_for(a.url, a.key)
    with open(a.bundle, encoding="utf-8") as f:
        bundle = json.load(f)
    by_type = collections.defaultdict(list)
    for o in bundle["objects"]:
        by_type[o["type"]].append(o)

    started = time.time()
    response = misp.upload_stix(a.bundle, version="2")
    body = response.json() if hasattr(response, "json") else response
    upload_ok = getattr(response, "status_code", 200) < 400 and not (isinstance(body, dict) and body.get("errors"))

    # Find what the import created: events whose info is the report name.
    report_name = by_type["report"][0]["name"]
    found = misp.search(controller="events", eventinfo=report_name, pythonify=True) or []
    events = [json.loads(misp.get_event(e.id, pythonify=True).to_json()) for e in found]
    result = {"misp_version": version, "upload_ok": upload_ok,
              "upload_response": body if isinstance(body, (dict, list)) else str(body)[:2000],
              "seconds": round(time.time() - started, 1), **compare(bundle, events)}
    failed = not upload_ok or bool(result["missing_indicators"]) or bool(result["missing_objects"]) or not events
    attrs = result["attributes"]
    tags = result["tags"]
    missing_indicators = result["missing_indicators"]
    relations = result["cluster_relations"]

    with open(a.out + ".json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    md = [
        f"## MISP import: {'PASS' if not failed else 'FAIL'}",
        "",
        f"MISP {version}; bundle with {sum(result['bundle_objects'].values())} objects.",
        "",
        "| | |", "|---|---|",
        f"| Upload accepted | {upload_ok} |",
        f"| Events created | {len(events)} |",
        f"| Attributes (to_ids) | {sum(attrs.values())} ({result['attributes_to_ids']}): {attrs} |",
        f"| Galaxy clusters | {result['galaxy_clusters']} |",
        f"| Event reports | {result['event_reports']} |",
        f"| Tags | {', '.join(tags)} |",
        f"| Missing indicators | {missing_indicators or 'none'} |",
        f"| Missing objects | {result['missing_objects'] or 'none'} |",
        f"| \"uses\" relationships kept as cluster relations | {relations} of {result['uses_relationships_in_bundle']} (known loss) |",
    ]
    with open(a.out + ".md", "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    print("\n".join(md))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
