#!/usr/bin/env python3
"""Build data/kev-affected.json: the affected products and versions for every
CISA KEV CVE, taken from the official CVE records (CVE Project cvelistV5).

This is the vulnerability side of the Exposure Matcher. It holds no inventory
data and never sees one: users' inventories are matched against this file in
their own browser (or with the local CLI).

    python scripts/build_affected.py                # new CVEs + this week's refresh slice
    python scripts/build_affected.py --fetch all    # every KEV CVE
    python scripts/build_affected.py --offline      # no network: re-sync with the KEV feed
    python scripts/build_affected.py --from-dir D   # read records from D/<CVE>.json (tests)

What is kept, and how
---------------------
For each CVE, every `affected` entry from the CNA container and any ADP
container (for example CISA's vulnrichment), as the CNA wrote it: vendor,
product, defaultStatus, versions (version, status, lessThan,
lessThanOrEqual, versionType, changes), cpes, platforms, modules. Nothing is
interpreted here; the matcher decides what is comparable and says so.

Fetching is best-effort. A failed fetch keeps the previous entry (or records
"unavailable") and is counted in `coverage`; it never stops the feed update.
Records are refreshed on a rotation (one seventh of the cache per day, by CVE
id) so corrections by CNAs are picked up within a week without refetching
everything twice a day.

The output depends only on the KEV feed and the record contents, so a rebuild
with nothing new produces an identical file.
"""
import concurrent.futures as cf
import datetime as dt
import json
import os
import sys
import urllib.request
import zlib

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
KEV = os.path.join(ROOT, "data", "exploited-cve.json")
OUT = os.path.join(ROOT, "data", "kev-affected.json")
CVELIST = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
REFRESH_DAYS = 7

VERSION_KEYS = {"version": "version", "status": "status", "lessThan": "less_than",
                "lessThanOrEqual": "less_than_or_equal", "versionType": "version_type"}


def record_path(cve):
    _, year, num = cve.split("-")
    return f"{year}/{num[:-3]}xxx/{cve}.json"


def fetch_record(cve):
    with urllib.request.urlopen(f"{CVELIST}/{record_path(cve)}", timeout=30) as r:
        return json.load(r)


def normalise_versions(versions):
    out = []
    for v in versions or []:
        n = {VERSION_KEYS[k]: str(val) for k, val in v.items() if k in VERSION_KEYS and val is not None}
        if v.get("changes"):
            n["changes"] = [{"at": str(c.get("at")), "status": c.get("status")} for c in v["changes"]]
        if n:
            out.append(n)
    return out


def normalise_affected(entry, source):
    p = {
        "source": source,
        "vendor": entry.get("vendor") or "",
        "product": entry.get("product") or entry.get("packageName") or "",
        "default_status": entry.get("defaultStatus") or "unknown",
        "versions": normalise_versions(entry.get("versions")),
    }
    for key in ("cpes", "platforms", "modules"):
        if entry.get(key):
            p[key] = sorted(set(entry[key])) if key == "cpes" else list(entry[key])
    return p


def normalise(cve, record):
    """CVE JSON 5 record -> the tracker's entry for that CVE."""
    meta = record.get("cveMetadata", {})
    state = meta.get("state", "UNKNOWN")
    entry = {"cve": cve, "record_state": state, "record_updated": meta.get("dateUpdated")}
    if state != "PUBLISHED":
        entry["products"] = []
        return entry
    containers = record.get("containers", {})
    products = [normalise_affected(a, "cna") for a in containers.get("cna", {}).get("affected", [])]
    for adp in containers.get("adp", []):
        name = (adp.get("providerMetadata") or {}).get("shortName") or "adp"
        products += [normalise_affected(a, f"adp:{name}") for a in adp.get("affected", [])]
    entry["products"] = products
    return entry


def due_for_refresh(cve, today):
    return zlib.crc32(cve.encode()) % REFRESH_DAYS == today.toordinal() % REFRESH_DAYS


def build(kev_items, previous, getter, mode, today):
    """Return the new file contents.

    mode: "offline" (no fetching), "rotate" (missing + today's slice) or "all".
    getter(cve) returns a CVE record or raises."""
    prev = {e["cve"]: e for e in (previous or {}).get("items", [])}
    cves = sorted({i["cve"] for i in kev_items})
    if mode == "offline":
        todo = []
    elif mode == "all":
        todo = cves
    else:
        todo = [c for c in cves if c not in prev or prev[c].get("record_state") == "unavailable"
                or due_for_refresh(c, today)]

    fetched, failures = {}, 0

    def one(cve):
        try:
            return cve, normalise(cve, getter(cve)), None
        except Exception as e:  # best-effort
            return cve, None, e

    if todo:
        with cf.ThreadPoolExecutor(8) as ex:
            for cve, entry, err in ex.map(one, todo):
                if entry is not None:
                    fetched[cve] = entry
                else:
                    failures += 1
                    print(f"::warning::CVE record for {cve} could not be fetched: {err}")

    items = []
    for cve in cves:
        if cve in fetched:
            items.append(fetched[cve])
        elif cve in prev:
            items.append(prev[cve])
        else:
            items.append({"cve": cve, "record_state": "unavailable", "record_updated": None, "products": []})

    with_versions = sum(1 for e in items if any(p.get("versions") or p.get("cpes") for p in e.get("products", [])))
    return {
        "feed": "kev-affected",
        "description": ("Affected products and versions for every CISA KEV CVE, as written by the CVE "
                        "Numbering Authority (and ADPs such as CISA vulnrichment) in the official CVE "
                        "records. Not interpreted: see EXPOSURE-MATCHER.md for how versions are compared."),
        "source": "CVE Project cvelistV5 (https://github.com/CVEProject/cvelistV5)",
        "kev_generated_at": None,  # set by the caller from the KEV feed
        "coverage": {
            "kev_cves": len(items),
            "records_published": sum(1 for e in items if e["record_state"] == "PUBLISHED"),
            "with_version_entries": with_versions,
            "unavailable": sum(1 for e in items if e["record_state"] == "unavailable"),
            "fetch_failures_this_run": failures,
        },
        "items": items,
    }


def render(obj):
    return json.dumps(obj, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv):
    with open(KEV, encoding="utf-8") as f:
        kev = json.load(f)
    try:
        with open(OUT, encoding="utf-8") as f:
            previous = json.load(f)
    except FileNotFoundError:
        previous = None

    if "--from-dir" in argv:
        d = argv[argv.index("--from-dir") + 1]

        def getter(cve):
            with open(os.path.join(d, f"{cve}.json"), encoding="utf-8") as f:
                return json.load(f)
        mode = "all"
    else:
        getter = fetch_record
        mode = "offline" if "--offline" in argv else ("all" if "all" in argv else "rotate")

    today = dt.date.fromisoformat(kev["generated_at"][:10]) if kev.get("generated_at") else dt.date.today()
    out = build(kev["items"], previous, getter, mode, today)
    out["kev_generated_at"] = kev.get("generated_at")
    if previous and previous.get("kev_generated_at") == out["kev_generated_at"] and mode == "offline":
        out["coverage"]["fetch_failures_this_run"] = previous["coverage"].get("fetch_failures_this_run", 0)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(render(out))
    c = out["coverage"]
    print(f"Wrote data/kev-affected.json: {c['kev_cves']} KEV CVEs, {c['with_version_entries']} with version entries, "
          f"{c['unavailable']} unavailable, {c['fetch_failures_this_run']} fetch failures")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
