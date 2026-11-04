#!/usr/bin/env python3
"""Subscribe a running MISP instance to misp-feed/ and check what it pulled.

Used by .github/workflows/interop-misp.yml. The feed directory is copied into
the MISP container first and added as a *local* feed, so the test goes through
MISP's own feed code (manifest -> events) exactly as a subscription to the
GitHub URL would, without the container needing internet access.

    python interop/misp_feed_import.py --url https://localhost --key KEY \
        --feed-dir misp-feed --container-path /tmp/itt-feed --out misp-feed-results

Writes <out>.json and <out>.md. Exits 1 if any event or attribute in the feed
is missing from MISP after the fetch.
"""
import argparse
import json
import os
import sys
import time
import warnings

from pymisp import MISPFeed, PyMISP

warnings.filterwarnings("ignore")  # self-signed certificate on the disposable instance


def expected(feed_dir):
    with open(os.path.join(feed_dir, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    out = {}
    for uid in manifest:
        with open(os.path.join(feed_dir, f"{uid}.json"), encoding="utf-8") as f:
            e = json.load(f)["Event"]
        out[uid] = {"info": e["info"], "values": sorted(a["value"] for a in e["Attribute"])}
    return out


def stored(misp, uid):
    try:
        e = misp.get_event(uid, pythonify=True)
    except Exception:
        return None
    if not hasattr(e, "uuid"):
        return None
    return sorted(a.value for a in e.attributes)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--feed-dir", default="misp-feed")
    ap.add_argument("--container-path", required=True, help="where the feed was copied inside the MISP container")
    ap.add_argument("--out", default="misp-feed-results")
    ap.add_argument("--timeout", type=int, default=600)
    a = ap.parse_args()

    want = expected(a.feed_dir)
    misp = PyMISP(a.url, a.key, ssl=False, timeout=60)
    feed = MISPFeed()
    feed.from_dict(name="India Threat Tracker (interop test)", provider="India Threat Tracker",
                   url=a.container_path, source_format="misp", input_source="local",
                   enabled=True, caching_enabled=False, distribution=0)
    added = misp.add_feed(feed, pythonify=True)
    if not hasattr(added, "id"):
        raise SystemExit(f"MISP refused the feed: {added}")
    fetch = misp.fetch_feed(added.id)

    started = time.time()
    got = {}
    while time.time() - started < a.timeout:
        got = {uid: stored(misp, uid) for uid in want}
        if all(got[uid] == want[uid]["values"] for uid in want):
            break
        time.sleep(15)

    rows, failed = [], False
    for uid, w in want.items():
        g = got.get(uid)
        status = "ok" if g == w["values"] else ("missing event" if g is None else
                                                 f"{len(set(w['values']) - set(g))} attribute(s) missing")
        failed |= status != "ok"
        rows.append({"uuid": uid, "info": w["info"], "expected": len(w["values"]),
                     "stored": 0 if g is None else len(g), "status": status})
    result = {"fetch_response": fetch if isinstance(fetch, (dict, list)) else str(fetch)[:2000],
              "seconds": round(time.time() - started, 1), "events": rows, "pass": not failed}
    with open(a.out + ".json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    md = [f"## MISP feed subscription: {'PASS' if not failed else 'FAIL'}", "",
          f"Local feed with {len(want)} events, fetched through MISP's feed code in {result['seconds']}s.", "",
          "| Event | Expected | Stored | Status |", "|---|---|---|---|"]
    md += [f"| {r['info'][:70]} | {r['expected']} | {r['stored']} | {r['status']} |" for r in rows]
    with open(a.out + ".md", "w", encoding="utf-8") as f:
        f.write("\n".join(md) + "\n")
    print("\n".join(md))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
