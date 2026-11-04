#!/usr/bin/env python3
"""Watch for lookalike domains of Indian banks, payment apps and government sites.

For each brand in config/lookalike-brands.json, generates typo, hyphen,
dictionary ("sbi-kyc", "parivahan-challan") and TLD-swap variants with
dnstwist's permutation engine, resolves every variant, and keeps the ones that
are registered (they resolve or have name servers). New registrations since the
previous scan are the leads; for those it also asks crt.sh (certificate
transparency) for the first TLS certificate issued, because a fresh certificate
on a lookalike usually means a live site.

Writes data/lookalike-domains.json. Everything in it is a LEAD, not a verdict:
a lookalike may be parked, unrelated, or the brand's own defensive
registration. Domains are stored defanged.

The first scan is the baseline: what already existed is marked
`baseline: true` and is not presented as new. Entries not seen for 90 days are
dropped.

    python scripts/scan_lookalikes.py --cache DIR       # scan (needs DNS), save results
    python scripts/scan_lookalikes.py --from-cache DIR  # re-apply a saved scan, no network

Run by .github/workflows/lookalikes.yml once a day. Needs dnstwist and
dnspython (requirements-lookalikes.txt).
"""
import argparse
import collections
import concurrent.futures as cf
import datetime as dt
import json
import os
import sys
import urllib.parse
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG = os.path.join(ROOT, "config", "lookalike-brands.json")
OUT = os.path.join(ROOT, "data", "lookalike-domains.json")
DROP_AFTER_DAYS = 90
CRT_MAX = 40


def defang(d):
    return d.replace(".", "[.]")


def refang(d):
    return d.replace("[.]", ".")


def load(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def official_match(domain, officials):
    return any(domain == o or domain.endswith("." + o) for o in officials)


def candidates(config, fuzzer_cls=None):
    """{domain: (brand_id, label, fuzzer)} for every permutation of every brand."""
    if fuzzer_cls is None:
        from dnstwist import Fuzzer as fuzzer_cls
    out = {}
    for b in config["brands"]:
        for label in b["labels"]:
            fuzzers = config["short_fuzzers"] if len(label) < config["short_label_length"] else config["fuzzers"]
            for tld in config["seed_tlds"]:
                f = fuzzer_cls(f"{label}.{tld}", dictionary=config["dictionary"], tld_dictionary=list(config["tlds"]))
                f.generate(fuzzers=fuzzers)
                for p in f.domains:
                    d = p["domain"].lower()
                    if d.startswith("xn--") or ".xn--" in d or official_match(d, b["official"]):
                        continue
                    out.setdefault(d, (b["id"], label, p["fuzzer"]))
    return out


def dns_lookup(domain, resolver=None):
    """{'a': [...], 'ns': [...], 'mx': bool} if registered, else None."""
    import dns.exception
    import dns.resolver
    r = resolver or dns.resolver.Resolver()
    r.lifetime = 4.0

    def q(rtype):
        try:
            return [str(x).rstrip(".") for x in r.resolve(domain, rtype)]
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            return []

    try:
        a = q("A")
    except dns.resolver.NXDOMAIN:
        return None
    try:
        ns = q("NS")
        mx = bool(q("MX"))
    except dns.resolver.NXDOMAIN:
        return None
    if not (a or ns):
        return None
    return {"a": sorted(a)[:4], "ns": sorted(ns)[:4], "mx": mx}


def resolve_all(names, lookup=dns_lookup, threads=32):
    found = {}
    with cf.ThreadPoolExecutor(threads) as pool:
        for name, res in zip(names, pool.map(lambda n: _safe(lookup, n), names)):
            if res:
                found[name] = res
    return found


def _safe(lookup, name):
    try:
        return lookup(name)
    except Exception:
        return None


def first_cert(domain, fetch=None):
    """Earliest not_before date crt.sh knows for the exact domain, or None."""
    url = "https://crt.sh/?q=" + urllib.parse.quote(domain) + "&output=json"
    try:
        if fetch:
            body = fetch(url)
        else:
            req = urllib.request.Request(url, headers={"User-Agent": "india-threat-tracker (lookalike watch)"})
            with urllib.request.urlopen(req, timeout=30) as r:
                body = r.read().decode("utf-8", errors="replace")
        rows = json.loads(body)
    except Exception:
        return None
    dates = [str(r.get("not_before", ""))[:10] for r in rows if isinstance(r, dict) and r.get("not_before")]
    return min(dates) if dates else None


def merge(previous, scan, config, today):
    """Fold one scan (domain -> dns facts) into the stored feed."""
    brands = {b["id"]: b for b in config["brands"]}
    prev_items = {refang(i["domain"]): i for i in (previous or {}).get("items", [])}
    baseline_run = not (previous or {}).get("scans")
    items = {}
    for domain, facts in scan["found"].items():
        brand_id, label, fuzzer = scan["candidates"][domain]
        old = prev_items.get(domain)
        item = {
            "domain": defang(domain),
            "brand": brand_id,
            "brand_name": brands[brand_id]["name"],
            "sector": brands[brand_id]["sector"],
            "label": label,
            "fuzzer": fuzzer,
            "first_seen": old["first_seen"] if old else today,
            "last_seen": today,
            "active": True,
            "baseline": old["baseline"] if old else baseline_run,
            "a": facts["a"],
            "ns": facts["ns"],
            "mx": facts["mx"],
            "first_cert": (old or {}).get("first_cert") or scan.get("certs", {}).get(domain),
        }
        items[domain] = item
    cutoff = (dt.date.fromisoformat(today) - dt.timedelta(days=DROP_AFTER_DAYS)).isoformat()
    for domain, old in prev_items.items():
        if domain not in items and old["last_seen"] >= cutoff:
            items[domain] = {**old, "active": False}
    # New leads first (newest first), then the baseline; ties by brand and domain.
    rows = sorted(items.values(), key=lambda i: (i["brand"], i["domain"]))
    rows.sort(key=lambda i: i["first_seen"], reverse=True)
    rows.sort(key=lambda i: i["baseline"])
    since = (dt.date.fromisoformat(today) - dt.timedelta(days=30)).isoformat()
    new_30 = [i for i in rows if not i["baseline"] and i["first_seen"] >= since]
    return {
        "feed": "lookalike-domains",
        "generated_at": today,
        "warning": "Leads, not verdicts. A lookalike may be parked, unrelated or the brand's own defensive "
                   "registration. Check before blocking or reporting.",
        "baseline_date": (previous or {}).get("baseline_date") or today,
        "scans": (previous or {}).get("scans", 0) + 1,
        "candidates_checked": len(scan["candidates"]),
        "summary": {
            "registered": len([i for i in rows if i["active"]]),
            "new_last_30_days": len(new_30),
            "new_with_certificate_last_30_days": len([i for i in new_30 if i["first_cert"]]),
            "by_brand_new_last_30_days": dict(sorted(collections.Counter(i["brand"] for i in new_30).items())),
        },
        "count": len(rows),
        "items": rows,
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Lookalike-domain watch for Indian brands.")
    ap.add_argument("--cache")
    ap.add_argument("--from-cache")
    ap.add_argument("--date")
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--threads", type=int, default=32)
    a = ap.parse_args(argv)
    today = a.date or dt.datetime.now(dt.timezone.utc).date().isoformat()
    config = load(CONFIG)
    previous = load(a.out)

    cache_file = os.path.join(a.from_cache or a.cache or "", "lookalikes.json")
    if a.from_cache:
        scan = load(cache_file)
        if scan is None:
            print("No cached lookalike scan; leaving the file as it is.")
            return 0
    else:
        cands = candidates(config)
        found = resolve_all(sorted(cands), threads=a.threads)
        if cands and not found:
            print("::warning::Lookalikes: no candidate resolved at all; DNS is probably unavailable. "
                  "Not updating the file.", file=sys.stderr)
            return 0
        known = {refang(i["domain"]) for i in (previous or {}).get("items", [])}
        first_scan = not (previous or {}).get("scans")
        new = [] if first_scan else [d for d in sorted(found) if d not in known]
        certs = {}
        for d in new[:CRT_MAX]:
            c = first_cert(d)
            if c:
                certs[d] = c
        scan = {"candidates": {d: list(v) for d, v in cands.items()}, "found": found, "certs": certs}
        if a.cache:
            os.makedirs(a.cache, exist_ok=True)
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(scan, f)
    feed = merge(previous, scan, config, today)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(feed, f, indent=2, ensure_ascii=False)
        f.write("\n")
    s = feed["summary"]
    print(f"Lookalikes: {feed['candidates_checked']} checked, {s['registered']} registered, "
          f"{s['new_last_30_days']} new in 30 days ({s['new_with_certificate_last_30_days']} with a certificate)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
