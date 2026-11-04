#!/usr/bin/env python3
"""ATT&CK Navigator layers and a coverage summary for the tracker.

Reads the techniques the tracker maps for each actor (data/apt-campaigns.json,
data/ransomware.json, data/hacktivist.json), each fraud campaign
(data/smishing-apk.json, Mobile ATT&CK) and each detection rule (the attack.*
tags in detections/sigma/), checks every id against the committed ATT&CK
reference (config/attack-techniques.json), and writes:

  layers/india-actors.json        Enterprise: how many tracked actors use each technique
  layers/detection-coverage.json  Enterprise: actor techniques, coloured by whether a rule covers them
  layers/india-fraud-mobile.json  Mobile: techniques used by the fraud campaigns
  data/attack-coverage.json       the same coverage as data, for the site and for people

Open a layer at https://mitre-attack.github.io/attack-navigator/ (Open Existing
Layer -> Upload from local, or paste the raw GitHub URL).

Coverage is by technique id: "exact" when a rule is tagged with the technique
itself, "related" when a rule is tagged with its parent or one of its
sub-techniques, "none" otherwise. A tag is the rule author's claim; it does
not mean every procedure of that technique is detected.

    python scripts/build_layers.py
    python scripts/build_layers.py --check   # exit 1 if anything is stale or an id is unknown
"""
import glob
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REF = os.path.join(ROOT, "config", "attack-techniques.json")
LAYERS = os.path.join(ROOT, "layers")
COVERAGE = os.path.join(ROOT, "data", "attack-coverage.json")
NAVIGATOR = "5.1.0"
LAYER_FORMAT = "4.5"
GREEN, AMBER, RED, CYAN = "#3fb68b", "#e9b45e", "#ef7d62", "#4fc6d6"
TAG_RE = re.compile(r"^\s*-\s*attack\.(t\d{4}(?:\.\d{3})?)\s*$", re.M)


def load(path):
    with open(os.path.join(ROOT, path), encoding="utf-8") as f:
        return json.load(f)


def actor_usage():
    """{technique: [(kind, id, name)]} for Enterprise, and the same for Mobile fraud campaigns."""
    enterprise, mobile = {}, {}
    for kind, path, name_key in (("apt", "data/apt-campaigns.json", "actor"),
                                 ("ransomware", "data/ransomware.json", "name"),
                                 ("hacktivist", "data/hacktivist.json", "name")):
        for it in load(path)["items"]:
            for t in it.get("attack") or []:
                enterprise.setdefault(t["id"], []).append((kind, it["id"], it.get(name_key) or it["id"]))
    for it in load("data/smishing-apk.json")["items"]:
        for t in it.get("attack") or []:
            mobile.setdefault(t["id"], []).append(("fraud", it["id"], it["title"]))
    return enterprise, mobile


def rule_tags():
    """{technique: [rule stem]} from the Sigma rules' attack.tNNNN tags."""
    out = {}
    for path in sorted(glob.glob(os.path.join(ROOT, "detections", "sigma", "*.yml"))):
        stem = os.path.basename(path)[:-4]
        with open(path, encoding="utf-8") as f:
            for tid in TAG_RE.findall(f.read()):
                out.setdefault(tid.upper(), []).append(stem)
    return out


def unknown_ids(ids, domain_ref):
    bad = []
    for tid in sorted(ids):
        if tid not in domain_ref["techniques"]:
            hint = domain_ref["retired"].get(tid, "not in this ATT&CK version")
            bad.append(f"{tid} ({'replaced by ' + hint if hint and hint.startswith('T') else hint or 'retired'})")
    return bad


def coverage_for(tid, rules):
    """('exact'|'related'|'none', rules). Related: a rule tagged with the parent
    of a sub-technique, or with a sub-technique of a parent. Siblings don't count."""
    if rules.get(tid):
        return "exact", sorted(rules[tid])
    parent = tid.split(".")[0]
    related = sorted({r for t, rs in rules.items()
                      if (t == parent and t != tid) or t.startswith(tid + ".") for r in rs})
    return ("related", related) if related else ("none", [])


def layer(name, description, domain, version, techniques, legend, gradient=None):
    out = {
        "name": name,
        "versions": {"attack": version.split(".")[0], "navigator": NAVIGATOR, "layer": LAYER_FORMAT},
        "domain": domain,
        "description": description,
        "sorting": 3,
        "layout": {"layout": "side", "showName": True, "showID": False},
        "hideDisabled": False,
        "techniques": techniques,
        "legendItems": legend,
        "showTacticRowBackground": True,
        "tacticRowBackground": "#1b2129",
        "selectTechniquesAcrossTactics": True,
        "metadata": [{"name": "source", "value": "https://github.com/sohankanna/india-threat-tracker"}],
    }
    if gradient:
        out["gradient"] = gradient
    return out


def actor_label(u):
    return f"{u[2]} ({u[0]})"


def build():
    ref = load("config/attack-techniques.json")["domains"]
    E, M = ref["enterprise"], ref["mobile"]
    ent, mob = actor_usage()
    rules = rule_tags()
    problems = [f"actors: {x}" for x in unknown_ids(ent, E)] + \
               [f"fraud campaigns (Mobile): {x}" for x in unknown_ids(mob, M)] + \
               [f"Sigma tags: {x}" for x in unknown_ids(rules, E)]
    if problems:
        raise ValueError("ATT&CK ids not in the reference:\n  " + "\n  ".join(problems))

    rows = []
    for tid in sorted(ent):
        users = sorted(set(ent[tid]), key=lambda u: (u[0], u[2]))
        cov, by = coverage_for(tid, rules)
        rows.append({"id": tid, "name": E["techniques"][tid]["name"], "tactics": E["techniques"][tid]["tactics"],
                     "actors": [{"kind": k, "id": i, "name": n} for k, i, n in users],
                     "coverage": cov, "rules": by})
    rule_only = sorted(t for t in rules if t not in ent)

    actors_layer = layer(
        "India Threat Tracker: techniques of actors targeting India",
        "Enterprise techniques mapped for the state-nexus, ransomware and hacktivist actors in the India Threat "
        "Tracker. Score = number of tracked actors using the technique.",
        "enterprise-attack", E["version"],
        [{"techniqueID": r["id"], "score": len(r["actors"]), "enabled": True, "showSubtechniques": "." in r["id"],
          "comment": "Used by: " + "; ".join(actor_label((a["kind"], a["id"], a["name"])) for a in r["actors"])}
         for r in rows],
        [], gradient={"colors": ["#fde2d8", RED], "minValue": 1, "maxValue": max((len(r["actors"]) for r in rows), default=1)})

    cov_colour = {"exact": GREEN, "related": AMBER, "none": RED}
    coverage_layer = layer(
        "India Threat Tracker: detection coverage",
        "Techniques used by actors targeting India, coloured by whether a tracker detection rule is tagged with "
        "them. Green: a rule is tagged with this technique. Amber: only with its parent or a sub-technique. "
        "Red: no rule. Blue: covered by a rule but not mapped to any tracked actor.",
        "enterprise-attack", E["version"],
        [{"techniqueID": r["id"], "color": cov_colour[r["coverage"]], "enabled": True, "showSubtechniques": "." in r["id"],
          "comment": (f"Rules: {', '.join(r['rules'])}. " if r["rules"] else "No rule. ")
                     + "Used by: " + "; ".join(a["name"] for a in r["actors"])}
         for r in rows] +
        [{"techniqueID": t, "color": CYAN, "enabled": True, "comment": "Rules: " + ", ".join(rules[t])} for t in rule_only],
        [{"label": "Rule tagged with the technique", "color": GREEN},
         {"label": "Rule tagged with parent or sub-technique only", "color": AMBER},
         {"label": "No rule", "color": RED},
         {"label": "Rule, but no tracked actor uses it", "color": CYAN}])

    mob_rows = [{"id": t, "name": M["techniques"][t]["name"], "campaigns": sorted({u[2] for u in mob[t]})}
                for t in sorted(mob)]
    mobile_layer = layer(
        "India Threat Tracker: fake-APK and fraud campaigns (Mobile)",
        "Mobile ATT&CK techniques mapped for the fraud campaigns against Indian users. Score = number of "
        "campaigns using the technique.",
        "mobile-attack", M["version"],
        [{"techniqueID": r["id"], "score": len(r["campaigns"]), "enabled": True, "showSubtechniques": "." in r["id"],
          "comment": "Campaigns: " + "; ".join(r["campaigns"])} for r in mob_rows],
        [], gradient={"colors": ["#d8f3f6", CYAN], "minValue": 1, "maxValue": max((len(r["campaigns"]) for r in mob_rows), default=1)})

    counts = {k: sum(r["coverage"] == k for r in rows) for k in ("exact", "related", "none")}
    gaps = sorted((r for r in rows if r["coverage"] == "none"), key=lambda r: (-len(r["actors"]), r["id"]))[:15]
    coverage = {
        "feed": "attack-coverage",
        "attack_version": {"enterprise": E["version"], "mobile": M["version"]},
        "method": "Technique ids from the tracker's actor mappings matched against the attack.* tags of its Sigma "
                  "rules. exact: a rule is tagged with the technique. related: only with its parent or a "
                  "sub-technique. A tag is the rule author's claim, not proof that every procedure is detected.",
        "summary": {"actor_techniques": len(rows), **counts, "rules": len({r for rs in rules.values() for r in rs}),
                    "rule_techniques_not_used_by_actors": len(rule_only),
                    "mobile_fraud_techniques": len(mob_rows)},
        "top_gaps": [{"id": r["id"], "name": r["name"], "actors": len(r["actors"])} for r in gaps],
        "count": len(rows),
        "items": rows,
        "mobile": mob_rows,
    }
    files = {
        "layers/india-actors.json": actors_layer,
        "layers/detection-coverage.json": coverage_layer,
        "layers/india-fraud-mobile.json": mobile_layer,
        "data/attack-coverage.json": coverage,
    }
    return {p: json.dumps(v, indent=1, ensure_ascii=False) + "\n" for p, v in files.items()}


def main(argv):
    try:
        files = build()
    except ValueError as e:
        print(f"FAIL {e}")
        return 1
    if "--check" in argv:
        stale = []
        for rel, text in files.items():
            try:
                with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
                    if f.read() != text:
                        stale.append(rel)
            except OSError:
                stale.append(rel)
        if stale:
            print(f"FAIL stale: {', '.join(stale)}. Run: python scripts/build_layers.py")
            return 1
        print("OK   ATT&CK layers and coverage match the data")
        return 0
    os.makedirs(LAYERS, exist_ok=True)
    for rel, text in files.items():
        with open(os.path.join(ROOT, rel), "w", encoding="utf-8") as f:
            f.write(text)
    s = json.loads(files["data/attack-coverage.json"])["summary"]
    print(f"Layers written. {s['actor_techniques']} actor techniques: {s['exact']} exact, {s['related']} related, "
          f"{s['none']} without a rule")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
