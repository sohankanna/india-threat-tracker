#!/usr/bin/env python3
"""Detection-pack inventory check.

Every canonical Sigma rule must have a Splunk and an Elastic counterpart, the
shared Wazuh ruleset and a test fixture must exist, and the YAML/XML must parse.
Exits non-zero on any gap so CI fails the PR.
"""
import glob
import os
import sys
import xml.dom.minidom

import yaml

ROOT = os.path.join(os.path.dirname(__file__), "..", "detections")


def main() -> int:
    ok = True
    sigma = sorted(glob.glob(os.path.join(ROOT, "sigma", "*.yml")))
    if not sigma:
        print("FAIL no Sigma rules found")
        return 1

    for path in sigma:
        stem = os.path.splitext(os.path.basename(path))[0]

        # Sigma parses + has the minimum metadata
        try:
            doc = yaml.safe_load(open(path))
            for key in ("title", "id", "status", "detection", "logsource"):
                if key not in doc:
                    ok = False
                    print(f"FAIL {stem}: Sigma missing '{key}'")
        except Exception as e:
            ok = False
            print(f"FAIL {stem}: Sigma YAML parse error: {e}")

        # Splunk counterpart
        if not os.path.exists(os.path.join(ROOT, "splunk", f"{stem}.spl")):
            ok = False
            print(f"FAIL {stem}: missing splunk/{stem}.spl")

        # Elastic counterpart (.eql or .kql)
        if not (
            os.path.exists(os.path.join(ROOT, "elastic", f"{stem}.eql"))
            or os.path.exists(os.path.join(ROOT, "elastic", f"{stem}.kql"))
        ):
            ok = False
            print(f"FAIL {stem}: missing elastic/{stem}.(eql|kql)")

        # Test fixture
        if not os.path.exists(os.path.join(ROOT, "tests", f"{stem}.events.json")):
            ok = False
            print(f"FAIL {stem}: missing tests/{stem}.events.json")

        if ok:
            print(f"OK   {stem}")

    # Shared Wazuh ruleset parses
    wazuh = os.path.join(ROOT, "wazuh", "local_rules.xml")
    if not os.path.exists(wazuh):
        ok = False
        print("FAIL missing wazuh/local_rules.xml")
    else:
        try:
            xml.dom.minidom.parseString("<root>" + open(wazuh).read() + "</root>")
            print("OK   wazuh/local_rules.xml parses")
        except Exception as e:
            ok = False
            print(f"FAIL wazuh/local_rules.xml: {e}")

    # Fraud YAML parses
    for path in glob.glob(os.path.join(ROOT, "fraud", "*.yaml")):
        try:
            yaml.safe_load(open(path))
            print(f"OK   {os.path.relpath(path, ROOT)} parses")
        except Exception as e:
            ok = False
            print(f"FAIL {path}: {e}")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
