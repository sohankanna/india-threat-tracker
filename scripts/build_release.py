#!/usr/bin/env python3
"""Build the release assets for a tagged version.

    python scripts/build_release.py v1.0.0          # writes dist/

dist/india-threat-tracker-detections-<v>.zip
    Every rule in Sigma, Splunk, Elastic and Wazuh form, the fraud signals,
    test fixtures and the deployment docs.
dist/india-threat-tracker-data-<v>.zip
    Every data feed and its schema, the IOC exports, the STIX bundle and the
    MISP feed, with the data guides.
dist/SHA256SUMS

The zips are deterministic: fixed file order and timestamps, so the same tree
always produces the same bytes and the checksums can be reproduced.
Run by .github/workflows/release.yml when a v* tag is pushed.
"""
import hashlib
import os
import re
import sys
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EPOCH = (2026, 1, 1, 0, 0, 0)
SKIP_DIRS = {"__pycache__"}
SKIP_FILES = re.compile(r"\.(pyc|pyo)$")

BUNDLES = {
    "detections": {
        "dirs": ["detections"],
        "files": ["LICENSE", "README.md", "CHANGELOG.md"],
    },
    "data": {
        "dirs": ["data", "schema", "misp-feed", "layers"],
        "files": ["LICENSE", "DATA-GUIDE.md", "STIX-GUIDE.md", "METHODOLOGY.md", "docs/USING.md"],
    },
}


def members(spec):
    out = []
    for d in spec["dirs"]:
        base = os.path.join(ROOT, d)
        if not os.path.isdir(base):
            continue
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(x for x in dirnames if x not in SKIP_DIRS)
            for name in sorted(filenames):
                if not SKIP_FILES.search(name):
                    out.append(os.path.relpath(os.path.join(dirpath, name), ROOT).replace(os.sep, "/"))
    out += [f for f in spec["files"] if os.path.exists(os.path.join(ROOT, f))]
    return sorted(set(out))


def write_zip(path, prefix, files):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for rel in files:
            info = zipfile.ZipInfo(f"{prefix}/{rel}", date_time=EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            with open(os.path.join(ROOT, rel), "rb") as f:
                z.writestr(info, f.read())


def build(version, out_dir):
    if not re.fullmatch(r"v\d+\.\d+\.\d+", version):
        raise SystemExit(f"version must look like v1.2.3, got {version!r}")
    os.makedirs(out_dir, exist_ok=True)
    sums = []
    for name, spec in BUNDLES.items():
        prefix = f"india-threat-tracker-{name}-{version}"
        path = os.path.join(out_dir, prefix + ".zip")
        write_zip(path, prefix, members(spec))
        with open(path, "rb") as f:
            sums.append(f"{hashlib.sha256(f.read()).hexdigest()}  {prefix}.zip")
    with open(os.path.join(out_dir, "SHA256SUMS"), "w") as f:
        f.write("\n".join(sums) + "\n")
    return sums


def main(argv):
    if len(argv) != 1:
        print(__doc__)
        return 2
    for line in build(argv[0], os.path.join(ROOT, "dist")):
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
