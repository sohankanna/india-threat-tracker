# India Threat Tracker

[![Validate data + detections](https://github.com/sohankanna/india-threat-tracker/actions/workflows/validate-pr.yml/badge.svg)](https://github.com/sohankanna/india-threat-tracker/actions/workflows/validate-pr.yml)
[![Feed update](https://github.com/sohankanna/india-threat-tracker/actions/workflows/update.yml/badge.svg)](https://github.com/sohankanna/india-threat-tracker/actions/workflows/update.yml)
[![Data: CC BY 4.0](https://img.shields.io/badge/data-CC%20BY%204.0-blue)](https://creativecommons.org/licenses/by/4.0/)
[![Code: MIT](https://img.shields.io/badge/code-MIT-green)](LICENSE)

Open, machine-readable threat intelligence for defenders and researchers in
India: actively exploited vulnerabilities prioritised for Indian organisations,
the fake-APK and UPI fraud campaigns hitting Indian users, the state-nexus
actors behind targeted intrusions, and detection rules for all of it.

**Browse it:** [sohankanna.com/tracker](https://www.sohankanna.com/tracker) ·
**Use the data:** [DATA-GUIDE.md](DATA-GUIDE.md) ·
**How it's scored:** [METHODOLOGY.md](METHODOLOGY.md)

> Defensive and research use only. Indicators only — no malware samples are
> hosted here, ever.

---

## What's inside

| File | Contents | Updated |
|------|----------|---------|
| [`data/watchlist.json`](data/watchlist.json) | KEV entries that are India-relevant and recent or ransomware-linked, with EPSS and the reason for each relevance tag | Twice daily, automated |
| [`data/exploited-cve.json`](data/exploited-cve.json) | Every CISA KEV entry, enriched with FIRST EPSS and an India-relevance tag | Twice daily, automated |
| [`data/smishing-apk.json`](data/smishing-apk.json) | Fake-APK / smishing campaigns: sources, confidence, ATT&CK mapping, key findings, defensive actions, indicators and separate infrastructure context | Curated |
| [`data/apt-campaigns.json`](data/apt-campaigns.json) | State-nexus actors targeting India, with reported attribution kept apart from the tracker's confidence | Curated |
| [`data/iocs.txt`](data/iocs.txt) · [`data/iocs.csv`](data/iocs.csv) | Defanged campaign indicators; the CSV adds campaign, source, confidence and status per row | Rebuilt with every update |
| [`data/assessment.json`](data/assessment.json) | The monthly ranked analyst assessment | Monthly |
| [`data/relevance-overrides.json`](data/relevance-overrides.json) | Hand-reviewed India-relevance decisions; the pipeline reads them and never overwrites them | When reviewed |
| [`data/india-threat-tracker-stix.json`](data/india-threat-tracker-stix.json) | STIX 2.1 Bundle of the campaigns, actors, indicators, techniques and assessment: see [STIX-GUIDE.md](STIX-GUIDE.md) | Twice daily, automated |
| [`data/kev-affected.json`](data/kev-affected.json) | Affected products and versions for every KEV CVE, from the official CVE records; feeds the [Exposure Matcher](EXPOSURE-MATCHER.md) | Twice daily, automated |
| [`data/meta.json`](data/meta.json) | Manifest of every data file, with its schema and cadence | When files change |

Every JSON feed is validated against a schema in [`schema/`](schema/) on every
change.

## Quick start

```bash
RAW=https://raw.githubusercontent.com/sohankanna/india-threat-tracker/main/data

# High-relevance watchlist entries with EPSS of 50% or more
curl -s $RAW/watchlist.json \
  | jq '.items[] | select(.india_relevance=="high" and .epss>=0.5) | {cve, vendor, product, epss, due_date}'

# Campaign indicators, one per line (defanged - re-fang deliberately)
curl -s $RAW/iocs.txt | grep -v '^#' | grep -v '^$'

# Indicators with provenance, for a spreadsheet or SIEM lookup
curl -s $RAW/iocs.csv
```

## Exposure Matcher (research preview)

Check an asset inventory against every KEV CVE, using the version data in the
official CVE records: [in your browser](https://www.sohankanna.com/tracker/exposure)
(the file never leaves it) or offline with `matcher/cli.ts`. Results are
"affected version", "candidate" or "insufficient evidence", each with its
evidence and a documented priority tier. About 40% of KEV CVEs carry version
data that can be compared; the rest stay candidates. See
[EXPOSURE-MATCHER.md](EXPOSURE-MATCHER.md).

## Detections

[`detections/`](detections/) holds five rules, each shipped as **Sigma**,
**Splunk SPL**, **Elastic** (EQL/KQL, ECS) and **Wazuh**, plus payments-fraud
logic for the UPI kill chain:

| Rule | Detects | Covers |
|------|---------|--------|
| `office_document_spawns_script_interpreter` | Office spawning wscript/cscript/PowerShell/mshta/cmd | Crimson RAT macro delivery (APT36) |
| `office_archive_lnk_spawns_lolbin` | Archive utility or Explorer spawning a LOLBin | SideCopy / APT36 delivery |
| `windows_suspicious_dns_server_change` | Endpoint DNS set outside the trusted-resolver policy | FrostArmada router DNS hijack |
| `pan_os_mgmt_auth_from_unexpected_source` | PAN-OS admin login from outside the allowlist | CVE-2026-0322 precondition |
| `entra_aitm_risky_signin_token_replay` | High-risk Entra ID sign-in that succeeded | FrostArmada AiTM token theft |

Read [**DATA-SOURCES.md**](detections/DATA-SOURCES.md) for the telemetry each
rule needs and [**TESTING.md**](detections/TESTING.md) for a matching and a
non-matching event per rule. All rules are `experimental`: deploy in
alert-only mode, validate, then tune.

## Why you can trust it (and where not to)

- **Every claim has a source**, and sources are specific reports, not tag pages.
- **Three timestamps, three meanings:** *feed updated* (data regenerated),
  *source checked* (a person re-read the report), *indicator last seen* (not
  tracked, so never implied).
- **Indicators are separate from infrastructure.** Abused legitimate services
  (GitHub, Firebase, hosting) are context and never appear in `iocs.txt`,
  `iocs.csv` or any copy/export.
- **ATT&CK mappings are checked** against MITRE's published data.
- **Reported attribution is separate from tracker confidence.**
- **India relevance is a transparent heuristic**, recorded with the keyword
  that triggered it. It is triage, not proof of exposure.

Full details: [METHODOLOGY.md](METHODOLOGY.md).

## How it runs

```
scripts/fetch_exploited.py   CISA KEV + FIRST EPSS -> exploited-cve.json + watchlist.json
scripts/build_iocs.py        campaign feed         -> iocs.txt + iocs.csv
scripts/validate.py          every JSON feed       -> checked against schema/
scripts/check_inventory.py   detection pack        -> every rule has all formats + a test
scripts/make_tweet_draft.py  today's KEV adds      -> drafts/<date>.md (a draft, not post-ready)
```

Two GitHub Actions run it. [`update.yml`](.github/workflows/update.yml)
regenerates the feeds **twice a day**, rebuilds the IOC exports, runs the
pipeline tests, and retries its push if someone pushed during the run.
[`validate-pr.yml`](.github/workflows/validate-pr.yml) checks every push and pull
request: schemas, that the IOC exports match the campaign data, the detection
inventory, the test suite, Sigma validation and a Sigma→Splunk conversion.

The test suite (`tests/`) covers the pipeline (including that hand-set
relevance tiers survive repeated regeneration), the IOC exports (infrastructure
context can never leak in), the example client, and every detection rule
against its fixtures. [TESTING.md](detections/TESTING.md) says exactly which
backends are executed and which are only checked.

```bash
pip install -r requirements.txt -r requirements-ci.txt
python scripts/fetch_exploited.py                      # needs open internet
python scripts/fetch_exploited.py --rebuild-watchlist  # offline: re-derive both feeds
python scripts/build_iocs.py                           # --check to verify without writing
python scripts/validate.py && python scripts/check_inventory.py
python -m unittest discover -s tests -v
```

## Contributing

New campaign, indicator or correction? See [CONTRIBUTING.md](CONTRIBUTING.md).
Every pull request is validated automatically, and every entry needs a real,
specific source.

## License

Code is [MIT](LICENSE). Data is [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/):
use it, and credit **Sohan Kanna** ([@sohankanna](https://x.com/sohankanna)).
