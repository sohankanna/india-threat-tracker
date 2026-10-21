# Changelog

Dates are when the change reached `main`. Data feeds update twice a day and are
not listed here.

## v0.2.0 — Phase 2 research preview (2026-10-21)

Three new capabilities, each with its validation level stated plainly.

### Exposure Matcher (research preview)

* Match an asset inventory (CSV) against every CISA KEV CVE, in the browser at
  [/tracker/exposure](https://www.sohankanna.com/tracker/exposure) or offline
  with `matcher/cli.ts`. The inventory never leaves the device.
* Version data from the official CVE records for all KEV CVEs
  (`data/kev-affected.json`), refreshed by the update job.
* Results are *affected version*, *candidate* or *insufficient evidence*, each
  with its evidence. Priority tiers P1–P4 are documented; there is no hidden
  score. CSV (formula-safe) and JSON (schema) exports.
* Handles real vendor schemes: PAN-OS hotfixes per maintenance branch, Citrix
  branch + build ranges, Ivanti R-releases, and the hotfix carried in the CPE
  update field. Non-comparable versions are never guessed.
* About 40% of KEV CVEs carry version data that can be compared; the rest
  produce candidates. See [EXPOSURE-MATCHER.md](EXPOSURE-MATCHER.md).

### STIX 2.1 export

* `data/india-threat-tracker-stix.json`: campaigns, intrusion sets,
  indicators, malware, ATT&CK techniques, cited CVEs and the monthly assessment
  as a report, 121 objects with sources and confidence.
* Stable ids (UUIDv4, generated once, committed in `stix/id-registry.json`);
  unchanged data rebuilds byte-identically; `modified` moves only when content
  changes.
* Valid against the OASIS STIX 2.1 schemas and pattern grammar in CI. Indicator
  values are type-checked and escaped, so a malformed value cannot change a
  pattern's logic.
* MISP: converted in CI with misp-stix (the library MISP uses for STIX import);
  every object and indicator survives, the `uses` relationships do not. A full
  MISP instance import is automated (`interop-misp.yml`); OpenCTI is untested.
  See [STIX-GUIDE.md](STIX-GUIDE.md).

### Detections validated in a real SIEM

* All five rules replayed through a real Wazuh 4.14.9 manager in CI: **29/29**
  events behaved as expected
  ([report](detections/validation/wazuh-4.14.9-2026-10-20.md)).
* The real engine found three defects emulation had missed, all fixed with
  regression tests:
  1. Wazuh's Palo Alto decoder cuts the description field at the first comma,
     so the PAN-OS rule now matches the full log.
  2. `wazuh-logtest` cannot test Windows eventchannel rules at all, so Sysmon is
     replayed through the agent queue instead.
  3. The eventchannel decoder doubles backslashes, which silently broke the DNS
     resolver rule.

### Pipeline and data quality

* Update job is race-safe: if a human pushes mid-run, it rebuilds on top of
  that commit instead of resolving conflicts.
* EPSS enrichment health in both feeds (`enrichment`), with a site notice when
  degraded; feed-staleness warning on the site after 36 hours.
* Watchlist window is exactly 24 calendar months.
* Monthly assessment cites evidence (campaigns, actors, CVEs, detections,
  primary sources); CI checks every reference resolves.
* `data/meta.json` is a schema-validated manifest of every data file.
* Site: compact cards with expandable details; the tracker page is about half
  as long.

### Validation levels at this release

| Capability | Level |
|---|---|
| Sigma rules | Behaviour tested by fixtures; conversion checked |
| Wazuh rules | Executed in the real engine (4.14.9), 29/29 |
| Splunk / Elastic queries | Fixture-tested from query text; not run in a live instance |
| STIX bundle | OASIS schema- and pattern-valid; MISP library conversion tested; MISP instance and OpenCTI import not yet confirmed |
| Exposure Matcher | 20 engine tests plus contract tests; not yet validated on real enterprise inventories |

Everything above is a research preview: use it, check it, and report what's
wrong.

## v0.1.0 — Launch (2026-10-16)

* Public tracker at [sohankanna.com/tracker](https://www.sohankanna.com/tracker).
* Feeds: CISA KEV with FIRST EPSS and India relevance, the India watchlist,
  fake-APK and smishing campaigns, state-nexus actors, defanged IOC exports,
  and the monthly analyst assessment.
* Five detections in Sigma, Splunk, Elastic and Wazuh with test fixtures.
