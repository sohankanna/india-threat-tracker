# Changelog

Dates are when the change reached `main`. Data feeds update twice a day and are
not listed here.

## Unreleased

### Detections

* New rule `chm_help_file_spawns_script_or_lolbin`: the HTML Help viewer
  (hh.exe) starting a script host, shell or download-capable binary. It covers
  the help-file delivery Mustang Panda used against Indian banks in 2026
  (LOTUSLITE). Shipped as Sigma, Splunk, Elastic EQL and Wazuh rule 100213, with
  fixtures; the process lists are checked to be identical in every backend.
* Fixed CI after pySigma 2.x: the DNS-change rule's regex no longer uses a
  `(?!...)` lookahead, which RE2 rejects. The new pattern lists every first and
  second octet outside RFC1918 and matches exactly the same inputs (checked on
  37,000 single and multi-resolver values). Approved public resolvers now go in
  a separate filter instead of inside the pattern.
* ATT&CK tactic tags use the hyphenated form pySigma 2.x expects
  (`attack.credential-access`, `attack.initial-access`,
  `attack.command-and-control`).
* Sigma tooling pinned to its current major versions.

### Phase 3: deeper actors, hacktivists and fraud

Every new entry was researched against vendor, CERT, police and court
reporting; only sources that were read are cited.

**Threat actors (4 new, all 9 deepened)**

* Added **Mustang Panda** (China-nexus, MITRE G0129): LOTUSLITE against Indian
  banks through HDFC-themed CHM files (Acronis, April 2026), and SHARDLOADER,
  MINIRECON and ZOHOMURK against Indian government and hydropower targets with
  Zoho WorkDrive as C2 (Acronis with CERT-In, June 2026). Confidence high.
* Added **Lazarus Group** (DPRK, G0032): DTrack and ATMDtrack in Indian banks and
  research centres (Kaspersky, 2019), DTrack on Kudankulam's administrative
  network (confirmed by NPCIL, October 2019), the Cosmos Bank heist (2018,
  vendor attribution) and the US$235 million WazirX theft (2024, attributed by
  the US, Japan and South Korea). Confidence high.
* Added **APT41** (China-nexus, G0096): India in the 2020 Citrix/Zoho exploitation
  wave, a November 2020 campaign against Indian oil and gas, and 2021 tax- and
  COVID-themed phishing of Indian nationals (BlackBerry). Confidence medium.
* Added **RedFoxtrot** (PLA Unit 69010, as reported by Recorded Future): Indian
  aerospace, defence and telecom targeting to 2021. Status historical.
* New `timeline` field: every actor now has dated, sourced milestones.
* **RedEcho**: added MITRE G1042, ATT&CK techniques, the full Recorded Future
  findings, and a correction: TAG-38 is a separate cluster that Recorded Future
  could not link to RedEcho, so it is no longer listed as an alias. The October
  2020 Mumbai outage is recorded as unsubstantiated.
* **Transparent Tribe** and **SideCopy**: first public reports (2016, 2020) and
  Operation Sindoor-era phishing added.
* Researched and **not added**: Patchwork and Bitter, which are assessed as
  India-nexus actors targeting Pakistan, China, Bangladesh and others, not
  threats to India; North Korea's Contagious Interview campaign (no Indian
  victims named in reporting).

**Hacktivists (new feed)**

* New `data/hacktivist.json` and `schema/hacktivist.schema.json`: 9 entries.
  The #OpIndia wave after Pahalgam and Operation Sindoor, RipperSec, Mysterious
  Team Bangladesh, SYLHET GANG-SG, Team Insane PK, Pakistan Cyber Force (including
  the March 2026 ABP News claim), Keymous+, AnonSec and the Holy League alliance.
* Each notable claim records the verification status the source reached
  (confirmed, partly-true, overstated, recycled, false, unverified).
* Exported to STIX as `threat-actor` (activist) and `campaign` objects; no claim
  becomes an indicator.

**Fraud (4 new entries)**

* SpyMax RAT spread as a WhatsApp wedding-invitation APK, with two package-name
  indicators (K7 Labs, Broadcom, Maharashtra Cyber).
* "Digital arrest" extortion: I4C figures 2022-2025, Skype/SIM/IMEI blocking and
  the Supreme Court's December 2025 order for a CBI probe.
* Fake stock-tip groups and trading apps (I4C, CloudSEK).
* Task-based part-time job scams (MeitY blocking order, the Rs 712 crore
  Hyderabad case).

### Threat actors

* Added **MuddyWater** (Iran-nexus, MOIS), the tracker's first Iranian actor.
  India appears in its documented target lists (Unit 42, 2017; HarfangLab,
  2024), and DSCI's March 2026 advisory names it among Iranian actors posing
  risk to Indian organisations. Confidence is medium: no India-specific
  campaign has been publicly reported. Exported to STIX as an intrusion set.
* Researched and **not added**: OilRig/APT34, Charming Kitten/APT35,
  CyberAv3ngers and the pro-Iran hacktivist groups active in 2026. No public
  reporting found names Indian targets for them; they will be added if that
  changes.

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
