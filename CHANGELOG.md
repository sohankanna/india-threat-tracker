# Changelog

Dates are when the change reached `main`. Data feeds update twice a day and are
not listed here.

## Unreleased

<<<<<<< ours
<<<<<<< ours
=======
=======
### ATT&CK layers and coverage (Phase 6)

* New `layers/`: ATT&CK Navigator layers for the techniques of the actors
  targeting India, detection coverage (rule tagged with the technique, only a
  related one, or none) and the Mobile techniques of the fraud campaigns. The
  same coverage is in `data/attack-coverage.json`.
* Every technique id and name in the data and every Sigma tag is now checked
  against ATT&CK v20.0 (`config/attack-techniques.json`, refreshed with
  `scripts/update_attack_ref.py`). CI fails on an unknown or renamed technique.
* Correction: GhostBat RAT (`sm-2025-001`) was mapped to T1496 Resource
  Hijacking, which is not a Mobile ATT&CK technique. The mapping is removed;
  the cryptominer stays in the campaign's capabilities and findings.

### Lookalike domains (Phase 6)

* New `data/lookalike-domains.json` and daily `lookalikes.yml`: typo,
  dictionary (`sbi-kyc`, `parivahan-challan`) and TLD-swap variants of 15
  Indian bank, payment and government brands are resolved every day; new
  registrations since the baseline are leads, and new ones are checked against
  certificate transparency (crt.sh). Defanged, never marked for blocking, and
  documented as leads, not verdicts. New leads also go into the MISP feed.
* The manifest can now name the workflow behind an automated file, and the
  cadence test checks each file against its own workflow.

### CERT-In coverage (Phase 6)

* New `data/certin-notes.json`: CERT-In vulnerability notes (code, date,
  severity, CVEs, affected software), collected by `scripts/fetch_certin.py` in
  rate-limited batches by the update job, so the first days backfill this year
  and last. Seeded with five notes checked by hand.
* New `data/certin-gap.json`: every India-relevant KEV entry since the start of
  last year matched against those notes, with the lag between CERT-In and KEV.
  "No note" is never claimed until the scan is complete. See METHODOLOGY.md.
* Tweet drafts now say when a CERT-In note covers a CVE.

>>>>>>> theirs
### Distribution (Phase 6)

* New `misp-feed/`: the tracker as a native MISP feed (one event per fraud
  campaign with indicators, one with the high-relevance KEV CVEs). A MISP
  instance can subscribe to the raw GitHub URL. Rebuilt by the update job,
  checked in CI, and `interop-misp.yml` now subscribes a real MISP to it.
* New release workflow: pushing a `v*` tag publishes the rule pack and the data
  bundle as reproducible zips with SHA256SUMS (`scripts/build_release.py`).
* New [docs/USING.md](docs/USING.md): recipes for MISP, Wazuh, Splunk, Elastic,
  OpenCTI and fraud teams, each marked tested or untested.
* `CITATION.cff` so the dataset can be cited.

### Automation

* `scripts/make_tweet_draft.py` now drafts India-relevant KEV additions from
  the last three days (high relevance, or medium with ransomware use or EPSS of
  10% or more), never drafts the same CVE twice, notes where the tracker already
  covers a CVE, and writes a rough post that fits 280 characters with a link to
  the tracker. On Mondays it also writes a weekly draft. Drafts are never posted.
* New `scripts/ransomware_counts.py` and monthly `ransomware-counts.yml`: counts
  ransomware leak-site claims against India from ransomware.live, by month and
  group, into the run summary. Victim names are never read or stored, nothing is
  committed, and an API failure is a warning, not a failed run.

### Corrections

* November assessment, item 2: UTA0576 *searched for* BitLocker recovery keys
  and administrator passwords; the source does not say keys were taken. The
  earlier wording said they were stolen.

<<<<<<< ours
>>>>>>> theirs
=======
>>>>>>> theirs
### Detections (Phase 5)

* New rule `ad_bitlocker_recovery_information_read` (Wazuh 100240): a user
  account reading BitLocker recovery information from Active Directory, which
  UTA0576 went after following the Ivanti Connect Secure chain. The first rule on
  the Windows Security log; the Wazuh emulator and the real-manager replay now
  handle Security audit events.
* New rule `zoho_workdrive_api_from_unexpected_process` (Wazuh 100215): a DNS
  lookup of the Zoho API or WorkDrive hosts by a process that is not a browser
  or a Zoho client, the cloud dead drop Mustang Panda's ZOHOMURK used against
  Indian government networks.
* New rule `sysvol_payload_or_gpo_scheduled_task_written` (Wazuh 100214): an
  executable, script or Group Policy scheduled-task file created under SYSVOL on a
  domain controller, the staging step The Gentlemen use to deploy ransomware
  across a domain.

### Ransomware (new feed)

* New `data/ransomware.json` and `schema/ransomware.schema.json`.
  * Six groups: RansomEXX (C-Edge, 2024), LockBit, Akira, Hunters International
    (Tata Technologies, 2025), The Gentlemen and Qilin, each with how strongly
    it is linked to India and the KEV flaws the sources tie to it.
  * Six disclosed incidents, marked confirmed or claimed: Motilal Oswal,
    Polycab, C-Edge, Cipla, Tata Technologies and Bajaj Auto.
  * Landscape figures from Cyble and Threat Atlas India, each with what it
    counts.
* Groups exported to STIX as `threat-actor` (crime-syndicate). New tests check
  every linked CVE is in KEV with known ransomware use and that claimed
  incidents never read as confirmed.

### Assessment

* November 2026 assessment. Five items: fraud fed by fake apps, impersonation
  and leaked customer data (SBI, October); the Ivanti Connect Secure zero-day
  chain and CERT-In's 12-hour guidance for exploited internet-facing flaws;
  Mustang Panda reaching Indian banks and government; PHP2Shell, the Node.js
  Brotli flaw and the eMudhra CA distrust; Pakistan-nexus espionage alongside
  hacktivist claims that mostly did not hold up.
* Assessment evidence can now cite hacktivist records (`type: hacktivist`).

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
