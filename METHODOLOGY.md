# Methodology

How this tracker decides what goes in, how confident it is, and where the
limits are. The whole point of writing this down is that intelligence you can't
audit is just an opinion with a logo — and anyone contributing data needs to
know the bar they're meeting.

---

## What this is

A curated, machine-readable feed of threats **relevant to India**, in three
parts, plus a monthly analyst assessment on top:

| Feed | Source of truth | Cadence |
|------|-----------------|---------|
| `data/exploited-cve.json` / `watchlist.json` | CISA KEV + FIRST EPSS, auto-enriched | Twice daily (GitHub Action) |
| `data/smishing-apk.json` | Hand-curated from public reporting & busts | On new, credible reporting |
| `data/apt-campaigns.json` | Hand-curated from vendor/CERT reporting | On new, credible reporting |
| `data/assessment.json` | Analyst judgement over the above | Monthly |
| `data/iocs.txt` / `iocs.csv` | Derived from the campaign feed | Rebuilt with every update |

The assessment is the opinionated layer: a dated, ranked read of what matters
*this month*. The feeds are the evidence under it.

---

## Actively-exploited CVEs

### Three signals, three meanings

- **CISA KEV** — the vulnerability is **known exploited in the wild**. Fact, not
  forecast. Pulled from the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- **EPSS** — the **probability** a CVE is exploited in the next 30 days, 0–100%,
  from [FIRST](https://www.first.org/epss/). A forecast, re-pulled on every feed update.
- **India relevance** — a transparent heuristic (below) for whether the affected
  product is part of the attack surface Indian orgs actually expose. A starting
  filter, **not** proof your org is exposed.

Read them together. KEV says "it's being used," EPSS says "how likely, soon,"
relevance says "does this map to the Indian attack surface." No single one of
them is a priority on its own.

### The India-relevance heuristic

A lowercase substring match over `"<vendor> <product>"`, scored in three tiers.
The source of truth is [`scripts/india_relevance.py`](scripts/india_relevance.py).

- **high** — internet-facing **edge / VPN / identity / enterprise-server**
  products that make up the attack surface Indian orgs expose and attackers
  actually hit: Fortinet, PAN-OS / GlobalProtect, Citrix NetScaler, Ivanti
  Connect Secure, SonicWall, F5 BIG-IP, Zimbra, Exchange/SharePoint server,
  Confluence/Jira, MOVEit, ManageEngine/Zoho, VMware/vCenter, SAP NetWeaver,
  Struts/Tomcat, GitLab/Jenkins, and Cisco **network/security** products only.
- **medium** — ubiquitous desktop/consumer/server software (Windows, Chrome,
  Office, Adobe, Android, Oracle, WordPress, OpenSSL, Linux kernel, common SOHO
  gear). Real risk, but not an India-*specific* signal.
- **global** — everything else.

It is deliberately a blunt, legible rule rather than a black box, and it can
be **overridden by hand** per CVE.

### Editorial overrides

Hand-reviewed tiers live in [`data/relevance-overrides.json`](data/relevance-overrides.json),
each with a `reason` and a `reviewed` date. The pipeline only ever **reads** that
file, so automation can never overwrite an editorial decision. The behaviour is
explicit and covered by regression tests (`tests/test_pipeline.py`):

- An override sets the tier, marks the record `_manual_relevance: true` and
  `relevance_match: "manual review"`, and carries its `reason`. It survives every
  regeneration.
- The watchlist rule then runs as normal with the overridden tier, so an old,
  non-ransomware CVE raised to `high` stays off the watchlist. An override can
  force the outcome with `"watchlist": true` or `false`.
- If an overridden CVE leaves the KEV catalog, nothing is emitted for it, the
  override is **kept**, and it is reported as orphaned in the feed's
  `manual_overrides` block and in the job log. It is never deleted automatically.
- Older feeds stored overrides as `_manual_relevance` flags on generated records.
  Those are still honoured; the overrides file wins where both exist.

> **Known limitation:** this scores the *product*, not *your* exposure. "high"
> means "this is the kind of thing Indian orgs run on the edge," not "you are
> running it, unpatched, exposed." Treat it as triage, not a finding.

### The watchlist

`watchlist.json` is the slim, high-signal subset the site leads with. A CVE is on
the watchlist when:

```
india_relevance ∈ {high, medium}  AND  (added to KEV within 24 months  OR  known ransomware use)
```

In words: India-relevant, and either **recent** or **ransomware-linked**. This
keeps the watchlist focused on what's current and what's financially dangerous,
while the full KEV set stays available in `exploited-cve.json` for anyone who
wants it. The site opens on the high-relevance part of the watchlist; medium is
one click away.

Every entry also records:

- **`relevance_match`** — the keyword that set its relevance tier (for example
  `fortinet`), or `manual review` for a hand override. The tag is never a
  black box.
- **`epss_date`** — the FIRST model date the EPSS score was taken from. A
  missing EPSS score is shown as *unavailable*, never as zero: no score is not a
  low score.

> **Honest caveat on the "past CISA due date" filter:** most KEV remediation
> deadlines (set for US federal agencies) are already in the past, so that
> toggle marks almost everything. The selective tools are the **EPSS
> threshold**, **ransomware-linked**, **added in the last 30 days**, and the
> **due-date sort**.

---

## Smishing / fake-APK campaigns & APT activity

These two feeds are **hand-curated** from public reporting — vendor research,
CERT-In / national-CERT advisories, court and police bust records, and primary
malware analysis. Each entry carries its own audit trail:

- **`confidence`** —
  - `high`: corroborated by named primary research or a concrete, verifiable
    event (a specific bust, a published sample analysis, a vendor report).
  - `medium`: credible single-source reporting, or an event reported but not
    independently corroborated here.
  - `low`: plausible but thin; included for tracking, flagged as such.
- **`last_verified`** — the date the entry was last checked against its sources
  (shown on the site as *Source checked*).
- **`first_seen`** — when the activity was first observed/reported, where known.
- **`references_blog` / `sources`** — where the claim comes from. Every entry
  links to something you can check, and sources are specific reports, not tag
  or index pages.
- **`key_findings` / `recommended_actions`** — taken from the cited reporting
  and the linked write-up. Nothing in them goes beyond what a source supports.
- **`attack`** — MITRE ATT&CK techniques **mapped by the tracker** from the
  behaviour the sources describe. Every ID is checked against MITRE's published
  ATT&CK data; revoked or deprecated IDs are not used. Entries with no
  described technical behaviour (a police case, a lure reference) carry no
  mapping rather than a guessed one.

### Status

Status describes the state of the **public reporting** about an entry. It never
claims that a domain, server or app is operational right now.

| Value | Shown as | Meaning |
|-------|----------|---------|
| `active` | Ongoing | Still appearing in recent public reporting. |
| `law-enforcement` | Police action | Known mainly from an arrest or seizure. That network was disrupted; allegations are not yet proven in court, and the wider ecosystem continues. |
| `historical` | Historical | No new reporting in the last 12 months. Kept for reference and detection engineering. |

### Indicators versus infrastructure context

Each campaign separates two things that look alike and must never be confused:

- **`iocs`** — specific, campaign-associated indicators suitable for
  investigation: domains, URLs, SHA-256 hashes, Android package names, bot
  handles. Defanged. These are what `iocs.txt`, `iocs.csv` and the site's copy
  and export actions contain.
- **`infrastructure`** — context only: legitimate platforms the campaign abused
  (GitHub, Firebase), hosting providers, C2 technology. These are shared
  services that also serve legitimate users, so they are **excluded from every
  copy and export** and must not become blocklist entries.

Indicators are published *as reported* by the cited source. They are not
re-validated, and a last-seen date is not tracked.

### On attribution

APT attribution here is **assessed, not proven**. `suspected_origin` reflects the
consensus of public reporting (e.g. "Pakistan-nexus"), and groups don't map
cleanly onto governments. Two things are kept deliberately separate:

- **Reported attribution** — what vendors, MITRE ATT&CK (`mitre_group`) or the
  police claim, with the basis in `attribution_note`. For fraud campaigns this
  is the `attribution` field, e.g. "Arrests by Mumbai Cyber Police
  (allegations, not yet proven in court)".
- **Tracker confidence** — the tracker's own rating of the evidence for the
  activity described. A high-confidence entry can still carry contested
  attribution.

The global actor map is context for *who operates and
who they target* — it is not a live attack map, and it is not a courtroom claim.

---

## Timestamps

Three timestamps mean three different things, and the site labels each one:

| Label | Field | Meaning |
|-------|-------|---------|
| **Feed updated** | `generated_at` | When automation regenerated a dataset. Shown in IST. A rebuilt dataset does not mean every item in it is still current. |
| **Source checked** | `last_verified` | When a person last checked the cited report behind a campaign or actor entry. |
| **Indicator last seen** | — | When evidence shows an indicator was observed in use. **Not tracked yet**, so the tracker never implies an indicator is active. |

The site reads every timestamp from the feed file itself rather than keeping a
separate copy, so the page and the JSON cannot disagree. If the live feed can't
be reached, the page falls back to a bundled copy and says so.

---

## The monthly assessment

`data/assessment.json` ranks what matters for Indian defenders **this month**,
each item with two lines of reasoning and links to the evidence. It is
explicitly **analyst judgement**, dated and signed, over the feeds above — the
one subjective layer, kept clearly labelled as such. When the data changes, the
assessment is expected to change with it.

---

## Hard rules

- **Indicators, never samples.** This repo hosts defanged IOCs and analysis. It
  never hosts live malware, working exploit code, or anything that provides
  offensive uplift. Defensive and research use only.
- **Everything links to a source.** If a claim can't point to something
  checkable, it doesn't go in.
- **Relevance ≠ exposure, attribution ≠ proof.** Both are stated as what they
  are, every time.

## Contributing to this standard

If you're adding data, it has to clear the bar above: a real source, a
`confidence` you can defend, a `last_verified` date, and defanged indicators
only. CI validates every entry against the schemas in [`schema/`](schema/)
before it can merge.
