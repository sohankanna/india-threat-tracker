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
| `data/exploited-cve.json` / `watchlist.json` | CISA KEV + FIRST EPSS, auto-enriched | Daily (GitHub Action) |
| `data/smishing-apk.json` | Hand-curated from public reporting & busts | On new, credible reporting |
| `data/apt-campaigns.json` | Hand-curated from vendor/CERT reporting | On new, credible reporting |
| `data/assessment.json` | Analyst judgement over the above | Monthly |

The assessment is the opinionated layer: a dated, ranked read of what matters
*this month*. The feeds are the evidence under it.

---

## Actively-exploited CVEs

### Three signals, three meanings

- **CISA KEV** — the vulnerability is **known exploited in the wild**. Fact, not
  forecast. Pulled from the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
- **EPSS** — the **probability** a CVE is exploited in the next 30 days, 0–100%,
  from [FIRST](https://www.first.org/epss/). A forecast, re-pulled daily.
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

It is deliberately a blunt, legible rule rather than a black box. It can be
**overridden by hand** per-CVE (`_manual_relevance`), and those overrides win
over the heuristic.

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
wants it.

> **Honest caveat on the "overdue" filter:** most KEV remediation deadlines are
> already in the past, so an "overdue" toggle marks almost everything. The
> selective tools are the **EPSS threshold** and the **due-date sort**, not
> overdue-vs-not.

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
- **`last_verified`** — the date the entry was last checked against its sources.
- **`first_seen`** — when the activity was first observed/reported, where known.
- **`references_blog` / `reference_url` / `sources`** — where the claim comes
  from. Every entry links to something you can check.

### On attribution

APT attribution here is **assessed, not proven**. `suspected_origin` reflects the
consensus of public reporting (e.g. "Pakistan-nexus"), and groups don't map
cleanly onto governments. The global actor map is context for *who operates and
who they target* — it is not a live attack map, and it is not a courtroom claim.

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
