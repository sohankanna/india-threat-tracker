# Data guide

Everything you need to pull the India Threat Tracker into your own tooling:
what each feed contains, what the fields mean, how fresh it is, and how to use
the indicators safely. The same guide is on the site at
[sohankanna.com/tracker/data](https://www.sohankanna.com/tracker/data).

Base URL for every file:

```
https://raw.githubusercontent.com/sohankanna/india-threat-tracker/main/data/
```

## Feeds

| File | Contents | Updated | Schema |
|------|----------|---------|--------|
| `watchlist.json` | KEV entries that are India-relevant (high or medium) **and** added in the last 24 months or ransomware-linked | Twice daily, automated | [`watchlist.schema.json`](schema/watchlist.schema.json) |
| `exploited-cve.json` | Every CISA KEV entry, with EPSS and an India-relevance tier | Twice daily, automated | [`exploited-cve.schema.json`](schema/exploited-cve.schema.json) |
| `smishing-apk.json` | Fake-APK and smishing campaigns | When new reporting appears | [`smishing-apk.schema.json`](schema/smishing-apk.schema.json) |
| `apt-campaigns.json` | State-nexus actors targeting India | When new reporting appears | [`apt-campaign.schema.json`](schema/apt-campaign.schema.json) |
| `iocs.csv` / `iocs.txt` | Defanged campaign indicators (CSV adds provenance per row) | Rebuilt by every automated update (twice daily); CI rejects a change that leaves them stale | — |
| `assessment.json` | The monthly ranked analyst assessment | Monthly | [`assessment.schema.json`](schema/assessment.schema.json) |
| `relevance-overrides.json` | Hand-reviewed India-relevance decisions the pipeline applies | When an entry is reviewed | [`relevance-overrides.schema.json`](schema/relevance-overrides.schema.json) |
| `india-threat-tracker-stix.json` | STIX 2.1 Bundle for CTI platforms; mapping, validation and limitations in [STIX-GUIDE.md](STIX-GUIDE.md) | Rebuilt by every automated update; CI rejects a stale bundle | OASIS STIX 2.1 |
| `kev-affected.json` | Affected products and versions for every KEV CVE, from the official CVE records, not interpreted; used by the [Exposure Matcher](EXPOSURE-MATCHER.md) | Twice daily, automated | [`kev-affected.schema.json`](schema/kev-affected.schema.json) |
| `meta.json` | Manifest of every data file: kind, format, schema, who updates it and how often | When a file is added or its cadence changes | [`meta.schema.json`](schema/meta.schema.json) |

Each JSON file has its **own** schema; there is no single envelope shared by
all of them. The four data feeds are objects with `feed`, `generated_at` and an
`items` array. `assessment.json` uses `period`, `updated` and ranked `items`;
`relevance-overrides.json` holds an `overrides` map; `meta.json` is a manifest
with a `resources` map. Read `meta.json` to discover files and their schemas
programmatically. Every JSON file is validated against its schema on every
change; new fields are only ever added, and existing fields keep their meaning.

## Field reference

### `watchlist.json` and `exploited-cve.json`

| Field | Meaning |
|-------|---------|
| `cve`, `vendor`, `product`, `name`, `description` | From the CISA KEV catalog |
| `date_added` | When CISA added it to KEV (`YYYY-MM-DD`) |
| `due_date` | CISA's remediation deadline for US federal agencies. Most are already past; it is a reference, not your deadline |
| `required_action` | CISA's required action, verbatim |
| `known_ransomware` | `true` when CISA lists known ransomware use |
| `epss` | FIRST EPSS probability of exploitation in the next 30 days, 0–1. **`null` means no score, not a low score** |
| `epss_percentile` | Where that score ranks among all scored CVEs, 0–1 |
| `epss_date` | The FIRST model date the score was taken from |
| `india_relevance` | `high`, `medium` or `global` (see labels below) |
| `relevance_match` | The keyword that set the tier (e.g. `fortinet`), or `manual review` |
| `_manual_relevance`, `relevance_reason` | Present when the tier was set by an editorial override |
| `watchlist` | Whether the entry meets the watchlist rule |
| `sources` | CISA KEV and NVD links |

Both feeds carry `enrichment`, the health of the EPSS lookup for that run:
`epss_available`, `epss_missing`, `epss_coverage` (0–1), `epss_failed_requests`,
`previous_epss_coverage`, and `status`. `status` is `degraded` when EPSS
requests failed or coverage fell by more than two percentage points against the
previous run, with the `reasons`. A fresh feed with degraded enrichment is
current for KEV but has incomplete EPSS scores; FIRST not scoring a few new CVEs
is normal and stays `ok`.

`exploited-cve.json` also carries `manual_overrides`: how many overrides were
applied, and any **orphaned** ones whose CVE is no longer in KEV.

### `smishing-apk.json`

| Field | Meaning |
|-------|---------|
| `id`, `title`, `category`, `summary` | What the campaign is |
| `status` | `active`, `law-enforcement` or `historical` (see labels below) |
| `attribution` | Who the **source** attributes it to, as reported |
| `confidence` | The tracker's rating of the evidence: `high`, `medium`, `low` |
| `first_seen` | When the activity was first reported (`YYYY` or `YYYY-MM` where that's all that's known) |
| `last_verified` | When a person last checked the cited source |
| `targets`, `impersonates`, `lure_themes`, `capabilities` | Who it hits and how |
| `attack` | MITRE ATT&CK techniques mapped by the tracker from the reported behaviour |
| `key_findings`, `recommended_actions` | Drawn from the cited sources |
| `iocs` | **Indicators** for investigation: `domains`, `urls`, `sha256`, `package_names`, `telegram_bots`. Defanged |
| `infrastructure` | **Context only**: `abused_platforms`, `hosting_providers`, `c2_technology`. Never block these |
| `sources`, `references_blog` | Where every claim comes from |

### `apt-campaigns.json`

Same pattern: `actor`, `aliases`, `suspected_origin` (reported attribution),
`attribution_note` (its basis), `mitre_group`, `confidence` (the tracker's
rating of the evidence, kept separate from attribution), `targets`,
`known_tools`, `typical_vectors`, `attack`, `key_findings`,
`recommended_actions`, `last_verified`, `sources`.

### `iocs.csv`

`indicator, type, campaign_id, campaign, confidence, source, source_url, source_checked, status`

`status` is always `as reported; not re-validated; last seen not tracked`.

## Labels

**India relevance** is a transparent keyword rule over vendor and product:
`high` for internet-facing edge, VPN, identity and enterprise-server products
Indian organisations run; `medium` for ubiquitous software that is not an
India-specific signal; `global` for everything else. It is triage, not proof
that you are exposed.

**Watchlist** = relevance `high` or `medium`, **and** added to KEV in the last
24 calendar months (on 20 October 2026, from 20 October 2024 inclusive) **or**
ransomware-linked.

**Status** describes the public reporting, never whether infrastructure is live:
`active` = still being reported; `law-enforcement` = known from a police action
(allegations, not yet proven in court); `historical` = no new reporting in 12
months.

**Confidence** rates the evidence: `high` = corroborated by named primary
research or a verifiable event; `medium` = credible single-source reporting;
`low` = plausible but thin.

**Timestamps:** `generated_at` = when the feed was rebuilt; `last_verified` =
when a person checked the source; indicator last-seen is **not tracked**.

Full scoring rules: [METHODOLOGY.md](METHODOLOGY.md).

## Using the indicators safely

1. **Use `iocs.csv` or `iocs.txt`, not the raw campaign JSON.** The exports
   contain indicators only; infrastructure context (GitHub, Firebase, hosting
   providers) is excluded, and CI fails if it ever leaks in.
2. **Indicators are defanged** (`example[.]com`, `hxxps://`). Re-fang only for a
   blocklist you control, and on purpose.
3. **They are as reported, not re-validated.** A domain listed here may have
   been taken down or re-registered. Alert on them before you block them.
4. **Check freshness first.** If `generated_at` in `watchlist.json` is more than
   36 hours old, the update job may have failed; treat the data as stale.
5. **Keep the provenance.** The CSV carries campaign, source, confidence and the
   date the source was checked. Keep those columns when you import, so an analyst
   can see why an indicator is there.

## Examples

**curl + jq** — high-relevance watchlist entries with EPSS of 50% or more:

```bash
RAW=https://raw.githubusercontent.com/sohankanna/india-threat-tracker/main/data
curl -s $RAW/watchlist.json \
  | jq '.items[] | select(.india_relevance=="high" and .epss!=null and .epss>=0.5) | {cve, vendor, product, epss, epss_date}'
```

**Python** — [`examples/consume_feeds.py`](examples/consume_feeds.py), standard
library only, tested in CI:

```bash
python examples/consume_feeds.py health
python examples/consume_feeds.py watchlist --relevance high --min-epss 0.5
python examples/consume_feeds.py iocs --type sha256
```

**PowerShell**:

```powershell
$raw = "https://raw.githubusercontent.com/sohankanna/india-threat-tracker/main/data"
(Invoke-RestMethod "$raw/watchlist.json").items |
  Where-Object { $_.india_relevance -eq "high" -and $_.known_ransomware } |
  Select-Object cve, vendor, product, epss, due_date
Invoke-RestMethod "$raw/iocs.csv" | ConvertFrom-Csv | Where-Object type -eq "sha256"
```

**Splunk** — load the indicators as a lookup with provenance:

```
| inputlookup india_tracker_iocs.csv
```

after saving `iocs.csv` into a lookup table (Settings → Lookups → Lookup table
files).

## License and attribution

Data is [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/): use it, and
credit **Sohan Kanna** ([@sohankanna](https://x.com/sohankanna)). Code is MIT.
