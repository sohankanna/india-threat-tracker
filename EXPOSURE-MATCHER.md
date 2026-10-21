# Exposure Matcher

**Status: research preview.** Check an asset inventory against every CVE in
CISA's Known Exploited Vulnerabilities (KEV) catalogue and get an explainable,
prioritised list of possible exposures. Every result states its evidence, and
anything the data cannot settle is marked uncertain instead of guessed.

* **In the browser:** [sohankanna.com/tracker/exposure](https://www.sohankanna.com/tracker/exposure)
* **Offline:** `node --experimental-strip-types matcher/cli.ts inventory.csv` (Node.js 22.6+)

Both run the same engine, [`matcher/exposure.ts`](matcher/exposure.ts).

## Privacy and data processing

* **Your inventory never leaves your device.** In the browser the file is read
  with the local file API and matched in the page. It is not uploaded, not
  stored (no cookies, local storage or server), and not logged. Closing the tab
  discards it. The site has no analytics.
* **The only network requests** are two public data files, fetched the same way
  for everyone: `exploited-cve.json` and `kev-affected.json` from this
  repository. Nothing from your inventory is in those requests. This was checked
  in a browser test that records every request the page makes.
* **The CLI makes no network requests at all.** It reads the data files from your
  clone of the repository.
* You do not need real hostnames, IP addresses or credentials. `asset_id` can be
  any label.

## Inventory format

CSV with a header row. Template:
[`matcher/inventory-template.csv`](matcher/inventory-template.csv); synthetic
sample: [`matcher/sample-inventory.csv`](matcher/sample-inventory.csv).

| Column | Required | Values |
|---|---|---|
| `asset_id` | no | Any label (defaults to the row number) |
| `vendor` | recommended | e.g. `Palo Alto Networks` |
| `product` | yes, unless `cpe` | e.g. `PAN-OS` |
| `version` | recommended | e.g. `12.1.4-h11`; without it, results stay candidates |
| `cpe` | no | CPE 2.3 string; used for identity, and for version if `version` is empty |
| `internet_exposed` | no | `yes`, `no`, `unknown` (blank = unknown) |
| `criticality` | no | `low`, `medium`, `high`, `critical` (blank = unspecified) |
| `environment` | no | Any label, e.g. `production` |

Validation runs before matching. Invalid values, a missing product, malformed
CPEs and rows with the wrong number of fields are reported with their row
number and that row is not processed; duplicate `asset_id`s and missing
versions are warnings, and those rows are processed. Nothing is dropped silently.
Limit: 50,000 rows.

## Where the vulnerability data comes from

[`data/kev-affected.json`](data/kev-affected.json) is built by
[`scripts/build_affected.py`](scripts/build_affected.py) from the **official CVE
record** of every KEV CVE ([CVE Project cvelistV5](https://github.com/CVEProject/cvelistV5)):
each `affected` entry from the CNA (usually the vendor) and from ADPs such as
CISA's vulnrichment, kept as written. KEV status, dates, required action,
ransomware use and EPSS come from [`data/exploited-cve.json`](data/exploited-cve.json).

It is rebuilt by every automated update. New KEV CVEs are fetched immediately;
existing records are refreshed on a seven-day rotation so corrections reach the
matcher within a week. A failed fetch keeps the previous data and is counted in
the file's `coverage` block; it never stops the feed. CI fails if the file is
out of step with the KEV feed.

## Methodology

### Identity

A result needs the asset to name the same product as the CVE record:

* **Exact:** same vendor and same product after normalisation (case and
  punctuation ignored, the vendor's own name stripped from the front of the
  product, so "Microsoft SharePoint Server 2019" = "SharePoint Server 2019"),
  or the same CPE vendor:product.
* **Reviewed aliases only:** a short list in the engine, for names that refer to
  the same product line, such as FortiGate and FortiOS, Pulse Connect Secure
  and Connect Secure, Citrix ADC and NetScaler ADC, or Palo Alto and Palo Alto
  Networks. Anything not on the list must match exactly.
* **Partial** (one product name contains the other, or no vendor given):
  *insufficient evidence*, never a match.
* If the CVE record names the product in a way that does not match but CISA's
  KEV listing does, the result is a *candidate* with no version check.

### Versions

Versions are compared only when both sides are plain version numbers in a
recognised scheme: dotted (`16.0.10417.20037`), dash builds
(`13.1-49.15`), PAN-OS hotfixes (`12.1.4-h11`) and Ivanti releases
(`22.7R2.3`). Missing trailing parts count as zero. Anything else, such as F5
engineering hotfixes, "FIPS" builds, "All other versions" or Windows edition
names, is **not comparable**, and no ordering is invented for it.

The CVE JSON 5 version entries are read conservatively:

* **Ranges** `[version, lessThan)` or `[version, lessThanOrEqual]`. Ranges whose
  upper bound is below the lower bound are treated as not comparable.
* **Change points inside a range** (Palo Alto lists hotfix fixes such as
  `12.1.4-h12`, `12.1.7-h8`) apply **per maintenance branch**. A version on a
  branch with no listed fix (say 12.1.5) is *uncertain*, not fixed.
* **Several open-ended fixes on different branches** (`< 14.1-73.41`,
  `< 13.1-64.28`) are per-branch fixes. Only the fix on the asset's branch
  applies, and if none is listed the result is uncertain.
* **Citrix branch + build ranges** (`13.1 < 49.15` means 13.1 builds below
  49.15) are read as such, and need the full build (`13.1-49.14`).
* **CPE-listed versions** match exactly, including the CPE `update` field, where
  Palo Alto puts the hotfix (`pan-os:10.2.10:h1` is `10.2.10-h1`).
* **`defaultStatus: affected`** with only fixed versions listed: a version that is
  not one of them is a *candidate*, because the record does not say whether
  later releases are fixed.

### Statuses

| Status | Meaning |
|---|---|
| **Affected version** | The record's own data places the supplied version in an affected range or list. |
| **Candidate** | The product matches, but the version is missing, not comparable, or not settled by the record. |
| **Insufficient evidence** | Only a partial product-name match. |
| **No match** | No listed affected configuration matched. Not proof that the asset has no vulnerabilities. |

An affected version is not proof of compromise or even of exploitability (a
vulnerable feature may be disabled). A match against the threat intelligence
elsewhere in the tracker, such as India relevance, is **threat context**, shown
separately; it is never evidence about a specific asset.

### Priority

No composite score. Every result is a KEV CVE, so exploitation in the wild is
already established; the tier combines how strong the match is with the
business context you supplied.

| Tier | Rule |
|---|---|
| **P1** | Affected version **and** (internet-exposed **or** critical asset **or** known ransomware use) |
| **P2** | Affected version otherwise; **or** candidate on an internet-exposed or critical asset |
| **P3** | Candidate otherwise |
| **P4** | Insufficient evidence |

Exposure `unknown` is not treated as exposed; such a P2 says "Would be P1 if
internet-exposed". EPSS (with its model date) is shown and only orders results
within a tier; a missing EPSS score is unknown, not low, and sorts last. CVSS
severity is not used: KEV listing already answers "is this being exploited".
Each result carries a one-line explanation of its tier.

## Coverage, measured

Measured on 21 October 2026 across all 1,748 KEV CVEs, by what the official
record's version data allows:

| Record version data | CVEs | What the matcher can do |
|---|---|---|
| Comparable ranges | 513 | Version verdicts |
| Comparable exact version lists | 151 | Version verdicts |
| Versions only in CPEs | 43 | Version verdicts |
| Not comparable (`*`, "unspecified", editions, prose) | 560 | Candidates |
| No product data (old records, `n/a`) | 481 | Candidates via the KEV listing |

So roughly 40% of KEV CVEs can get a confident version verdict. The rest are
candidates. That is the honest result, not a gap the matcher papers over: check
those against the vendor advisory. NVD's CPE configurations could improve the
older records; that is planned, not done.

## Outputs

* **On screen:** summary counts, file issues, filters (status, priority, internet
  exposure, criticality, known ransomware use), and for each result the
  evidence, the record's affected versions, KEV date, EPSS and date, ransomware
  use, required action and CISA deadline, your exposure and criticality, the
  tier explanation, and links to the CVE record, NVD and KEV.
* **CSV export** of the filtered results. Cells beginning with `=`, `+`, `-`,
  `@`, tab or carriage return are prefixed with `'` so spreadsheets cannot run
  them as formulas.
* **JSON export** with the scope note, summary, file issues and results, matching
  [`schema/exposure-report.schema.json`](schema/exposure-report.schema.json).

The same inventory and data always give the same output, in the same order.

## Tests

* [`matcher/test/exposure.test.ts`](matcher/test/exposure.test.ts) covers:
  * every case in the Phase 2 plan: in range, out of range, unknown version,
    ambiguous identity, missing fields, CPE match and mismatch, missing EPSS,
    exposure and criticality tiers, malformed CSV, multiple ranges;
  * each vendor scheme above;
  * formula-safe exports.

  Disabling any of the safeguards (Citrix branch builds, per-branch fixes,
  off-branch uncertainty, inverted ranges, partial-identity handling, formula
  escaping) fails the suite.
* [`tests/test_exposure.py`](tests/test_exposure.py) checks:
  * the data file covers exactly the KEV feed;
  * failed fetches are kept and counted;
  * CVE records are normalised faithfully;
  * the rotation reaches every record within a week;
  * the JSON export validates against its schema and is deterministic.

```bash
node --experimental-strip-types --test matcher/test/*.test.ts
python -m unittest tests.test_exposure
```

## Limitations

* KEV CVEs only. Not a general vulnerability scanner.
* Results are only as good as the CVE records. Some CNAs publish no usable
  version data; some ranges are wrong. The matcher reports what the record says.
* No configuration awareness: an affected version may have the vulnerable
  feature disabled.
* The alias list is short by design and will miss some product names. A miss
  shows as no result for that product, so check the products you care most
  about against the sample to see they are recognised.
* Not validated against real enterprise inventories yet.
