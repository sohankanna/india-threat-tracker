# India Threat Tracker

A small, honest, **machine-readable** feed of threat intelligence that matters
for defenders and users in India — actively-exploited CVEs, fake-APK / smishing
campaigns, and India-focused APT activity.

Not another CVE mirror. The goal is **curation + India context + a clean schema
you can actually pull into tooling**, with human explainers on
[sohankanna.com](https://www.sohankanna.com).

> Data is for defensive and research use. No malware samples are hosted here —
> indicators only.

## Feeds

| File | What it is | Updated |
|------|------------|---------|
| [`data/exploited-cve.json`](data/exploited-cve.json) | CISA KEV enriched with FIRST **EPSS** and a coarse **India-relevance** tag | **Automated**, daily |
| [`data/smishing-apk.json`](data/smishing-apk.json) | Fake-APK / smishing campaigns (RTO challan, bank KYC, utility lures) with IOCs | Curated |
| [`data/apt-campaigns.json`](data/apt-campaigns.json) | India-focused APT actors and campaigns | Curated |

Each file is a JSON object: `{ feed, generated_at, count, items: [...] }`.
Schemas live in [`schema/`](schema/) and are enforced in CI.

## Pull the data

```bash
# latest actively-exploited CVEs relevant to India
curl -s https://raw.githubusercontent.com/sohankanna/india-threat-tracker/main/data/exploited-cve.json \
  | jq '.items[] | select(.india_relevance=="high" and .watchlist==true) | {cve, vendor, product, epss, due_date}'

# fake-APK campaign IOCs
curl -s https://raw.githubusercontent.com/sohankanna/india-threat-tracker/main/data/smishing-apk.json \
  | jq '.items[] | {title, iocs}'
```

## Field notes

- **`india_relevance`** (`high` / `medium` / `global`) is a transparent keyword
  heuristic over the vendor/product string
  (see [`scripts/india_relevance.py`](scripts/india_relevance.py)). It is a
  *starting filter*, not ground truth — real exposure needs scan and sector
  data. Tags can be overridden by hand.
- **`watchlist`** is `true` for high/medium-relevance CVEs added in the last 24
  months, or any with known ransomware use.
- **`epss`** is the probability of exploitation in the next 30 days (FIRST EPSS).

## How it runs

```
scripts/fetch_exploited.py   CISA KEV + EPSS  -> data/exploited-cve.json
scripts/validate.py          every data file  -> checked against schema/
scripts/make_tweet_draft.py  today's KEV adds -> drafts/<date>.md  (a draft, not post-ready)
```

A GitHub Action ([`.github/workflows/update.yml`](.github/workflows/update.yml))
runs the pipeline daily and commits any changes. Run it by hand from the
**Actions** tab (**Run workflow**) to populate the KEV feed immediately.

### Run locally

```bash
pip install -r requirements.txt
python scripts/fetch_exploited.py   # needs open internet (not inside sandboxes)
python scripts/validate.py
```

## Contributing

New campaign or IOC? See [CONTRIBUTING.md](CONTRIBUTING.md). Open a PR that adds
an item to the right `data/*.json` file — CI validates it against the schema.

## License

Code: MIT. Data: CC-BY-4.0 — use it, credit [@sohankanna](https://x.com/sohankanna).
