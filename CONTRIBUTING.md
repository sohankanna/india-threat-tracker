# Contributing

Thanks for helping keep this accurate.

## Adding an entry

1. Pick the right file in `data/`:
   - `smishing-apk.json` — fake-APK / smishing campaigns
   - `apt-campaigns.json` — India-focused APT actors / campaigns
   - `exploited-cve.json` — **do not hand-edit**; it is generated. (You may set
     `india_relevance` and add `"_manual_relevance": true` to pin a tag against
     the heuristic.)
2. Copy an existing item as a template and fill it in.
3. Every entry needs at least one real **source** (`title` + `url`).
4. Validate before opening a PR:
   ```bash
   pip install -r requirements.txt
   python scripts/validate.py
   ```
   CI re-runs this on every PR (schema validation, the detection inventory
   check, Sigma validation and a conversion smoke test), so a PR that breaks a
   feed or a rule fails automatically before review.

## Adding or changing a detection

- Edit the canonical rule in `detections/sigma/`, then keep the
  `splunk/`, `elastic/` and `wazuh/` counterparts in sync — the inventory check
  fails a PR that adds a Sigma rule without them.
- Add a test fixture in `detections/tests/<rule>.events.json` (one match, one
  non-match) and document it in `detections/TESTING.md`.
- Read `detections/DATA-SOURCES.md` for the telemetry each rule needs.

## Ground rules

- **Indicators only — never commit malware samples or live payload URLs that
  serve a binary.** Defang domains/URLs (`example[.]com`).
- Sources must be public and verifiable. No speculation stated as fact.
- Keep summaries short and defender-focused: what it is, who it hits, what to do.
- Personal data of named private individuals does not belong here.
