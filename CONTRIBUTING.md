# Contributing

Thanks for helping keep this accurate.

## Adding an entry

1. Pick the right file in `data/`:
   - `smishing-apk.json` — fake-APK / smishing campaigns
   - `apt-campaigns.json` — India-focused APT actors / campaigns
   - `relevance-overrides.json` — to correct an India-relevance tier. Add the CVE
     with `tier`, a `reason` (why, in a sentence) and the `reviewed` date. Never
     edit `exploited-cve.json` or `watchlist.json`: they are regenerated twice a day.
2. Copy an existing item as a template and fill it in.
3. Every entry needs at least one real **source** (`title` + `url`).
4. Validate before opening a PR:
   ```bash
   pip install -r requirements.txt
   python scripts/validate.py
   ```
   If you changed `smishing-apk.json`, also run `python scripts/build_iocs.py`
   so the IOC exports match; CI fails a PR whose exports are stale. CI re-runs
   everything on every PR (schemas, IOC exports, the detection inventory, the
   test suite, Sigma validation and a conversion test), so a PR that breaks a
   feed or a rule fails automatically before review. Domains and URLs must be
   defanged (`example[.]com`, `hxxps://`); the schema rejects live ones.

## Adding or changing a detection

- Edit the canonical rule in `detections/sigma/`, then keep the
  `splunk/`, `elastic/` and `wazuh/` counterparts in sync — the inventory check
  fails a PR that adds a Sigma rule without them.
- Add fixtures in `detections/tests/<rule>.events.json`: events that must alert
  and events that must not, each with a `_why`. They are executed against the
  Sigma and Wazuh rules in CI, so a fixture that disagrees with the rule fails
  the build. Document the cases in `detections/TESTING.md`.
- Read `detections/DATA-SOURCES.md` for the telemetry each rule needs.

## Ground rules

- **Indicators only — never commit malware samples or live payload URLs that
  serve a binary.** Defang domains/URLs (`example[.]com`).
- Sources must be public and verifiable. No speculation stated as fact.
- Keep summaries short and defender-focused: what it is, who it hits, what to do.
- Personal data of named private individuals does not belong here.
