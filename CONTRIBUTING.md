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

## Ground rules

- **Indicators only — never commit malware samples or live payload URLs that
  serve a binary.** Defang domains/URLs (`example[.]com`).
- Sources must be public and verifiable. No speculation stated as fact.
- Keep summaries short and defender-focused: what it is, who it hits, what to do.
- Personal data of named private individuals does not belong here.
