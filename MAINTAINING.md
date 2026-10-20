# Maintaining the tracker

The whole point of this is that it stays *alive*. A stale tracker is worse than
none. Here's the minimum to keep it real without it eating your life.

## Automated (you don't touch this)
- The "Update feeds" GitHub Action runs twice a day (~08:00 and ~20:00 IST). It
  refreshes `exploited-cve.json` and `watchlist.json` from CISA KEV + EPSS,
  rebuilds `iocs.csv`/`iocs.txt`, validates and tests, then pushes. If you push
  while it runs, it resets to your commit and rebuilds on top of it, so your edit
  always wins; it never resolves a merge conflict. If it goes red, check the
  Actions tab.
- If the job log shows "EPSS enrichment degraded", the feed is current for KEV
  but EPSS scores are incomplete; the next run normally recovers.

## Weekly (~10 min)
- Skim the week's India security news (THN, the moneylife/news APK busts, CERT-In
  advisories). If there's a notable new fake-APK campaign or IOC set, add an entry
  to `data/smishing-apk.json` (copy an existing item as a template).
- Check `drafts/` for the auto-generated tweet draft. Rewrite it in your own voice
  and post it — don't post it raw.

## Monthly (the flagship, ~2-3 hrs)
- Write the next **India Threat Landscape** issue on the blog: what the tracker
  catalogued this month + the 2-3 things that actually mattered. Link the tracker.
  This is the piece that gets shared — it's worth the time.

## Adding an entry
1. Open the right file in `data/` and copy an existing item.
2. Fill it in. Every entry needs at least one real source (title + url).
3. Defang IOCs (`example[.]com`). Never commit a sample or a live payload URL.
4. `python scripts/build_iocs.py` if you changed campaign indicators, then
   `python scripts/validate.py` and `python -m unittest discover -s tests`. CI
   runs all of these too.

## If you ever add true auto-posting to X
- Store the API keys as GitHub repo **secrets** (Settings -> Secrets -> Actions),
  never in the code. Add a step to the workflow that reads them from `env`.
- Keep a human in the loop at first — post the draft, don't auto-fire, until you
  trust it.

## Health checks
- `watchlist.json` `generated_at` should be under 36 hours old (the site warns
  past that), and `enrichment.status` should be `ok`.
- `python scripts/validate.py` passes.
- The blog `/tracker` page shows data (it reads this repo's raw JSON).
