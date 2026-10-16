# Maintaining the tracker

The whole point of this is that it stays *alive*. A stale tracker is worse than
none. Here's the minimum to keep it real without it eating your life.

## Automated (you don't touch this)
- The GitHub Action runs daily (~08:00 IST) and refreshes `data/exploited-cve.json`
  from CISA KEV + EPSS. If it ever goes red, check the Actions tab.

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
4. `python scripts/validate.py` before committing. CI checks it too.

## If you ever add true auto-posting to X
- Store the API keys as GitHub repo **secrets** (Settings -> Secrets -> Actions),
  never in the code. Add a step to the workflow that reads them from `env`.
- Keep a human in the loop at first — post the draft, don't auto-fire, until you
  trust it.

## Health checks
- `exploited-cve.json` `generated_at` should be within ~2 days of today.
- `python scripts/validate.py` passes.
- The blog `/tracker` page shows data (it reads this repo's raw JSON).
