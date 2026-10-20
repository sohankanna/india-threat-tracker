# Repo integration files

## CI workflow (do this once)

`github-workflow-validate-pr.yml` → copy to **`.github/workflows/validate-pr.yml`**
in the repo root (the file-bridge can't write under `.github/`, so it's staged
here). It runs on every push and PR: schema validation, the detection inventory
check, Sigma validation, and a Sigma→Splunk conversion smoke test. On Windows:

```cmd
copy /Y site-integration\github-workflow-validate-pr.yml .github\workflows\validate-pr.yml
```

---

# Adding the tracker page to the blog

Two files, then (optionally) a nav link. Do this **after** the repo is pushed,
so the raw data URLs resolve.

1. Copy `lib-tracker.ts` → `lib/tracker.ts` in the blog.
2. Copy `threat-tracker-page.tsx` → `app/tracker/page.tsx`.
3. (Optional) add a `Tracker` link to `components/navigation.tsx` pointing at `/tracker`.
4. (Optional) add `/tracker` to `app/sitemap.ts`.

The page fetches the three feeds from
`raw.githubusercontent.com/sohankanna/india-threat-tracker/main/data` with
hourly revalidation, so it refreshes when the daily Action commits — no redeploy
needed. It fails soft: if the repo is unreachable it just shows empty sections.

Styling uses the same utility classes as the research pages (`text-accent`,
`border-border`, `bg-card`, `text-muted-foreground`). Tweak to taste.
