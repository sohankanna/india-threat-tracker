#!/usr/bin/env bash
# Regenerate the automated feeds and push them, without ever overriding a
# human edit.
#
# Everything this job commits (exploited-cve.json, watchlist.json, iocs.*,
# drafts/) is derived from upstream data plus the curated files in the repo. So
# if someone pushes while the job runs, the push is rejected and the job:
#
#   1. resets to the new main (their edit included, untouched),
#   2. rebuilds every derived file from the upstream data it already fetched,
#   3. validates and tests again, then pushes.
#
# There is no pull, rebase or merge, so no conflict is ever resolved in the
# bot's favour. If the rebuild fails against the new main (say the human edit
# breaks a schema), the job fails visibly and nothing is pushed.
#
# Environment (all optional):
#   UPDATE_FROM_CACHE  rebuild from this cache dir instead of fetching (tests)
#   UPDATE_REMOTE      default: origin
#   UPDATE_BRANCH      default: main
#   UPDATE_ATTEMPTS    default: 4
set -euo pipefail

REMOTE="${UPDATE_REMOTE:-origin}"
BRANCH="${UPDATE_BRANCH:-main}"
ATTEMPTS="${UPDATE_ATTEMPTS:-4}"
CACHE="${UPDATE_FROM_CACHE:-$(mktemp -d)}"
PY="${PYTHON:-python}"

generate() {
  local attempt="$1"
  if [[ -n "${UPDATE_FROM_CACHE:-}" || "$attempt" -gt 1 ]]; then
    "$PY" scripts/fetch_exploited.py --from-cache "$CACHE"
  else
    "$PY" scripts/fetch_exploited.py --cache "$CACHE"
  fi
  # Affected versions for the Exposure Matcher. Best-effort network fetch on the
  # first attempt; a retry (or a test run) re-syncs with the KEV feed offline.
  if [[ -n "${UPDATE_FROM_CACHE:-}" || "$attempt" -gt 1 ]]; then
    "$PY" scripts/build_affected.py --offline
  else
    "$PY" scripts/build_affected.py
  fi
  "$PY" scripts/build_iocs.py
  "$PY" scripts/build_stix.py
  "$PY" scripts/validate.py
  "$PY" -m unittest tests.test_pipeline tests.test_iocs tests.test_stix tests.test_exposure
  (cd scripts && "$PY" make_tweet_draft.py)
}

for attempt in $(seq 1 "$ATTEMPTS"); do
  if [[ "$attempt" -gt 1 ]]; then
    echo "::notice::$BRANCH moved while the update ran. Rebuilding on top of it (attempt $attempt)."
    git fetch --quiet "$REMOTE" "$BRANCH"
    git reset --quiet --hard "$REMOTE/$BRANCH"
    git clean --quiet -fd -- data drafts stix
  fi

  generate "$attempt"

  git add data/ drafts/ stix/
  if git diff --cached --quiet; then
    echo "No changes."
    exit 0
  fi
  git commit --quiet -m "chore: feed update ($(date -u +%Y-%m-%dT%H:%MZ))"

  if git push --quiet "$REMOTE" "HEAD:$BRANCH"; then
    echo "Pushed on attempt $attempt."
    exit 0
  fi
  sleep $(( attempt * ${UPDATE_BACKOFF:-10} ))
done

echo "::error::Could not push the feed update after $ATTEMPTS attempts"
exit 1
