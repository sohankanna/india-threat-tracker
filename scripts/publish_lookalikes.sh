#!/usr/bin/env bash
# Scan for lookalike domains once, then commit data/lookalike-domains.json the
# same way publish_update.sh commits the feeds: if main moved, reset to it and
# re-apply the saved scan (no second scan, no merge, no conflict resolution).
set -euo pipefail

REMOTE="${UPDATE_REMOTE:-origin}"
BRANCH="${UPDATE_BRANCH:-main}"
ATTEMPTS="${UPDATE_ATTEMPTS:-4}"
CACHE="${UPDATE_FROM_CACHE:-$(mktemp -d)}"
PY="${PYTHON:-python}"

for attempt in $(seq 1 "$ATTEMPTS"); do
  if [[ "$attempt" -gt 1 ]]; then
    echo "::notice::$BRANCH moved during the scan. Re-applying it on top (attempt $attempt)."
    git fetch --quiet "$REMOTE" "$BRANCH"
    git reset --quiet --hard "$REMOTE/$BRANCH"
  fi
  if [[ -n "${UPDATE_FROM_CACHE:-}" || "$attempt" -gt 1 ]]; then
    "$PY" scripts/scan_lookalikes.py --from-cache "$CACHE"
  else
    "$PY" scripts/scan_lookalikes.py --cache "$CACHE"
  fi
  "$PY" scripts/build_misp_feed.py
  "$PY" scripts/validate.py
  "$PY" -m unittest tests.test_lookalikes tests.test_misp_feed

  git add data/lookalike-domains.json misp-feed/
  if git diff --cached --quiet; then
    echo "No changes."
    exit 0
  fi
  git commit --quiet -m "chore: lookalike scan ($(date -u +%Y-%m-%d))"
  if git push --quiet "$REMOTE" "HEAD:$BRANCH"; then
    echo "Pushed on attempt $attempt."
    exit 0
  fi
  sleep $(( attempt * ${UPDATE_BACKOFF:-10} ))
done
echo "::error::Could not push the lookalike scan after $ATTEMPTS attempts"
exit 1
