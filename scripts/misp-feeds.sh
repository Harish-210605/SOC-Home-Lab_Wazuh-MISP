#!/usr/bin/env bash
# Populate MISP from the curated public threat-intel feeds (Phase 4).
#
# Idempotent: safe to re-run to refresh the intel. Feeds are matched on URL, so
# re-running updates the existing entries rather than duplicating them, and a
# re-fetch merges new indicators into the same event.
#
# The feed list itself lives in misp/feeds.json so it can be reviewed as data;
# the API work is in scripts/misp_feeds.py.

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

FEED_SPECS="$REPO_ROOT/misp/feeds.json"
[[ -f "$FEED_SPECS" ]] || die "$FEED_SPECS is missing."

# shellcheck source=/dev/null
set -a; source "$MISP_ENV"; set +a
[[ -n "${ADMIN_KEY:-}" ]] || die "ADMIN_KEY is not set in $MISP_ENV."

# Fail early with a useful message rather than letting every API call time out.
state="$(docker_run docker inspect --format '{{.State.Health.Status}}' misp-misp-core-1 2>/dev/null || true)"
[[ "$state" == "healthy" ]] \
  || die "misp-core is '${state:-not running}'. Start it with scripts/misp-up.sh first."

log "Feeds are pulled from the public internet (abuse.ch). ~5 MB, ~26k indicators."
exec python3 "$REPO_ROOT/scripts/misp_feeds.py" --specs "$FEED_SPECS" "$@"
