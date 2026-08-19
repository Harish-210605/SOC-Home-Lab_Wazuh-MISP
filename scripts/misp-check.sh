#!/usr/bin/env bash
# Verify the MISP deployment: services healthy, API reachable, credentials
# changed, and nothing published beyond the loopback interface.
#
# Exits non-zero if any check fails.

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

# shellcheck source=/dev/null
set -a; source "$MISP_ENV"; set +a

pass=0; fail=0
ok() { printf '  \033[1;32mPASS\033[0m  %s\n' "$*"; pass=$((pass + 1)); }
no() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; fail=$((fail + 1)); }

printf '\n\033[1mMISP deployment checks\033[0m\n\n'

# --- services ---------------------------------------------------------------
running="$(docker_run docker compose -p "$MISP_PROJECT" ps --status running --services 2>/dev/null || true)"
for svc in db redis mail misp-core misp-modules; do
  grep -qx "$svc" <<<"$running" && ok "$svc is running" || no "$svc is NOT running"
done

state="$(docker_run docker inspect --format '{{.State.Health.Status}}' misp-misp-core-1 2>/dev/null || true)"
[[ "$state" == "healthy" ]] && ok "misp-core is healthy" || no "misp-core health is '$state'"

# --- web --------------------------------------------------------------------
code="$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1/users/login 2>/dev/null || true)"
[[ "$code" == "200" ]] && ok "login page responds (HTTP $code)" || no "login page HTTP $code"

# --- api --------------------------------------------------------------------
ver="$(curl -sk -H "Authorization: $ADMIN_KEY" -H 'Accept: application/json' \
  https://127.0.0.1/servers/getVersion 2>/dev/null \
  | sed -n 's/.*"version"[: ]*"\([^"]*\)".*/\1/p')"
if [[ -n "$ver" ]]; then
  ok "API authenticates and reports MISP $ver"
else
  no "API did not return a version for the configured ADMIN_KEY"
fi

# Pinned images, not :latest — the deployment must be reproducible.
[[ "$ver" == "${CORE_RUNNING_TAG#v}" ]] \
  && ok "running version matches the pinned tag ($CORE_RUNNING_TAG)" \
  || no "version '$ver' does not match pinned tag '$CORE_RUNNING_TAG'"

code="$(curl -sk -o /dev/null -w '%{http_code}' -H 'Accept: application/json' \
  https://127.0.0.1/servers/getVersion 2>/dev/null || true)"
[[ "$code" == "403" || "$code" == "401" ]] \
  && ok "API rejects unauthenticated requests (HTTP $code)" \
  || no "API answered an unauthenticated request with HTTP $code"

# --- credentials ------------------------------------------------------------
# Upstream's documented defaults must not work.
for pair in "admin@admin.test:admin" "admin@soclab.local:admin"; do
  body="$(curl -sk -c /dev/null "https://127.0.0.1/users/login" \
    --data-urlencode "data[User][email]=${pair%%:*}" \
    --data-urlencode "data[User][password]=${pair##*:}" 2>/dev/null || true)"
  if grep -qiE 'invalid|incorrect|error' <<<"$body" || [[ -z "$body" ]]; then
    ok "default login '${pair}' is rejected"
  else
    no "default login '${pair}' may still work"
  fi
done

# Credentials must not be echoed into container logs.
if [[ -n "${REDIS_PASSWORD:-}" ]] \
   && docker_run docker logs misp-misp-core-1 2>&1 | grep -qF "$REDIS_PASSWORD"; then
  no "the Redis password appears in plaintext in misp-core logs"
else
  ok "no plaintext credentials in misp-core logs"
fi

# --- exposure ---------------------------------------------------------------
exposed="$(ss -tulnH 2>/dev/null | awk '{print $5}' \
  | grep -E ':(80|443)$' | grep -vE '^(127\.0\.0\.1|\[::1\]):' || true)"
[[ -z "$exposed" ]] && ok "MISP ports are bound to loopback only" \
                    || no "reachable off-loopback: $(tr '\n' ' ' <<<"$exposed")"

# --- secrets ----------------------------------------------------------------
leaked="$(git -C "$REPO_ROOT" ls-files | grep -E '(^|/)misp/\.env$|(^|/)\.env$' || true)"
[[ -z "$leaked" ]] && ok "no MISP env file tracked by git" \
                   || no "git is tracking: $leaked"

printf '\n%d passed, %d failed\n\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
