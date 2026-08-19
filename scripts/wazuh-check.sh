#!/usr/bin/env bash
# Verify the Wazuh deployment: services healthy, credentials actually changed,
# and nothing published beyond the loopback interface.
#
# Exits non-zero if any check fails.

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

# shellcheck source=/dev/null
set -a; source "$ENV_FILE"; set +a

pass=0; fail=0
ok()   { printf '  \033[1;32mPASS\033[0m  %s\n' "$*"; pass=$((pass + 1)); }
no()   { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; fail=$((fail + 1)); }
check() { if eval "$2" >/dev/null 2>&1; then ok "$1"; else no "$1"; fi; }

printf '\n\033[1mWazuh deployment checks\033[0m\n\n'

# --- services ---------------------------------------------------------------
running="$(docker_run docker compose -p "$COMPOSE_PROJECT" ps --status running --services 2>/dev/null || true)"
for svc in wazuh.manager wazuh.indexer wazuh.dashboard; do
  if grep -qx "$svc" <<<"$running"; then ok "$svc is running"; else no "$svc is NOT running"; fi
done

# --- indexer ----------------------------------------------------------------
health="$(curl -sk -u "admin:$INDEXER_PASSWORD" https://127.0.0.1:9200/_cluster/health 2>/dev/null || true)"
if grep -q '"status":"green"' <<<"$health"; then
  ok "indexer cluster health is green"
else
  no "indexer cluster health is not green (got: ${health:-no response})"
fi

# The real proof the password change took effect, rather than merely that the
# script ran: the documented upstream default must now be rejected.
code="$(curl -sk -o /dev/null -w '%{http_code}' -u 'admin:SecretPassword' \
  https://127.0.0.1:9200/_cluster/health 2>/dev/null || true)"
if [[ "$code" == "401" ]]; then
  ok "upstream default password 'SecretPassword' is rejected (401)"
else
  no "upstream default password was not rejected (HTTP $code) — credentials did NOT change"
fi

# Demo accounts upstream ships that this deployment removes.
for demo in kibanaro logstash readall snapshotrestore; do
  code="$(curl -sk -o /dev/null -w '%{http_code}' -u "$demo:$demo" \
    https://127.0.0.1:9200/_cluster/health 2>/dev/null || true)"
  [[ "$code" == "401" ]] && ok "demo account '$demo' is gone" \
                         || no "demo account '$demo' still authenticates (HTTP $code)"
done

# --- manager API ------------------------------------------------------------
if curl -sk -u "wazuh-wui:$API_PASSWORD" -X POST \
     https://127.0.0.1:55000/security/user/authenticate 2>/dev/null | grep -q '"token"'; then
  ok "manager API issues a JWT for wazuh-wui"
else
  no "manager API did not return a token"
fi

# --- dashboard --------------------------------------------------------------
code="$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/app/login 2>/dev/null || true)"
[[ "$code" =~ ^(200|302)$ ]] && ok "dashboard responds on https://127.0.0.1:8443 (HTTP $code)" \
                             || no "dashboard did not respond (HTTP $code)"

# --- exposure ---------------------------------------------------------------
# Every published port must be on the loopback address and nowhere else.
exposed="$(ss -tulnH 2>/dev/null \
  | awk '{print $5}' \
  | grep -E ':(8443|9200|1514|1515|514|55000)$' \
  | grep -vE '^(127\.0\.0\.1|\[::1\]):' || true)"
if [[ -z "$exposed" ]]; then
  ok "all published ports are bound to loopback only"
else
  no "ports reachable off-loopback: $(tr '\n' ' ' <<<"$exposed")"
fi

# --- secrets ----------------------------------------------------------------
leaked="$(git -C "$REPO_ROOT" ls-files | grep -E '\.(pem|key|crt)$|(^|/)\.env$' || true)"
if [[ -z "$leaked" ]]; then
  ok "no credentials or TLS material tracked by git"
else
  no "git is tracking secrets: $(tr '\n' ' ' <<<"$leaked")"
fi

printf '\n%d passed, %d failed\n\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
