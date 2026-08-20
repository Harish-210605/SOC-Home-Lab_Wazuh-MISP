#!/usr/bin/env bash
# Verify the Wazuh <-> MISP integration (Phase 5): the network path, the
# configuration, the lookup itself, and the rules that turn a hit into an alert.
#
# Exits non-zero if any check fails.

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

# shellcheck source=/dev/null
set -a; source "$MISP_ENV"; set +a

MANAGER="wazuh-wazuh.manager-1"
CORE="misp-misp-core-1"

pass=0; fail=0
ok() { printf '  \033[1;32mPASS\033[0m  %s\n' "$*"; pass=$((pass + 1)); }
no() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; fail=$((fail + 1)); }

dex() { docker_run docker exec "$@" 2>/dev/null; }

printf '\n\033[1mWazuh <-> MISP integration checks\033[0m\n\n'

# --- the network path -------------------------------------------------------
if docker_run docker network inspect "$SHARED_NET" >/dev/null 2>&1; then
  ok "shared network '$SHARED_NET' exists"
  internal="$(docker_run docker network inspect "$SHARED_NET" -f '{{.Internal}}' 2>/dev/null)"
  # An internal bridge has no gateway to the outside. It carries manager->MISP
  # traffic only, so it has no business routing off-box.
  [[ "$internal" == "true" ]] \
    && ok "shared network is internal (no route off-host)" \
    || no "shared network is NOT internal — it can route off-host"
else
  no "shared network '$SHARED_NET' does not exist"
fi

for c in "$MANAGER" "$CORE"; do
  nets="$(docker_run docker inspect "$c" -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null || true)"
  grep -q "$SHARED_NET" <<<"$nets" \
    && ok "$c is attached to $SHARED_NET" \
    || no "$c is NOT attached to $SHARED_NET"
  # Losing the project default would cut the manager off from the indexer, or
  # MISP off from its own database — the classic cost of adding a `networks`
  # key to a service that had none.
  grep -qE '(wazuh|misp)_default' <<<"$nets" \
    && ok "$c kept its project default network" \
    || no "$c lost its project default network"
done

# Name resolution plus TLS plus auth, in one call from where it actually matters.
code="$(dex "$MANAGER" sh -c \
  "curl -sk -o /dev/null -w '%{http_code}' --max-time 15 \
   -H 'Authorization: $ADMIN_KEY' -H 'Accept: application/json' \
   https://misp-core/servers/getVersion" || true)"
[[ "$code" == "200" ]] \
  && ok "manager reaches the MISP API by service name (HTTP $code)" \
  || no "manager could not reach https://misp-core (HTTP ${code:-none})"

# --- configuration ----------------------------------------------------------
conf="$(dex "$MANAGER" cat /var/ossec/etc/ossec.conf || true)"
grep -q '<name>custom-misp</name>' <<<"$conf" \
  && ok "integration block is in the running manager config" \
  || no "no custom-misp integration in the running manager config"

# The template ships a placeholder; wazuh-up.sh substitutes the real key. If the
# placeholder survived into the running config the integration would get a 403
# on every lookup and quietly never enrich anything.
grep -q 'MISP_API_KEY_PLACEHOLDER' <<<"$conf" \
  && no "the API key placeholder was never substituted" \
  || ok "API key was substituted into the running config"

dex "$MANAGER" sh -c 'ps -ef | grep -q "[w]azuh-integratord"' \
  && ok "wazuh-integratord is running" \
  || no "wazuh-integratord is NOT running"

# Integratord runs as the `wazuh` user (uid 999) while bind-mounted files keep
# their HOST ownership (uid 1000 here), so the owner and group bits apply to
# nobody relevant inside the container: only the world bits decide whether the
# integration can be read at all. A mode-750 script owned by the host user fails
# with a bare "Permission denied" that never mentions ownership.
#
# The bits are tested directly rather than by becoming the wazuh user — the
# manager image has neither `su` nor `runuser`, and a missing command exits 127,
# which reads exactly like a failed permission test.
mode_of() { dex "$MANAGER" stat -c '%a' "$1"; }

m="$(mode_of /var/ossec/integrations/custom-misp.py || true)"
[[ -n "$m" && $(( 8#$m & 8#004 )) -ne 0 ]] \
  && ok "custom-misp.py is world-readable (mode $m) so uid 999 can read it" \
  || no "custom-misp.py is mode ${m:-unknown}; integratord (uid 999) cannot read it"

m="$(mode_of /var/ossec/integrations/custom-misp || true)"
[[ -n "$m" && $(( 8#$m & 8#005 )) -eq 8#005 ]] \
  && ok "the integration wrapper is world read+execute (mode $m)" \
  || no "the wrapper is mode ${m:-unknown}; integratord cannot execute it"

# The definitive check: integratord logs a failure to run the integration, which
# catches a permission problem, a bad shebang and a Python import error alike.
#
# Scoped to the CURRENT integratord run, not the whole file. ossec.log lives in
# a named volume and outlives every container recreate, so an unscoped grep
# keeps reporting a fault that was fixed hours ago — a check that never forgets
# is a check nobody believes.
errs="$(dex "$MANAGER" sh -c '
  log=/var/ossec/logs/ossec.log
  start=$(grep -n "wazuh-integratord: INFO: Started" "$log" | tail -1 | cut -d: -f1)
  [ -n "$start" ] || start=1
  tail -n +"$start" "$log" | grep -c "Unable to run integration for custom-misp" || true
' || true)"
if [[ "${errs:-0}" -eq 0 ]]; then
  ok "integratord reports no failures in the current run"
else
  last="$(dex "$MANAGER" sh -c 'grep "Unable to run integration for custom-misp" /var/ossec/logs/ossec.log | tail -1' || true)"
  no "integratord failed to run the integration $errs time(s) this run: ${last:0:110}"
fi

# --- rules ------------------------------------------------------------------
rules="$(dex "$MANAGER" cat /var/ossec/etc/rules/local_rules.xml || true)"
for rid in 100100 100101 100102 100103; do
  grep -q "id=\"$rid\"" <<<"$rules" \
    && ok "rule $rid is present in local_rules.xml" \
    || no "rule $rid is missing from local_rules.xml"
done

# Presence in the file is not the same as being loaded: one malformed rule makes
# analysisd reject the WHOLE file, and it says so only in ossec.log.
#
# Scoped to the current analysisd run for the same reason as the integratord
# check below — ossec.log is on a named volume and outlives container recreates,
# so an unscoped grep keeps failing on rule errors that were fixed hours ago.
errs="$(dex "$MANAGER" sh -c '
  log=/var/ossec/logs/ossec.log
  start=$(grep -n "wazuh-analysisd: INFO: Started" "$log" | tail -1 | cut -d: -f1)
  tail -n +"${start:-1}" "$log" | grep -ciE "error.*local_rules|local_rules.*error" || true
' || true)"
if [[ "${errs:-0}" -eq 0 ]]; then
  ok "analysisd loaded local_rules.xml without errors"
else
  no "analysisd reported $errs error(s) loading local_rules.xml this run"
fi

# --- the lookup, live -------------------------------------------------------
# Drive the integration directly with two synthetic alerts. This tests the real
# code path in seconds without waiting on the agent -> manager pipeline, and it
# is the only way to assert the negative case deterministically.
BAD_IP="$(curl -sk -H "Authorization: $ADMIN_KEY" -H 'Accept: application/json' \
  -H 'Content-Type: application/json' -X POST https://127.0.0.1/attributes/restSearch \
  -d '{"type":"ip-dst","limit":1,"returnFormat":"json"}' 2>/dev/null \
  | python3 -c 'import sys,json
try: print(json.load(sys.stdin)["response"]["Attribute"][0]["value"])
except Exception: print("")')"

probe() {
  local ip="$1" tag="$2"
  dex -i "$MANAGER" sh -c "cat > /tmp/misp-check-$tag.json" <<JSON
{"timestamp":"2026-01-01T00:00:00.000+0000",
 "rule":{"id":"5710","level":5,"description":"integration check","groups":["sshd","authentication_failed"]},
 "agent":{"id":"000","name":"check"},
 "data":{"srcip":"$ip"}}
JSON
  dex "$MANAGER" sh -c \
    "/var/ossec/integrations/custom-misp /tmp/misp-check-$tag.json '$ADMIN_KEY' https://misp-core >/dev/null 2>&1; \
     tail -3 /var/ossec/logs/integrations.log | grep -c 'MISP HIT ip=$ip' || true"
}

if [[ -n "$BAD_IP" ]]; then
  n="$(probe "$BAD_IP" bad)"
  [[ "${n:-0}" -ge 1 ]] \
    && ok "integration resolves a known-bad IP end to end ($BAD_IP)" \
    || no "integration did NOT resolve known-bad IP $BAD_IP"
else
  no "could not sample an IP indicator from MISP (run scripts/misp-feeds.sh)"
fi

# 203.0.113.45 is RFC 5737 TEST-NET-3: routable-looking, reserved for docs, and
# guaranteed never to appear in a real threat feed.
n="$(probe 203.0.113.45 benign)"
[[ "${n:-0}" -eq 0 ]] \
  && ok "benign IP produces no MISP hit (203.0.113.45)" \
  || no "benign IP 203.0.113.45 produced a MISP hit"

# Private addresses must never be sent to MISP at all — not merely miss. In any
# deployment where MISP is remote, that would leak internal addressing.
dex -i "$MANAGER" sh -c 'cat > /tmp/misp-check-priv.json' <<'JSON'
{"timestamp":"2026-01-01T00:00:00.000+0000",
 "rule":{"id":"5710","level":5,"description":"integration check","groups":["sshd"]},
 "agent":{"id":"000","name":"check"},
 "data":{"srcip":"10.11.12.13"}}
JSON
out="$(dex "$MANAGER" sh -c \
  "MISP_DEBUG=1 /var/ossec/integrations/custom-misp /tmp/misp-check-priv.json '$ADMIN_KEY' https://misp-core >/dev/null 2>&1; \
   tail -2 /var/ossec/logs/integrations.log" || true)"
grep -q "10.11.12.13" <<<"$out" \
  && no "a private IP was sent to MISP (10.11.12.13)" \
  || ok "private IPs are filtered before any MISP lookup"

# --- end-to-end evidence ----------------------------------------------------
# The checks above exercise the integration; this one proves the whole chain ran
# for real, agent through indexer. Populated by scripts/demo-misp-enrichment.sh.
set -a; source "$ENV_FILE"; set +a
indexed="$(curl -sk -u "admin:$INDEXER_PASSWORD" \
  "https://127.0.0.1:9200/wazuh-alerts-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"terms":{"rule.id":["100101","100102","100103","100231","100240"]}}}' 2>/dev/null \
  | python3 -c 'import sys,json
try: print(json.load(sys.stdin)["hits"]["total"]["value"])
except Exception: print(0)')"
[[ "${indexed:-0}" -ge 1 ]] \
  && ok "$indexed enriched alert(s) indexed and visible in the dashboard" \
  || no "no enriched alerts indexed (run scripts/demo-misp-enrichment.sh)"

# --- secrets hygiene --------------------------------------------------------
# The rendered config carries the API key in cleartext and must never be tracked.
gen="$REPO_ROOT/wazuh/config/generated/wazuh_manager.conf"
if [[ -f "$gen" ]]; then
  git -C "$REPO_ROOT" check-ignore -q "$gen" \
    && ok "the rendered manager config is gitignored" \
    || no "the rendered manager config is NOT gitignored"
  [[ "$(stat -c '%a' "$gen")" == "600" ]] \
    && ok "the rendered manager config is mode 600" \
    || no "the rendered manager config is mode $(stat -c '%a' "$gen"), expected 600"
else
  no "no rendered manager config at $gen (run scripts/wazuh-up.sh)"
fi

grep -q 'MISP_API_KEY_PLACEHOLDER' "$REPO_ROOT/wazuh/config/wazuh_manager.conf" \
  && ok "the tracked template holds a placeholder, not a key" \
  || no "the tracked manager template does not contain the placeholder"

if git -C "$REPO_ROOT" grep -qI "$ADMIN_KEY" -- . 2>/dev/null; then
  no "the MISP API key appears in a tracked file"
else
  ok "no MISP API key in tracked files"
fi

printf '\n%d passed, %d failed\n\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
