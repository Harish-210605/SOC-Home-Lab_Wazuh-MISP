#!/usr/bin/env bash
# End-to-end demonstration of Wazuh -> MISP threat-intel enrichment (Phase 5).
#
# Simulates SSH brute-force attempts from two sources and shows that Wazuh
# treats them differently *because of* what MISP knows:
#
#   known-bad IP  -> rule 5710 fires, MISP is queried, a hit comes back, and
#                    rule 100101 raises a level 12 threat-intel alert
#   benign IP     -> rule 5710 fires, MISP is queried, no hit, no extra alert
#
# The negative case is half the demo. Enrichment that flags everything is
# indistinguishable from enrichment that flags nothing.
#
# Nothing here talks to the malicious address. The attack is simulated purely by
# writing syslog lines the stock sshd decoder parses; no packet is ever sent to
# a C2 server, which is the only responsible way to test this.

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

# shellcheck source=/dev/null
set -a; source "$MISP_ENV"; set +a

AGENT="wazuh-wazuh.agent.endpoint01-1"
MANAGER="wazuh-wazuh.manager-1"
LOGFILE="/var/log/simulated/auth.log"
BENIGN_IP="203.0.113.45"   # TEST-NET-3 (RFC 5737): routable-looking, never real

for c in "$MANAGER" "$AGENT" misp-misp-core-1; do
  docker_run docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null | grep -q true \
    || die "$c is not running. Start the lab with scripts/wazuh-up.sh and scripts/misp-up.sh."
done

# Pull a live known-bad IP straight out of MISP rather than hardcoding one, so
# the demo keeps working as feeds rotate. Feodo is preferred because it is
# dormant upstream and therefore stable; ThreatFox is the fallback.
# wazuh-logcollector opens each <localfile> once when it starts and does not
# retry a path that was missing at that moment: it logs "Could not open file"
# and then never reads it, even once the file appears. On a fresh lab the
# simulated log has never been written, so the first demo run would silently
# produce nothing. Make sure the file exists AND that logcollector actually has
# it open, restarting the agent's daemons if not.
ensure_log_source() {
  docker_run docker exec "$AGENT" sh -c \
    "mkdir -p \$(dirname $LOGFILE) && touch $LOGFILE"

  if docker_run docker exec "$AGENT" sh -c \
      'pid=$(ps -ef | awk "/[w]azuh-logcollector/{print \$2; exit}"); \
       [ -n "$pid" ] && ls -l /proc/$pid/fd 2>/dev/null | grep -q "simulated/auth.log"' \
      2>/dev/null; then
    return 0
  fi

  log "logcollector is not tailing $LOGFILE yet — restarting agent daemons"
  docker_run docker exec "$AGENT" /var/ossec/bin/wazuh-control restart >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do
    if docker_run docker exec "$AGENT" sh -c \
        'ps -ef | grep -q "[w]azuh-logcollector"' 2>/dev/null; then
      sleep 3; return 0
    fi
    sleep 2
  done
  warn "agent logcollector did not come back up cleanly"
}

log "Ensuring the simulated log source is being collected"
ensure_log_source

log "Selecting a known-bad IP from MISP"
BAD_IP="$(curl -sk -H "Authorization: $ADMIN_KEY" -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  -X POST https://127.0.0.1/attributes/restSearch \
  -d '{"type":"ip-dst","limit":1,"returnFormat":"json"}' 2>/dev/null \
  | python3 -c 'import sys,json
try: print(json.load(sys.stdin)["response"]["Attribute"][0]["value"])
except Exception: print("")')"

if [[ -z "$BAD_IP" ]]; then
  BAD_IP="$(curl -sk -H "Authorization: $ADMIN_KEY" -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -X POST https://127.0.0.1/attributes/restSearch \
    -d '{"type":"ip-dst|port","limit":1,"returnFormat":"json"}' 2>/dev/null \
    | python3 -c 'import sys,json
try: print(json.load(sys.stdin)["response"]["Attribute"][0]["value"].split("|")[0])
except Exception: print("")')"
fi
[[ -n "$BAD_IP" ]] || die "no IP indicators in MISP. Run scripts/misp-feeds.sh first."

log "Known-bad (from MISP): $BAD_IP"
log "Benign control:        $BENIGN_IP (RFC 5737 TEST-NET-3)"

# Alert files are read by line offset afterwards, so record the current end of
# the file first. Grepping the whole file would happily match a previous run.
before="$(docker_run docker exec "$MANAGER" sh -c \
  'wc -l < /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo 0')"

emit() {
  local ip="$1" count="$2" user="$3"
  local ts; ts="$(date '+%b %d %H:%M:%S')"
  local lines=""
  for i in $(seq 1 "$count"); do
    lines+="$ts endpoint01 sshd[$((4000 + RANDOM % 900))]: Failed password for invalid user $user from $ip port $((30000 + RANDOM % 20000)) ssh2"$'\n'
  done
  printf '%s' "$lines" | docker_run docker exec -i "$AGENT" \
    sh -c "mkdir -p \$(dirname $LOGFILE) && cat >> $LOGFILE"
}

log "Simulating 5 failed SSH logins from the known-bad IP"
emit "$BAD_IP" 5 admin

log "Simulating 5 failed SSH logins from the benign IP"
emit "$BENIGN_IP" 5 backup

# The agent batches log reads, the manager queues the integration, and the
# integration makes a network round-trip to MISP, so the enriched alert lands a
# few seconds after the triggering one.
log "Waiting for enrichment to complete (up to 90s)"
found=0
for _ in $(seq 1 30); do
  n="$(docker_run docker exec "$MANAGER" sh -c \
    "tail -n +$((before + 1)) /var/ossec/logs/alerts/alerts.json 2>/dev/null | grep -c '\"id\":\"100101\"' || true")"
  if [[ "${n:-0}" -ge 1 ]]; then found=1; break; fi
  sleep 3
done

printf '\n'
if [[ "$found" -ne 1 ]]; then
  warn "no threat-intel alert appeared within 90s."
  warn "Check: docker exec $MANAGER tail /var/ossec/logs/integrations.log"
  exit 1
fi

log "Enriched alerts raised:"
docker_run docker exec "$MANAGER" sh -c \
  "tail -n +$((before + 1)) /var/ossec/logs/alerts/alerts.json" \
  | python3 -c '
import sys, json

BOLD, GREEN, RESET = "\033[1m", "\033[1;32m", "\033[0m"
WANTED = ("100101", "100102", "100103")

seen = 0
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        alert = json.loads(line)
    except ValueError:
        continue
    rule = alert.get("rule", {})
    if rule.get("id") not in WANTED:
        continue
    seen += 1
    m = alert.get("data", {}).get("misp", {})
    agent = alert.get("agent", {}).get("name", "?")
    print()
    print("  %srule %s  level %s%s" % (BOLD, rule["id"], rule["level"], RESET))
    print("    %s" % rule["description"])
    print("    agent        : %s" % agent)
    print("    observable   : %s (%s)" % (m.get("observable"), m.get("observable_kind")))
    print("    MISP type    : %s   category: %s" % (m.get("attribute_type"), m.get("category")))
    print("    to_ids       : %s   MISP event: %s" % (m.get("to_ids"), m.get("event_id")))
    print("    triggered by : rule %s - %s" % (m.get("source_rule_id"), m.get("source_rule_description")))
print()
print("%s%d threat-intel alert(s).%s" % (GREEN, seen, RESET))
'

printf '\n'
log "Control check: the benign IP must NOT have produced a threat-intel alert"
bad_control="$(docker_run docker exec "$MANAGER" sh -c \
  "tail -n +$((before + 1)) /var/ossec/logs/alerts/alerts.json" \
  | grep -c "$BENIGN_IP.*100101" || true)"
if [[ "${bad_control:-0}" -eq 0 ]]; then
  printf '  \033[1;32mPASS\033[0m  %s triggered rule 5710 but no MISP alert\n' "$BENIGN_IP"
else
  printf '  \033[1;31mFAIL\033[0m  benign IP %s raised a threat-intel alert\n' "$BENIGN_IP"
  exit 1
fi

printf '\nView in the dashboard: https://127.0.0.1:8443  (Threat Hunting -> filter rule.id:100101)\n'
