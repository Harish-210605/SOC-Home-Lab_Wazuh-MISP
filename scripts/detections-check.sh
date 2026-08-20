#!/usr/bin/env bash
# Verify the Phase 6 custom detections: rules present and loaded, every
# detection mapped to MITRE ATT&CK, and each one actually firing.
#
# Exits non-zero if any check fails.

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

# shellcheck source=/dev/null
set -a; source "$ENV_FILE"; set +a

MANAGER="wazuh-wazuh.manager-1"
RULES="$REPO_ROOT/wazuh/rules/local_rules.xml"
ART="$REPO_ROOT/docs/detections/phase6-alerts.json"

# The five detections, and the rule that proves each one.
DETECTIONS="100200:D1 brute force then successful login
100210:D2 security-critical file modified
100220:D3 executable dropped in a system bin directory
100231:D4 outbound connection to known-malicious host
100240:D5 authentication attack from a threat-intel host"

pass=0; fail=0
ok() { printf '  \033[1;32mPASS\033[0m  %s\n' "$*"; pass=$((pass + 1)); }
no() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; fail=$((fail + 1)); }
dex() { docker_run docker exec "$@" 2>/dev/null; }

printf '\n\033[1mCustom detection checks (Phase 6)\033[0m\n\n'

[[ -f "$RULES" ]] || die "$RULES is missing."

# --- rules exist and are loaded ---------------------------------------------
for rid in 100200 100210 100220 100227 100228 100229 100230 100231 100240; do
  grep -q "id=\"$rid\"" "$RULES" \
    && ok "rule $rid is defined" \
    || no "rule $rid is missing"
done

# Every id must be unique and inside the user range. A duplicate id is accepted
# by analysisd and then one of the two rules simply never fires.
dupes="$(grep -oE 'rule id="[0-9]+"' "$RULES" | sort | uniq -d)"
[[ -z "$dupes" ]] && ok "no duplicate rule ids" || no "duplicate rule ids: $dupes"

low="$(grep -oE 'rule id="[0-9]+"' "$RULES" | grep -oE '[0-9]+' | awk '$1 < 100000' | tr '\n' ' ')"
[[ -z "$low" ]] \
  && ok "all rule ids are in the user range (>= 100000)" \
  || no "rule ids below 100000 collide with Wazuh's own ruleset: $low"

# Presence in the file is not the same as loaded: one bad rule takes the WHOLE
# file down, and analysisd says so only in ossec.log.
if dex "$MANAGER" /var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -qiE 'error|critical'; then
  detail="$(dex "$MANAGER" /var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -iE 'error|critical' | head -1)"
  no "analysisd rejects the ruleset: ${detail##*: }"
else
  ok "analysisd loads the ruleset cleanly"
fi

# A list that fails to compile is only a WARNING — the referencing rule is
# silently dropped and everything else carries on looking healthy.
if dex "$MANAGER" sh -c '
    log=/var/ossec/logs/ossec.log
    start=$(grep -n "wazuh-analysisd: INFO: Started" "$log" | tail -1 | cut -d: -f1)
    tail -n +"${start:-1}" "$log" | grep -q "will be ignored"'; then
  detail="$(dex "$MANAGER" sh -c 'grep "will be ignored" /var/ossec/logs/ossec.log | tail -1' || true)"
  no "analysisd is ignoring a rule: ${detail##*: }"
else
  ok "no rules are being silently ignored"
fi

# --- MITRE mapping ----------------------------------------------------------
# The phase requires every detection to map to ATT&CK, so it is asserted rather
# than assumed. Checked per detection rule, not file-wide: a single <mitre>
# block anywhere would otherwise satisfy a naive grep.
while IFS=: read -r rid label; do
  [[ -n "$rid" ]] || continue
  block="$(python3 - "$RULES" "$rid" <<'PY'
import re, sys
data = open(sys.argv[1]).read()
m = re.search(r'<rule id="%s".*?</rule>' % sys.argv[2], data, re.S)
print(m.group(0) if m else "")
PY
)"
  ids="$(grep -oE '<id>[^<]+</id>' <<<"$block" | sed 's/<[^>]*>//g' | tr '\n' ' ')"
  if [[ -z "$ids" ]]; then
    no "rule $rid ($label) has no MITRE mapping"
    continue
  fi
  bad=""
  for t in $ids; do
    [[ "$t" =~ ^T[0-9]{4}(\.[0-9]{3})?$ ]] || bad="$bad $t"
  done
  [[ -z "$bad" ]] \
    && ok "rule $rid mapped to ATT&CK:$(printf ' %s' $ids)" \
    || no "rule $rid has malformed ATT&CK technique id(s):$bad"
done <<<"$DETECTIONS"

# --- live behaviour ---------------------------------------------------------
# logtest drives the real decoder and rule engine, so these assert behaviour
# rather than configuration, and do so in seconds.
# `|| true` is load-bearing: _common.sh sets `set -euo pipefail`, and grep exits
# non-zero when a log line matches no rule at all — which is exactly the outcome
# the negative checks below are testing for. Without it the script dies at the
# first correctly-suppressed event instead of recording a PASS.
# NOTE the 2>&1: wazuh-logtest writes its decode/rule analysis to STDERR, not
# stdout. Piping stdout alone yields nothing at all, which looks exactly like
# "no rule matched" — every check here would report a plausible-looking failure.
# (This is why dex() is not used: it discards stderr.)
logtest() {
  printf '%s\n' "$@" \
    | docker_run docker exec -i "$MANAGER" /var/ossec/bin/wazuh-logtest 2>&1 \
    | grep -oE "id: '[0-9]+'" | tail -1 | grep -oE '[0-9]+' || true
}

fw_line() { printf 'Aug 20 16:00:0%s endpoint01 kernel: OUTBOUND-ACCEPT IN= OUT=eth0 SRC=172.20.0.5 DST=%s LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=%s DF PROTO=TCP SPT=44321 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0' "$2" "$1" "$2"; }

r="$(logtest "$(fw_line 162.243.103.246 1)" || true)"
[[ "$r" == "100230" ]] \
  && ok "external destination raises the outbound rule (100230)" \
  || no "external destination produced rule ${r:-none}, expected 100230"

# The negative half. Without it, a rule that fired on everything would pass the
# check above just as happily.
for ip in 172.20.0.9 10.5.5.5 192.168.1.10; do
  r="$(logtest "$(fw_line "$ip" 2)" || true)"
  [[ "$r" =~ ^10022[789]$ ]] \
    && ok "internal destination $ip is suppressed (rule $r, level 0)" \
    || no "internal destination $ip produced rule ${r:-none}, expected 100227-100229"
done

# D1 needs the sequence, not a single line: 9 failures then a success.
d1_lines=()
for i in $(seq 1 9); do
  d1_lines+=("Aug 20 16:01:0$i endpoint01 sshd[80$i]: Failed password for invalid user oracle from 198.51.100.77 port 4400$i ssh2")
done
d1_lines+=("Aug 20 16:01:19 endpoint01 sshd[8010]: Accepted password for backupsvc from 198.51.100.77 port 44010 ssh2")
r="$(logtest "${d1_lines[@]}" || true)"
[[ "$r" == "100200" ]] \
  && ok "brute force followed by success raises D1 (100200)" \
  || no "D1 sequence produced rule ${r:-none}, expected 100200"

# A successful login with no preceding brute force must stay quiet — that is the
# whole distinction D1 exists to make.
r="$(logtest 'Aug 20 16:02:01 endpoint01 sshd[8100]: Accepted password for alice from 203.0.113.200 port 44100 ssh2' || true)"
[[ "$r" != "100200" ]] \
  && ok "a clean successful login does not raise D1 (rule ${r:-none})" \
  || no "a clean successful login incorrectly raised D1"

# --- captured evidence ------------------------------------------------------
if [[ -f "$ART" ]]; then
  ok "detection artifact exists: docs/detections/phase6-alerts.json"
  missing="$(python3 - "$ART" <<'PY'
import json, sys
want = {"100200","100210","100220","100230","100231","100240"}
try:
    got = {a["rule"]["id"] for a in json.load(open(sys.argv[1]))}
except Exception:
    print("unreadable"); raise SystemExit
print(" ".join(sorted(want - got)))
PY
)"
  [[ -z "$missing" ]] \
    && ok "artifact contains a real alert for every detection" \
    || no "artifact is missing alerts for: $missing"
else
  no "no artifact at $ART (run scripts/demo-detections.sh)"
fi

# --- indexed ----------------------------------------------------------------
# Proof the alerts reached the indexer, so they are visible in the dashboard
# rather than only in a log file on the manager.
indexed="$(curl -sk -u "admin:$INDEXER_PASSWORD" \
  "https://127.0.0.1:9200/wazuh-alerts-*/_search" -H 'Content-Type: application/json' \
  -d '{"size":0,"query":{"terms":{"rule.id":["100200","100210","100220","100231","100240"]}}}' 2>/dev/null \
  | python3 -c 'import sys,json
try: print(json.load(sys.stdin)["hits"]["total"]["value"])
except Exception: print(0)')"
[[ "${indexed:-0}" -ge 1 ]] \
  && ok "$indexed custom-detection alert(s) indexed and visible in the dashboard" \
  || no "no custom-detection alerts indexed (run scripts/demo-detections.sh)"

printf '\n%d passed, %d failed\n\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
