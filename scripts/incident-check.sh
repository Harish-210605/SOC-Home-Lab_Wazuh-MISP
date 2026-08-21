#!/usr/bin/env bash
# Verify the Phase 7 incident report against the capture it is written from.
#
# The point of this suite is narrow and specific: an incident report is a set of
# CLAIMS, and a report whose claims have quietly drifted from the evidence is
# worse than no report. So every check here either (a) asserts the captured
# alerts really do show what the report says they show, or (b) guards a defect
# the replay itself uncovered, so it cannot come back unnoticed.
#
# Exits non-zero if any check fails.

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

# shellcheck source=/dev/null
set -a; source "$ENV_FILE"; set +a

MANAGER="wazuh-wazuh.manager-1"
RULES="$REPO_ROOT/wazuh/rules/local_rules.xml"
AGENT_CONF="$REPO_ROOT/agents/config/ossec.conf"
REPORT="$REPO_ROOT/docs/incident-report-example.md"
ART="$REPO_ROOT/docs/incidents/incident-001-alerts.json"

pass=0; fail=0
ok() { printf '  \033[1;32mPASS\033[0m  %s\n' "$*"; pass=$((pass + 1)); }
no() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; fail=$((fail + 1)); }
dex() { docker_run docker exec "$@" 2>/dev/null; }

# Query the capture with a small python expression; prints one value.
q() { python3 - "$ART" "$1" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
alerts = doc["alerts"]
cap = doc["captured"]

def by(rid):
    return [a for a in alerts if a["rule"]["id"] == rid]

def misp(a):
    return a.get("data", {}).get("misp", {})

print(eval(sys.argv[2]))
PY
}

printf '\n\033[1mIncident report checks (Phase 7)\033[0m\n\n'

# --- the deliverables exist --------------------------------------------------
[[ -f "$REPORT" ]] && ok "incident report exists: docs/incident-report-example.md" \
                   || { no "no report at $REPORT"; printf '\n%d passed, %d failed\n\n' "$pass" "$fail"; exit 1; }

if [[ -f "$ART" ]] && python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$ART" 2>/dev/null; then
  ok "capture exists and is valid JSON: docs/incidents/incident-001-alerts.json"
else
  no "no valid capture at $ART (run scripts/demo-incident.sh)"
  printf '\n%d passed, %d failed\n\n' "$pass" "$fail"; exit 1
fi

# --- the kill chain is present in the evidence -------------------------------
# Each stage of the story the report tells must be backed by a real alert.
while IFS=: read -r rid label; do
  n="$(q "len(by('$rid'))")"
  [[ "${n:-0}" -ge 1 ]] && ok "stage evidence present — $label (rule $rid, x$n)" \
                        || no "no alert for $label (rule $rid) in the capture"
done <<'STAGES'
100240:credential access, D5 auth attack from a listed host
100200:initial access, D1 brute force then success
100210:persistence, D2 security-critical file changed
100220:defense evasion, D3 implant in a system bin directory
100230:command and control, D4a outbound connection observed
100231:command and control, D4b outbound to known-malicious infrastructure
100103:correlation, repeated intel matches from one host
STAGES

# --- severity, because the report leads with it ------------------------------
for pair in 100200:14 100103:14 100240:13 100231:13 100210:12 100220:12; do
  rid="${pair%%:*}"; want="${pair##*:}"
  got="$(q "by('$rid')[0]['rule']['level']")"
  [[ "$got" == "$want" ]] && ok "rule $rid alerts at level $want as documented" \
                          || no "rule $rid alerted at level $got, report says $want"
done

# --- the two named indicators actually drove the alerts ----------------------
# The report names concrete addresses. If the capture were regenerated against a
# different feed entry those names would go stale silently, and the report would
# be quoting an incident that did not happen.
att="$(q "cap['attacker_ip']")"
c2="$(q "cap['c2_ip']")"

grep -q "$att" "$REPORT" && ok "report names the attacker address in the capture ($att)" \
                         || no "report does not mention $att — report and capture have diverged"
grep -q "$c2" "$REPORT" && ok "report names the C2 address in the capture ($c2)" \
                        || no "report does not mention $c2 — report and capture have diverged"

[[ "$(q "all(misp(a)['observable'] == cap['attacker_ip'] for a in by('100240'))")" == "True" ]] \
  && ok "every D5 alert names the attacker address as its observable" \
  || no "a D5 alert fired on an observable other than $att"

[[ "$(q "all(misp(a)['observable'] == cap['c2_ip'] for a in by('100231'))")" == "True" ]] \
  && ok "every D4b alert names the C2 address as its observable" \
  || no "a D4b alert fired on an observable other than $c2"

# to_ids is the whole basis for treating these as actionable rather than context.
[[ "$(q "all(misp(a).get('to_ids') == 'True' for a in by('100240') + by('100231'))")" == "True" ]] \
  && ok "both indicators are to_ids=True (actionable intel, not context)" \
  || no "an alert was raised on a to_ids=False indicator"

# --- persistence: all three mechanisms, including the one that used to be dead
for p in /root/.ssh/authorized_keys /etc/sudoers.d/99-backupsvc /etc/cron.d/systemd-udevd-refresh; do
  [[ "$(q "any(a.get('syscheck',{}).get('path') == '$p' for a in by('100210'))")" == "True" ]] \
    && ok "persistence detected at $p" \
    || no "no D2 alert for $p"
done

[[ "$(q "any(a.get('syscheck',{}).get('path','').startswith('/usr/bin/') for a in by('100220'))")" == "True" ]] \
  && ok "implant detected in a system binary directory" \
  || no "no D3 alert for a file in /usr/bin"

# --- the controls ------------------------------------------------------------
# A negative result is only evidence if the events were ingested. Assert BOTH:
# the control traffic reached analysisd, and it raised no threat-intel alert.
unl="$(q "cap['control_unlisted_ip']")"
[[ "$(q "any(a.get('data',{}).get('srcip') == cap['control_unlisted_ip'] for a in alerts)")" == "True" ]] \
  && ok "control brute force from $unl was ingested (so its silence means something)" \
  || no "no alert at all from $unl — the control never reached analysisd"

[[ "$(q "not any(misp(a).get('observable') == cap['control_unlisted_ip'] for a in alerts)")" == "True" ]] \
  && ok "unlisted source $unl raised no threat-intel alert" \
  || no "$unl produced a threat-intel alert — enrichment is not discriminating"

[[ "$(q "not any(a.get('data',{}).get('dstip','').startswith(('10.','172.','192.168.')) for a in by('100230'))")" == "True" ]] \
  && ok "internal destinations suppressed before enrichment" \
  || no "an internal destination reached the outbound rule"

# --- stock context retained --------------------------------------------------
# D1 claims a correlation. Without the stock alerts in the file, that claim is
# unverifiable by whoever reads the artifact.
for rid in 5710 5712; do
  [[ "$(q "len(by('$rid'))")" -ge 1 ]] \
    && ok "stock alert $rid retained, so D1's correlation can be checked" \
    || no "stock alert $rid missing from the capture"
done

# --- ATT&CK mapping ----------------------------------------------------------
[[ "$(q "all(a['rule'].get('mitre',{}).get('id') for a in by('100200')+by('100210')+by('100220')+by('100231')+by('100240'))")" == "True" ]] \
  && ok "every detection alert carries an ATT&CK technique id" \
  || no "a detection alert reached the capture with no ATT&CK mapping"

for t in T1110.001 T1078 T1098.004 T1053.003 T1136 T1036.005 T1071.001; do
  grep -q "$t" "$REPORT" && ok "report maps the incident to $t" \
                         || no "report does not reference $t"
done

# --- regression guards for what this phase found -----------------------------
#
# 1. FIM must still cover the SSH key stores. Without this, D2's authorized_keys
#    branch goes back to being a rule that cannot fire — with no error anywhere.
grep -qE '<directories[^>]*>[^<]*/root/\.ssh' "$AGENT_CONF" \
  && ok "agent FIM covers /root/.ssh (D2's authorized_keys branch is reachable)" \
  || no "no syscheck directory covers /root/.ssh — D2 cannot fire on authorized_keys"

if dex "$AGENT_CONTAINER" grep -qE '<directories[^>]*>[^<]*/root/\.ssh' /var/ossec/etc/ossec.conf; then
  ok "the running agent has the key-store FIM config, not just the repo"
else
  no "the agent container is running an older config — recreate it"
fi

# 2. Correlation rules must be defined AFTER everything they count.
#    if_matched_sid/if_matched_group resolve at PARSE time against rules seen so
#    far; a forward reference is dropped with only a startup WARNING, leaving a
#    correct-looking rule that is not in the running ruleset.
line_corr="$(grep -n 'rule id="100103"' "$RULES" | cut -d: -f1)"
last_counted="$(grep -n 'rule id="100231"\|rule id="100240"' "$RULES" | cut -d: -f1 | sort -n | tail -1)"
if [[ -n "$line_corr" && -n "$last_counted" && "$line_corr" -gt "$last_counted" ]]; then
  ok "correlation rule 100103 is defined after the rules it counts (line $line_corr > $last_counted)"
else
  no "rule 100103 at line ${line_corr:-?} precedes the rules it counts (line ${last_counted:-?}) — it will be silently dropped at load"
fi

# 3. A correlation rule must not belong to the group it counts, or it feeds its
#    own counter.
if awk '/rule id="100103"/,/<\/rule>/' "$RULES" | grep -q '<group>.*misp_alert'; then
  no "rule 100103 is a member of misp_alert, the group it counts — it would feed itself"
else
  ok "rule 100103 is not a member of the group it counts"
fi

# 4. Nothing in the ruleset may be silently ignored. Scoped to the CURRENT
#    analysisd run: ossec.log is on a named volume and outlives container
#    recreates, so an unscoped grep reports faults fixed hours ago.
ignored="$(dex "$MANAGER" sh -c '
  start=$(grep -n "Started (pid" /var/ossec/logs/ossec.log | tail -1 | cut -d: -f1)
  [ -n "$start" ] && tail -n +$((start - 30)) /var/ossec/logs/ossec.log \
    | grep -E "will be ignored|was not found" | head -3')"
[[ -z "$ignored" ]] \
  && ok "no rule is being silently ignored by the running analysisd" \
  || no "analysisd is ignoring a rule: ${ignored%%$'\n'*}"

# --- the capture is internally consistent with the report --------------------
n="$(q "len(alerts)")"
grep -q "$n alerts" "$REPORT" \
  && ok "report's alert count ($n) matches the capture" \
  || no "report does not state the captured alert count of $n"

[[ "$(q "alerts == sorted(alerts, key=lambda a: a['timestamp'])")" == "True" ]] \
  && ok "capture is in timestamp order, as the timeline assumes" \
  || no "capture is not timestamp-ordered"

[[ "$(q "len({a['agent']['name'] for a in alerts if 'agent' in a}) == 1")" == "True" ]] \
  && ok "the whole incident is attributed to a single host" \
  || no "the capture spans more than one agent"

# --- hygiene -----------------------------------------------------------------
if grep -qEi "$(printf '%s' 'ADMIN_KEY|INDEXER_PASSWORD|API_KEY|PASSWORD=')" "$REPORT" "$ART"; then
  no "the report or capture contains something that looks like a credential"
else
  ok "no credentials in the report or the capture"
fi

# Every relative link in the report must resolve, or the write-up rots.
broken=""
while read -r target; do
  [[ -e "$REPO_ROOT/docs/$target" ]] || broken="$broken $target"
done < <(grep -oE '\]\(\.\.?/[^)#]+\)|\]\([a-z0-9][^):#]*\.(md|json|sh)\)' "$REPORT" \
         | sed -E 's/^\]\(//; s/\)$//')
[[ -z "$broken" ]] && ok "every link in the report resolves" \
                   || no "broken link(s) in the report:$broken"

printf '\n%d passed, %d failed\n\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
