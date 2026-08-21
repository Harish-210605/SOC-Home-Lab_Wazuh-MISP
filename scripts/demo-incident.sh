#!/usr/bin/env bash
# Phase 7 — replay ONE coherent intrusion, end to end, and capture what fired.
#
# Phase 6's demo proved each detection works in isolation. That is a different
# claim from "these detections tell a story an analyst can actually work". This
# script runs a single intrusion by a single attacker across six stages, in kill
# chain order, so the alerts it produces read as ONE incident rather than six
# unrelated findings.
#
#   Stage 1  credential access   brute force from a threat-intel-listed host
#   Stage 2  initial access      one of the guesses works
#   Stage 3  persistence         authorized_keys, sudoers drop-in, cron job
#   Stage 4  defense evasion     implant dropped under a legitimate-looking name
#   Stage 5  command and control  beacon to known C2 infrastructure
#   Stage 6  controls            the same activity from unlisted/internal hosts
#
# Stage 6 is not decoration. An incident report that only shows what fired
# proves nothing about false positives; the controls are what let the report
# claim the enrichment DISCRIMINATES rather than merely triggers.
#
# Safety: identical stance to Phase 6. Authentication and firewall activity is
# log injection parsed by Wazuh's STOCK decoders; file activity is real but
# inert. Nothing in this lab ever connects to a malicious address — the C2 IP is
# only ever written into a log line.

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

# shellcheck source=/dev/null
set -a; source "$MISP_ENV"; set +a

MANAGER="wazuh-wazuh.manager-1"
AGENT="$AGENT_CONTAINER"
AUTH_LOG="/var/log/simulated/auth.log"
FW_LOG="/var/log/simulated/firewall.log"
ART="$REPO_ROOT/docs/incidents"
RAW="$ART/incident-001-alerts.json"

# RFC 5737 TEST-NET-2: routable-looking, guaranteed never in a real feed. This
# is the control attacker — same behaviour, no threat intel behind it.
UNLISTED_IP="198.51.100.77"
INTERNAL_IP="172.20.0.9"
VICTIM_IP="172.20.0.5"
COMPROMISED_ACCOUNT="backupsvc"

# Files the intrusion touches. Fixed names, not run-unique ones, so the incident
# report can name a concrete IOC — and pre-removed below so FIM sees an ADD.
IMPLANT="/usr/bin/systemd-udevd-helper"
SUDOERS_DROPIN="/etc/sudoers.d/99-backupsvc"
CRON_DROPIN="/etc/cron.d/systemd-udevd-refresh"
AUTHKEYS="/root/.ssh/authorized_keys"

for c in "$MANAGER" "$AGENT" misp-misp-core-1; do
  docker_run docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null | grep -q true \
    || die "$c is not running. Start the lab with scripts/wazuh-up.sh and scripts/misp-up.sh."
done

mkdir -p "$ART"
ensure_agent_log_source "$AUTH_LOG"
ensure_agent_log_source "$FW_LOG"

# --- pick the two hostile addresses -----------------------------------------
#
# Preferred source is the Feodo Tracker event, whose five entries are frozen
# upstream and therefore stable across re-runs — an incident report that names a
# concrete IP is worthless if that IP rotates out of the feed next week. Falls
# back to any ip-dst so the script still works against a differently populated
# MISP.
misp_ips() {  # misp_ips <json-body>
  curl -sk -H "Authorization: $ADMIN_KEY" -H 'Accept: application/json' \
    -H 'Content-Type: application/json' -X POST \
    https://127.0.0.1/attributes/restSearch -d "$1" 2>/dev/null \
    | python3 -c 'import sys, json
try:
    for a in json.load(sys.stdin)["response"]["Attribute"]:
        print(a["value"].split("|")[0])
except Exception:
    pass'
}

mapfile -t POOL < <(misp_ips '{"eventid":1,"type":"ip-dst","limit":10,"returnFormat":"json"}')
if (( ${#POOL[@]} < 2 )); then
  warn "Feodo Tracker event not usable; falling back to any ip-dst in MISP"
  mapfile -t POOL < <(misp_ips '{"type":"ip-dst","limit":10,"returnFormat":"json"}')
fi
(( ${#POOL[@]} >= 2 )) || die "need at least 2 IP indicators in MISP. Run scripts/misp-feeds.sh first."

ATTACKER_IP="${POOL[1]}"   # brute-force source
C2_IP="${POOL[0]}"         # beacon destination

log "Attacker (threat-intel listed): $ATTACKER_IP"
log "C2 destination (listed):        $C2_IP"
log "Unlisted control attacker:      $UNLISTED_IP"

# --- reset the file artifacts BEFORE the capture window ----------------------
#
# D3 keys on rule 554 (file ADDED), not 550 (changed), so a second run against a
# path left behind by the first would produce a "modified" event and D3 would
# correctly not fire. Removing the paths here — and letting realtime FIM settle
# — is what makes this script re-runnable rather than first-run-only.
log "Resetting file artifacts from any previous run"
docker_run docker exec "$AGENT" sh -c \
  "rm -f $IMPLANT $SUDOERS_DROPIN $CRON_DROPIN $AUTHKEYS" >/dev/null 2>&1 || true
sleep 8

# Everything after this line number belongs to this incident.
before="$(docker_run docker exec "$MANAGER" sh -c \
  'wc -l < /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo 0')"
T0="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

emit() { printf '%s\n' "$2" | docker_run docker exec -i "$AGENT" sh -c "cat >> $1"; }
ts()   { date '+%b %d %H:%M:%S'; }

fail_login() {  # fail_login <srcip> <user> <pid> <port>
  emit "$AUTH_LOG" "$(ts) endpoint01 sshd[$3]: Failed password for invalid user $2 from $1 port $4 ssh2"
}

beacon() {  # beacon <dstip> <sport> <id>
  emit "$FW_LOG" "$(ts) endpoint01 kernel: OUTBOUND-ACCEPT IN= OUT=eth0 SRC=$VICTIM_IP DST=$1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=$3 DF PROTO=TCP SPT=$2 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0"
}

printf '\n'
log "Stage 1/6  credential access — brute force from $ATTACKER_IP (T1110.001)"
# Twelve attempts across the account names an opportunistic SSH sweep tries
# first. Stock rule 5712 needs several failures in its window before it calls
# this a brute force, and D5 needs 5712's enrichment to land.
i=0
for user in root root admin admin oracle postgres ubuntu jenkins git test ftpuser "$COMPROMISED_ACCOUNT"; do
  i=$((i + 1))
  fail_login "$ATTACKER_IP" "$user" "$((8000 + i))" "$((45000 + i))"
  sleep 1
done

log "Stage 2/6  initial access — a guess lands (T1078)"
sleep 4
emit "$AUTH_LOG" "$(ts) endpoint01 sshd[8100]: Accepted password for $COMPROMISED_ACCOUNT from $ATTACKER_IP port 45100 ssh2"
sleep 6

log "Stage 3/6  persistence — authorized_keys, sudoers, cron (T1098.004, T1136, T1053.003)"
# A real key blob would be noise in the report; what matters is that the file at
# this path changed at all, which is exactly what D2 asserts.
docker_run docker exec "$AGENT" sh -c \
  "mkdir -p /root/.ssh /etc/sudoers.d /etc/cron.d
   echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI0000000000SOCLAB0SIMULATED0KEY0000 attacker@offsec' > $AUTHKEYS
   chmod 600 $AUTHKEYS
   echo '$COMPROMISED_ACCOUNT ALL=(ALL) NOPASSWD: ALL' > $SUDOERS_DROPIN
   echo '*/5 * * * * root $IMPLANT' > $CRON_DROPIN" >/dev/null
sleep 6

log "Stage 4/6  defense evasion — implant dropped as $IMPLANT (T1036.005)"
# Named to sit unremarkably in a process list next to the real systemd-udevd.
# The file itself is inert text; the detection cannot tell, which is the point.
docker_run docker exec "$AGENT" sh -c \
  "printf '#!/bin/sh\n# inert marker file — SOC lab incident simulation\n' > $IMPLANT
   chmod 755 $IMPLANT" >/dev/null
sleep 6

log "Stage 5/6  command and control — beacon to $C2_IP:443 (T1071.001)"
# Three connections rather than one: a single outbound connection is ambiguous,
# a repeating one at a fixed interval is what beaconing looks like.
for n in 1 2 3; do
  beacon "$C2_IP" "$((44320 + n))" "$((5000 + n))"
  sleep 5
done

log "Stage 6/6  controls — identical activity that must NOT raise these alerts"
# Same brute force, unlisted source: stock rules should still call it a brute
# force, but with no MISP hit there must be no D5.
for n in 1 2 3 4 5 6 7 8 9; do
  fail_login "$UNLISTED_IP" "admin" "$((8200 + n))" "$((46000 + n))"
done
# Same outbound shape, internal destination: suppressed by 100227-100229.
beacon "$INTERNAL_IP" 44400 5100

# --- collect -----------------------------------------------------------------
#
# The control brute force has to be WAITED FOR, not merely emitted. "The unlisted
# host raised no D5" is only evidence if the events reached analysisd at all —
# otherwise the report is quoting a race, not a negative result, and a capture
# that stops the moment the last attack alert lands will always win that race.
# So the wait condition includes a stock alert that can only come from the
# control source.
log "Waiting for the incident to land in full (up to 3 minutes)"
WANTED="100240 100200 100210 100220 100230 100231"
for _ in $(seq 1 36); do
  got="$(docker_run docker exec "$MANAGER" sh -c \
    "tail -n +$((before + 1)) /var/ossec/logs/alerts/alerts.json 2>/dev/null" \
    | python3 -c '
import sys, json
ids = set()
for line in sys.stdin:
    try: ids.add(json.loads(line)["rule"]["id"])
    except Exception: pass
print(" ".join(sorted(ids)))' || true)"
  missing=""
  for w in $WANTED; do grep -qw "$w" <<<"$got" || missing="$missing $w"; done
  # ...and the control source must have been processed too.
  docker_run docker exec "$MANAGER" sh -c \
    "tail -n +$((before + 1)) /var/ossec/logs/alerts/alerts.json 2>/dev/null" \
    | grep -q "$UNLISTED_IP" || missing="$missing control"
  [[ -z "$missing" ]] && break
  sleep 5
done
# Analysisd may still be mid-window on the control brute force when the loop
# breaks; give the composite rules their moment before slicing the log.
sleep 10

# Unlike Phase 6's artifact, the STOCK alerts are kept. An incident report has to
# show the brute force (5712) and the successful login (5715) that D1 correlated,
# or the correlation is an assertion rather than something a reader can check.
docker_run docker exec "$MANAGER" sh -c \
  "tail -n +$((before + 1)) /var/ossec/logs/alerts/alerts.json" > "$RAW.tmp" 2>/dev/null || true

T1="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

ATTACKER_IP="$ATTACKER_IP" C2_IP="$C2_IP" UNLISTED_IP="$UNLISTED_IP" \
INTERNAL_IP="$INTERNAL_IP" T0="$T0" T1="$T1" \
python3 - "$RAW.tmp" "$RAW" <<'PY'
import json, os, sys

alerts = []
with open(sys.argv[1]) as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            alerts.append(json.loads(line))
        except ValueError:
            continue

alerts.sort(key=lambda a: a.get("timestamp", ""))

doc = {
    "incident": "INC-2026-001",
    "captured": {
        "started": os.environ["T0"],
        "ended": os.environ["T1"],
        "attacker_ip": os.environ["ATTACKER_IP"],
        "c2_ip": os.environ["C2_IP"],
        "control_unlisted_ip": os.environ["UNLISTED_IP"],
        "control_internal_ip": os.environ["INTERNAL_IP"],
    },
    "note": "Every alert below was produced by scripts/demo-incident.sh against "
            "the live lab. Stock alerts are retained alongside the custom ones so "
            "the correlations can be checked rather than taken on trust.",
    "alert_count": len(alerts),
    "alerts": alerts,
}
with open(sys.argv[2], "w") as fh:
    json.dump(doc, fh, indent=2)
print(f"captured {len(alerts)} alert(s) -> {sys.argv[2]}")
PY
rm -f "$RAW.tmp"

printf '\n\033[1mIncident timeline\033[0m\n'
ATTACKER_IP="$ATTACKER_IP" C2_IP="$C2_IP" UNLISTED_IP="$UNLISTED_IP" \
  INTERNAL_IP="$INTERNAL_IP" python3 - "$RAW" <<'PY'
import json, os, sys

STAGE = {
    "100240": "1  credential access   D5  auth attack from listed host",
    "100200": "2  initial access      D1  brute force -> success",
    "100210": "3  persistence         D2  security-critical file changed",
    "100220": "4  defense evasion     D3  implant in system bin dir",
    "100230": "5  command & control   D4a outbound connection observed",
    "100231": "5  command & control   D4b outbound to known C2",
    "100103": "*  correlation         repeated intel matches from one host",
    "100101": "*  enrichment          known-bad observable seen",
}
doc = json.load(open(sys.argv[1]))
alerts = doc["alerts"]

seen = {}
for a in alerts:
    seen.setdefault(a["rule"]["id"], []).append(a)

for rid, label in STAGE.items():
    hits = seen.get(rid, [])
    if not hits and rid in ("100103", "100101"):
        continue
    mark = "\033[1;32mFIRED\033[0m" if hits else "\033[1;31mMISS \033[0m"
    lvl = hits[0]["rule"]["level"] if hits else "-"
    print(f"  {mark}  {label:<48} x{len(hits):<3} level {lvl}")

print("\n\033[1mStock alerts that carried the incident\033[0m")
for rid in ("5710", "5712", "5715", "5716", "5760", "554", "550", "553"):
    if rid in seen:
        print(f"    {rid:<6} x{len(seen[rid]):<3} {seen[rid][0]['rule']['description'][:70]}")

print("\n\033[1mControls\033[0m")
unlisted = os.environ["UNLISTED_IP"]
d5_srcs = {
    a.get("data", {}).get("misp", {}).get("observable")
    for a in seen.get("100240", [])
}
ok = unlisted not in d5_srcs
print(f"  {'\033[1;32mPASS\033[0m' if ok else '\033[1;31mFAIL\033[0m'}  "
      f"unlisted source {unlisted} raised no D5")
suppressed = not any(
    a.get("data", {}).get("dstip", "").startswith("172.")
    for a in seen.get("100230", [])
)
print(f"  {'\033[1;32mPASS\033[0m' if suppressed else '\033[1;31mFAIL\033[0m'}  "
      f"internal destination suppressed before enrichment")

missing = [r for r in ("100240", "100200", "100210", "100220", "100230", "100231")
           if r not in seen]
print(f"\n  {len(alerts)} alert(s) captured -> docs/incidents/incident-001-alerts.json")
sys.exit(1 if missing else 0)
PY
rc=$?

printf '\n'
if [[ $rc -eq 0 ]]; then
  log "Full intrusion reproduced. Write-up: docs/incident-report-example.md"
else
  warn "Some stages did not produce their alert — see above."
  warn "Check: docker exec $MANAGER tail /var/ossec/logs/integrations.log"
fi
exit $rc
