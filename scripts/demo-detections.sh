#!/usr/bin/env bash
# Exercise every custom detection from Phase 6, end to end (D1-D5).
#
# Each scenario is simulated safely:
#   - authentication and firewall activity by writing log lines that Wazuh's
#     STOCK decoders parse, so the decoder, rule and alert path exercised are
#     the production ones
#   - file-integrity activity by making REAL file changes inside the agent
#     container, so syscheck genuinely observes them
#
# Nothing here contacts a malicious host, and nothing runs hostile code. The
# "malware" dropped in D3 is a text file; what is being tested is the detection,
# and the detection cannot tell the difference — which is the point.

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

# shellcheck source=/dev/null
set -a; source "$MISP_ENV"; set +a

MANAGER="wazuh-wazuh.manager-1"
AGENT="$AGENT_CONTAINER"
AUTH_LOG="/var/log/simulated/auth.log"
FW_LOG="/var/log/simulated/firewall.log"
ART="$REPO_ROOT/docs/detections"

BENIGN_IP="198.51.100.77"   # RFC 5737 TEST-NET-2 — never in a real feed

for c in "$MANAGER" "$AGENT" misp-misp-core-1; do
  docker_run docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null | grep -q true \
    || die "$c is not running. Start the lab with scripts/wazuh-up.sh and scripts/misp-up.sh."
done

mkdir -p "$ART"

ensure_agent_log_source "$AUTH_LOG"
ensure_agent_log_source "$FW_LOG"

# A known-bad IP taken live from MISP, so the demo keeps working as feeds rotate.
BAD_IP="$(curl -sk -H "Authorization: $ADMIN_KEY" -H 'Accept: application/json' \
  -H 'Content-Type: application/json' -X POST https://127.0.0.1/attributes/restSearch \
  -d '{"type":"ip-dst","limit":1,"returnFormat":"json"}' 2>/dev/null \
  | python3 -c 'import sys,json
try: print(json.load(sys.stdin)["response"]["Attribute"][0]["value"])
except Exception: print("")')"
[[ -n "$BAD_IP" ]] || die "no IP indicators in MISP. Run scripts/misp-feeds.sh first."

log "Known-bad IP (from MISP): $BAD_IP"
log "Benign control:           $BENIGN_IP"

# Everything after this line number is what this run produced.
before="$(docker_run docker exec "$MANAGER" sh -c \
  'wc -l < /var/ossec/logs/alerts/alerts.json 2>/dev/null || echo 0')"

emit() {  # emit <container-path> <line>
  printf '%s\n' "$2" | docker_run docker exec -i "$AGENT" sh -c "cat >> $1"
}

ts() { date '+%b %d %H:%M:%S'; }

# --- D1: brute force followed by a successful login -------------------------
log "D1  brute force then success from $BENIGN_IP (T1110.001 -> T1078)"
for i in $(seq 1 9); do
  emit "$AUTH_LOG" "$(ts) endpoint01 sshd[$((6000+i))]: Failed password for invalid user oracle from $BENIGN_IP port $((44000+i)) ssh2"
done
sleep 2
emit "$AUTH_LOG" "$(ts) endpoint01 sshd[6100]: Accepted password for backupsvc from $BENIGN_IP port 44100 ssh2"

# --- D2: persistence / credential-store modification ------------------------
log "D2  writing to /etc/sudoers.d and /etc/cron.d (T1053.003, T1098.004)"
docker_run docker exec "$AGENT" sh -c \
  'mkdir -p /etc/sudoers.d /etc/cron.d
   echo "soclab-demo ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/soclab-demo
   echo "* * * * * root /tmp/.soclab-demo" > /etc/cron.d/soclab-demo' >/dev/null

# --- D3: executable dropped into a system binary directory ------------------
log "D3  dropping a file into /usr/bin (T1036.005)"
docker_run docker exec "$AGENT" sh -c \
  'printf "#!/bin/sh\n# inert marker file for SOC lab detection D3\n" > /usr/bin/soclab-demo-implant
   chmod 755 /usr/bin/soclab-demo-implant' >/dev/null

# --- D4: outbound connection to known-malicious infrastructure --------------
log "D4  outbound connection to $BAD_IP (T1071.001)"
emit "$FW_LOG" "$(ts) endpoint01 kernel: OUTBOUND-ACCEPT IN= OUT=eth0 SRC=172.20.0.5 DST=$BAD_IP LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=4001 DF PROTO=TCP SPT=44321 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0"
# Control: an internal destination must be suppressed by 100227-100229.
emit "$FW_LOG" "$(ts) endpoint01 kernel: OUTBOUND-ACCEPT IN= OUT=eth0 SRC=172.20.0.5 DST=172.20.0.9 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=4002 DF PROTO=TCP SPT=44322 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0"

# --- D5: authentication attack from a threat-intel-listed host --------------
log "D5  failed logins from the MISP-listed host $BAD_IP (T1110.001)"
for i in $(seq 1 3); do
  emit "$AUTH_LOG" "$(ts) endpoint01 sshd[$((7000+i))]: Failed password for invalid user admin from $BAD_IP port $((45000+i)) ssh2"
done

# --- collect -----------------------------------------------------------------
# FIM is realtime but not instant, and D4/D5 need a MISP round-trip on top.
log "Waiting for detections to land (up to 3 minutes)"
WANTED="100200 100210 100220 100230 100231 100240"
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
  [[ -z "$missing" ]] && break
  sleep 5
done

RAW="$ART/phase6-alerts.json"
docker_run docker exec "$MANAGER" sh -c \
  "tail -n +$((before + 1)) /var/ossec/logs/alerts/alerts.json" > "$RAW.tmp" 2>/dev/null || true

# Keep only our own rules in the artifact. The raw slice also contains the stock
# alerts that triggered them (5710, 5712, 554...), which are useful context but
# would bury the six alerts this phase is actually about.
python3 - "$RAW.tmp" "$RAW" <<'PY'
import json, sys
WANTED = {"100200","100210","100220","100230","100231","100240"}
out = []
with open(sys.argv[1]) as fh:
    for line in fh:
        line = line.strip()
        if not line:
            continue
        try:
            a = json.loads(line)
        except ValueError:
            continue
        if a.get("rule", {}).get("id") in WANTED:
            out.append(a)
with open(sys.argv[2], "w") as fh:
    json.dump(out, fh, indent=2)
print(f"captured {len(out)} alert(s) -> {sys.argv[2]}")
PY
rm -f "$RAW.tmp"

printf '\n\033[1mDetections triggered\033[0m\n'
python3 - "$RAW" <<'PY'
import json, sys
NAMES = {
    "100200": "D1  brute force -> successful login",
    "100210": "D2  security-critical file modified",
    "100220": "D3  executable dropped in system bin dir",
    "100230": "D4a outbound connection observed",
    "100231": "D4b outbound to known-malicious host",
    "100240": "D5  auth attack from threat-intel host",
}
alerts = json.load(open(sys.argv[1]))
seen = {}
for a in alerts:
    seen.setdefault(a["rule"]["id"], []).append(a)
for rid, label in NAMES.items():
    hits = seen.get(rid, [])
    mark = "\033[1;32mFIRED\033[0m" if hits else "\033[1;31mMISS \033[0m"
    lvl = hits[0]["rule"]["level"] if hits else "-"
    mitre = ",".join(hits[0]["rule"].get("mitre", {}).get("id", [])) if hits else ""
    print(f"  {mark}  {label:<44} level {lvl:<3} {mitre}")
    if hits:
        print(f"         {hits[0]['rule']['description'][:110]}")
missing = [r for r in NAMES if r not in seen]
sys.exit(1 if missing else 0)
PY
rc=$?

printf '\n'
if [[ $rc -eq 0 ]]; then
  log "All six rules fired. Artifact: docs/detections/phase6-alerts.json"
else
  warn "Some detections did not fire — see above."
  warn "Check: docker exec $MANAGER tail /var/ossec/logs/integrations.log"
fi
exit $rc
