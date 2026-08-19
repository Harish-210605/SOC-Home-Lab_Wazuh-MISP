#!/usr/bin/env bash
# Demonstrate file integrity monitoring end to end.
#
# Creates, modifies and deletes a file inside the monitored /var/lab directory
# on endpoint01, then pulls the resulting alerts back out of the indexer.
#
# Exercises the full path: inotify on the agent -> manager analysisd -> Filebeat
# -> indexer. Expect rules 554 (added), 550 (modified) and 553 (deleted).

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

# shellcheck source=/dev/null
set -a; source "$ENV_FILE"; set +a

AGENT_CT="wazuh-wazuh.agent.endpoint01-1"
TARGET="/var/lab/fim-demo-$(date +%H%M%S).conf"

log "Creating  $TARGET"
docker_run docker exec "$AGENT_CT" sh -c "echo 'setting=original' > $TARGET"
sleep 5

log "Modifying $TARGET"
docker_run docker exec "$AGENT_CT" sh -c "echo 'setting=tampered' > $TARGET"
sleep 5

log "Deleting  $TARGET"
docker_run docker exec "$AGENT_CT" rm -f "$TARGET"

log "Waiting for alerts to reach the indexer"
query='{"size":10,"sort":[{"timestamp":"desc"}],
        "query":{"term":{"syscheck.path":"'"$TARGET"'"}},
        "_source":["timestamp","rule.id","rule.level","rule.description","syscheck.event"]}'

for _ in $(seq 1 24); do
  body="$(curl -sk -u "admin:$INDEXER_PASSWORD" \
    'https://127.0.0.1:9200/wazuh-alerts-*/_search' \
    -H 'Content-Type: application/json' -d "$query" 2>/dev/null || true)"
  total="$(sed -n 's/.*"hits":{"total":{"value":\([0-9]*\).*/\1/p' <<<"$body")"
  [[ -n "$total" && "$total" -ge 3 ]] && break
  sleep 5
done

printf '\n\033[1mAlerts for %s\033[0m\n\n' "$TARGET"
python3 - "$body" <<'PY'
import json, sys
hits = json.loads(sys.argv[1])["hits"]["hits"]
if not hits:
    print("  none found — check: scripts/wazuh-logs.sh wazuh.manager")
    raise SystemExit(1)
print(f"  {'RULE':<6}{'LVL':<5}{'EVENT':<10}DESCRIPTION")
for h in reversed(hits):
    s = h["_source"]
    r = s["rule"]
    print(f"  {r['id']:<6}{r['level']:<5}{s.get('syscheck',{}).get('event',''):<10}{r['description']}")
PY
