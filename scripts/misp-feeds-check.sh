#!/usr/bin/env bash
# Verify the threat-intel feeds (Phase 4): registered, fetched, and — the part
# that actually matters for Phase 5 — searchable through the same API call the
# Wazuh integration will make.
#
# Exits non-zero if any check fails.

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

# shellcheck source=/dev/null
set -a; source "$MISP_ENV"; set +a

FEED_SPECS="$REPO_ROOT/misp/feeds.json"

pass=0; fail=0
ok() { printf '  \033[1;32mPASS\033[0m  %s\n' "$*"; pass=$((pass + 1)); }
no() { printf '  \033[1;31mFAIL\033[0m  %s\n' "$*"; fail=$((fail + 1)); }

api()  { curl -sk -H "Authorization: $ADMIN_KEY" -H 'Accept: application/json' \
             -H 'Content-Type: application/json' "$@" 2>/dev/null; }

# The enrichment lookup, isolated in one place: this is exactly the call the
# Wazuh MISP integration makes for every observable it extracts from an alert.
hits() {
  api -X POST https://127.0.0.1/attributes/restSearch \
      -d "{\"value\":\"$1\",\"returnFormat\":\"json\"}" \
    | python3 -c 'import sys,json
try: print(len(json.load(sys.stdin)["response"]["Attribute"]))
except Exception: print(-1)'
}

printf '\n\033[1mMISP threat-intel feed checks\033[0m\n\n'

# --- registration -----------------------------------------------------------
index="$(api https://127.0.0.1/feeds/index)"

while IFS=$'\t' read -r url name; do
  [[ -n "$url" ]] || continue
  read -r found enabled caching settings_ok <<<"$(
    FEED_URL="$url" python3 -c '
import json,os,sys
url=os.environ["FEED_URL"]
feeds=json.load(sys.stdin)
m=[f["Feed"] for f in feeds if f["Feed"]["url"]==url]
if not m:
    print("0 0 0 0"); raise SystemExit
f=m[0]
s=f.get("settings")
try:
    p=json.loads(s) if isinstance(s,str) else s
    sok=int(isinstance(p,dict) and bool(p))
except Exception:
    sok=0
print(int(bool(f.get("enabled"))!=0), int(bool(f.get("enabled"))), int(bool(f.get("caching_enabled"))), sok)
' <<<"$index"
  )"
  if [[ "$found" == "0" && "$enabled" == "0" ]]; then
    no "feed is not registered: $name"
    continue
  fi
  [[ "$enabled" == "1" ]] && ok "feed enabled: $name" || no "feed registered but DISABLED: $name"
  [[ "$caching" == "1" ]] || no "feed caching is off: $name"
  # Guards the double-encoding trap: a string-serialised `settings` round-trips
  # as an escaped string, the CSV column mapping is dropped, and the import
  # silently produces wrong or zero attributes.
  [[ "$settings_ok" == "1" ]] \
    && ok "feed settings stored as an object (column mapping intact): $name" \
    || no "feed settings are malformed/double-encoded: $name"
done < <(python3 -c '
import json,sys
for f in json.load(open(sys.argv[1])):
    print(f["url"], f["name"], sep="\t")
' "$FEED_SPECS")

# --- ingested data ----------------------------------------------------------
events="$(api https://127.0.0.1/events/index)"
total="$(python3 -c '
import json,sys
print(sum(int(e.get("attribute_count") or 0) for e in json.load(sys.stdin)))
' <<<"$events")"

[[ "${total:-0}" -ge 1000 ]] \
  && ok "feeds ingested $total attributes" \
  || no "only ${total:-0} attributes ingested (expected >= 1000)"

# Every curated feed must have produced a non-empty event of its own. A feed
# that registers cleanly but imports nothing is the usual symptom of a broken
# column mapping, and it would otherwise hide behind a healthy total.
while read -r name; do
  cnt="$(FEED_NAME="$name" python3 -c '
import json,os,sys
n=os.environ["FEED_NAME"]
tot=0
for e in json.load(sys.stdin):
    if (e.get("info") or "").startswith(n):
        tot+=int(e.get("attribute_count") or 0)
print(tot)
' <<<"$events")"
  [[ "${cnt:-0}" -ge 1 ]] \
    && ok "ingested $cnt attributes from: $name" \
    || no "no attributes ingested from: $name"
done < <(python3 -c '
import json,sys
for f in json.load(open(sys.argv[1])): print(f["name"])
' "$FEED_SPECS")

# --- IOC coverage -----------------------------------------------------------
# Phase 5 can only enrich the observable classes present here, so each is a
# check in its own right rather than a footnote.
for pair in "ip-dst|port:C2 IP addresses" "domain:domains" "url:URLs" "md5:file hashes"; do
  t="${pair%%:*}"; label="${pair##*:}"
  n="$(api -X POST https://127.0.0.1/attributes/restSearch \
        -d "{\"type\":\"$t\",\"limit\":1,\"returnFormat\":\"json\"}" \
      | python3 -c 'import sys,json
try: print(len(json.load(sys.stdin)["response"]["Attribute"]))
except Exception: print(0)')"
  [[ "${n:-0}" -ge 1 ]] \
    && ok "intel covers $label (type $t)" \
    || no "no $label in MISP (type $t) — Phase 5 cannot enrich them"
done

# --- the enrichment lookup itself -------------------------------------------
# Sample a real indicator of each class and look it up by bare value, the way
# Wazuh will. The IP case is the interesting one: ThreatFox stores C2s as the
# composite type ip-dst|port ("1.2.3.4|8080"), so a bare-IP search only works
# because MISP matches composite attributes on either half.
for t in "ip-dst|port" domain md5; do
  v="$(api -X POST https://127.0.0.1/attributes/restSearch \
        -d "{\"type\":\"$t\",\"limit\":1,\"returnFormat\":\"json\"}" \
      | python3 -c 'import sys,json
try: print(json.load(sys.stdin)["response"]["Attribute"][0]["value"])
except Exception: print("")')"
  [[ -n "$v" ]] || { no "could not sample a $t attribute to test the lookup"; continue; }
  bare="${v%%|*}"   # composite -> left half; plain types are unchanged
  h="$(hits "$bare")"
  [[ "${h:-0}" -ge 1 ]] \
    && ok "enrichment lookup resolves a known-bad $t ($bare)" \
    || no "enrichment lookup MISSED a known-bad $t ($bare)"
done

# Negative controls. Without these the lookup could be matching everything,
# which would make every Wazuh alert look like a threat-intel hit.
for v in 8.8.8.8 example.com d41d8cd98f00b204e9800998ecf8427e; do
  h="$(hits "$v")"
  [[ "${h:-1}" -eq 0 ]] \
    && ok "benign control returns no intel hit ($v)" \
    || no "benign control '$v' unexpectedly matched $h attribute(s)"
done

# --- hygiene ----------------------------------------------------------------
# feeds.json is meant to be tracked (it is public URLs and column mappings, no
# secrets); the API key that drives it must never be.
git -C "$REPO_ROOT" ls-files --error-unmatch misp/feeds.json >/dev/null 2>&1 \
  && ok "misp/feeds.json is tracked by git" \
  || no "misp/feeds.json is not tracked by git yet"

if git -C "$REPO_ROOT" grep -qI "$ADMIN_KEY" -- . 2>/dev/null; then
  no "the MISP API key appears in a tracked file"
else
  ok "no MISP API key in tracked files"
fi

printf '\n%d passed, %d failed\n\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
