#!/usr/bin/env bash
# Start the Wazuh single-node stack and wait for the indexer to report green.

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

# Test the directory, not a file inside it. The certificate generator leaves
# this directory root-owned and mode 0500, so an unprivileged user cannot
# traverse it to stat its contents. The containers are unaffected: the Docker
# daemon runs as root and resolves each bind-mounted file path itself.
[[ -d "$WAZUH_DIR/config/wazuh_indexer_ssl_certs" ]] \
  || die "certificates are missing. Run scripts/wazuh-bootstrap.sh first."

# shellcheck source=/dev/null
set -a; source "$ENV_FILE"; set +a

# Render the manager config from its tracked template, substituting the MISP
# API key. The template lives in git with a placeholder; the rendered copy lands
# in wazuh/config/generated/ (gitignored) and is what actually gets mounted, so
# the key never has a chance to be committed.
render_manager_config() {
  local template="$REPO_ROOT/wazuh/config/wazuh_manager.conf"
  local out_dir="$REPO_ROOT/wazuh/config/generated"
  local out="$out_dir/wazuh_manager.conf"

  [[ -f "$template" ]] || die "$template is missing."
  mkdir -p "$out_dir"

  local key=""
  if [[ -f "$MISP_ENV" ]]; then
    key="$(grep -E '^ADMIN_KEY=' "$MISP_ENV" | tail -1 | cut -d= -f2-)"
  fi
  if [[ -z "$key" ]]; then
    warn "no ADMIN_KEY in $MISP_ENV — the MISP integration will not authenticate."
    warn "Run scripts/misp-bootstrap.sh, then re-run this script."
    key="MISP_API_KEY_UNSET"
  fi

  # Written via a temp file and moved into place so a partial write can never be
  # mounted, and with 600 because this copy holds the API key in cleartext.
  local tmp="$out.tmp"
  MISP_KEY="$key" python3 -c '
import os, sys
src, dst = sys.argv[1], sys.argv[2]
data = open(src).read()
placeholder = "MISP_API_KEY_PLACEHOLDER"
if placeholder not in data:
    sys.exit("template does not contain " + placeholder)
open(dst, "w").write(data.replace(placeholder, os.environ["MISP_KEY"]))
' "$template" "$tmp" || die "could not render the manager config"
  chmod 600 "$tmp"
  mv "$tmp" "$out"
}

log "Rendering manager config (injecting the MISP API key)"
render_manager_config

# Both stacks attach to this; it is created outside Compose because neither
# project can own an external network's lifecycle without ordering the other
# behind it. Safe to call when MISP is not running — the network simply waits.
ensure_shared_network

# Bind-mounted files keep their HOST ownership inside the container, so the uid
# that owns them almost never matches the container's `wazuh` user. Only the
# permission bits are portable, and wazuh-integratord runs as `wazuh`, not root:
# a mode-750 script owned by the host user is unreadable to it, and integratord
# reports that as a bare "Permission denied" with no hint at the cause. Git only
# tracks the executable bit, so the modes are asserted here rather than assumed.
chmod 755 "$REPO_ROOT/wazuh/integrations/custom-misp"
chmod 644 "$REPO_ROOT/wazuh/integrations/custom-misp.py" \
          "$REPO_ROOT/wazuh/rules/local_rules.xml"

# The agent's ossec.conf is bind-mounted too, so it needs the same SELinux
# treatment as the manager and indexer config.
relabel_path "$REPO_ROOT/agents/config"
# Phase 5 adds three more bind-mount sources: the rendered manager config, the
# integration scripts and the local ruleset. Same SELinux reasoning.
relabel_path "$REPO_ROOT/wazuh/config"
relabel_path "$REPO_ROOT/wazuh/integrations"
relabel_path "$REPO_ROOT/wazuh/rules"
relabel_path "$REPO_ROOT/wazuh/lists"

log "Starting stack (project: $COMPOSE_PROJECT)"
compose up -d

# The dashboard's own copy of the wazuh-wui API password lives in wazuh.yml on
# a named volume, templated once by the dashboard image's entrypoint on first
# boot. It is never re-templated afterwards, so if that volume predates the
# current API_PASSWORD (e.g. .env was regenerated, or the volume is older than
# the password currently in it), the dashboard silently keeps authenticating
# with the stale value and every Server API connection reads "Offline" with a
# 401 in its logs — the UI itself loads fine, which makes this easy to miss.
sync_dashboard_api_password() {
  local current
  current="$(compose exec -T wazuh.dashboard \
    grep -oP '(?<=password: ")[^"]*' /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml 2>/dev/null | tail -1)"
  [[ "$current" == "$API_PASSWORD" ]] && return 0
  log "Dashboard's stored API password is stale — resyncing from .env"
  API_PW="$API_PASSWORD" compose exec -T wazuh.dashboard python3 -c '
import os
p = "/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"
s = open(p).read()
import re
s2 = re.sub(r"password: \"[^\"]*\"", "password: \"" + os.environ["API_PW"] + "\"", s, count=1)
open(p, "w").write(s2)
' || { warn "could not resync the dashboard API password"; return 1; }
  compose restart wazuh.dashboard
}
sync_dashboard_api_password

log "Waiting for the indexer to report green (up to 5 minutes)"
# The dashboard restarts a few times while the indexer initialises. That is
# expected on a cold start and not a failure.
for i in $(seq 1 60); do
  # `|| true` matters: until the indexer is listening curl exits non-zero, and
  # set -e/pipefail would abort the wait loop on the very first attempt.
  status="$(curl -sk -u "admin:$INDEXER_PASSWORD" \
    https://127.0.0.1:9200/_cluster/health 2>/dev/null \
    | sed -n 's/.*"status":"\([a-z]*\)".*/\1/p' || true)"
  if [[ "$status" == "green" ]]; then
    log "Indexer is green after ~$((i * 5))s"
    compose ps
    printf '\nDashboard: https://127.0.0.1:8443  (user: admin)\n'
    printf 'The certificate is self-signed, so expect a browser warning.\n'
    exit 0
  fi
  sleep 5
done

warn "Indexer did not reach green within 5 minutes. Current state:"
compose ps
printf '\nInspect with: scripts/wazuh-logs.sh wazuh.indexer\n' >&2
exit 1
