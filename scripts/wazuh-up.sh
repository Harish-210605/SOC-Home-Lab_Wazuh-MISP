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

# The agent's ossec.conf is bind-mounted too, so it needs the same SELinux
# treatment as the manager and indexer config.
relabel_path "$REPO_ROOT/agents/config"

log "Starting stack (project: $COMPOSE_PROJECT)"
compose up -d

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
