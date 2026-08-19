#!/usr/bin/env bash
# Replace Wazuh's shipped demo credentials with the ones in .env.
#
# The upstream single-node deployment ships publicly documented passwords
# ("SecretPassword", "kibanaserver", "MyS3cr37P450r.*-") and six demo accounts,
# four of which Wazuh never uses. This rewrites internal_users.yml with fresh
# bcrypt hashes and drops the unused accounts.
#
# Run it AFTER wazuh-bootstrap.sh and BEFORE the first wazuh-up.sh: on a cold
# start the indexer initialises its security index straight from this file, so
# the stack comes up already using the new credentials.
#
# Re-running it against a live stack rotates the passwords instead: the security
# index already exists by then, so the new config has to be pushed with
# securityadmin.sh and the other two services restarted to pick up the change.

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

[[ -f "$ENV_FILE" ]] || die "$ENV_FILE is missing. Run scripts/wazuh-bootstrap.sh first."
# shellcheck source=/dev/null
set -a; source "$ENV_FILE"; set +a

: "${INDEXER_PASSWORD:?not set in .env}"
: "${DASHBOARD_PASSWORD:?not set in .env}"

USERS_FILE="$WAZUH_DIR/config/wazuh_indexer/internal_users.yml"
[[ -f "$USERS_FILE" ]] || die "$USERS_FILE not found. Run scripts/wazuh-bootstrap.sh first."

# bcrypt, cost 12, in the $2y$ form OpenSearch expects.
#
# htpasswd is preferred over the indexer image's own hash.sh because it keeps
# the plaintext out of a container's process arguments (visible to anyone who
# can run `docker inspect` while it executes) and avoids spinning up a ~1GB
# image just to hash a string.
bcrypt() {
  local pw="$1"
  if command -v htpasswd >/dev/null 2>&1; then
    htpasswd -bnBC 12 "" "$pw" | tr -d '\n' | sed 's/^://'
  else
    docker_run docker run --rm "wazuh/wazuh-indexer:${WAZUH_TAG#v}" \
      bash -c "JAVA_HOME=/usr/share/wazuh-indexer/jdk \
        /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh -p '$pw'" \
      | grep -oE '^\$2[aby]\$.*' | tail -1
  fi
}

log "Hashing credentials"
ADMIN_HASH="$(bcrypt "$INDEXER_PASSWORD")"
KIBANA_HASH="$(bcrypt "$DASHBOARD_PASSWORD")"
[[ "$ADMIN_HASH" == \$2* && "$KIBANA_HASH" == \$2* ]] || die "bcrypt hashing produced no usable hash"

if [[ ! -f "$USERS_FILE.upstream" ]]; then
  cp "$USERS_FILE" "$USERS_FILE.upstream"
  log "Kept the original as internal_users.yml.upstream for reference"
fi

log "Writing internal_users.yml"
cat > "$USERS_FILE" <<EOF
---
# Managed by scripts/wazuh-passwords.sh — do not edit by hand.
# Hashes are bcrypt (cost 12) of the passwords in the gitignored .env.
#
# Only the two accounts Wazuh actually uses are defined here. Upstream also
# ships kibanaro, logstash, readall and snapshotrestore with published demo
# passwords; none are needed for this deployment, so they are omitted rather
# than left enabled. The original file is kept as internal_users.yml.upstream.

_meta:
  type: "internalusers"
  config_version: 2

admin:
  hash: "$ADMIN_HASH"
  reserved: true
  backend_roles:
  - "admin"
  description: "Indexer superuser and web UI login"

kibanaserver:
  hash: "$KIBANA_HASH"
  reserved: true
  description: "Service account the dashboard uses to reach the indexer"
EOF

relabel_config

# If the indexer is already running its security index was initialised from the
# old file, so the new config has to be pushed explicitly.
if docker_run docker compose -p "$COMPOSE_PROJECT" ps --status running --services 2>/dev/null | grep -qx "wazuh.indexer"; then
  log "Indexer is running — pushing the new security config with securityadmin"
  # -f/-t uploads just the internalusers config type. Pushing the whole
  # directory with -cd would also overwrite roles, mappings and the rest with
  # whatever happens to sit in the mounted config dir — which here is only
  # internal_users.yml, so it would wipe the live security configuration.
  compose exec -T wazuh.indexer bash -c '
    set -e
    export JAVA_HOME=/usr/share/wazuh-indexer/jdk
    CERTS=/usr/share/wazuh-indexer/config/certs
    bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
      -f /usr/share/wazuh-indexer/config/opensearch-security/internal_users.yml \
      -t internalusers \
      -nhnv -icl \
      -cacert  $CERTS/root-ca.pem \
      -cert    $CERTS/admin.pem \
      -key     $CERTS/admin-key.pem \
      -h 127.0.0.1 -p 9200'
  log "Restarting manager and dashboard so they pick up the new credentials"
  compose up -d --force-recreate wazuh.manager wazuh.dashboard
  log "Credentials rotated."
else
  log "Stack is not running. The new credentials apply on the next scripts/wazuh-up.sh"
fi
