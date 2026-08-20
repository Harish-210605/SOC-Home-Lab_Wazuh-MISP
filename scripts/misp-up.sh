#!/usr/bin/env bash
# Start the MISP stack and wait for misp-core to become healthy.

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

[[ -d "$MISP_DIR" ]] || die "misp/misp-docker is missing. Run scripts/misp-bootstrap.sh first."

# The shared bridge is declared `external: true` in misp/compose.override.yml,
# so Compose will not create it. Either stack may be started first, so both
# ensure it exists.
ensure_shared_network

log "Starting MISP (project: $MISP_PROJECT)"
misp_compose up -d

# First boot is slow: MISP initialises the database schema, generates a GPG
# key and warms its caches before the heartbeat endpoint answers. 15 minutes is
# a generous ceiling, not an expectation.
log "Waiting for misp-core to become healthy (up to 15 minutes)"
for i in $(seq 1 180); do
  state="$(docker_run docker inspect --format '{{.State.Health.Status}}' \
    misp-misp-core-1 2>/dev/null || true)"
  case "$state" in
    healthy)
      log "misp-core is healthy after ~$((i * 5))s"
      misp_compose ps
      # tail -1: the key appears twice in .env (upstream template, then our
      # override) and the last assignment is the one Compose uses.
      printf '\nMISP: https://127.0.0.1  (user: %s)\n' \
        "$(grep -E '^ADMIN_EMAIL=' "$MISP_ENV" | tail -1 | cut -d= -f2-)"
      printf 'Password is ADMIN_PASSWORD in misp/.env. Self-signed cert, expect a warning.\n'
      exit 0
      ;;
    unhealthy)
      warn "misp-core reports unhealthy — still retrying, check scripts/misp-logs.sh misp-core"
      ;;
  esac
  sleep 5
done

warn "misp-core did not become healthy within 15 minutes. Current state:"
misp_compose ps
printf '\nInspect with: scripts/misp-logs.sh misp-core\n' >&2
exit 1
