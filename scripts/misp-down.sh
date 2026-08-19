#!/usr/bin/env bash
# Stop the MISP stack.
#
#   misp-down.sh            stop containers, keep all data
#   misp-down.sh --purge    also delete the named volumes (events, database)

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

if [[ "${1:-}" == "--purge" ]]; then
  warn "This deletes the MISP database and every stored event."
  read -rp "Type 'purge' to confirm: " reply
  [[ "$reply" == "purge" ]] || die "aborted"
  log "Stopping MISP and removing volumes"
  misp_compose down -v
else
  log "Stopping MISP (volumes preserved)"
  misp_compose down
fi
