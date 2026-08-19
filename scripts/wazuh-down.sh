#!/usr/bin/env bash
# Stop the Wazuh stack.
#
#   wazuh-down.sh            stop containers, keep all data
#   wazuh-down.sh --purge    also delete the named volumes (indexer data,
#                            registered agents, manager state)

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

if [[ "${1:-}" == "--purge" ]]; then
  warn "This deletes all indexed alerts and registered agents."
  read -rp "Type 'purge' to confirm: " reply
  [[ "$reply" == "purge" ]] || die "aborted"
  log "Stopping stack and removing volumes"
  compose down -v
else
  log "Stopping stack (volumes preserved)"
  compose down
fi
