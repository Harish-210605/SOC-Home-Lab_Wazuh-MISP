#!/usr/bin/env bash
# Tail logs for the stack, or for one service.
#
#   wazuh-logs.sh                  all services
#   wazuh-logs.sh wazuh.indexer    just the indexer

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

compose logs -f --tail 200 "$@"
