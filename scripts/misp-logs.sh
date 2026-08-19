#!/usr/bin/env bash
# Tail MISP logs, or those of one service.
#
#   misp-logs.sh              all services
#   misp-logs.sh misp-core    just the core

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

misp_compose logs -f --tail 200 "$@"
