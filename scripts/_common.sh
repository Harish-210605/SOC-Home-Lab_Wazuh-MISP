#!/usr/bin/env bash
# Shared setup for the lab helper scripts. Sourced, not executed.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --- Wazuh ---
WAZUH_TAG="v4.14.7"
WAZUH_UPSTREAM="https://github.com/wazuh/wazuh-docker.git"
WAZUH_DIR="$REPO_ROOT/wazuh/wazuh-docker/single-node"
COMPOSE_PROJECT="wazuh"
ENV_FILE="$REPO_ROOT/.env"

# --- MISP ---
# misp-docker publishes no release tags, so the clone is pinned to a commit and
# the images are pinned separately via *_RUNNING_TAG in misp/.env.
MISP_UPSTREAM="https://github.com/MISP/misp-docker.git"
MISP_COMMIT="223b675c4480730832f928e113b6f2e5260b450d"
MISP_DIR="$REPO_ROOT/misp/misp-docker"
MISP_PROJECT="misp"
MISP_ENV="$REPO_ROOT/misp/.env"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m warn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# 24 random alphanumerics plus a fixed ".Aa1" tail. The tail guarantees the
# upper/lower/digit/symbol mix that both the Wazuh API and MISP enforce, and
# every character is safe to carry through YAML, .env and the shell.
gen_pw() {
  printf '%s.Aa1' "$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24)"
}

# Run a command with docker group credentials.
#
# Membership in the `docker` group is granted by PAM when a login session is
# created. If the group was added with usermod after the current session began,
# the shell carries stale supplementary groups and talking to the daemon fails
# with EACCES even though /etc/group is correct. `sg` starts a process with the
# group applied, which works around it until the next login.
docker_run() {
  if docker info >/dev/null 2>&1; then
    "$@"
  elif id -nG 2>/dev/null | tr ' ' '\n' | grep -qx docker || getent group docker | grep -q "\b$(id -un)\b"; then
    sg docker -c "$(printf '%q ' "$@")"
  else
    die "cannot reach the Docker daemon, and $(id -un) is not in the 'docker' group.
       Run: sudo usermod -aG docker $(id -un)   (then log out and back in)"
  fi
}

# docker compose, with our overlay layered on top of the pinned upstream file.
#
# The project name is pinned so container names stay stable no matter which
# directory this is invoked from. Compose resolves relative paths in the base
# file against the FIRST -f file's directory, which is why upstream's
# ./config/... mounts keep working from here.
compose() {
  [[ -f "$ENV_FILE" ]] || die "$ENV_FILE is missing. Run scripts/wazuh-bootstrap.sh first."
  # LAB_ROOT lets the agent overlay use absolute bind-mount paths. Compose
  # resolves relative paths against the first -f file's directory (upstream's
  # single-node/), so an agent file written with ./ paths would look for them
  # in the wrong tree.
  # Exported on its own line rather than as a `VAR=x func` prefix: for shell
  # functions bash does not reliably pass prefix assignments through to the
  # commands the function runs.
  export LAB_ROOT="$REPO_ROOT"
  docker_run docker compose \
    -p "$COMPOSE_PROJECT" \
    -f "$WAZUH_DIR/docker-compose.yml" \
    -f "$REPO_ROOT/wazuh/compose.override.yml" \
    -f "$REPO_ROOT/agents/compose.agents.yml" \
    --env-file "$ENV_FILE" \
    "$@"
}

# SELinux relabel for the bind-mounted config tree.
#
# On an SELinux-enforcing host these files inherit user_home_t, which the
# container_t domain cannot read; the indexer then fails to start with cert and
# config errors that do not mention SELinux at all. Relabelling to
# container_file_t fixes it. This cannot be expressed as a :z flag in our
# override, because Compose CONCATENATES service `volumes` lists across files
# rather than replacing them, so re-declaring the mounts would duplicate them.
selinux_active() {
  command -v getenforce >/dev/null 2>&1 || return 1
  [[ "$(getenforce)" == "Disabled" ]] && return 1
  command -v chcon >/dev/null 2>&1 || { warn "chcon not found; skipping SELinux relabel"; return 1; }
  return 0
}

# Relabel an arbitrary bind-mount source so containers can read it.
relabel_path() {
  selinux_active || return 0
  [[ -e "$1" ]] || return 0
  chcon -Rt container_file_t "$1" || warn "could not relabel $1"
}

# Shared network between the two Compose projects.
#
# Wazuh and MISP run as separate projects, each with its own default network, so
# by default wazuh.manager has no route to the MISP API at all. Rather than
# merging the stacks into one project (which would tie their lifecycles
# together), a single user-defined bridge is created outside Compose and both
# projects attach the one service that needs it: wazuh.manager and misp-core.
#
# Declared `external: true` in both overrides, which means Compose will not
# create it — hence this helper, called by both up scripts before `compose up`.
SHARED_NET="soclab-intel"

ensure_shared_network() {
  if docker_run docker network inspect "$SHARED_NET" >/dev/null 2>&1; then
    return 0
  fi
  log "Creating shared network $SHARED_NET"
  # internal: no gateway to the outside world is added for this bridge. The
  # containers keep their own default networks for egress; this one exists only
  # to carry manager -> MISP API traffic, so it has no business routing off-box.
  docker_run docker network create --internal "$SHARED_NET" >/dev/null \
    || die "could not create the $SHARED_NET network"
}

# docker compose for the MISP stack.
#
# A separate Compose project from Wazuh: independent lifecycles, and MISP is
# heavy enough to want stopping on its own. Phase 5 adds a shared network so
# the Wazuh manager can reach the MISP API.
misp_compose() {
  [[ -f "$MISP_ENV" ]] || die "$MISP_ENV is missing. Run scripts/misp-bootstrap.sh first."
  docker_run docker compose \
    -p "$MISP_PROJECT" \
    -f "$MISP_DIR/docker-compose.yml" \
    -f "$REPO_ROOT/misp/compose.override.yml" \
    --env-file "$MISP_ENV" \
    "$@"
}

relabel_config() {
  selinux_active || return 0

  log "Relabelling config tree for SELinux (container_file_t)"
  # The certificate directory is skipped on purpose. The generator chowns it to
  # uid 999/1000, so an unprivileged chcon -R cannot even read it — and it does
  # not need to: those files inherit container_file_t from this directory,
  # which is relabelled before the certificates are ever generated.
  find "$WAZUH_DIR/config" -mindepth 1 -maxdepth 1 \
    ! -name wazuh_indexer_ssl_certs -print0 \
    | xargs -0 --no-run-if-empty chcon -Rt container_file_t
  chcon -t container_file_t "$WAZUH_DIR/config"
}
