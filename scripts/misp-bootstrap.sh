#!/usr/bin/env bash
# One-time setup for the MISP stack.
#
#   1. clones upstream misp-docker at a pinned commit
#   2. pre-creates the bind-mount directories
#   3. writes misp/.env with generated credentials (if absent)
#
# Idempotent: safe to re-run.

source "$(dirname "${BASH_SOURCE[0]}")/_common.sh"

cd "$REPO_ROOT"

# --- 1. upstream ------------------------------------------------------------
if [[ -d "$MISP_DIR" ]]; then
  log "Upstream already present at misp/misp-docker (skipping clone)"
else
  # misp-docker publishes no release tags, so pin a commit instead. A shallow
  # clone cannot check out an arbitrary SHA, hence fetch-then-checkout.
  log "Cloning misp-docker at ${MISP_COMMIT:0:12}"
  git init -q misp/misp-docker
  git -C misp/misp-docker remote add origin "$MISP_UPSTREAM"
  git -C misp/misp-docker fetch -q --depth 1 origin "$MISP_COMMIT"
  git -C misp/misp-docker checkout -q FETCH_HEAD
  rm -rf misp/misp-docker/.git
fi

# --- 2. bind-mount directories ----------------------------------------------
# Create these ourselves rather than letting Docker do it. Docker creates a
# missing bind source as root:root, and with no passwordless sudo on this host
# that leaves directories we cannot later clean up or relabel.
log "Pre-creating bind-mount directories"
for d in configs logs files ssl gnupg; do
  mkdir -p "$MISP_DIR/$d"
done

# --- 3. credentials ---------------------------------------------------------
if [[ -f "$MISP_ENV" ]]; then
  log "misp/.env already exists (leaving credentials untouched)"
else
  log "Generating credentials into misp/.env"
  umask 077

  # Start from upstream's template rather than a minimal file of our own.
  # docker-compose.yml declares CORE_TAG, MODULES_TAG and GUARD_TAG as
  # *required* build args, and Compose interpolates the entire file even when
  # it only ever pulls images — so omitting them fails outright with
  # "required variable CORE_TAG is missing a value". The template also defines
  # the couple of dozen SES_/SMARTHOST_/PYPI_ keys, which silences a wall of
  # "variable is not set" warnings on every compose invocation.
  cat "$MISP_DIR/template.env" > "$MISP_ENV"

  # Lab overrides are appended: within a single env file, a later assignment
  # wins, so these take precedence over the template's values above.
  cat >> "$MISP_ENV" <<EOF

################################################################################
# LAB OVERRIDES — appended by scripts/misp-bootstrap.sh on $(date -Iseconds)
# Everything above this line is upstream template.env, unmodified.
################################################################################

# --- image pinning ---
# Upstream defaults these to :latest, which makes the deployment
# unreproducible. Pinned to the versions upstream builds at this commit.
CORE_RUNNING_TAG=v2.5.44
MODULES_RUNNING_TAG=v3.0.9

# --- addressing ---
# Must stay portless: the misp-core healthcheck curls this URL from inside the
# container, where only 443 exists. See misp/compose.override.yml.
BASE_URL=https://localhost

# --- admin account ---
ADMIN_EMAIL=admin@soclab.local
ADMIN_ORG=SOCLAB
ADMIN_PASSWORD=$(gen_pw)

# Set explicitly rather than left blank. Blank makes MISP mint a random key at
# first boot that is never written down anywhere, so the only way to recover it
# is 'cake user change_authkey', which invalidates the old one. Phase 5 needs a
# stable key for the Wazuh integration. MISP auth keys are 40 alphanumerics.
ADMIN_KEY=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 40)

# --- database (replaces upstream defaults 'example' / 'password') ---
MYSQL_PASSWORD=$(gen_pw)
MYSQL_ROOT_PASSWORD=$(gen_pw)

# --- cache (replaces upstream default 'redispassword') ---
REDIS_PASSWORD=$(gen_pw)

# --- internal job supervisor (replaces upstream default 'supervisor') ---
SUPERVISOR_PASSWORD=$(gen_pw)

# --- log hygiene ---
# Left unset, misp-core echoes the Redis and supervisor passwords in clear
# text into its container logs on every boot ("Enforcing minimum_config
# setting 'MISP.redis_password' to ... '<password>'"), where any user who can
# run docker logs — or anything that ships those logs — can read them.
DISABLE_PRINTING_PLAINTEXT_CREDENTIALS=true

# --- resource tuning ---
# Upstream defaults the buffer pool to 2048M, sized for a dedicated MISP host.
# This lab runs MISP alongside the Wazuh indexer's 1G JVM heap on a 15G
# machine, and the dataset is a few public feeds, so 512M is ample.
INNODB_BUFFER_POOL_SIZE=512M
EOF
  chmod 600 "$MISP_ENV"
fi

# --- 4. silence Compose's "variable is not set" warnings ---------------------
# template.env leaves a couple of dozen optional keys (SUPERVISOR_*, STUNNEL_*,
# HSTS_MAX_AGE, ...) commented out, but docker-compose.yml interpolates them
# regardless, so every single compose invocation prints a wall of warnings.
# Defining them as empty is safe: every default in docker-compose.yml uses the
# ${VAR:-default} form, where an empty value falls back to the default exactly
# as an unset one does. (The ${VAR-default} form, which distinguishes the two,
# does not appear in the file — checked.)
#
# Derived from Compose's own output rather than a hardcoded list, so it stays
# correct if upstream adds variables. The names are unwrapped with grep/sed
# rather than one pattern because Compose escapes the quotes in its log line,
# so the variable is surrounded by a literal \" pair.
missing="$(misp_compose config 2>&1 >/dev/null \
  | grep -o 'The .* variable is not set' \
  | sed -e 's/^The //' -e 's/ variable is not set$//' -e 's/[\\"]//g' \
  | sort -u)"

if [[ -n "$missing" ]]; then
  log "Defining $(wc -w <<<"$missing") optional variables as empty to quiet Compose"
  {
    printf '\n# --- optional keys, left empty ---\n'
    printf '# Declared here only to stop Compose warning about them. Empty is\n'
    printf '# what interpolation would have used anyway.\n'
    # Skip anything already defined. `missing` is derived from a config run
    # that already saw the lab overrides, so this cannot currently fire — but
    # it means adding a new lab override later can never be silently clobbered
    # by this block, which is appended after it and would otherwise win.
    while read -r var; do
      [[ -n "$var" ]] || continue
      grep -qE "^${var}=" "$MISP_ENV" || printf '%s=\n' "$var"
    done <<<"$missing"
  } >> "$MISP_ENV"
fi

log "Bootstrap complete. Next: scripts/misp-up.sh"
