# Deploying MISP

Phase 3 of the lab: a MISP threat intelligence platform running in Docker alongside
the Wazuh stack, bound to loopback, with every shipped default credential replaced.

Upstream [`MISP/misp-docker`](https://github.com/MISP/misp-docker) is used unmodified.
The only structural change is in
[`misp/compose.override.yml`](../misp/compose.override.yml); everything else is
environment configuration in the gitignored `misp/.env`.

## Version pinning

`misp-docker` publishes **no release tags**, so there is nothing to check out by
version. Two separate things therefore need pinning, and both are easy to miss:

- **The repository**, pinned to commit `223b675c` (2026-07-13). A shallow clone cannot
  check out an arbitrary SHA, so `misp-bootstrap.sh` does `git init` + `fetch --depth 1
  <sha>` rather than `git clone`.
- **The images**, via `CORE_RUNNING_TAG` and `MODULES_RUNNING_TAG`. These default to
  **`latest`**, which would make the deployment silently unreproducible. Pinned to
  `v2.5.44` and `v3.0.9`, the versions upstream builds at that commit.

`misp-check.sh` asserts the running version matches the pinned tag, so a drift back to
`latest` fails the check rather than passing unnoticed.

## Services

| Service | Image | Published |
|---|---|---|
| `misp-core` | `misp-core:v2.5.44` | `127.0.0.1:80`, `127.0.0.1:443` |
| `misp-modules` | `misp-modules:v3.0.9` | — |
| `db` | `mariadb:10.11` | — |
| `redis` | `valkey/valkey:7.2` | — |
| `mail` | `egos-tech/smtp:1.1.3` | — |

`misp-guard` is defined upstream behind a Compose profile and stays off — it is a
sync-filtering proxy between MISP instances, which this single-instance lab has no
use for.

`misp-modules` is **not** optional despite contributing nothing to Phases 4–5:
`misp-core` declares `depends_on: misp-modules: condition: service_healthy`, so core
will not start without it.

## Why MISP keeps ports 80/443

The Wazuh dashboard was moved to 8443 in Phase 1, leaving 443 free, and MISP is left on
the standard ports deliberately rather than by default.

`misp-core`'s healthcheck runs `curl ${BASE_URL}/users/heartbeat` **from inside the
container**, where only ports 80 and 443 exist. Remapping the host port to, say, 8444
would force `BASE_URL=https://localhost:8444`, the healthcheck would fail forever, and
every service gated on `condition: service_healthy` would hang with it. Keeping the
container-side ports standard keeps `BASE_URL` portless and the healthcheck honest.

Both are still bound to `127.0.0.1` by the override, so nothing is reachable off-host.

## Deploy

```bash
scripts/misp-bootstrap.sh   # pinned clone, bind-mount dirs, generate misp/.env
scripts/misp-up.sh          # start, wait for misp-core to report healthy
scripts/misp-check.sh       # verify
```

Both scripts are idempotent. First boot takes a few minutes while MISP imports its
database schema and warms caches.

| Script | Purpose |
|---|---|
| `misp-bootstrap.sh` | Pinned clone, pre-create bind mounts, generate credentials |
| `misp-up.sh` | Start and wait for health |
| `misp-down.sh` | Stop (`--purge` also deletes the database volume) |
| `misp-logs.sh` | Tail logs, optionally for one service |
| `misp-check.sh` | 15 assertions covering health, API, credentials and exposure |

Log in at <https://127.0.0.1> as `admin@soclab.local` with `ADMIN_PASSWORD` from
`misp/.env`. Self-signed certificate, so expect a browser warning.

## How `misp/.env` is built

Upstream's `template.env` is copied verbatim, then a clearly marked **LAB OVERRIDES**
block is appended. Within one env file the last assignment wins, so the overrides take
precedence over the template above them.

Starting from the template rather than writing a minimal file is not optional:
`docker-compose.yml` declares `CORE_TAG`, `MODULES_TAG` and `GUARD_TAG` as **required**
build arguments, and Compose interpolates the entire file even when it only pulls
images. Omitting them fails outright with
`required variable CORE_TAG is missing a value`.

A third block then defines ~135 optional keys (`OIDC_*`, `LDAP_*`, `S3_*`, `PYPI_*`, …)
as empty. `template.env` leaves these commented out but `docker-compose.yml`
interpolates them anyway, so every compose invocation otherwise prints a wall of
`variable is not set` warnings. Defining them empty is safe because every default in
the compose file uses the `${VAR:-default}` form, where empty and unset behave
identically — the `${VAR-default}` form, which would distinguish them, does not appear
in the file. The list is derived from Compose's own output, not hardcoded, so it stays
correct if upstream adds variables.

## Hardening applied

| Upstream default | Changed to |
|---|---|
| `ADMIN_PASSWORD=admin` | 28-character generated |
| `MYSQL_PASSWORD=example` | 28-character generated |
| `MYSQL_ROOT_PASSWORD=password` | 28-character generated |
| `REDIS_PASSWORD=redispassword` | 28-character generated |
| `SUPERVISOR_PASSWORD` unset → `supervisor` | 28-character generated |
| `ADMIN_KEY` blank → random, unrecorded | Explicitly set and stored |
| Ports on `0.0.0.0` | `127.0.0.1` only |
| Credentials printed to logs | `DISABLE_PRINTING_PLAINTEXT_CREDENTIALS=true` |

That last one is worth calling out. Left unset, `misp-core` writes lines like
`Enforcing minimum_config setting 'MISP.redis_password' to ... '<the password>'` into
its container log on every boot, readable by anyone who can run `docker logs` and by
anything that ships those logs elsewhere. With the flag set it prints `<hidden>`.
`misp-check.sh` greps the live logs for the actual Redis password and fails if it
finds it.

`INNODB_BUFFER_POOL_SIZE` is also reduced from upstream's 2048M to 512M — that default
assumes a dedicated MISP host, whereas here MariaDB shares a 15 GB machine with the
Wazuh indexer's 1 GB JVM heap. With that trim the whole lab (nine containers) idles at
about 2.5 GB.

## Verify

`scripts/misp-check.sh` should report **15 passed, 0 failed**: five services running,
core healthy, login page serving, the API authenticating and reporting a version that
matches the pinned tag, unauthenticated API calls rejected, upstream default logins
rejected, no plaintext credentials in the logs, loopback-only binding, and no env file
tracked by git.

```bash
# API smoke test by hand
source misp/.env
curl -sk -H "Authorization: $ADMIN_KEY" -H 'Accept: application/json' \
  https://127.0.0.1/servers/getVersion
```

## Troubleshooting

**`required variable CORE_TAG is missing a value`.** `misp/.env` was not built from
`template.env`. Delete it and re-run `scripts/misp-bootstrap.sh`.

**A wall of `variable is not set` warnings.** The optional-keys block is missing.
Re-run `scripts/misp-bootstrap.sh`; it appends whatever is still undefined and is
idempotent.

**`misp-core` never becomes healthy.** It is gated on `db` and `redis` being healthy
first — check those with `scripts/misp-logs.sh db`. If `BASE_URL` has been given a
port, the in-container healthcheck cannot reach it and will never pass; it must stay
portless.

**Changing `MYSQL_PASSWORD` after first boot breaks the stack.** The MariaDB volume
already holds a user created with the old password; the variable does not retro-fit it.
Either change it inside the database, or start over with
`scripts/misp-down.sh --purge`. For the same reason `misp-bootstrap.sh` never
regenerates an existing `misp/.env`.

**Lost the admin API key.** `docker exec misp-misp-core-1 su -s /bin/bash -c
"/var/www/MISP/app/Console/cake user change_authkey admin@soclab.local" www-data`
issues a new one — and invalidates the old one. Record it back into `misp/.env`.

## Not done here

MISP is empty. No feeds are configured and no events exist yet — Phase 4 populates it
from public sources.

The Wazuh and MISP stacks are also still separate Compose projects on separate
networks, so nothing connects them yet. Phase 5 adds a shared network so the Wazuh
manager can reach the MISP API for alert enrichment.

## Next

Phase 4: populate MISP from a free public threat feed.
