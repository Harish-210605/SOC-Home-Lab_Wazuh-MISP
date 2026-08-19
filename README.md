# SOC Home Lab — Wazuh + MISP

A local, Docker-only security operations lab that pairs **Wazuh** (SIEM/XDR) with
**MISP** (threat intelligence platform), so that alerts raised by Wazuh are
automatically enriched with real-world threat intel.

Built as a portfolio project to demonstrate SIEM deployment, detection engineering
mapped to MITRE ATT&CK, threat intel integration, and an end-to-end incident response
workflow — all reproducible on a single machine with nothing but Docker.

> **Status:** work in progress. This README is a placeholder; the full write-up
> (architecture diagram, detection rule table, example alerts, incident report) lands
> once the lab is complete.

## Build log

| Phase | Scope | Status |
|------:|-------|--------|
| 0 | Environment check, repo scaffolding | Done |
| 1 | Deploy Wazuh single-node (manager, indexer, dashboard) | Done |
| 2 | Feed real data into Wazuh via an agent | Done |
| 3 | Deploy MISP | Done |
| 4 | Populate MISP from a public threat feed | Not started |
| 5 | Integrate Wazuh with MISP for alert enrichment | Not started |
| 6 | Custom detection rules mapped to MITRE ATT&CK | Not started |
| 7 | Simulated end-to-end incident report | Not started |
| 8 | Final documentation pass | Not started |

## Documentation

- [`docs/setup-wazuh.md`](docs/setup-wazuh.md) — deploying and hardening the Wazuh stack
- [`docs/setup-agent.md`](docs/setup-agent.md) — the monitored endpoint, and proving events flow
- [`docs/setup-misp.md`](docs/setup-misp.md) — deploying and hardening MISP

## Ground rules

This lab is deliberately constrained:

- **Docker only** — no cloud provider, no hypervisor, no full VMs.
- **Localhost only** — no published port is reachable beyond `127.0.0.1`.
- **No secrets in git** — all credentials live in a gitignored `.env`; `.env.example`
  documents the required keys.
