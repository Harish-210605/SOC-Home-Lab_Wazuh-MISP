# SOC Lab — Explanation Notes

Running notes written *as the lab was built*, in plain language, so the project can be
explained end to end (interview, viva, README walkthrough) without re-reading the code.

Each section answers three questions: **what was done**, **why it was done that way**,
and **what to say if asked**.

---

## 0. The one-paragraph version

A self-contained Security Operations Centre lab running entirely in Docker on a single
Fedora laptop. **Wazuh** is the SIEM/XDR — it collects logs and file-integrity events
from a monitored endpoint, runs detection rules against them, and raises alerts.
**MISP** is the threat-intelligence platform — it stores indicators of compromise (IOCs)
pulled from public feeds. The two are wired together so that when Wazuh sees an event
containing an IP, domain or file hash, it asks MISP "do you know this indicator?" and
attaches the answer to the alert. That turns a generic alert into an enriched one an
analyst can triage. On top of that sit custom detection rules mapped to MITRE ATT&CK
and a written incident report that walks a single simulated attack from detection to
remediation.

---

## Session log

### 2026-08-20 — resuming the lab

**Situation on resume.** Zero containers running, but all 10 images and all 18 named
volumes present. That combination is the fingerprint of a `docker compose down`, which
deletes containers but leaves named volumes alone. Nothing had been lost — the Wazuh
indexer's data, the MISP MariaDB database and all generated credentials live in those
volumes, not in the containers.

*Worth saying out loud:* this is exactly why the stack keeps state in **named volumes**
rather than inside the container filesystem. Containers are disposable; the volumes are
the lab. Recreating containers on top of surviving volumes restores the whole lab with
its credentials, users, agent registration and indexed events intact.

**One environment change.** The `docker` group finally applies to the login session
(`id` now lists `963(docker)`), so the `sg docker` wrapper the helper scripts carry is
no longer strictly needed. The wrapper is harmless — it only engages when a direct
`docker info` fails — so it stays in place for portability.

---

## Phase 4 — Loading threat intelligence into MISP

**The point of the phase, in one line.** Phase 3 gave us a MISP instance that worked but
was *empty*. Enrichment needs something to enrich against, so this phase fills it with
real indicators and — importantly — proves they can be looked up the way Wazuh will look
them up.

### What "threat intelligence" concretely means here

An **IOC** (indicator of compromise) is just an observable that is known to be bad: an
IP address, a domain, a URL, or a file hash. A threat-intel platform is a database of
those, with provenance. There is no magic in it. The value comes from the join:
Wazuh sees `endpoint01 connected to 143.246.216.114` and, on its own, has no opinion
about that. MISP knows that address is a QakBot command-and-control server. Putting the
two together is the entire point of the lab.

### Choosing feeds — the decision worth explaining

MISP ships a catalogue of **102** default feeds. Enabling all of them is the obvious
move and the wrong one, and *why* it's wrong is the interesting part:

- Most are unvetted, and several are dead.
- The two MISP registers out of the box (CIRCL OSINT, Botvrij.eu) are **MISP-format**,
  which imports as *thousands of separate events* rather than one event with many
  attributes. Correct for a production instance, far too heavy for a laptop.
- One (Tor exit nodes) states in its own description that it locks you out after each
  pull — hostile to a lab built around being re-runnable.

So four abuse.ch feeds were picked deliberately. The selection criterion was **IOC type
coverage, not volume**. Phase 5 can only enrich an observable if MISP holds indicators
of that type, and Phase 6's rules span network, process and file activity. So the set had
to cover all four classes an analyst pivots on: **IP, domain, URL, file hash.**

| Feed | Gives us | Count |
|---|---|---|
| ThreatFox | domains, C2 `ip:port`, URLs, hashes — all four classes | ~8,100 |
| URLhaus | malware distribution URLs + extracted hostnames | ~16,800 |
| MalwareBazaar | MD5 hashes of malware samples | ~1,400 |
| Feodo Tracker | Emotet/QakBot/Dridex C2 IPs | 5 |

*If asked "why include MalwareBazaar when ThreatFox already has hashes?"* — ThreatFox
carries only ~240 hashes; file-integrity enrichment in Phase 6 needs a deeper hash pool
than that.

### The stale-feed judgement call

Feodo Tracker returned **5 entries**, and its own header said it was last refreshed
`2026-03-04` — about five months stale. That's a real finding, and the interesting part
is what to do with it.

It was kept, and *labelled as dormant in the docs*, for a specific reason: being frozen
makes it **useful**. Those five IPs are stable fixtures that can be hard-coded into a
Phase 6 attack simulation without the test silently breaking next week when a live feed
rotates its contents. Every other feed here is a moving target.

*Worth saying out loud:* noticing a feed has gone stale and making a deliberate call
about it is ordinary threat-intel work. Hiding it would have been the mistake.

### Design choice: feeds as data, not clicks

The feed list lives in a version-controlled file, `misp/feeds.json`, not in the MISP UI.
Three reasons, and this generalises well beyond this project:

1. **Reviewable.** A reviewer can see exactly which sources the lab trusts, in a diff.
2. **Reproducible.** Rebuilding MISP from scratch is one command, not a UI walkthrough.
3. **Explainable.** Each entry carries a `_note` saying why that feed is there.

The work is split by what it *is*: `misp/feeds.json` is data, `scripts/misp_feeds.py`
does the API calls, `scripts/misp-feeds.sh` is a thin wrapper matching the repo's other
helpers. The API layer is Python rather than curl-plus-`sed` deliberately — every step
is a JSON round-trip, and the bug below is precisely what string-munging JSON produces.

### Idempotency, and how it was proven

Re-running the script is how intel gets refreshed, so it must not duplicate anything.
Feeds are matched on **URL** — not name, not ID. Names are cosmetic and IDs are assigned
by MISP, but a feed fundamentally *is* the thing at its URL. That also means the script
can adopt a feed someone already added by hand.

This was **verified, not asserted**: the script was run twice, and the second run
reported the same 26,290 attributes across the same 4 events, updating the four feeds
rather than creating four more.

### Bug of the phase: the double-encoding trap

The most instructive thing that went wrong, and it fails **silently**.

MISP's feed `settings` field holds the CSV column mapping — for ThreatFox,
`{"csv":{"value":"3"}}` meaning "the indicator is in column 3". Upstream's
`defaults.json` stores it as a pre-serialised JSON *string*, so the natural move is to
send it that way. MISP accepts it, returns **HTTP 200**, and stores:

```
"\"{\\\"csv\\\":{\\\"value\\\":\\\"3\\\"}}\""
```

It encoded the string again. The column mapping is now unreachable, there is no error,
and the feed simply imports the wrong column — or nothing. The fix is to send `settings`
as a **nested object** and let MISP serialise it once.

*The lesson worth stating:* an API returning 200 does not mean it stored what you meant.
Because this failure is invisible, both scripts now **read the value back** after
writing it and fail loudly if it isn't a parseable object. Verifying writes matters most
exactly where the failure is silent.

### Surprise of the phase: composite attribute types

ThreatFox publishes C2 servers as `ip:port`, which MISP imports as the **composite** type
`ip-dst|port`, storing the value as `143.246.216.114|38990`.

This looked fatal for Phase 5. A Wazuh alert contains a *bare* destination IP, so an
exact-value lookup should miss all ~3,300 of them — most of the lab's IP intel.

Tested rather than assumed: searching the bare IP `143.246.216.114` **does** return the
composite attribute. MISP matches a composite on **either half** of its value. So
enrichment works, and the port comes along as free extra context. The check script now
pins this down, so a future MISP upgrade that changed the behaviour would fail loudly
instead of quietly halving the lab's IP coverage.

### Result

26,290 indicators across 4 events:

| Type | Count | What it will enrich |
|---|---:|---|
| `url` | 17,292 | web/proxy log URLs |
| `ip-dst\|port` | 3,302 | outbound connection destinations |
| `domain` | 3,061 | DNS lookups, HTTP Host headers |
| `md5` | 1,440 | file-integrity event hashes |
| `hostname` | 1,031 | DNS lookups |
| `sha256` / `sha1` | 159 | file-integrity event hashes |
| `ip-dst` | 5 | outbound connection destinations |

`hostname` is MISP's doing, not the feed's — its import runs each value through type
detection and pulls the host out of a URL as a second attribute. Free extra coverage: a
detection that only ever sees a DNS query, never the full URL, can still get a hit.

### Verification, and why the negative controls matter

`scripts/misp-feeds-check.sh` runs 25 checks: registration, per-feed ingestion, IOC
coverage, live lookups, and **negative controls**.

The negative controls are the part worth pointing at in an interview. `8.8.8.8`,
`example.com` and the MD5 of the empty file must return **zero** hits. Without them the
whole suite would pass just as happily if the lookup matched *everything* — and a
lookup that matches everything means every Wazuh alert looks like a threat-intel hit,
analysts stop trusting the enrichment, and the feature is worse than not having it.

*Generalisable point:* a test that only checks the positive case cannot tell "it works"
apart from "it always says yes".

### Deliberately not done

- **No scheduled auto-refresh.** `misp-docker` supports cron feed pulls
  (`FETCH_FEED_INTERVAL`, `CRON_PULLALL`); left off on purpose, because a background job
  that silently changes the dataset makes lab results irreproducible. Refresh is an
  explicit command.
- **Correlation disabled on URLhaus.** MISP's correlation engine compares attributes
  pairwise, so ~17k URLs is where a laptop starts to hurt. `restSearch` — what actually
  drives enrichment — is unaffected.

### Handover to Phase 5

The blocker is already known: **the two stacks cannot reach each other.** They run as
separate Compose projects on separate Docker networks, so `wazuh.manager` has no route
to the MISP API. A shared network comes first, then the integration, then proving an
alert actually gets enriched.
