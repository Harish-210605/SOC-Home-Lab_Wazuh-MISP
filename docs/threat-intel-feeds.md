# Populating MISP with Threat Intelligence

Phase 4 of the lab: turning the empty MISP instance from Phase 3 into a usable
intelligence source, so that Phase 5 has something to enrich Wazuh alerts *against*.

A MISP with no indicators in it is just a database. This phase loads ~26,000 real
indicators of compromise from four free [abuse.ch](https://abuse.ch) feeds and proves
they are searchable through the exact API call the Wazuh integration will make.

## Which feeds, and why these

MISP ships a catalogue of 102 default feeds (`app/files/feed-metadata/defaults.json`).
Loading all of them is the obvious move and the wrong one: most are unvetted, several
are dead, and the largest would take longer to import than the rest of this lab took to
build. Four were picked deliberately instead, and they are version-controlled as data in
[`misp/feeds.json`](../misp/feeds.json) rather than clicked into the UI.

| Feed | Format | Contributes | Indicators |
|---|---|---|---|
| ThreatFox — Recent IOCs | CSV | domains, C2 `ip:port`, URLs, MD5/SHA1/SHA256 | ~8,100 |
| URLhaus — Recent Malware URLs | CSV | malware distribution URLs + hostnames | ~16,800 |
| MalwareBazaar — Recent Sample Hashes | CSV | MD5 hashes of submitted samples | ~1,400 |
| Feodo Tracker — Botnet C2 IPs | CSV | Emotet / QakBot / Dridex C2 IPs | 5 |

The selection criterion was **IOC coverage**, not volume. Phase 5 can only enrich an
observable if MISP holds indicators of that type, and Phase 6's detection rules span
network connections, process execution and file integrity. So the set had to cover all
four classes an analyst actually pivots on — IP, domain, URL, file hash — which is why
ThreatFox (the only feed here carrying all four) does most of the work and
MalwareBazaar is included at all despite overlapping with it.

### Feeds deliberately left out

- **CIRCL OSINT Feed** and **Botvrij.eu** — the two feeds MISP registers out of the box.
  Both are MISP-format, meaning they import as *thousands of separate events* rather
  than one event of many attributes. That is the right shape for a production instance
  and the wrong shape for a laptop.
- **Tor exit nodes** — upstream's own description warns the source "applies a lock-out
  after each pull". A feed that punishes re-fetching is a poor fit for a lab whose
  entire premise is being reproducible.

### A note on Feodo Tracker

Feodo Tracker is **effectively dormant**: it returns 5 entries and its own header says
it was last refreshed `2026-03-04`, roughly five months before this phase was built. It
is kept anyway, and honestly labelled, for two reasons. It is genuinely abuse.ch data,
and being frozen makes it *useful* — those five IPs are stable fixtures that can be
hard-coded into a Phase 6 attack simulation without the test breaking next week when a
live feed rotates. Every other feed here is a moving target.

This is worth stating rather than hiding: noticing that a feed has gone stale, and
deciding what to do about it, is ordinary threat-intel work.

## How it runs

```bash
scripts/misp-feeds.sh              # register, enable and pull all four feeds
scripts/misp-feeds.sh --no-fetch   # register only, no network pull
scripts/misp-feeds-check.sh        # verify the result
```

The script is **idempotent** and re-running it is how the intel gets refreshed. Feeds
are matched on **URL**, not name or ID — names are cosmetic and IDs are assigned by
MISP, but a feed fundamentally *is* the thing at its URL. A second run therefore
updates the four existing feeds instead of creating four duplicates, and re-fetching
merges into the same event. This was verified by running it twice: the attribute count
came back identical at 26,290 across the same 4 events.

Work is split by what it is rather than by language: [`misp/feeds.json`](../misp/feeds.json)
is reviewable data, [`scripts/misp_feeds.py`](../scripts/misp_feeds.py) does the API
work, and [`scripts/misp-feeds.sh`](../scripts/misp-feeds.sh) is a thin wrapper matching
the other helpers. The API layer is Python rather than curl-and-`sed` on purpose —
every step is a JSON round-trip, and the failure directly below is exactly what
string-munging JSON produces.

## The double-encoding trap

This one cost real time and fails **silently**, so it is worth documenting properly.

MISP's feed `settings` field holds the CSV column mapping — for ThreatFox,
`{"csv":{"value":"3"}}`, meaning "the indicator is in column 3". The upstream
`defaults.json` stores it as a *pre-serialised JSON string*, so the natural move is to
POST it the same way:

```jsonc
// WRONG — MISP serialises the field itself, so this is encoded twice
"settings": "{\"csv\":{\"value\":\"3\"}}"
```

MISP accepts it, returns HTTP 200, and stores this:

```
"\"{\\\"csv\\\":{\\\"value\\\":\\\"3\\\"}}\""
```

The column mapping is now unreachable. There is no error — the feed just imports the
wrong column, or nothing at all. Sending `settings` as a **nested object** is correct:

```jsonc
// RIGHT
"settings": { "csv": { "value": "3", "delimiter": "," } }
```

Because this fails quietly, both scripts guard it rather than trusting the write:
`misp_feeds.py` reads every feed back after syncing and aborts if `settings` is not
parseable as an object, and `misp-feeds-check.sh` asserts the same thing independently.

## Composite attribute types

ThreatFox publishes C2 servers as `ip:port`, which MISP imports as the **composite**
type `ip-dst|port` with the value stored as `143.246.216.114|38990`.

This looked like a problem for Phase 5. A Wazuh alert contains a bare destination IP,
not an `ip|port` pair, so an exact-value lookup should miss all ~3,300 of them — which
would be most of the IP intel in the lab.

It does not, and that was verified rather than assumed:

```console
$ # searching the bare IP still resolves the composite attribute
  hits=1   ip-dst|port   143.246.216.114|38990
```

MISP matches a composite attribute on **either half** of its value. So bare-IP
enrichment works, and the port stays available as extra context on the hit. The check
script pins this behaviour down so a future MISP upgrade that changed it would fail
loudly instead of quietly halving the lab's IP coverage.

## What actually landed

```
event 1        5 attributes   Feodo Tracker
event 2     8084 attributes   ThreatFox
event 3     1360 attributes   MalwareBazaar
event 4    16841 attributes   URLhaus
            26290 attributes across 4 events
```

By attribute type:

| Type | Count | Enriches (Phase 5) |
|---|---:|---|
| `url` | 17,292 | web/proxy log URLs |
| `ip-dst\|port` | 3,302 | outbound connection destinations |
| `domain` | 3,061 | DNS lookups, HTTP Host headers |
| `md5` | 1,440 | file-integrity (FIM) event hashes |
| `hostname` | 1,031 | DNS lookups |
| `sha256` | 81 | FIM event hashes |
| `sha1` | 78 | FIM event hashes |
| `ip-dst` | 5 | outbound connection destinations |

`hostname` and the extra `url` entries beyond URLhaus's row count are MISP's doing, not
the feed's: its CSV import runs each value through type detection and extracts the
embedded host from a URL as a second attribute. That is free extra coverage — a
detection that only sees a DNS query, never the full URL, can still get a hit.

## Verify

`scripts/misp-feeds-check.sh` runs 25 checks in four groups:

1. **Registration** — all four feeds present, enabled, caching on, and `settings`
   stored as an object (the double-encoding guard).
2. **Ingestion** — total attributes above a floor, *and* every individual feed produced
   a non-empty event. The per-feed check matters: a broken column mapping on one feed
   would otherwise hide behind a healthy total.
3. **Coverage and lookup** — all four IOC classes present, and a real sampled indicator
   of each class resolves through `/attributes/restSearch`, the same call Wazuh will
   make.
4. **Negative controls** — `8.8.8.8`, `example.com` and the MD5 of the empty file must
   return **zero** hits. Without these the suite would pass just as happily if the
   lookup matched everything, which in a live SOC means every alert looks like a threat
   intel hit and analysts stop believing the enrichment.

```console
$ scripts/misp-feeds-check.sh
25 passed, 0 failed
```

## Browsing it in the UI

The intel is at <https://127.0.0.1> under **Event Actions → List Events** (four events,
one per feed) or **Sync Actions → List Feeds** for the feed configuration. Searching a
single indicator is **Event Actions → Search Attributes**.

Caching is enabled on all four feeds, which populates MISP's Redis-backed feed lookup
and makes the "feed hits" panel appear on an attribute — a quick visual demonstration
of the same correlation Phase 5 automates.

## Not done here

- **No scheduled refresh.** `misp-docker` supports cron-driven feed pulls via
  `FETCH_FEED_INTERVAL` / `CRON_PULLALL`, left unset on purpose: in a lab a background
  job that silently changes the dataset makes results irreproducible. Refresh is an
  explicit `scripts/misp-feeds.sh`.
- **No feed-specific tagging or taxonomies.** Attributes carry the feed's own metadata
  and nothing more. Phase 5 will show whether tagging is needed to make an enriched
  alert readable.
- **Correlation is off for URLhaus.** MISP's correlation engine compares attributes
  pairwise, so 17k URLs is where a laptop starts to hurt. `restSearch` — what actually
  drives enrichment — is unaffected.

## Next

Phase 5: connect the two stacks. The Wazuh manager cannot currently reach MISP at all —
they run as separate Compose projects on separate networks — so a shared Docker network
comes first, then Wazuh's MISP integration, then proving an alert gets enriched.
