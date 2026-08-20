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
---

## Phase 5 — Connecting Wazuh to MISP

**The point of the phase, in one line.** Phases 1–4 built a SIEM that detects and a
threat-intel platform that knows things. This phase makes the SIEM *ask* the intel
platform, so an alert stops saying "endpoint01 had failed SSH logins from 162.243.103.246"
and starts saying "…from a known Emotet command-and-control server".

### The finding that changed the plan

The plan said "use Wazuh's MISP integration module". **There isn't one.** The manager
image ships integrations for VirusTotal, Maltiverse, Slack, PagerDuty and Shuffle, and
a search for "misp" across the integrations, config and ruleset directories returns
nothing at all.

So this phase *wrote* an integration rather than enabling one. What Wazuh does give you
is the framework — the `wazuh-integratord` daemon, a documented calling convention, and
a queue socket to write results back into. The shipped `virustotal.py` was used as the
reference for the socket protocol, which is the kind of thing you want to copy from a
working example rather than infer.

*Worth saying out loud:* checking whether the thing you planned to use actually exists,
before designing around it, is cheap. Assuming it exists because the docs mention MISP
somewhere is how you lose an afternoon.

### The architecture, and the one detail that matters

```
endpoint01 → manager(analysisd) → integratord → custom-misp.py
                    ↑                                  ↓
                    └──── hit re-injected ──── MISP restSearch
                    ↓
             local_rules.xml → indexer → dashboard
```

The load-bearing decision is that a MISP hit is **written back into analysisd as a new
event**, not emailed or posted somewhere. Because it re-enters the pipeline, the
enriched result is decoded, matched by rules, indexed, correlated, and could trigger
active response — all for free. An integration that merely notified would have to
reimplement every one of those.

*If asked "why not just have the integration send a Slack message?"* — because then the
enrichment lives outside the SIEM. It can't be searched, correlated with other alerts,
or used in a rule. Re-injection is what makes it part of the system rather than a
side-channel.

### The network problem, and three decisions inside it

The two stacks were separate Compose projects, each on its own bridge, with no route
between them. The fix is one shared bridge, `soclab-intel`. Three choices worth
defending:

1. **Kept the stacks as separate projects.** Merging them would make the network
   trivial, at the cost of tying their lifecycles together. MISP is the heavy half and
   should be stoppable on its own.
2. **Made the bridge `--internal`** — no gateway off the host. It exists only to carry
   manager→MISP traffic, so it should not be capable of becoming an egress path. Both
   containers keep their normal default networks for outside access.
3. **Listed `default` explicitly** on both services. This is the subtle one: upstream
   declares no `networks:` key, so the moment an override adds one, the implicit default
   is *replaced*, not extended. Forget it and the manager loses the indexer, or MISP
   loses its own database — and the symptom looks like an unrelated outage. Both check
   scripts now assert the default survived.

### Keeping a secret out of a tracked config file

Enabling the integration means putting an API key in the manager's `ossec.conf` — a file
that now needs to be version-controlled (the vendored upstream tree is gitignored and
disposable, so editing it there would vanish at the next bootstrap).

The pattern used: the **tracked** file holds `MISP_API_KEY_PLACEHOLDER`, and
`wazuh-up.sh` renders a real copy into `wazuh/config/generated/` (already gitignored) at
mode 600, which is what actually gets mounted.

The check script asserts all three parts — template still has the placeholder, rendered
copy is gitignored and mode 600, and the placeholder did *not* survive into the running
config. That last one matters: if it had, every lookup would return 403 and the lab
would look perfectly healthy while enriching nothing.

### Design choice: an explicit field table, not a recursive scrape

The integration pulls observables from a named list of alert fields (`data.srcip`,
`syscheck.sha256_after`, `data.dns.question.name`, …) rather than walking the alert JSON
for anything IP-shaped.

The recursive version is less code and much worse: it also collects the agent's own IP,
the manager's hostname, and every hash of every file an alert happens to mention — each
one a MISP round-trip that can only ever return a miss.

Private, loopback, link-local and multicast IPs are filtered before any lookup. In this
lab they would simply miss; in any deployment where MISP is remote, sending them means
broadcasting your internal addressing to a third party. The check script tests that such
an address is **never sent**, not merely that it doesn't match.

### Rule design: the `to_ids` split

Four rules in the 100100–100199 range (Wazuh reserves everything under 100000, so user
rules there can never collide with an upgrade).

| Rule | Level | Fires when |
|---|---|---|
| 100100 | 0 | any lookup result — parent only, never alerts |
| 100101 | 12 | hit where MISP marks the indicator `to_ids=True` |
| 100102 | 6 | hit on context-only intel (`to_ids=False`) |
| 100103 | 14 | 4+ hits from the same agent in 5 minutes |

**The `to_ids` split is the interesting bit.** MISP flags an attribute `to_ids` when it
is reliable enough to alert on, versus context worth recording. Alerting identically on
both would turn enrichment into a second noise stream — and an analyst who can't tell
the two apart stops reading either. Level 12 vs level 6 encodes that distinction where
it's actionable.

### Three bugs, each instructive

**1. `$(agent.name)` renders empty in a rule description.** Wazuh expands `$(field)` in
descriptions only for *decoded* fields, so alerts read `known-bad ip seen on  —` despite
being correctly attributed. Fix: have the integration carry the agent name in its own
payload as `misp.agent_name`.

The related trap: rule 100103 originally correlated on `<same_source_ip />`, which would
**never have fired** — these events are injected by the integration and carry no `srcip`
at all. It would have sat there looking correct forever. Now it correlates on
`<same_field>misp.agent_name</same_field>`.

**2. Bind-mounted scripts and the `wazuh` user.** `integratord` runs as uid 999
(`wazuh`), but bind-mounted files keep their *host* ownership (uid 1000). So the owner
and group bits apply to nobody relevant inside the container — only the **world** bits
decide whether the file is readable. A mode-750 script failed with a bare
`Permission denied`.

What makes this nasty: testing by hand works fine, because `docker exec` runs as root.
The lesson is that "it works when I run it manually" and "it works when the daemon runs
it" are different claims when the daemon drops privileges.

**3. A check that never forgets.** My own verification script failed on a stale
`ossec.log` line from a bug I'd already fixed — the log lives in a named volume and
outlives container recreates. Now scoped to the current integratord run. *A check that
reports faults fixed hours ago is a check people learn to ignore.*

### The defect this phase exposed

Recreating the agent container broke it permanently: `Duplicate agent name: endpoint01`,
retried forever, while the manager just showed it as disconnected.

Cause: the agent doesn't persist `/var/ossec/etc`, so a recreate loses its `client.keys`
and it must re-enroll — and `authd` refuses because the old registration still owns the
name. This was latent since Phase 2; Phase 5's container recreate is simply what
triggered it.

Fixed with `<force>` in `<auth>`, letting an agent replace its own stale record.
Verified by recreating the container and confirming zero duplicate-name errors and no
accumulating registrations.

*The part worth saying in an interview:* the timers are set to `0` here because in a lab
a re-registration is always a deliberate recreate. **On a real network they should not
be** — those timers are exactly what stops an attacker re-registering as an existing
endpoint in order to blind it. Knowing why a lab setting is unsafe in production is more
useful than the setting itself.

### The debugging story worth telling

The demo wrote ten valid log lines. The file contained them. Logcollector had logged
`Analyzing file` for that exact path. No alert appeared.

Cause: **`wazuh-logcollector` opens each monitored file once at startup, and never
retries a path that was missing at that moment.** It logs `Could not open file` and then
sits there. The file can appear a second later and be written to forever — it will not
be read until logcollector restarts.

Fixed with a named volume so the directory persists, plus a guard in the demo that
checks logcollector actually holds the file open (via `/proc/<pid>/fd`) rather than
trusting the config.

*Generalisable point:* "the config says it's monitoring the file" and "it is reading the
file" are different claims. The demo now verifies the second one.

### Safety note worth stating explicitly

The attack simulation **never contacts the malicious IP**. It writes syslog lines that
Wazuh's stock `sshd` decoder parses — the same decoder, the same rules, the same alert
path the real thing would take. Actually connecting to a live command-and-control server
to test a detection would be indefensible, and the fact that the detection path is
identical either way means there's nothing to gain from it.

The benign control uses `203.0.113.45` — RFC 5737 TEST-NET-3, which is routable-looking,
reserved for documentation, and guaranteed never to appear in a real threat feed.

### Result

```
26 passed, 0 failed     (integration)
+ 17 wazuh, 15 misp, 25 feeds  =  83 checks green
```

12 enriched alerts indexed and visible in the dashboard, including the level 14
correlation rule firing on repeated hits from the same host.

### Handover to Phase 6

Groundwork is already in place: rule 5710 arrives carrying MITRE **T1110.001** (Password
Guessing), and the simulated auth log gives a safe, repeatable way to drive brute-force
scenarios without needing a real sshd.
---

## Phase 6 — Writing custom detections

**The point of the phase, in one line.** Phases 1–5 built a SIEM that collects, detects
with stock rules, and enriches with threat intel. This phase adds *our own* detection
logic — five rules that catch things the stock ruleset cannot, each mapped to MITRE
ATT&CK so coverage is measurable rather than asserted.

### The decision that shaped the whole phase

The obvious move is to write a brute-force rule and a file-integrity rule. **Both would
have been worthless**, because Wazuh already ships them (5712/5763 for brute force,
550/553/554 for FIM). Re-implementing a stock rule adds rule count and zero detection
value.

So I set a constraint: every rule must add something stock does not have. Working
through it, the missing thing was consistently **context**:

- stock detects a brute force, but not one that then **succeeded**
- stock reports a file changed, but scores `/etc/shadow` the same as a scratch file
- stock has no concept of the far end of a connection being **known-malicious**

Every rule therefore *builds on* the stock ones via `<if_sid>` / `<if_matched_sid>`
rather than replacing them. A nice property falls out: a Wazuh upgrade that improves
rule 5712 improves our D1 for free.

*If asked "why only five rules?"* — because five that each add something beat fifteen
that mostly restate the ruleset. Rule count is not coverage.

### The five, and why each earns its place

| Rule | Level | Detects | ATT&CK |
|---|---|---|---|
| D1 / 100200 | 14 | successful SSH login from a source that was just brute-forcing | T1110.001, T1078 |
| D2 / 100210 | 12 | sudoers / cron / authorized_keys / passwd modified | T1098.004, T1053.003, T1136 |
| D3 / 100220 | 12 | new executable in a system binary directory | T1036.005, T1543 |
| D4 / 100231 | 13 | outbound connection to infrastructure MISP knows | T1071.001, T1571 |
| D5 / 100240 | 13 | authentication attack from a threat-intel-listed host | T1110.001 |

**D1 is the one to talk about.** A brute force alone is noise — the internet knocks on
every SSH port all day, and 5712 fires on it constantly. A brute force *followed by a
successful login from the same source* is a credential compromise in progress. Nothing
stock joins those two facts. Level 14 sits above the brute force (10) and far above a
successful login (3), because neither half is interesting alone — the conjunction is the
entire signal.

**D2's path list is deliberately short.** Every path added costs an analyst an alert, so
the bar is "a change here is suspicious by default", not "this file is important".

**D3 is scoped to file-*added*, not file-changed**, because package updates legitimately
rewrite `/usr/bin` all the time. Alerting on that would train the analyst to ignore the
rule — the most expensive failure mode a detection has.

**D4 is split into two rules** (observe at level 3, judge at level 13). Not stylistic:
`integratord` only receives *alerts*, and the stock firewall rule is level 0, so without
a quiet alerting rule the outbound connections would be invisible to enrichment
entirely.

*Small design point worth mentioning:* D4 and D5 match on the triggering rule's
**groups**, not its ID. Group membership is stable across Wazuh upgrades; stock rule IDs
are not guaranteed to be.

### Four Wazuh behaviours that had to be found by testing

This is the real story of the phase. Every one of these fails **silently or
misleadingly** — which is exactly why they are worth telling.

**1. `<field name="dstip">` takes down the entire rules file.** `srcip`/`dstip`/
`srcport`/`dstport`/`protocol`/`action`/`srcuser`/`dstuser` are *static* fields with
dedicated rule elements; `<field>` only addresses *dynamic* decoded ones. Using it on a
static field doesn't get ignored — analysisd rejects the **whole file**, which silently
took the Phase 5 MISP rules offline too. One bad line, every rule gone.

**2. `<dstip>` accepts exactly one address or CIDR.** Comma lists fail. Pipe lists fail.
And the dangerous one: `!172.16.0.0/12` **parses fine and then never matches anything**.
Positive forms match correctly, so the address is being read — the negation is broken.
I verified it against both a CIDR and an exact address.

That forced an inverted design: three single-CIDR *level-0* rules placed ahead of the
real one, relying on Wazuh's first-match-wins evaluation to suppress internal traffic.
Verbose, but built only from primitives I had actually verified rather than documented
ones that don't work.

**3. CDB lists are inert until compiled — and say so only as a WARNING.** The documented
answer to "not in this set of networks" is `not_address_match_key`. I tried it. A list
is useless until compiled to `.cdb`, and nothing in this deployment compiled it: not a
restart, and not the manager API, which returned *"CDB list file uploaded successfully"*
and produced no `.cdb`. (The API also can't write a read-only bind mount — that attempt
gave a bare "Wazuh Internal Error".) The result:

```
WARNING: List 'etc/lists/internal-networks' could not be loaded.
         Rule '100230' will be ignored.
```

Ruleset loads, everything looks healthy, one rule quietly does not exist. I removed the
dead config rather than leave it, and the check script now **fails on any "will be
ignored" line**.

**4. FIM path matching uses `file`, not `syscheck.path`.** The alert JSON nests the path
at `syscheck.path`, so that's the obvious field — and it matches nothing, with no error.
The rule loads, is evaluated, never fires. Wazuh's own ruleset is no help because **no
stock rule does path-based FIM matching at all**. I settled it by firing both candidates
at one probe file and seeing which produced an alert.

*The theme worth stating:* three of these four produce **no error at all**. The rule
loads, looks correct in the file, and simply never fires. That is the characteristic
failure mode of detection engineering — a detection that doesn't exist looks exactly
like a detection that hasn't triggered yet. It is the entire argument for testing every
rule against live input rather than reviewing it and moving on.

### A bug in my own test harness, worth including

The check script reported every live detection as failing. The rules were fine —
**`wazuh-logtest` writes its analysis to stderr**, and my helper discarded stderr. Piping
stdout alone yields nothing, which looks *exactly* like "no rule matched".

That's a nasty class of bug: a broken test that produces plausible failures rather than
an obvious crash. I only caught it because the failures contradicted results I'd already
verified by hand.

I also hit the "check that never forgets" problem again — the Phase 5 rule-loading check
kept failing on `ossec.log` entries from mistakes I'd made and fixed earlier in the same
session, because `ossec.log` lives on a named volume and outlives container recreates.
Scoped it to the current analysisd run, same as I'd already done for integratord.

### Safety, and how the attacks are simulated

- **Authentication and firewall activity**: log lines that Wazuh's **stock** decoders
  parse (`sshd`, and `kernel`/iptables). No custom decoder, so the decode → rule → alert
  path under test is the production one.
- **File-integrity activity is real** — files genuinely created and modified in the
  agent container, observed by syscheck in realtime.

Nothing contacts a malicious host and nothing runs hostile code. The "implant" in D3 is
an inert text file — what's being tested is the detection, and the detection can't tell
the difference. The known-bad IP is pulled live from MISP and only ever written into a
log line. Benign controls use RFC 5737 documentation ranges, which are routable-looking
and guaranteed never to be in a real feed.

### Result

```
27 passed, 0 failed     (detections)
110 checks green across all six phases
```

All six rules fired, captured in `docs/detections/phase6-alerts.json`, and indexed.
The negative controls matter as much: internal destinations suppressed, and a clean
successful login with no preceding brute force does **not** raise D1.

### The gap I chose to leave open

**No process-execution detection.** "Suspicious child process" and "reverse shell
spawned" need `auditd` or Sysmon, and the agent container has neither. Writing a rule
against telemetry the lab doesn't collect would produce a rule that can never fire —
worse than an acknowledged gap, because it *looks* like coverage. Also no tuning against
a real baseline (these thresholds are reasoned, not measured) and no active response
(auto-blocking on an untuned detection is how you take your own network down).

### Handover to Phase 7

D1 and D5 together already tell one coherent story — a brute force from a host threat
intel already lists, which then succeeds. That is the incident to write up.

### Postscript: a side effect worth understanding

Adding D5 broke Phase 5's demo, and the reason is a genuinely useful thing to know.

Wazuh raises **one** rule per event, and a more specific sibling supersedes a general
one. Failed logins from a known-bad IP used to match 100101 ("MISP: known-bad ip seen").
Once D5 existed — "authentication attack from a threat-intel-listed host" — the same
scenario matched **D5 instead**, because D5 is the more precise statement of what
happened. The enrichment was identical; the classification got sharper, which is the
entire reason D5 exists.

But it meant everything asserting on rule ID `100101` had to be widened to the
threat-intel rule *family*.

*The lesson worth stating:* pinning a test to a specific rule ID makes it brittle
against your own future rules. Matching on rule **groups** (`rule.groups:threat_intel`)
is the durable way to ask "did enrichment fire?" — and it's how the dashboard query in
this lab is now written.
