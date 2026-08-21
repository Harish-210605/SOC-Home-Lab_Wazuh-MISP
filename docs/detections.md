# Custom Detection Rules

Phase 6 of the lab: five custom detections, each mapped to MITRE ATT&CK, each
simulated safely and captured as a real alert in
[`docs/detections/phase6-alerts.json`](detections/phase6-alerts.json).

## The design constraint that shaped everything

Wazuh's stock ruleset is good. It already detects SSH brute force (5712/5763) and
already alerts on file-integrity changes (550/553/554). Re-implementing either would
have added rule count and no detection value.

So every rule here had to earn its place by adding something stock does not have —
which, consistently, turned out to be **context**:

- stock detects a brute force, but not a brute force that then **succeeded**
- stock reports that a file changed, but scores `/etc/shadow` identically to a scratch
  file, because it has no notion of which paths matter
- stock has no concept of the other end of a connection being **known-malicious**

Every rule therefore *builds on* the stock ones with `<if_sid>` / `<if_matched_sid>`
rather than replacing them. A Wazuh upgrade that improves rule 5712 improves D1 too.

## The detections

| ID | Level | Detection | ATT&CK | Builds on |
|---|---|---|---|---|
| **100200** | 14 | **D1** — successful SSH login from a source that was brute-forcing moments ago | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1078](https://attack.mitre.org/techniques/T1078/) | 5715 after 5712 |
| **100210** | 12 | **D2** — security-critical file created or modified (passwd/shadow/sudoers/cron/authorized_keys) | [T1098.004](https://attack.mitre.org/techniques/T1098/004/), [T1053.003](https://attack.mitre.org/techniques/T1053/003/), [T1136](https://attack.mitre.org/techniques/T1136/) | 550/553/554 + path |
| **100220** | 12 | **D3** — new executable dropped into a system binary directory | [T1036.005](https://attack.mitre.org/techniques/T1036/005/), [T1543](https://attack.mitre.org/techniques/T1543/) | 554 + path |
| **100231** | 13 | **D4** — outbound connection to infrastructure MISP knows | [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1571](https://attack.mitre.org/techniques/T1571/) | 100230 → MISP → 100100 |
| **100240** | 13 | **D5** — authentication attack from a threat-intel-listed host | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | 5710/5712 → MISP → 100100 |

Supporting rules: **100227–100229** (level 0) suppress internal destinations, and
**100230** (level 3) is the quiet observation rule that feeds enrichment.

### Why D1 is the most valuable rule here

A brute force on its own is noise — the internet knocks on every SSH port constantly,
and rule 5712 fires on it all day. A brute force *followed by a successful login from
the same source* is a credential compromise in progress. Nothing in the stock ruleset
joins those two facts.

Level 14 is above the brute force itself (10) and far above a successful login (3),
because neither part is interesting alone. The conjunction is the entire signal.

### Why D2's path list is deliberately short

Every path added to that list costs an analyst an alert. The bar is *"a change here is
suspicious by default"* — not *"this file is important"*. `/etc/sudoers.d/`,
`/etc/cron*`, `authorized_keys` and the passwd/shadow family qualify; most of `/etc`
does not.

D3 is scoped to rule 554 (file **added**) rather than 550 (changed), because package
updates legitimately change files in `/usr/bin` all the time. Alerting on that would
train the analyst to ignore the rule — the most expensive failure mode a detection has.

### Why D4 is split into two rules

`100230` observes ("this host connected outbound", level 3) and `100231` judges ("that
destination is known-malicious", level 13). The split is necessary, not stylistic:
`integratord` only ever receives *alerts*, and stock firewall rule 4100 is level 0, so
without an alerting observation rule outbound connections would be invisible to
enrichment entirely. A single combined rule would either alert on every outbound
connection or be unable to enrich at all.

D4 and D5 both match on the triggering rule's **groups** rather than its ID. Group
membership is stable across Wazuh upgrades; stock rule IDs are not guaranteed to be.

## Simulating the attacks

```bash
scripts/demo-detections.sh
```

- **Authentication and firewall activity** is simulated by writing log lines that
  Wazuh's **stock** decoders parse — the `sshd` decoder and the `kernel`/iptables
  decoder. No custom decoder is involved, so the decode → rule → alert path under test
  is the production one.
- **File-integrity activity is real.** Files are genuinely created and modified inside
  the agent container, and syscheck observes them through realtime monitoring.

**Nothing contacts a malicious host, and nothing runs hostile code.** The "implant"
dropped in D3 is an inert text file. What is being tested is the detection, and the
detection cannot tell the difference — which is precisely the point. The known-bad IP
is pulled live from MISP and only ever *written into a log line*.

The benign controls use RFC 5737 documentation ranges (`198.51.100.0/24`,
`203.0.113.0/24`), which are routable-looking and guaranteed never to appear in a real
threat feed.

## Verify

```console
$ scripts/detections-check.sh
27 passed, 0 failed
```

The suite asserts rules are defined, ids are unique and inside the user range, the
ruleset actually loads, **every detection carries a well-formed ATT&CK technique id**,
each detection fires against live input, and — equally important — that the negative
cases stay quiet: internal destinations are suppressed, and a clean successful login
with no preceding brute force does *not* raise D1.

## Six Wazuh behaviours that had to be found by testing

Each of these fails **silently or misleadingly**, which is what makes them worth
recording. Items 5 and 6 were found in Phase 7, by replaying a whole intrusion across
every rule at once — neither was reachable by testing the detections one at a time.

### 1. `<field name="dstip">` takes down the entire file

`srcip`, `dstip`, `srcport`, `dstport`, `protocol`, `action`, `srcuser` and `dstuser`
are **static** fields with dedicated rule elements. `<field>` addresses only *dynamic*
(decoded) fields. Using `<field>` on a static one is not ignored:

```
ERROR: Failure to read rule 100230. Field 'dstip' is static.
CRITICAL: (1220): Error loading the rules: 'etc/rules/local_rules.xml'.
```

analysisd then refuses to load **the whole file** — silently taking every other rule
down with it, including the Phase 5 MISP rules that had been working fine.

### 2. `<dstip>` is far more restrictive than it looks

It accepts **exactly one** address or CIDR:

| Form | Result |
|---|---|
| `162.243.103.246` | works |
| `162.243.0.0/16` | works |
| `10.0.0.0/8,192.168.0.0/16` | `Invalid ip address` → whole file fails |
| `10.0.0.0/8\|192.168.0.0/16` | `Invalid ip address` → whole file fails |
| `!172.16.0.0/12` | **parses, then matches nothing, ever** |

The negation case is the dangerous one: it loads without complaint and the rule simply
never fires. Verified against both a CIDR and an exact address with an unrelated
destination — positive forms match correctly, so the address is being parsed; the
negation is what is broken.

Hence the inverted shape in the ruleset: three single-CIDR level-0 rules
(100227–100229) placed *ahead* of 100230, relying on Wazuh's first-match-wins
evaluation. An internal destination matches one of those and stops. Verbose, but built
only from primitives that were verified to work.

### 3. CDB lists are inert until compiled, and say so only as a warning

`not_address_match_key` is the documented way to express "not in this set of networks",
and it was the first thing tried. A CDB list is useless until compiled to `.cdb`, and
in this deployment nothing compiled it — not an analysisd restart, and not the manager
API upload, which returned `CDB list file uploaded successfully` and produced no `.cdb`.
(The API also cannot write a list that is bind-mounted read-only; that attempt failed
with a bare `Wazuh Internal Error`.)

The result is a **warning**, not an error:

```
WARNING: (7616): List 'etc/lists/internal-networks' could not be loaded.
                 Rule '100230' will be ignored.
```

The ruleset loads, everything looks healthy, and one rule quietly does not exist. The
check script now fails on any `will be ignored` line for exactly this reason.

### 4. FIM path matching uses `file`, not `syscheck.path`

The alert JSON nests the path at `syscheck.path`, so that is the obvious field to match
on — and it matches nothing. No error is logged: the rule loads, is evaluated, and never
fires, so the only symptom is a detection that quietly does not exist.

The correct field is `file`:

```xml
<field name="file" type="pcre2">^/(usr/)?(local/)?s?bin/</field>
```

Wazuh's own ruleset is no help in discovering this — **no stock rule does path-based FIM
matching at all**. It was settled by firing both candidates at a single probe file and
seeing which one produced an alert.

### 5. Correlation rules must be defined *after* the rules they count

`<if_matched_sid>` and `<if_matched_group>` are resolved **when the file is parsed**,
against the rules seen *so far*. A correlation rule placed above the rules it references
resolves to nothing and is dropped:

```
WARNING: (7620): Signature ID '100240' was not found.
         Invalid 'if_matched_sid'. Rule '100103' will be ignored.
```

Rule 100103 (*"repeated threat-intel matches — possible active compromise"*) sat near the
top of `local_rules.xml`, grouped with the enrichment rules it belongs with, and pointed at
rules defined hundreds of lines below. It was absent from the running ruleset while looking
entirely correct in the file — a `WARNING` emitted once at manager startup being the only
sign.

Correlation rules now live at the **bottom** of the file, and
`scripts/incident-check.sh` asserts that ordering so it cannot regress.

*Two related constraints found alongside it:* a level-0 parent rule cannot be counted
(`if_matched_sid` on rule 100100 never advances), and a correlation rule must not be a
member of the group it counts, or it feeds its own counter.

### 6. A rule can match a path the agent never reports

Rule D2 matches `~/.ssh/authorized_keys` as a persistence location. No syscheck directory
in the agent configuration covered a home directory, so the agent **never sent an event for
that path** — the rule loaded, read correctly, listed `authorized_keys` in its
documentation, and that branch could not fire.

This is the same failure in a different place: the rule was fine, the *telemetry* was
missing. Fixed in the agent config, and now guarded by a check:

```xml
<directories realtime="yes" check_all="yes">/root/.ssh,/home</directories>
```

*The theme, restated:* of these six, **five produce no error at all**. The rule loads,
looks correct, and never fires. A detection that does not exist is indistinguishable from
a detection that has not triggered yet — which is the entire argument for testing every
rule against live input, and for replaying a full intrusion rather than only firing rules
one by one.

## A side effect worth understanding: rule specificity

Adding D5 changed the behaviour of Phase 5's demo, and the reason is worth knowing.

Wazuh raises **one** rule per event, and a more specific sibling supersedes a general
one. Failed logins from a known-bad IP previously matched rule 100101 (*"MISP: known-bad
ip seen"*). Once D5 (100240, *"authentication attack from a threat-intel-listed host"*)
existed, that same scenario started matching **D5 instead** — because D5 is the more
precise statement of what happened.

The enrichment is identical; the classification got sharper, which is exactly why D5 was
written. But it means anything asserting on rule 100101 by ID had to be widened to the
threat-intel rule family. Both `scripts/demo-misp-enrichment.sh` and
`scripts/misp-integration-check.sh` now match on the family rather than one ID.

*The general lesson:* pinning a test to a specific rule ID makes it brittle against your
own future rules. Matching on rule **groups** — `rule.groups:threat_intel` — is the
durable way to ask "did threat-intel enrichment fire?", and it is how the dashboard
query in this lab is now written.

## Not done here

- **No process-execution detection.** The classic "suspicious child process" and
  "reverse shell spawned" detections need `auditd` (Linux) or Sysmon (Windows), and the
  agent container has neither. Writing a rule against telemetry the lab does not collect
  would produce a rule that can never fire — worse than an acknowledged gap, because it
  looks like coverage. This is the honest limitation of a container-only lab.
- **No tuning against a real baseline.** These thresholds are reasoned, not measured. On
  a real network, D2's path list and D1's window would be tuned against weeks of normal
  activity before anyone trusted them.
- **No active response.** Every rule here observes. Wiring D1 or D4 to an active-response
  script that blocks the source IP is the obvious next step, and deliberately out of
  scope: auto-blocking on a detection that has never been tuned is how you take your own
  network down.

## Next

Phase 7 replays all of these as **one intrusion** rather than five separate tests:
[INC-2026-001](incident-report-example.md) walks a single attacker from brute force through
persistence and C2, and is where behaviours 5 and 6 above were found.
