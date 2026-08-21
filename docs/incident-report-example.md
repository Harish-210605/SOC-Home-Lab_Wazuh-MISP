# Incident Report — INC-2026-001

**SSH credential compromise of `endpoint01` originating from known botnet infrastructure**

> **This is a simulated incident.** No system was actually compromised and no
> malicious host was ever contacted. The intrusion was reproduced against the lab
> by [`scripts/demo-incident.sh`](../scripts/demo-incident.sh), and **every alert
> quoted below is a real alert** produced by the live Wazuh + MISP deployment —
> captured verbatim in
> [`docs/incidents/incident-001-alerts.json`](incidents/incident-001-alerts.json).
> How the simulation stays safe is set out in [Method and limits](#method-and-limits).

| | |
|---|---|
| **Incident ID** | INC-2026-001 |
| **Detected** | 2026-08-21 13:34:43 UTC |
| **Detection source** | Wazuh SIEM, custom rules D1–D5 + MISP enrichment |
| **Affected asset** | `endpoint01` (agent 006, 172.19.0.4) |
| **Classification** | Successful credential access → persistence → command and control |
| **Severity** | **High** — rule level 14, valid-account compromise with confirmed C2 |
| **Status** | Contained (simulated) |
| **Dwell time to first alert** | 1 second |
| **Time to highest-severity alert** | 5 seconds |

---

## 1. Executive summary

An external host at **`50.16.16.211`** ran an SSH password-guessing attack against
`endpoint01`, guessed the password for the service account **`backupsvc`**, and logged
in. Having gained access it established three independent persistence mechanisms, dropped
an implant into a system binary directory under a name designed to look like a legitimate
systemd component, and began beaconing to **`162.243.103.246`** on port 443.

The attack was not detected as generic internet background noise. **Both the source of the
attack and the destination of the beacon were already recorded in MISP as Feodo Tracker
botnet command-and-control infrastructure**, which is what moved this from "another SSH
brute force" to a targeted, attributable intrusion within one second of the first failed
login.

The whole intrusion — first packet to active C2 — produced **45 alerts in 52 seconds**,
including two distinct level-14 findings: the credential compromise itself, and a
correlation alert stating that one host was repeatedly matching threat intel across
unrelated signals.

**What made the difference:** an identical brute force from an address *not* in threat
intel ran in the same capture window and produced no threat-intel alert at all. The
enrichment discriminates; it does not simply amplify.

---

## 2. Timeline

Times are offsets from the first alert. The intrusion is deliberately compressed — a real
attacker would spread these stages over hours or days, and §7 addresses what that
compression hides.

| T+ | Rule | Lvl | Event | ATT&CK |
|---:|---:|---:|---|---|
| 0s | 5710 | 5 | Failed SSH login, non-existent user, from `50.16.16.211` | — |
| **1s** | **100240** | **13** | **D5** — authentication attack from a threat-intel-listed host | T1110.001 |
| 2–13s | 5710 ×10 | 5 | Password guessing continues across `root`, `admin`, `oracle`, `postgres`, `ubuntu`, `jenkins`, `git`, `test`, `ftpuser`, `backupsvc` — 12 attempts, 11 classified as 5710 and the 12th as 5712 below | — |
| **5s** | **100103** | **14** | **Correlation** — repeated intel matches from `endpoint01`, possible active compromise | — |
| 8s | 5712 | 10 | Stock ruleset classifies the activity as a brute force | — |
| **18s** | **100200** | **14** | **D1** — successful login from the source that was brute-forcing → **credential compromise** | T1110.001, T1078 |
| 19s | 100101 | 12 | MISP: known-bad IP seen on `endpoint01` (enrichment of the *successful* login) | — |
| **23s** | **100210** | **12** | **D2** — `/root/.ssh/authorized_keys` created | T1098.004 |
| **23s** | **100210** | **12** | **D2** — `/etc/sudoers.d/99-backupsvc` created | T1136 |
| **23s** | **100210** | **12** | **D2** — `/etc/cron.d/systemd-udevd-refresh` created | T1053.003 |
| **29s** | **100220** | **12** | **D3** — `/usr/bin/systemd-udevd-helper` dropped | T1036.005 |
| 36s | 100230 | 3 | Outbound connection to `162.243.103.246:443` observed | — |
| **38s** | **100231** | **13** | **D4** — that destination is known-malicious infrastructure | T1071.001 |
| 42–48s | 100230 ×2 / 100231 ×2 | 3 / 13 | Beacon repeats at a fixed interval | T1071.001 |
| **48s** | **100103** | **14** | **Correlation** fires again, now on the *C2* observable | — |
| 52s | 5710 ×9 | 5 | **Control:** identical brute force from `198.51.100.77` — no threat-intel alert | — |

The two level-14 alerts are the ones an analyst would be paged on. Everything else is
supporting evidence they would pull once they opened the case.

---

## 3. Detection walkthrough

### Stage 1 — Credential access (T1110.001)

The first failed login was enough. Wazuh's stock `sshd` decoder parsed it, stock rule 5710
classified it, and because 5710 belongs to `authentication_failed`, the alert was handed to
the MISP integration, which asked MISP about the source address and got a hit:

```json
{
  "rule": { "id": "100240", "level": 13,
            "description": "Authentication attack from threat-intel-listed host 50.16.16.211 against endpoint01",
            "mitre": { "id": ["T1110.001"], "tactic": ["Credential Access"],
                       "technique": ["Password Guessing"] } },
  "agent": { "id": "006", "name": "endpoint01", "ip": "172.19.0.4" },
  "data": { "misp": {
      "observable": "50.16.16.211", "attribute_type": "ip-dst",
      "category": "Network activity", "to_ids": "True", "event_id": "1",
      "source_rule_id": "5710",
      "source_rule_description": "sshd: Attempt to login using a non-existent user"
  } }
}
```

The `source_rule_id` field is the pivot that makes this alert actionable: it names the
event that caused the lookup, so the analyst goes from "we saw a known-bad IP" to "we saw
a known-bad IP *failing to log in*" without leaving the alert.

**Note the ordering.** Rule 5712 — the stock ruleset's own "this is a brute force"
verdict — did not fire until T+8s, because it must observe enough failures to be sure.
The threat-intel alert beat it by seven seconds, because intel needs one event, not a
pattern. That gap is the practical argument for enrichment.

### Stage 2 — Initial access (T1078)

```json
{ "rule": { "id": "100200", "level": 14,
            "description": "Successful SSH login from 50.16.16.211, which was brute-forcing moments ago — probable credential compromise",
            "mitre": { "id": ["T1110.001", "T1078"] } },
  "full_log": "sshd[8100]: Accepted password for backupsvc from 50.16.16.211 port 45100 ssh2" }
```

This is the finding the whole ruleset exists for. A brute force is noise and a successful
login is routine; the *conjunction*, from one source inside ten minutes, is a credential
compromise. Rule D1 joins them with `<if_matched_sid>5712</if_matched_sid>` and
`<same_source_ip/>`.

A detail worth stating because it will confuse anyone reading the raw capture: **stock rule
5715 ("sshd: authentication success") does not appear anywhere in the artifact.** Wazuh
raises exactly one rule per event and prefers the most specific sibling, so the successful
login surfaced as 100200 *instead of* 5715, not alongside it. The absence is correct
behaviour, not a missing alert.

### Stage 3 — Persistence (T1098.004, T1136, T1053.003)

Three writes, three alerts, three independent footholds — a key added to
`authorized_keys` (survives a password reset), a passwordless sudo drop-in (survives
privilege review), and a cron job (survives a reboot and re-launches the implant):

```
100210 L12  Security-critical file created or modified: /root/.ssh/authorized_keys
100210 L12  Security-critical file created or modified: /etc/sudoers.d/99-backupsvc
100210 L12  Security-critical file created or modified: /etc/cron.d/systemd-udevd-refresh
```

These are real file-integrity events: syscheck observed real writes inside the agent
container through inotify, and each alert carries the file's size, permissions, owner and
SHA-256 for evidence.

> **This stage did not work when the incident was first replayed.** Rule D2 matches
> `~/.ssh/authorized_keys`, but no monitored FIM directory covered a home directory, so the
> agent never sent an event for that path and the rule's most important branch could not
> fire. See §6.

### Stage 4 — Defense evasion (T1036.005)

```
100220 L12  New executable dropped into a system binary directory: /usr/bin/systemd-udevd-helper
```

The filename is the tradecraft: in a process listing it sits next to the real
`systemd-udevd` and reads as a system component. D3 does not care what the file is named —
it fires on *anything new* appearing in a system binary directory, which is why a
convincing name buys the attacker nothing here.

### Stage 5 — Command and control (T1071.001)

The observation is quiet by design (level 3), and the judgement is loud:

```json
{ "rule": { "id": "100231", "level": 13,
            "description": "Outbound connection to known-malicious infrastructure from endpoint01: 162.243.103.246 — MISP ip-dst",
            "mitre": { "id": ["T1071.001", "T1571"], "tactic": ["Command and Control"] } },
  "data": { "misp": { "observable": "162.243.103.246", "to_ids": "True", "event_id": "1",
                      "source_rule_id": "100230",
                      "source_rule_groups": "soclab,custom_detections,firewall,soclab_d4" } } }
```

Direction is what matters. Inbound scanning is background radiation; a host **reaching
out** to known C2 means the host is already owned. Three connections at a fixed interval
is a beacon, not a mistyped URL.

### The alert that names the incident

```
100103 L14  MISP: repeated threat-intel matches from endpoint01 — possible active compromise
```

This fired four times, and the last firing is the interesting one: it triggered on the
**C2 observable** after already having counted the **authentication** hits. One host, four
threat-intel matches inside five minutes, across two unrelated signals. That is not a
stage of the attack — it is the statement that the stages belong to one incident, and it
is the alert that would tell a triaging analyst to open a case rather than close a ticket.

---

## 4. Threat intelligence findings

Both hostile addresses resolved to the same MISP event:

| Observable | Role | MISP type | Category | `to_ids` | Event |
|---|---|---|---|---|---|
| `50.16.16.211` | Brute-force source | `ip-dst` | Network activity | `True` | 1 — abuse.ch Feodo Tracker — Botnet C2 IPs |
| `162.243.103.246` | Beacon destination | `ip-dst` | Network activity | `True` | 1 — abuse.ch Feodo Tracker — Botnet C2 IPs |

**Assessment.** Both addresses are tracked by abuse.ch as **botnet command-and-control
infrastructure**, and both carry `to_ids: True` — abuse.ch considers them reliable enough
to alert on rather than context to file away. The lab's enrichment rules split on exactly
that flag: `to_ids: True` produces a workable alert (100101/100240/100231), `to_ids: False`
produces a level-6 context record instead. Nothing in this incident relied on a low-
confidence indicator.

That the attacking host and the callback host appear in the *same* C2 event supports a
single-actor interpretation: infrastructure already doing botnet C2 was also used to
acquire the access, and the compromised host was pointed back at the same estate.

**Intel coverage at the time of the incident:** 26,290 indicators across four abuse.ch
feeds (ThreatFox, URLhaus, MalwareBazaar, Feodo Tracker). Feodo Tracker contributed only
5 of those — and both hits came from that 5. Volume is not the same thing as usefulness.

---

## 5. How we know this was not routine noise

An incident report that only lists what fired proves nothing about false positives. Two
controls ran inside the same capture window, on the same host, through the same rules:

| Control | Activity | Expected | Observed |
|---|---|---|---|
| Unlisted source `198.51.100.77` | Identical SSH brute force, source not in any feed | Stock brute-force handling, **no** threat-intel alert | 9 × rule 5710, **zero** D5 alerts |
| Internal destination `172.20.0.9` | Identical outbound connection shape | Suppressed before enrichment | No alert; matched level-0 rule 100227–100229 |

The first control is the important one. The *same attack* from an address threat intel
does not know produced ordinary low-severity alerts and no escalation. So the level-13
finding in §3 is a statement about **who** the source was, not an artefact of a rule that
fires on everything.

The second control matters for cost: private-range destinations are filtered before any
MISP request is made, so the lab's own internal traffic never generates lookups — and, in
any deployment where MISP is not local, never leaks internal addressing to an external
service.

> These controls are only meaningful because the capture *waits* for them. An earlier
> version of the replay script stopped collecting the moment the last attack alert landed,
> so the control events were emitted but never ingested — and "no alert fired" was
> measuring a race, not a detection. The script now blocks until a control alert is
> confirmed present before it slices the log.

---

## 6. What the exercise found

Replaying the intrusion end to end found **two defects that testing the rules individually
had missed**. Both are recorded here because finding them is the main argument for doing
this exercise at all.

### 6.1 Detection D2 had an unreachable branch

Rule 100210 matches `~/.ssh/authorized_keys` as a persistence location. No syscheck
directory in the agent configuration covered any home directory, so the agent **never sent
an event for that path**. The rule loaded, reviewed correctly, listed `authorized_keys` in
its documentation — and that branch could not fire.

This is the failure mode this lab keeps meeting: a rule matching telemetry nobody collects
looks exactly like coverage. Fixed by monitoring the key stores directly:

```xml
<directories realtime="yes" check_all="yes">/root/.ssh,/home</directories>
```

Verified by writing to `authorized_keys` and watching 100210 fire — which is the only
proof that counts.

### 6.2 The correlation rule was silently disabled — twice, for two different reasons

Rule 100103 ("repeated threat-intel matches — possible active compromise") did not fire
during the first replay. Two separate defects were stacked on top of each other:

**First, Phase 6 had orphaned it.** It counted matches of rule 100101, and D5 (100240) is a
more specific sibling — so every failed login from a listed host began matching D5
*instead of* 100101, and the counter this rule watches stopped advancing. Adding a rule
disabled another rule, at a distance, with no error anywhere. Fixed by counting the
`misp_alert` **group**, which every intel detection joins, rather than one rule id: a group
survives the next sibling somebody writes.

**Second, and worse: rule order in the file is load-bearing.** `<if_matched_sid>` and
`<if_matched_group>` are resolved **when the file is parsed**, against the rules seen *so
far*. Rule 100103 sat near the top of `local_rules.xml`, next to the enrichment rules it
belongs with, and referenced rules defined hundreds of lines below. analysisd resolved that
to nothing and dropped the rule:

```
WARNING: (7620): Signature ID '100240' was not found.
         Invalid 'if_matched_sid'. Rule '100103' will be ignored.
```

A `WARNING`, emitted once at manager startup. The ruleset loads. `Total rules enabled`
goes up. The file still contains a correct-looking rule that is **not in the running
ruleset**. This is the same shape as the uncompiled CDB list from Phase 6, and it is now
the third instance in this project of *a detection that does not exist looking exactly
like a detection that has not triggered yet*.

Fixed by moving all correlation rules to the **bottom** of the file, after everything they
count. Rule 100103 now fires — including, at T+48s, across two different signal types.

---

## 7. Impact assessment

| Question | Finding |
|---|---|
| Was access obtained? | **Yes** — valid credentials for `backupsvc`, confirmed by the successful-login event correlated to the brute force |
| Was privilege escalated? | **Effectively yes** — a passwordless sudo drop-in was created, granting root on demand |
| Is persistence established? | **Yes, three independent mechanisms** — SSH key, sudo drop-in, cron job |
| Is the host communicating with an adversary? | **Yes** — repeating beacon to a tracked botnet C2 on 443 |
| Was data exfiltrated? | **Unknown, and not knowable from this telemetry.** The lab collects no network flow volume, no process telemetry and no DNS. Absence of evidence here is not evidence of absence |
| Blast radius | Limited to `endpoint01` in this simulation. No lateral movement was attempted, so **no claim is made** about whether it would have been detected |

The honest summary: the lab can say with confidence **how the attacker got in, what they
did on disk, and who they are talking to**. It cannot say what they took.

---

## 8. Response

The containment actions below were **not executed** — this lab has no active response
configured, deliberately (auto-blocking on untuned detections is how you take your own
network down). This is the response an analyst would run, in the order it should happen.

### Immediate containment

1. **Isolate `endpoint01`** at the network layer rather than shutting it down; a powered-off
   host loses volatile evidence and tells the attacker they were seen.
2. **Block both addresses** at the perimeter — `50.16.16.211` inbound, `162.243.103.246`
   outbound — and check every other host for connections to the second one. The beacon
   destination is the higher-value indicator: it identifies *other* compromised hosts.
3. **Disable `backupsvc` and revoke its credentials everywhere.** A service account that was
   brute-forced successfully almost certainly shares that password with something else.

### Eradication

4. Remove all three persistence mechanisms — `/root/.ssh/authorized_keys` (audit every key,
   do not just truncate), `/etc/sudoers.d/99-backupsvc`, `/etc/cron.d/systemd-udevd-refresh`.
5. Remove `/usr/bin/systemd-udevd-helper` after preserving it and its SHA-256 for analysis.
   The FIM alert already recorded the hash, so this survives even if the file is deleted.
6. **Treat the host as untrusted and rebuild it.** Steps 4–5 remove what was *detected*.
   With confirmed root-level access and no process telemetry, that is not the same as
   removing everything present.

### Recovery and hardening

7. Rebuild from a known-good image; restore data, not configuration.
8. **Disable SSH password authentication** — keys only. This single change would have ended
   the intrusion at stage 1.
9. Rate-limit SSH and require a bastion for administrative access.
10. Rotate credentials for every account that touched the host.

### Follow-up

11. Submit both indicators plus the implant hash back to MISP as a local event, so the next
    detection is a lookup rather than an investigation. **This closes the loop the lab is
    built around:** intel drove the detection, and the incident should now produce intel.
12. Sweep historical alerts for either address to establish whether this was truly first
    contact.

---

## 9. Detection gaps this incident exposed

Stated plainly, because a report that only lists successes is marketing.

- **Enrichment amplifies alert volume.** One brute force produced **9 identical level-13
  D5 alerts** — one per failed login — and the correlation rule added 4 more. An analyst
  should get *one* alert per source per window, not one per packet. The fix is a `frequency`
  and `ignore` window on D5; it is not implemented, and at real-world volume this would be
  the first thing to break.
- **No process telemetry.** The implant was detected *as a file appearing*, never as
  something executing. Without auditd or Sysmon the lab cannot see the process, its parent,
  or its command line — so "was it run?" is unanswerable, and the cron job that would run it
  is inferred from its contents, not observed.
- **No network flow data.** The beacon was detected because a firewall log line was
  available. Byte counts, session duration and periodicity — the things that distinguish a
  beacon from a download — are not collected, so §7 cannot address exfiltration.
- **No DNS visibility.** Real C2 usually resolves a domain first. MISP holds URL and domain
  indicators that this lab currently has no telemetry to match against.
- **Thresholds are reasoned, not measured.** Every frequency and timeframe here was chosen
  from first principles against a lab with no baseline. On a real network they would need
  tuning against weeks of normal traffic before anyone trusted them.
- **The timeline is compressed into 52 seconds.** A patient attacker who waits a day
  between stages defeats every `timeframe` in this ruleset — D1's 600-second window most of
  all. Detecting slow intrusions needs stateful, per-entity tracking that rule-level
  correlation cannot express.

---

## Method and limits

**How the intrusion was simulated.** Authentication and firewall activity is **log
injection**: lines written into monitored log files, parsed by Wazuh's **stock** `sshd` and
`kernel`/iptables decoders — so the decode → rule → enrich → alert path under test is the
production one, with no custom decoder anywhere. File-integrity activity is **real**: files
genuinely created inside the agent container, observed by syscheck through inotify.

**What is not real.** No host was compromised, no credential was guessed, no hostile code
ran, and — the line this lab does not cross — **nothing ever connected to a malicious
address**. The C2 IP exists in this incident only as text inside a log line. The "implant"
is an inert two-line shell script; the detection cannot tell the difference, which is
exactly the point.

**Why these specific addresses.** Both are genuine abuse.ch Feodo Tracker entries, chosen
because that feed is dormant upstream and its five entries are therefore stable — an
incident report that names a concrete IP is worthless if the address rotates out of the
feed next week.

**Reproduce it:**

```bash
scripts/wazuh-up.sh && scripts/misp-up.sh    # if the lab is not running
scripts/demo-incident.sh                     # replay the intrusion, ~2 min
scripts/incident-check.sh                    # verify this report against the capture
```

`demo-incident.sh` is re-runnable: it clears the file artifacts of any previous run before
opening the capture window, so file-creation detections still see an *added* event rather
than a *modified* one.

## Artifacts

| Artifact | Contents |
|---|---|
| [`incidents/incident-001-alerts.json`](incidents/incident-001-alerts.json) | All 45 alerts, custom **and** stock, in timestamp order |
| [`../scripts/demo-incident.sh`](../scripts/demo-incident.sh) | The six-stage replay, including the controls |
| [`../scripts/incident-check.sh`](../scripts/incident-check.sh) | Verifies the capture supports every claim made here |
| [`detections.md`](detections.md) | The five rules, their ATT&CK mapping and design |
| [`integration-wazuh-misp.md`](integration-wazuh-misp.md) | How the enrichment path works |

The stock alerts are kept in the artifact on purpose: without 5710 and 5712 in the file, the
correlation claimed by D1 would be an assertion the reader has no way to check.

## Indicators

| Indicator | Type | Role |
|---|---|---|
| `50.16.16.211` | IPv4 | Brute-force source; MISP `ip-dst`, Feodo Tracker, `to_ids: True` |
| `162.243.103.246` | IPv4 | C2 destination, TCP/443; MISP `ip-dst`, Feodo Tracker, `to_ids: True` |
| `backupsvc` | Account | Compromised via password guessing |
| `/usr/bin/systemd-udevd-helper` | File | Implant, masquerading as a systemd component |
| `/etc/sudoers.d/99-backupsvc` | File | Persistence — passwordless sudo |
| `/etc/cron.d/systemd-udevd-refresh` | File | Persistence — scheduled re-launch |
| `/root/.ssh/authorized_keys` | File | Persistence — attacker SSH key |
