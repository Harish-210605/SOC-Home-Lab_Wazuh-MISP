# What I'd improve at scale

This lab is honest about being a lab. What follows is what would have to change before any
of it belonged in front of a real network — written as the design review I would expect to
be given.

## The architecture would not survive production

- **Everything is single-node.** One indexer holds every alert with no replica: it is a
  single point of failure *and* the durability story. Production needs a multi-node indexer
  cluster with replicas, and a manager cluster behind the agents.
- **There is no retention policy.** Alerts accumulate in one index forever. Real deployments
  need ISM/ILM — hot/warm/cold tiers, rollover on size, and a documented retention period
  driven by whichever compliance regime applies. Right now the lab's answer to "how far back
  can you search?" is "until the disk fills".
- **No backup or disaster recovery.** State lives in named volumes and nothing snapshots
  them. A corrupted MariaDB volume loses the entire intel database.
- **Secrets are files on disk.** Generated `.env` files at mode 600 are the right answer for
  a laptop and the wrong one for a fleet; this belongs in Vault, SOPS or a cloud secret
  manager, with rotation. Relatedly, the integration talks to MISP with
  `verify=False` — correct for a self-signed certificate on an internal bridge, unacceptable
  anywhere else, and the code says so at the call site.

## The enrichment would fall over first

- **Every lookup is a synchronous HTTP round-trip.** One alert, one `restSearch` call,
  blocking the integrator queue. At a few hundred EPS this is the bottleneck, and MISP
  becomes a hard dependency of the detection pipeline — if MISP is down, enrichment stops.
  The fix is to invert it: **pull** indicators out of MISP on a schedule into a local
  lookup structure (a compiled CDB list, or a Redis/bloom-filter cache), and query that.
  Latency goes to zero, MISP stops being on the critical path, and the freshness cost is
  one sync interval.
- **Enrichment amplifies alert volume, badly.** One brute force in the incident replay
  produced **nine identical level-13 alerts**, one per failed login, plus four correlation
  alerts. An analyst should get *one* alert per source per window. D5 needs a `frequency`
  and `ignore` window; at real volume this is the first thing that would break, and it is
  the lab's most obvious unfixed defect.
- **No indicator confidence, ageing or false-positive suppression.** Every IOC is treated as
  equally true forever. Real intel work needs MISP's warninglists (so a feed listing
  `8.8.8.8` cannot page anyone), decay scoring so stale indicators stop firing, and
  weighting by source reliability. The lab's four feeds are all abuse.ch — a single
  provider's view is not the same as corroboration.

## The detection coverage has real holes

- **No process telemetry.** The incident's implant was detected *as a file appearing*, never
  as something executing. Without auditd or Sysmon there is no process, parent process, or
  command line — so "was it run?" is unanswerable. This is the biggest single gap, and it
  is a consequence of the container-only constraint rather than an oversight.
- **No network flow or DNS data.** The C2 beacon was caught only because a firewall log line
  existed. Byte counts, session duration and periodicity — the things that separate a beacon
  from a download — are not collected, which is why the incident report says exfiltration is
  *unknown* rather than *ruled out*.
- **Thresholds are reasoned, not measured.** Every `frequency` and `timeframe` was chosen
  from first principles against a lab with no baseline. On a real network they need tuning
  against weeks of normal traffic before anyone trusts them — and the tuning, not the
  writing, is where detection engineering actually lives.
- **Correlation windows assume a fast attacker.** A patient adversary who waits a day
  between stages defeats every timeframe in the ruleset, D1's ten-minute window most of all.
  Catching slow intrusions needs stateful per-entity tracking that rule-level correlation
  cannot express.

## The workflow would need to become engineering

- **Detection-as-code.** The rules are version-controlled and tested, which is the right
  start, but the tests run by hand. This belongs in CI: lint the ruleset, load it into a
  throwaway manager, replay a corpus of labelled events, and fail the build on a regression.
  The two defects Phase 7 found — a rule dropped at parse time, a rule matching telemetry
  nobody collected — are exactly what such a pipeline catches automatically.
- **No active response.** Every rule here observes. Wiring D1 or D4 to block a source IP is
  the obvious next step and is deliberately out of scope: auto-blocking on detections that
  have never been tuned against a baseline is how you take your own network down.
- **The intel loop is only half closed.** Intel drives detection, but incidents produce no
  intel — the implant hash and both addresses should be written back to MISP as a local
  event so the next occurrence is a lookup rather than an investigation. The API path to do
  it already exists in `scripts/misp_feeds.py`.
