#!/usr/bin/env python3
"""Register, fetch and report on the curated threat-intel feeds.

Driven by misp/feeds.json. Split out of the surrounding bash because every step
here is a JSON round-trip against the MISP REST API, and doing that with curl
plus sed is how column mappings end up silently wrong.

Talks to MISP over https://127.0.0.1 with a self-signed certificate, so TLS
verification is disabled deliberately: the lab's own loopback cert has no CA to
verify against. Nothing here leaves the host.
"""

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

BASE = "https://127.0.0.1"
CTX = ssl._create_unverified_context()

BOLD, GREEN, YELLOW, RED, RESET = "\033[1m", "\033[1;32m", "\033[1;33m", "\033[1;31m", "\033[0m"


def log(msg):
    print(f"\033[1;34m==>{RESET} {msg}", flush=True)


def warn(msg):
    print(f"{YELLOW} warn:{RESET} {msg}", file=sys.stderr, flush=True)


def die(msg):
    print(f"{RED}error:{RESET} {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


def api(path, payload=None, key=None, timeout=180):
    """One MISP REST call. payload=None issues a GET, otherwise a POST."""
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        f"{BASE}{path}",
        data=data,
        method="POST" if data is not None else "GET",
        headers={
            "Authorization": key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=timeout) as r:
            body = r.read().decode()
    except urllib.error.HTTPError as e:
        die(f"{path} returned HTTP {e.code}: {e.read().decode()[:300]}")
    except urllib.error.URLError as e:
        die(f"cannot reach MISP at {BASE}{path}: {e.reason}")
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        die(f"{path} did not return JSON: {body[:300]}")


# --- feed registration ------------------------------------------------------

# Fields we own on every curated feed. Anything not listed keeps MISP's default.
#
# distribution "3" (all communities) is right for public OSINT: it is already
# world-readable, and restricting it would only complicate later sharing.
# caching_enabled turns on MISP's Redis-backed feed lookup, which is what makes
# the "feed hits" panel light up on an attribute in the UI.
FIXED = {
    "enabled": True,
    "caching_enabled": True,
    "distribution": "3",
    "input_source": "network",
    "fixed_event": True,
    "delta_merge": False,
    "publish": False,
    "override_ids": False,
    "delete_local_file": False,
    "lookup_visible": True,
}


def build_payload(spec):
    """Turn one misp/feeds.json entry into a MISP Feed payload.

    `settings` is passed through as a nested object, NOT a pre-serialised
    string. MISP serialises it on the way into the database, so handing it a
    string produces a double-encoded value ("\\"{\\\\\\"csv\\\\\\"...") and the
    CSV column mapping is silently ignored — every row then imports as the
    wrong attribute, or not at all.
    """
    feed = {k: v for k, v in spec.items() if not k.startswith("_")}
    feed.update(FIXED)
    return {"Feed": feed}


def sync(specs, key):
    """Create or update each curated feed. Idempotent, matched on URL.

    URL is the identity here rather than name or id: names are cosmetic and
    ids are assigned by MISP, but a feed is fundamentally the thing at its URL.
    That also lets the script adopt a feed someone already added by hand.
    """
    existing = {f["Feed"]["url"]: f["Feed"] for f in api("/feeds/index", key=key)}
    out = []
    for spec in specs:
        payload = build_payload(spec)
        url = spec["url"]
        if url in existing:
            fid = existing[url]["id"]
            api(f"/feeds/edit/{fid}", payload, key=key)
            log(f"updated feed {fid}: {spec['name']}")
        else:
            res = api("/feeds/add", payload, key=key)
            fid = res["Feed"]["id"]
            log(f"added   feed {fid}: {spec['name']}")
        out.append((fid, spec["name"]))

    # Read the feeds back and confirm settings survived the round-trip, rather
    # than trusting the write. This is the double-encoding trap above: it fails
    # silently at write time and only shows up as an empty or wrong import.
    after = {f["Feed"]["id"]: f["Feed"] for f in api("/feeds/index", key=key)}
    for fid, name in out:
        stored = after[fid].get("settings")
        try:
            parsed = json.loads(stored) if isinstance(stored, str) else stored
            if not isinstance(parsed, dict):
                raise ValueError
        except (ValueError, TypeError):
            die(f"feed {fid} ({name}) stored a malformed 'settings' value: {stored!r}\n"
                f"       This is the double-encoding trap — settings must be sent as an object.")
    return out


# --- fetching ---------------------------------------------------------------

def fetch(feeds, key, timeout=900):
    """Queue a fetch for each feed and wait for the background jobs to finish.

    MISP runs feed pulls on a Redis-backed worker, so /feeds/fetchFromFeed
    returns as soon as the job is queued, not when it is done. Completion is
    read back off /jobs/index, matched on the job_input MISP writes ("Feed: 7").
    Polling that is far more honest than sleeping and hoping.
    """
    baseline = {j["Job"]["id"] for j in api("/jobs/index", key=key)}
    for fid, name in feeds:
        api(f"/feeds/fetchFromFeed/{fid}", {}, key=key)
        log(f"queued fetch for feed {fid}: {name}")

    wanted = {f"Feed: {fid}" for fid, _ in feeds}
    log(f"waiting for {len(wanted)} fetch job(s) to finish (up to {timeout // 60} min)")
    deadline = time.time() + timeout
    done, failed = {}, {}
    while time.time() < deadline:
        for j in api("/jobs/index", key=key):
            job = j["Job"]
            if job["id"] in baseline or job.get("job_type") != "fetch_feeds":
                continue
            if job.get("job_input") not in wanted:
                continue
            if job.get("job_status") == "Completed":
                done[job["job_input"]] = job.get("message", "")
            elif job.get("failed"):
                failed[job["job_input"]] = job.get("message", "")
        if len(done) + len(failed) >= len(wanted):
            break
        time.sleep(5)

    for fid, name in feeds:
        tag = f"Feed: {fid}"
        if tag in failed:
            warn(f"fetch FAILED for {name}: {failed[tag]}")
        elif tag not in done:
            warn(f"fetch for {name} did not report completion within the timeout")
    return len(failed) == 0 and len(done) == len(wanted)


# --- reporting --------------------------------------------------------------

def report(key):
    """Summarise what actually landed in MISP, per feed and per attribute type."""
    events = api("/events/index", key=key)
    print(f"\n{BOLD}Ingested events{RESET}\n")
    total = 0
    for e in sorted(events, key=lambda x: int(x["id"])):
        count = int(e.get("attribute_count") or 0)
        total += count
        print(f"  event {e['id']:>3}  {count:>6} attributes  {e.get('info','')[:60]}")
    print(f"\n  {BOLD}{total} attributes across {len(events)} events{RESET}")

    # Attribute-type mix is the interesting number for the next phase: it says
    # which kinds of Wazuh field can actually be enriched against this data.
    types = {}
    for e in events:
        full = api(f"/events/view/{e['id']}", key=key)
        for a in full["Event"].get("Attribute", []):
            types[a["type"]] = types.get(a["type"], 0) + 1
    print(f"\n{BOLD}Attribute types{RESET}\n")
    for t, n in sorted(types.items(), key=lambda kv: -kv[1]):
        print(f"  {n:>6}  {t}")
    return types


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--specs", required=True, help="path to misp/feeds.json")
    ap.add_argument("--no-fetch", action="store_true",
                    help="register and enable the feeds but do not pull them")
    ap.add_argument("--timeout", type=int, default=900)
    args = ap.parse_args()

    key = os.environ.get("ADMIN_KEY")
    if not key:
        die("ADMIN_KEY is not set. Source misp/.env before running this.")

    with open(args.specs) as fh:
        specs = json.load(fh)

    log(f"syncing {len(specs)} curated feed(s) from {args.specs}")
    feeds = sync(specs, key)

    if args.no_fetch:
        log("--no-fetch given; skipping the pull")
        return 0

    ok = fetch(feeds, key, args.timeout)
    report(key)
    if not ok:
        warn("at least one feed did not fetch cleanly (see above)")
        return 1
    print(f"\n{GREEN}All curated feeds fetched.{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
