# Wazuh -> MISP threat-intel enrichment integration.
#
# Wazuh ships integrations for VirusTotal, Maltiverse, Slack, PagerDuty and
# Shuffle, but NOT for MISP, so this is written rather than enabled.
#
# How it is invoked
# -----------------
# wazuh-integratord runs this once per alert matching the <group> filter in
# ossec.conf, with:
#     argv[1] = path to a JSON file holding the single alert
#     argv[2] = api_key   (from <api_key>)
#     argv[3] = hook_url  (from <hook_url>)
#
# What it does
# ------------
#   1. pulls candidate observables out of the alert (IPs, domains, URLs, hashes)
#   2. asks MISP, once per unique observable, whether it knows it
#   3. on a hit, writes a new event back into analysisd's queue socket, where
#      etc/rules/local_rules.xml turns it into an alert of its own
#
# Step 3 is what makes this an enrichment rather than a notifier: the result
# re-enters the pipeline as a first-class Wazuh alert, so it indexes, shows up
# in the dashboard, and can drive active response like any other alert.
#
# Everything is logged to logs/integrations.log, which is the only practical way
# to debug an integration — integratord swallows stdout.

import ipaddress
import json
import os
import re
import sys
from socket import AF_UNIX, SOCK_DGRAM, socket

try:
    import requests
except ImportError:
    print("custom-misp: no 'requests' module; use Wazuh's bundled python3")
    sys.exit(1)

# urllib3 warns once per request about the self-signed MISP certificate, which
# would swamp integrations.log. The verification decision is made deliberately
# below, so the warning carries no information.
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

PWD = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LOG_FILE = f"{PWD}/logs/integrations.log"
SOCKET_ADDR = f"{PWD}/queue/sockets/queue"

TIMEOUT = 10
# A single alert can name many observables (a syscheck event carries three
# hashes). This caps the MISP round-trips one alert can cause, so a pathological
# alert cannot stall the integrator queue.
MAX_LOOKUPS = 12

DEBUG = os.environ.get("MISP_DEBUG", "").lower() in ("1", "true", "yes")

HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")


def log(msg):
    line = f"{os.path.basename(__file__)}: {msg}\n"
    try:
        with open(LOG_FILE, "a") as fh:
            fh.write(line)
    except OSError:
        pass


def debug(msg):
    if DEBUG:
        log(f"DEBUG {msg}")


# --- observable extraction --------------------------------------------------

def _dig(obj, path):
    """Fetch a dotted path out of nested dicts, tolerating missing keys."""
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


# Where observables actually live in a Wazuh alert. Kept as an explicit table
# rather than walking the whole alert recursively: a recursive scrape also
# collects the agent's own IP, the manager's hostname and every hash of a file
# the alert merely mentions, and each of those is a MISP round-trip that can
# only ever return a miss.
IP_FIELDS = (
    "data.srcip", "data.dstip",
    "data.win.eventdata.ipAddress", "data.win.eventdata.destinationIp",
    "data.aws.sourceIPAddress", "data.office365.ClientIP",
)
DOMAIN_FIELDS = (
    "data.dns.question.name", "data.hostname", "data.win.eventdata.queryName",
)
URL_FIELDS = (
    "data.url", "data.win.eventdata.destinationHostname",
)
HASH_FIELDS = (
    "syscheck.md5_after", "syscheck.sha1_after", "syscheck.sha256_after",
    "data.win.eventdata.hashes",
)


def is_routable(ip_str):
    """Reject anything MISP could never usefully hold.

    Private, loopback, link-local and multicast addresses are the bulk of the
    IPs in a lab's alert stream (the agent talking to the manager, mostly).
    Looking them up wastes a round-trip per alert to guarantee a miss, and worse,
    it would send the lab's internal addressing to an external service in any
    deployment where MISP is not local.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def extract(alert):
    """Return [(kind, value)] of observables worth asking MISP about."""
    found = []
    seen = set()

    def add(kind, value):
        if not value or not isinstance(value, str):
            return
        value = value.strip()
        key = (kind, value.lower())
        if value and key not in seen:
            seen.add(key)
            found.append((kind, value))

    for f in IP_FIELDS:
        v = _dig(alert, f)
        if isinstance(v, str) and is_routable(v):
            add("ip", v)

    for f in URL_FIELDS:
        v = _dig(alert, f)
        if isinstance(v, str) and v.lower().startswith(("http://", "https://")):
            add("url", v)

    for f in DOMAIN_FIELDS:
        v = _dig(alert, f)
        if isinstance(v, str) and DOMAIN_RE.match(v):
            add("domain", v)

    for f in HASH_FIELDS:
        v = _dig(alert, f)
        if not isinstance(v, str):
            continue
        # Sysmon packs several algorithms into one field:
        # "SHA1=...,MD5=...,SHA256=..." — split before matching.
        for part in re.split(r"[,\s]+", v):
            part = part.split("=")[-1]
            if HASH_RE.match(part):
                add("hash", part)

    return found[:MAX_LOOKUPS]


# --- MISP -------------------------------------------------------------------

def misp_lookup(session, base_url, value):
    """Ask MISP whether it knows `value`. Returns the first matching attribute.

    /attributes/restSearch matches composite types on either half, so a bare IP
    from an alert still resolves a ThreatFox C2 stored as ip-dst|port
    ("1.2.3.4|8080"). That is why no port-stripping is needed here.
    """
    try:
        r = session.post(
            f"{base_url}/attributes/restSearch",
            json={"value": value, "returnFormat": "json", "limit": 5},
            timeout=TIMEOUT,
            # The lab's MISP presents a self-signed certificate on an internal
            # Docker bridge that has no route off the host. There is no CA to
            # verify against, so verification is disabled knowingly. Against a
            # real MISP this must become the path to its CA bundle.
            verify=False,
        )
    except requests.RequestException as e:
        log(f"MISP request failed for {value}: {e}")
        return None

    if r.status_code != 200:
        log(f"MISP returned HTTP {r.status_code} for {value}")
        return None
    try:
        attrs = r.json().get("response", {}).get("Attribute", [])
    except ValueError:
        log(f"MISP returned non-JSON for {value}")
        return None
    return attrs[0] if attrs else None


# --- write back into Wazuh --------------------------------------------------

def send_event(msg, agent=None):
    """Inject an event into analysisd, using Wazuh's own queue protocol.

    Format and escaping follow the shipped integrations (see virustotal.py):
    location is '1:<program>:<json>' for a manager-local event, or
    '1:[id] (name) ip->custom-misp:<json>' when the alert came from an agent —
    which preserves the originating agent on the enriched alert instead of
    attributing every hit to the manager.
    """
    if not agent or agent.get("id") == "000":
        payload = f"1:custom-misp:{json.dumps(msg)}"
    else:
        location = "[{0}] ({1}) {2}".format(
            agent["id"], agent.get("name", ""), agent.get("ip", "any"))
        location = location.replace("|", "||").replace(":", "|:")
        payload = f"1:{location}->custom-misp:{json.dumps(msg)}"

    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(payload.encode())
        sock.close()
    except OSError as e:
        log(f"could not write to {SOCKET_ADDR}: {e}")
        sys.exit(1)


def main(argv):
    if len(argv) < 4:
        log("usage: custom-misp <alert-file> <api-key> <hook-url>")
        sys.exit(2)

    alert_file, api_key, hook_url = argv[1], argv[2], argv[3]
    base_url = hook_url.rstrip("/")

    try:
        with open(alert_file) as fh:
            alert = json.load(fh)
    except (OSError, ValueError) as e:
        log(f"could not read alert file {alert_file}: {e}")
        sys.exit(2)

    observables = extract(alert)
    if not observables:
        debug("no observables in alert %s" % _dig(alert, "rule.id"))
        return 0

    agent = alert.get("agent", {})
    rule = alert.get("rule", {})
    debug(f"alert rule {rule.get('id')} -> observables {observables}")

    session = requests.Session()
    session.headers.update({
        "Authorization": api_key,
        "Accept": "application/json",
        "Content-Type": "application/json",
    })

    hits = 0
    for kind, value in observables:
        attr = misp_lookup(session, base_url, value)
        if not attr:
            continue
        hits += 1

        # The shape below is what local_rules.xml decodes. Kept flat and
        # explicitly named so the rules can match on misp.* without a custom
        # decoder for nested structures.
        event = {
            "integration": "misp",
            "misp": {
                "source": "wazuh-custom-misp",
                "observable": value,
                "observable_kind": kind,
                "attribute_type": attr.get("type"),
                "attribute_value": attr.get("value"),
                "category": attr.get("category"),
                "to_ids": str(attr.get("to_ids")),
                "event_id": str(attr.get("event_id")),
                "comment": (attr.get("comment") or "")[:200],
                # Carry the triggering alert's identity so an analyst can pivot
                # straight back to what caused the lookup.
                "source_rule_id": str(rule.get("id", "")),
                "source_rule_description": (rule.get("description") or "")[:200],
                # The agent is duplicated into the payload on purpose. Wazuh's
                # $(field) expansion in a rule <description> only reaches
                # DECODED fields, so $(agent.name) renders empty even though the
                # alert itself is correctly attributed. Carrying the name as a
                # decoded field is what lets the description name the host, and
                # it is also what rule 100103 correlates on.
                "agent_name": agent.get("name") or "manager",
            },
        }
        log(f"MISP HIT {kind}={value} -> {attr.get('type')} (event {attr.get('event_id')})")
        send_event(event, agent)

    if hits == 0:
        debug(f"no MISP hits for {len(observables)} observable(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
