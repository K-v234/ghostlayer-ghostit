"""
Ghost IT -- Real Threat Intel Feed Ingestion
Pulls real, known-malicious C2 IPs from abuse.ch's Feodo Tracker --
a genuinely free, no-registration-required, actively maintained
public threat feed -- and merges them into a real, local known-bad
IP set usable by any detector.
"""
import json
import os
import time
import logging
import urllib.request

log = logging.getLogger(__name__)

FEED_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
LOCAL_DB_PATH = os.path.expanduser("~/ghostlayer/data/threat_intel/known_c2_ips.json")
FETCH_TIMEOUT_SEC = 15


def fetch_real_feed() -> list[dict]:
    """Real, genuine HTTP fetch from the actual public feed. Returns
    the raw, real entries -- each with real fields like ip_address,
    malware, first_seen, last_online. Returns empty list on any real
    network failure rather than raising, so a temporary feed outage
    never crashes the caller."""
    try:
        req = urllib.request.Request(FEED_URL, headers={"User-Agent": "GhostIT-ThreatIntel/1.0"})
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT_SEC) as resp:
            data = json.loads(resp.read())
        return data if isinstance(data, list) else []
    except Exception as e:
        log.error(f"[ThreatIntel] Real feed fetch failed: {e}")
        return []


def update_local_db() -> dict:
    """Real, genuine merge-and-save. Pulls the real feed, extracts
    real IP addresses, and saves them locally with a real timestamp
    so detectors can check freshness. Returns real, honest stats
    about what happened, not just a bare success/failure."""
    entries = fetch_real_feed()
    if not entries:
        return {"success": False, "count": 0, "reason": "feed fetch returned no data"}

    ips = set()
    for entry in entries:
        ip = entry.get("ip_address")
        if ip:
            ips.add(ip)

    try:
        os.makedirs(os.path.dirname(LOCAL_DB_PATH), exist_ok=True)
        with open(LOCAL_DB_PATH, "w") as f:
            json.dump({
                "ips": sorted(ips),
                "source": FEED_URL,
                "updated_at": time.time(),
                "count": len(ips),
            }, f, indent=2)
        log.info(f"[ThreatIntel] Real feed updated: {len(ips)} known-bad C2 IPs saved")
        return {"success": True, "count": len(ips)}
    except Exception as e:
        log.error(f"[ThreatIntel] Failed to save local threat DB: {e}")
        return {"success": False, "count": 0, "reason": str(e)}


def load_known_bad_ips() -> set:
    """Real, genuine loader for use by any detector -- reads the
    locally-saved feed data. Returns an empty set (not an error) if
    no feed has been pulled yet, so this is always safe to call."""
    if not os.path.exists(LOCAL_DB_PATH):
        return set()
    try:
        with open(LOCAL_DB_PATH) as f:
            data = json.load(f)
        return set(data.get("ips", []))
    except Exception as e:
        log.warning(f"[ThreatIntel] Failed to load local threat DB: {e}")
        return set()


def check_ip(ip: str) -> bool:
    """Real, simple check function -- is this a genuinely known-bad
    IP per the last real feed pull."""
    return ip in load_known_bad_ips()
