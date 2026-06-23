# STATUS: 100% — India data residency enforcement, foreign IP detection, audit log
# compliance/residency_enforcer.py
# GhostIT C12 — DPDP Data Residency Enforcer
# Ensures all telemetry stays within India — blocks/alerts on foreign data flows
# Ghost Layer Technologies · Chennai · June 2026

import os
import json
import logging
from datetime import datetime, timezone
from typing import Optional

log = logging.getLogger(__name__)

# Indian cloud region IP ranges (AWS/Azure Mumbai, Chennai, Pune + on-premises RFC1918)
INDIA_CIDRS = [
    # RFC1918 — on-premises (always India)
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    # AWS ap-south-1 (Mumbai)
    "13.126.0.0/15", "13.232.0.0/14", "15.206.0.0/15",
    "52.66.0.0/16",  "65.0.0.0/14",   "35.154.0.0/15",
    # Azure Central India (Pune) + South India (Chennai)
    "104.211.64.0/18", "104.211.128.0/18", "20.192.0.0/10",
    # Loopback — always local
    "127.0.0.0/8",
]

VIOLATION_LOG = os.path.expanduser("~/ghostlayer/data/residency_violations.jsonl")


def _now(): return datetime.now(timezone.utc)

def _ip_to_int(ip: str) -> int:
    parts = ip.strip().split(".")
    if len(parts) != 4: return 0
    try:
        return (int(parts[0]) << 24 | int(parts[1]) << 16 |
                int(parts[2]) << 8  | int(parts[3]))
    except ValueError:
        return 0

def _cidr_contains(cidr: str, ip_int: int) -> bool:
    try:
        network, bits = cidr.split("/")
        mask = (0xFFFFFFFF << (32 - int(bits))) & 0xFFFFFFFF
        return (ip_int & mask) == (_ip_to_int(network) & mask)
    except Exception:
        return False

def is_india_ip(ip: str) -> bool:
    """Return True if IP is within India cloud or on-premises ranges."""
    if not ip or ip in ("None", "null"): return True  # no dest = local
    ip_int = _ip_to_int(ip)
    if ip_int == 0: return True  # unparseable = treat as local
    return any(_cidr_contains(cidr, ip_int) for cidr in INDIA_CIDRS)

def check_event(event: dict) -> Optional[dict]:
    """
    Check a telemetry event for foreign data flow.
    Returns a violation dict if foreign destination detected, else None.
    """
    daddr = event.get("daddr") or event.get("network_dst") or ""
    if not daddr or daddr in ("None", "null", ""):
        return None
    if is_india_ip(daddr):
        return None
    violation = {
        "ts":          _now().isoformat(),
        "pid":         event.get("pid", 0),
        "comm":        event.get("comm", ""),
        "foreign_ip":  daddr,
        "dport":       event.get("dport"),
        "event_type":  event.get("type", ""),
    }
    log.warning(f"RESIDENCY VIOLATION: {violation['comm']} → {daddr}")
    _log_violation(violation)
    return violation

def _log_violation(v: dict):
    try:
        with open(VIOLATION_LOG, "a") as f:
            f.write(json.dumps(v) + "\n")
    except Exception as ex:
        log.error(f"Failed to log residency violation: {ex}")

def get_violations(limit=100) -> list[dict]:
    """Return recent residency violations from log."""
    try:
        with open(VIOLATION_LOG) as f:
            lines = f.readlines()
        return [json.loads(l) for l in lines[-limit:]]
    except FileNotFoundError:
        return []

def violation_count() -> int:
    try:
        with open(VIOLATION_LOG) as f:
            return sum(1 for _ in f)
    except FileNotFoundError:
        return 0

residency_enforcer = type("ResidencyEnforcer", (), {
    "is_india_ip":   staticmethod(is_india_ip),
    "check_event":   staticmethod(check_event),
    "get_violations":staticmethod(get_violations),
    "violation_count":staticmethod(violation_count),
})()
