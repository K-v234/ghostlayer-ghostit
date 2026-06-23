"""
Ghost IT — Event Enricher

Adds context to raw events before storage.
Enrichment happens in userspace pipeline, not kernel — keeps eBPF lean.
"""
from __future__ import annotations
import socket
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# Known safe internal IP ranges — reduce false positives
INTERNAL_RANGES = [
    "10.", "172.16.", "172.17.", "172.18.",
    "192.168.", "127.",
]

# Process risk classification
HIGH_RISK_COMMS = {
    "bash", "sh", "python3", "python", "perl",
    "ruby", "nc", "ncat", "socat", "curl", "wget",
}

MEDIUM_RISK_COMMS = {
    "apt", "apt-get", "pip", "pip3", "npm",
    "git", "ssh", "scp", "rsync",
}


def _classify_process(comm: str) -> str:
    if comm in HIGH_RISK_COMMS:
        return "high"
    if comm in MEDIUM_RISK_COMMS:
        return "medium"
    return "low"


def _is_internal_ip(ip: str) -> bool:
    return any(ip.startswith(r) for r in INTERNAL_RANGES)


def _resolve_ip(ip: str) -> str | None:
    """Best-effort reverse DNS — non-blocking with timeout."""
    try:
        socket.setdefaulttimeout(0.5)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


# C12 — DPDP compliance hooks
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.expanduser("~/ghostlayer"))
try:
    from compliance.pii_detector       import tag_event       as _tag_pii
    from compliance.residency_enforcer import check_event     as _check_residency
    _C12_READY = True
except ImportError:
    _C12_READY = False

def enrich(event: dict) -> dict:
    """
    Add enrichment fields to a single event dict.
    Never mutates the original — returns a new dict.
    """
    e = dict(event)

    # C12: PII detection + tagging
    if _C12_READY:
        try:
            e = _tag_pii(e)
        except Exception as _ex:
            log.debug(f"C12 PII tag error: {_ex}")

    # C12: Data residency check
    if _C12_READY:
        try:
            _check_residency(e)
        except Exception as _ex:
            log.debug(f"C12 residency check error: {_ex}")

    # Wall clock timestamp
    e["wall_time"] = datetime.now(timezone.utc).isoformat()

    # Process risk classification
    e["proc_risk"] = _classify_process(e.get("comm", ""))

    # Network enrichment
    if e.get("type") == "connect" and e.get("daddr"):
        ip = e["daddr"]
        e["is_internal"] = _is_internal_ip(ip)
        if not e["is_internal"]:
            e["rdns"] = _resolve_ip(ip)

    # Severity label
    score = e.get("score", 0)
    if score >= 60:
        e["severity"] = "high"
    elif score >= 30:
        e["severity"] = "medium"
    else:
        e["severity"] = "low"

    return e


def enrich_batch(events: list[dict]) -> list[dict]:
    """Enrich a batch of events. Skips and logs any failures."""
    enriched = []
    for ev in events:
        try:
            enriched.append(enrich(ev))
        except Exception as ex:
            log.error(f"Enrichment failed for event: {ex}")
            enriched.append(ev)
    return enriched
