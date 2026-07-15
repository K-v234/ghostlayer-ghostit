#!/usr/bin/env python3
"""
Ghost IT — V3: STIX 2.1 Threat Intelligence Export
Converts Ghost IT confirmed detections into STIX 2.1 Indicator
objects, the OASIS-standard format for threat intelligence sharing
used by CISA, India-CERT, and threat-sharing communities worldwide.
This is the technical prep piece for eventual India-CERT partnership
integration -- the actual government relationship is separate, but
the data format is genuinely buildable now.

STIX 2.1 reference: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
"""
from __future__ import annotations
import uuid
import hashlib
from datetime import datetime, timezone

STIX_VERSION = "2.1"
GHOST_IT_IDENTITY_ID = "identity--" + str(uuid.uuid5(
    uuid.NAMESPACE_DNS, "ghostit.ghostlayertech.com"))

def _stix_timestamp(ts_ns: int = None) -> str:
    """STIX requires RFC3339 UTC timestamps with millisecond precision."""
    if ts_ns:
        dt = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc)
    else:
        dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"

def _deterministic_id(object_type: str, seed: str) -> str:
    """STIX object IDs must be <type>--<UUID>. Using UUID5 (namespace-based,
    deterministic) rather than random UUID4 means the same underlying
    Ghost IT alert always produces the same STIX ID -- important for
    deduplication when re-exporting or when a receiving TAXII server
    processes the same indicator multiple times."""
    return f"{object_type}--{uuid.uuid5(uuid.NAMESPACE_DNS, seed)}"

# Map Ghost IT rule_ids to MITRE ATT&CK-aligned STIX indicator types
# and kill-chain phases, reusing the same MITRE mapping already
# established in detection/mitre.py -- keeping the two systems
# consistent rather than maintaining a separate mapping.
INDICATOR_LABELS = {
    "C15_RANSOMWARE": ["malicious-activity"],
    "C14_LOLBIN": ["malicious-activity"],
    "C19_LKRG_INTEGRITY": ["malicious-activity", "anomalous-activity"],
    "canary_hit": ["malicious-activity"],
    "R001": ["malicious-activity"],
    "R002": ["malicious-activity"],
    "R003": ["malicious-activity"],
    "R004": ["anomalous-activity"],
}

def _build_pattern(alert: dict) -> str:
    """
    Construct a STIX Patterning Language expression from a Ghost IT
    alert. STIX patterns describe WHAT to detect (e.g. a specific file
    path, a specific destination IP) so a receiving organization's own
    tools can search their own environment for the same indicator --
    the actual point of threat intel sharing: "here's what we saw,
    check if you have it too."
    """
    clauses = []
    file_val = alert.get("file", "")
    if file_val and not file_val.startswith(("Attacker", "fake")):
        # Looks like a real file path, not a human-readable description
        escaped = file_val.replace("'", "\\'")
        clauses.append(f"[file:name = '{escaped}']")
    daddr = alert.get("daddr")
    if daddr and daddr not in ("local_process", None):
        clauses.append(f"[ipv4-addr:value = '{daddr}']")
    comm = alert.get("comm", "")
    if comm and not comm.startswith("detection:"):
        clauses.append(f"[process:name = '{comm}']")
    if not clauses:
        # Fallback: at minimum, indicate this rule_id fired -- STIX
        # requires SOME pattern, even a minimal one.
        clauses.append("[x-ghostit:rule_id = 'unknown']")
    return " OR ".join(clauses) if len(clauses) > 1 else clauses[0]

def to_stix_indicator(alert: dict) -> dict:
    """Convert a single Ghost IT alert into a STIX 2.1 Indicator object."""
    comm = alert.get("comm", "")
    if comm.startswith("detection:"):
        rule_id = comm.replace("detection:", "")
    else:
        # comm is a real process/monitor name (c15_monitor, canary, etc.),
        # not a rule ID -- the actual rule/trigger is in reasons instead
        # (e.g. 'ransomware_extension', 'canary_hit:http'). Take the
        # first reason as the rule identifier in this case.
        reasons = alert.get("reasons", [])
        rule_id = next((r for r in reasons if ":" not in r or r.split(":")[0] in
                        ("ransomware_extension", "high_entropy_write", "canary_hit")),
                       reasons[0] if reasons else "unknown")

    alert_id = str(alert.get("id", ""))
    stix_id = _deterministic_id("indicator", f"ghostit-{alert_id}")
    created = _stix_timestamp(alert.get("ts"))

    reasons = alert.get("reasons", [])
    description = alert.get("file", "Ghost IT confirmed detection")
    confidence_reason = next((r for r in reasons if r.startswith("confidence:")), None)
    confidence = int(confidence_reason.split(":")[1]) if confidence_reason else 75

    return {
        "type": "indicator",
        "spec_version": STIX_VERSION,
        "id": stix_id,
        "created": created,
        "modified": created,
        "created_by_ref": GHOST_IT_IDENTITY_ID,
        "name": f"Ghost IT detection: {rule_id}",
        "description": description[:500],
        "indicator_types": INDICATOR_LABELS.get(rule_id, ["unknown"]),
        "pattern": _build_pattern(alert),
        "pattern_type": "stix",
        "valid_from": created,
        "confidence": min(100, max(0, confidence)),
        "labels": [rule_id],
    }

def to_stix_bundle(alerts: list[dict]) -> dict:
    """
    Wrap multiple Indicators in a STIX Bundle -- the standard
    transport container for bulk STIX data (per OASIS spec section 8),
    what a TAXII server or India-CERT ingestion endpoint would
    actually receive.
    """
    identity = {
        "type": "identity",
        "spec_version": STIX_VERSION,
        "id": GHOST_IT_IDENTITY_ID,
        "created": _stix_timestamp(),
        "modified": _stix_timestamp(),
        "name": "Ghost Layer Technologies - Ghost IT",
        "identity_class": "organization",
        "sectors": ["technology"],
    }
    indicators = [to_stix_indicator(a) for a in alerts]
    return {
        "type": "bundle",
        "id": _deterministic_id("bundle", f"ghostit-export-{_stix_timestamp()}"),
        "objects": [identity] + indicators,
    }

if __name__ == "__main__":
    import json
    sample_alerts = [
        {
            "id": 1826659925151415,
            "comm": "detection:R001",
            "score": 100,
            "file": "Attacker accessed decoy asset: fake .env via HTTP",
            "reasons": ["R001", "Canary Token Triggered", "confidence:100"],
            "ts": 1783948480153361224,
        },
        {
            "id": 41696669,
            "comm": "c15_monitor",
            "score": 96,
            "file": "/tmp/ransomware_test2/file9.docx.locked",
            "reasons": ["file_entropy_delta:8.00", "ransomware_extension"],
            "ts": 1784095365720219238,
        },
    ]
    bundle = to_stix_bundle(sample_alerts)
    print(json.dumps(bundle, indent=2))
