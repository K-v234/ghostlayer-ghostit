#!/usr/bin/env python3
"""
Ghost IT — V2: SIEM Export (Splunk CIM-compliant JSON)
Converts Ghost IT alerts into Splunk's Common Information Model (CIM)
"Alerts" data model field names, delivered as JSON suitable for the
Splunk HTTP Event Collector (HEC) -- the standard modern ingestion
path for Splunk, replacing older syslog-based methods.
"""
from __future__ import annotations
from datetime import datetime, timezone
import json

VENDOR_PRODUCT = "GhostLayerTechnologies GhostIT"

def to_splunk_cim(alert: dict) -> dict:
    """
    Convert a Ghost IT alert/detection dict into a Splunk HEC event
    payload, with CIM Alerts data model fields in the 'event' body.
    """
    rule_id = alert.get("comm", "").replace("detection:", "") or \
              (alert.get("reasons", ["UNKNOWN"])[0] if alert.get("reasons") else "UNKNOWN")

    severity_str = "critical" if alert.get("score", 0) >= 90 else \
                    "high" if alert.get("score", 0) >= 70 else \
                    "medium" if alert.get("score", 0) >= 40 else "low"

    ts = alert.get("ts")
    epoch_time = ts / 1e9 if ts else datetime.now(timezone.utc).timestamp()

    # CIM Alerts data model fields
    cim_event = {
        "signature": rule_id,
        "signature_id": rule_id,
        "severity": severity_str,
        "app": "ghostit",
        "vendor_product": VENDOR_PRODUCT,
        "src": alert.get("source_ip", ""),
        "dest": alert.get("daddr", "") or alert.get("host", ""),
        "dvc": alert.get("host", "unknown"),
        "user": str(alert.get("pid", "")) if alert.get("pid") else "",
        "action": "detected",
        "description": alert.get("file", ""),
        # Ghost IT-specific extensions beyond the base CIM fields --
        # Splunk's flexible JSON ingestion handles extra fields fine,
        # they just won't be part of the standard CIM search unless
        # explicitly mapped by the customer's Splunk admin.
        "ghostit_reasons": alert.get("reasons", []),
        "ghostit_score": alert.get("score", 0),
        "ghostit_alert_id": alert.get("id"),
    }

    return {
        "time": epoch_time,
        "host": alert.get("host", "unknown"),
        "source": "ghostit",
        "sourcetype": "ghostit:alert",
        "event": cim_event,
    }

if __name__ == "__main__":
    sample = {
        "id": 1826659925151415,
        "comm": "detection:R001",
        "score": 100,
        "host": "linux",
        "source_ip": "172.18.0.4",
        "pid": 12345,
        "file": "Attacker accessed decoy asset: fake .env via HTTP",
        "reasons": ["R001", "Canary Token Triggered", "confidence:100"],
        "ts": 1783948480153361224,
    }
    print(json.dumps(to_splunk_cim(sample), indent=2))
