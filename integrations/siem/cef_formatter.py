#!/usr/bin/env python3
"""
Ghost IT — V2: SIEM Export (CEF Format)
Converts Ghost IT detection events into Common Event Format (CEF),
the standard format understood by Microsoft Sentinel, ArcSight, and
many other SIEM platforms. This is the first of three planned SIEM
exporters (CEF for Sentinel, LEEF for QRadar, CIM-compliant JSON for
Splunk) -- CEF chosen first for broadest compatibility.

CEF format: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Extension
"""
from __future__ import annotations
import json
from datetime import datetime, timezone

CEF_VERSION = "0"
VENDOR      = "GhostLayerTechnologies"
PRODUCT     = "GhostIT"
PRODUCT_VERSION = "1.5"

# Map Ghost IT severity strings to CEF's 0-10 numeric scale
SEVERITY_MAP = {
    "critical": 10,
    "high":     8,
    "medium":   5,
    "low":      3,
    "info":     1,
}

def _cef_escape(value: str) -> str:
    """CEF requires escaping pipes and backslashes in header fields,
    and equals signs/backslashes in extension values."""
    if value is None:
        return ""
    return str(value).replace("\\", "\\\\").replace("|", "\\|")

def _cef_escape_ext(value: str) -> str:
    if value is None:
        return ""
    return str(value).replace("\\", "\\\\").replace("=", "\\=")

def to_cef(alert: dict) -> str:
    """
    Convert a Ghost IT alert/detection dict into a single CEF-formatted
    log line, ready to be sent to any CEF-compatible SIEM (Sentinel,
    ArcSight, etc.) via syslog or file forwarding.
    """
    rule_id  = alert.get("comm", "").replace("detection:", "") or alert.get("reasons", ["UNKNOWN"])[0]
    title    = alert.get("reasons", ["Ghost IT Detection"])
    title    = title[1] if len(title) > 1 else (title[0] if title else "Ghost IT Detection")
    severity_str = "critical" if alert.get("score", 0) >= 90 else \
                    "high" if alert.get("score", 0) >= 70 else \
                    "medium" if alert.get("score", 0) >= 40 else "low"
    severity = SEVERITY_MAP.get(severity_str, 5)

    header = "|".join([
        f"CEF:{CEF_VERSION}",
        _cef_escape(VENDOR),
        _cef_escape(PRODUCT),
        _cef_escape(PRODUCT_VERSION),
        _cef_escape(rule_id),
        _cef_escape(title),
        str(severity),
    ])

    ts = alert.get("ts")
    if ts:
        try:
            dt = datetime.fromtimestamp(ts / 1e9, tz=timezone.utc)
            rt = dt.strftime("%b %d %Y %H:%M:%S")
        except Exception:
            rt = datetime.now(timezone.utc).strftime("%b %d %Y %H:%M:%S")
    else:
        rt = datetime.now(timezone.utc).strftime("%b %d %Y %H:%M:%S")

    extensions = {
        "rt": rt,
        "dvc": alert.get("host", "unknown"),
        "src": alert.get("source_ip", ""),
        "dpt": alert.get("dport", ""),
        "dst": alert.get("daddr", ""),
        "spid": alert.get("pid", ""),
        "cs1": alert.get("file", "")[:500],
        "cs1Label": "GhostITEvidence",
        "cs2": ",".join(alert.get("reasons", []))[:500],
        "cs2Label": "GhostITReasons",
        "cn1": alert.get("score", 0),
        "cn1Label": "GhostITScore",
    }
    ext_str = " ".join(
        f"{k}={_cef_escape_ext(v)}" for k, v in extensions.items() if v != ""
    )

    return f"{header}|{ext_str}"

if __name__ == "__main__":
    # Quick self-test with a realistic sample alert
    sample = {
        "comm": "detection:R001",
        "score": 100,
        "host": "linux",
        "source_ip": "172.18.0.4",
        "pid": 12345,
        "file": "Attacker accessed decoy asset: fake .env via HTTP",
        "reasons": ["R001", "Canary Token Triggered", "confidence:100"],
        "ts": 1783948480153361224,
    }
    print(to_cef(sample))
