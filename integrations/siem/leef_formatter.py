#!/usr/bin/env python3
"""
Ghost IT — V2: SIEM Export (LEEF Format)
Converts Ghost IT alerts to LEEF (Log Event Extended Format), the
format IBM QRadar uses natively. Per IBM's official spec:
LEEF:Version|Vendor|Product|ProductVersion|EventID|key1=value1<TAB>key2=value2...
"""
from __future__ import annotations
from datetime import datetime, timezone

LEEF_VERSION = "2.0"
VENDOR       = "GhostLayerTechnologies"
PRODUCT      = "GhostIT"
PRODUCT_VERSION = "1.5"

SEVERITY_MAP = {
    "critical": 10,
    "high":     8,
    "medium":   5,
    "low":      3,
    "info":     1,
}

def _leef_escape(value) -> str:
    if value is None:
        return ""
    return str(value).replace("\t", " ").replace("=", "\\=")

def to_leef(alert: dict) -> str:
    rule_id = alert.get("comm", "").replace("detection:", "") or \
              (alert.get("reasons", ["UNKNOWN"])[0] if alert.get("reasons") else "UNKNOWN")

    severity_str = "critical" if alert.get("score", 0) >= 90 else \
                    "high" if alert.get("score", 0) >= 70 else \
                    "medium" if alert.get("score", 0) >= 40 else "low"
    sev = SEVERITY_MAP.get(severity_str, 5)

    header = "|".join([
        f"LEEF:{LEEF_VERSION}",
        VENDOR,
        PRODUCT,
        PRODUCT_VERSION,
        rule_id,
    ])

    ts = alert.get("ts")
    if ts:
        try:
            dt = datetime.fromtimestamp(ts / 1e9, tz=timezone.utc)
            devtime = dt.strftime("%b %d %Y %H:%M:%S")
        except Exception:
            devtime = datetime.now(timezone.utc).strftime("%b %d %Y %H:%M:%S")
    else:
        devtime = datetime.now(timezone.utc).strftime("%b %d %Y %H:%M:%S")

    attrs = {
        "devTime": devtime,
        "devTimeFormat": "MMM dd yyyy HH:mm:ss",
        "sev": sev,
        "src": alert.get("source_ip", ""),
        "dst": alert.get("daddr", ""),
        "dstPort": alert.get("dport", ""),
        "identHostName": alert.get("host", "unknown"),
        "cat": rule_id,
        "usrName": str(alert.get("pid", "")),
        "ghostit_evidence": alert.get("file", "")[:500],
        "ghostit_reasons": ",".join(alert.get("reasons", []))[:500],
        "ghostit_score": alert.get("score", 0),
    }

    attr_str = "\t".join(
        f"{k}={_leef_escape(v)}" for k, v in attrs.items() if v != ""
    )

    return f"{header}|{attr_str}"

if __name__ == "__main__":
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
    print(to_leef(sample))
