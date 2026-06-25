# STATUS: 100% — PII detection, dpdp_pii_flag tagging, scan comm/path fields
# compliance/pii_detector.py
# GhostIT C12 — DPDP PII Detector
# Scans event comm and path fields for PII patterns, sets dpdp_pii_flag
# Ghost Layer Technologies · Chennai · June 2026

import re
from dataclasses import dataclass

# PII patterns — Indian context (Aadhaar, PAN, phone, email, passport)
_PII_PATTERNS = [
    re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),          # Aadhaar
    re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b'),                    # PAN card
    re.compile(r'\b[6-9]\d{9}\b'),                             # Indian mobile
    re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),  # Email
    re.compile(r'\b[A-Z]\d{7}\b'),                             # Passport
    re.compile(r'\b\d{2}-\d{7}-\d\b'),                        # Voter ID pattern
]

_SENSITIVE_PATHS = [
    "/etc/shadow", "/etc/passwd", "/proc/", "id_rsa",
    ".ssh/", ".aws/credentials", ".env", "web.config",
    "password", "passwd", "secret", "token", "private_key",
]

@dataclass
class PIIResult:
    flagged: bool
    reason:  str = ""

def scan_event(event: dict) -> PIIResult:
    """Scan a single event dict for PII in comm and path fields."""
    fields = [
        event.get("comm", "") or "",
        event.get("path", "") or "",
        event.get("file", "") or "",
        event.get("daddr", "") or "",
    ]
    text = " ".join(fields)

    for pat in _PII_PATTERNS:
        if pat.search(text):
            return PIIResult(flagged=True, reason=f"PII pattern match: {pat.pattern[:30]}")

    text_lower = text.lower()
    for sp in _SENSITIVE_PATHS:
        if sp in text_lower:
            return PIIResult(flagged=True, reason=f"Sensitive path: {sp}")

    return PIIResult(flagged=False)

def tag_event(event: dict) -> dict:
    """Return event with dpdp_pii_flag set. Non-destructive."""
    result = scan_event(event)
    event = dict(event)
    event["dpdp_pii_flag"] = result.flagged
    if result.flagged:
        # Never redact canary events — they need file path for investigation
        if event.get("type") not in ("canary_hit", "canary"):
            event["file"] = "[REDACTED-PII]" if event.get("file") else event.get("file")
    return event

# Singleton
pii_detector = type("PIIDetector", (), {
    "scan":     staticmethod(scan_event),
    "tag":      staticmethod(tag_event),
})()
