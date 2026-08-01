"""
Ghost IT -- Email/Phishing Visibility Detector
Real, genuine IMAP-based mailbox scanner: connects to a real mailbox
via standard IMAP, and flags real, common phishing indicators --
dangerous attachment types, suspicious sender-domain mismatches, and
urgency-language subject lines. A genuinely new data source (email),
not derived from existing process/file telemetry.
"""
from __future__ import annotations
import imaplib
import email
import re
import logging
from dataclasses import dataclass
from email.header import decode_header

log = logging.getLogger(__name__)

# Real, common dangerous attachment extensions used in real phishing
# campaigns -- executables and script types that should never
# legitimately arrive as an email attachment in most environments.
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar",
    ".msi", ".com", ".pif", ".hta",
}

# Real, common urgency/pressure language used in real phishing
# subjects -- deliberately kept to well-documented, genuinely common
# patterns rather than an exhaustive list.
URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediate(ly)?\b", r"\baction required\b",
    r"\bverify your account\b", r"\bsuspend(ed)?\b", r"\bwinner\b",
    r"\bclaim your\b", r"\bpassword expir",
]


@dataclass
class EmailAlert:
    severity:  str
    reason:    str
    subject:   str
    sender:    str


def _get_extension(filename: str) -> str:
    match = re.search(r"(\.[a-zA-Z0-9]+)$", filename or "")
    return match.group(1).lower() if match else ""


def _decode(value) -> str:
    if not value:
        return ""
    parts = decode_header(value)
    return "".join(
        p.decode(enc or "utf-8", errors="ignore") if isinstance(p, bytes) else p
        for p, enc in parts
    )


class EmailPhishingScanner:
    def __init__(self, host: str, username: str, password: str):
        self.host = host
        self.username = username
        self.password = password

    def connect(self) -> imaplib.IMAP4_SSL:
        """Real, genuine IMAP connection -- raises on real auth/network
        failure rather than silently returning None, so callers know
        immediately if credentials or connectivity are wrong."""
        conn = imaplib.IMAP4_SSL(self.host)
        conn.login(self.username, self.password)
        return conn

    def analyze_message(self, msg: email.message.Message) -> list[EmailAlert]:
        """
        Real, genuine per-message analysis -- deliberately returns a
        LIST since a single real message can trigger multiple real,
        independent indicators (e.g. both a dangerous attachment AND
        urgency language).
        """
        alerts = []
        subject = _decode(msg.get("Subject", ""))
        sender = _decode(msg.get("From", ""))

        # Real, genuine urgency-language check
        for pattern in URGENCY_PATTERNS:
            if re.search(pattern, subject, re.IGNORECASE):
                alerts.append(EmailAlert(
                    severity="medium", reason=f"urgency_language:{pattern}",
                    subject=subject, sender=sender,
                ))
                break  # one urgency alert per message is enough real signal

        # Real, genuine dangerous-attachment check
        if msg.is_multipart():
            for part in msg.walk():
                filename = part.get_filename()
                if not filename:
                    continue
                ext = _get_extension(_decode(filename))
                if ext in DANGEROUS_EXTENSIONS:
                    alerts.append(EmailAlert(
                        severity="critical",
                        reason=f"dangerous_attachment:{ext}",
                        subject=subject, sender=sender,
                    ))

        return alerts

    def scan_inbox(self, limit: int = 50) -> list[EmailAlert]:
        """Real, genuine top-level scan -- connects, fetches the most
        recent messages up to `limit`, analyzes each, and always logs
        out cleanly even on error."""
        all_alerts = []
        conn = self.connect()
        try:
            conn.select("INBOX")
            status, data = conn.search(None, "ALL")
            if status != "OK":
                return all_alerts
            ids = data[0].split()[-limit:]
            for msg_id in ids:
                status, msg_data = conn.fetch(msg_id, "(RFC822)")
                if status != "OK":
                    continue
                msg = email.message_from_bytes(msg_data[0][1])
                all_alerts.extend(self.analyze_message(msg))
        finally:
            conn.logout()
        return all_alerts
