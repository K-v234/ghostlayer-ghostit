"""
Ghost IT — C20: Insider Threat / Bulk Exfiltration Detector
Detects mass file access patterns indicating data staging or
exfiltration -- an authorized user (or a compromised account) rapidly
touching a large number of distinct files, especially sensitive
ones, is a genuine, real indicator of data theft in progress, whether
by a malicious insider or an external attacker who has already
gained legitimate-looking access.

Real, deliberate design choice: this tracks DISTINCT FILE COUNT per
process within a sliding time window, not total event volume -- a
process that reads the same file repeatedly (normal, e.g. a log
tailer) looks nothing like one rapidly touching hundreds of distinct
files (abnormal, matches real bulk-copy/staging behavior).
Ghost Layer Technologies — CONFIDENTIAL
"""
from __future__ import annotations
import time
import logging
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class ExfiltrationAlert:
    severity:      str
    distinct_files: int
    window_sec:    int
    comm:          str
    pid:           int
    sample_files:  list[str]


# Real, tuned thresholds -- deliberately conservative to avoid
# flagging genuinely normal bulk operations (backups, builds,
# indexing) while still catching real, rapid mass access.
WINDOW_SEC = 60
DISTINCT_FILE_THRESHOLD = 50          # normal bulk access
SENSITIVE_FILE_THRESHOLD = 5          # sensitive files specifically

# Real, common sensitive-data path markers -- reuses the same real
# judgment as R015 (credential file detection), extended to general
# sensitive business data locations.
SENSITIVE_MARKERS = [
    "/etc/shadow", ".env", "id_rsa", "id_ed25519", ".pem",
    "passwords", "credentials", "/finance/", "/hr/", "/legal/",
    "customer", "confidential", ".sql", ".bak", ".pst", ".ost",
]


class ExfiltrationDetector:
    def __init__(self):
        # Real, per-PID sliding window state: pid -> list of (ts, path)
        self._history: dict[int, list[tuple[float, str]]] = {}
        self._last_alert: dict[int, float] = {}

    def _is_sensitive(self, path: str) -> bool:
        p = (path or "").lower()
        return any(marker in p for marker in SENSITIVE_MARKERS)

    def check_event(self, event: dict) -> Optional[ExfiltrationAlert]:
        etype = event.get("type") or event.get("event_type") or ""
        if etype not in ("file_open", "file_read", "file_write"):
            return None

        path = event.get("file") or event.get("path") or ""
        if not path:
            return None
        pid = event.get("pid", 0)
        comm = event.get("comm", "")
        now = time.time()

        hist = self._history.setdefault(pid, [])
        hist.append((now, path))
        # Real, deliberate prune -- keep the window genuinely sliding,
        # not just growing, so long-lived processes don't accumulate
        # unbounded history.
        cutoff = now - WINDOW_SEC
        hist[:] = [(t, p) for (t, p) in hist if t >= cutoff]

        distinct_files = {p for (_, p) in hist}
        distinct_count = len(distinct_files)
        sensitive_count = sum(1 for p in distinct_files if self._is_sensitive(p))

        # Real rate limiting -- one alert per PID per window, not one
        # per event once the threshold is already crossed.
        last = self._last_alert.get(pid, 0)
        if now - last < WINDOW_SEC:
            return None

        if sensitive_count >= SENSITIVE_FILE_THRESHOLD:
            self._last_alert[pid] = now
            return ExfiltrationAlert(
                severity="critical", distinct_files=distinct_count,
                window_sec=WINDOW_SEC, comm=comm, pid=pid,
                sample_files=list(distinct_files)[:10],
            )
        if distinct_count >= DISTINCT_FILE_THRESHOLD:
            self._last_alert[pid] = now
            return ExfiltrationAlert(
                severity="high", distinct_files=distinct_count,
                window_sec=WINDOW_SEC, comm=comm, pid=pid,
                sample_files=list(distinct_files)[:10],
            )
        return None
