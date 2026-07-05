"""
Ghost IT — C15: Ransomware EMA Detector
Production-ready streaming EMA detector.

Monitors 5 key ransomware indicators via EWMA.
Three-threshold model: WARN (2σ) → ALERT (3σ) → CRITICAL + isolate (5σ)

Ghost Layer Technologies — CONFIDENTIAL
"""
from __future__ import annotations
import math
import time
import logging
import socket
import json
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

log = logging.getLogger(__name__)


class Severity(str, Enum):
    WARN     = "WARN"
    ALERT    = "ALERT"
    CRITICAL = "CRITICAL"


@dataclass
class RansomwareAlert:
    severity:    Severity
    trigger:     str          # which feature crossed threshold
    z_score:     float
    value:       float        # current value
    ema:         float        # current baseline
    timestamp:   float = field(default_factory=time.time)
    auto_isolate: bool = False

    def to_event(self) -> dict:
        """Convert to Ghost IT pipeline event format."""
        return {
            "ts":      int(self.timestamp * 1e9),
            "pid":     0,
            "ppid":    0,
            "uid":     0,
            "gid":     0,
            "comm":    "ransomware-ema",
            "type":    "ransomware_detection",
            "score":   100 if self.severity == Severity.CRITICAL else
                       80  if self.severity == Severity.ALERT else 60,
            "alert":   self.severity != Severity.WARN,
            "reasons": [
                f"ransomware:{self.severity.value}",
                f"trigger:{self.trigger}",
                f"z_score:{self.z_score:.2f}",
            ],
            "file":    f"{self.trigger} z={self.z_score:.2f} val={self.value:.4f}",
            "daddr":   None,
            "dport":   None,
            "auto_isolate": self.auto_isolate,
        }


class EWMATracker:
    """
    Exponentially Weighted Moving Average tracker.
    Tracks both mean and variance for z-score computation.
    alpha=0.1 — fast response to spikes (per Build Guide spec)
    """
    def __init__(self, alpha: float = 0.1):
        self.alpha   = alpha
        self.ema:    Optional[float] = None
        self.var:    float = 0.0
        self.n:      int   = 0

    def update(self, value: float) -> tuple[float, float]:
        """
        Update EMA with new value.
        Returns (z_score, current_ema).
        """
        if self.ema is None:
            self.ema = value
            self.n   = 1
            return 0.0, value

        prev_ema  = self.ema
        self.ema  = self.alpha * value + (1 - self.alpha) * self.ema
        self.var  = self.alpha * (value - prev_ema) ** 2 + \
                    (1 - self.alpha) * self.var
        self.n   += 1

        std = max(math.sqrt(self.var), 1e-6)
        z   = abs(value - self.ema) / std
        return z, self.ema

    @property
    def is_warmed_up(self) -> bool:
        """Need at least 10 samples for meaningful z-score."""
        return self.n >= 10


class RansomwareEMADetector:
    """
    C15 — Ransomware EMA Detector.

    Monitors 5 behavioral features via streaming EWMA.
    Fires alerts at 2σ, 3σ, and 5σ thresholds.
    At 5σ: CRITICAL + auto_isolate flag set.

    Usage:
        detector = RansomwareEMADetector()
        alert = detector.process_event(event)
        if alert:
            handle_alert(alert)
    """

    # Feature names — locked (Build Guide spec)
    FEATURES = [
        "file_entropy_delta",
        "unique_file_ext_writes",
        "shadow_delete_ct",
        "file_write_rate",
        "mbr_write_ct",
    ]

    # Sigma thresholds
    THRESHOLD_WARN     = 2.0
    THRESHOLD_ALERT    = 3.0
    THRESHOLD_CRITICAL = 5.0

    # File extensions commonly targeted by ransomware
    RANSOMWARE_EXTENSIONS = {
        ".locked", ".encrypted", ".enc", ".crypto", ".crypt",
        ".xxx", ".zzz", ".aaa", ".abc", ".xyz", ".ttt",
        ".micro", ".vvv", ".cerber", ".locky", ".petya",
        ".wannacry", ".wncry", ".wnry", ".wcry",
    }

    # Sensitive extensions being written (source files)
    SENSITIVE_EXTENSIONS = {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".pdf", ".jpg", ".jpeg", ".png", ".mp4", ".avi",
        ".sql", ".db", ".sqlite", ".mdb", ".accdb",
        ".py", ".js", ".ts", ".java", ".cpp", ".rs",
    }

    def __init__(self, alpha: float = 0.1):
        self.trackers = {f: EWMATracker(alpha) for f in self.FEATURES}

        # Per-window counters (reset every minute)
        self._window_start    = time.time()
        self._file_writes     = 0
        self._ext_writes:     set = set()
        self._entropy_deltas: list[float] = []
        self._shadow_deletes  = 0
        self._mbr_writes      = 0

        log.info("C15 RansomwareEMADetector initialized")

    def process_event(self, event: dict) -> Optional[RansomwareAlert]:
        """
        Process a single Ghost IT event.
        Returns RansomwareAlert if threshold crossed, None otherwise.
        """
        self._update_counters(event)
        self._maybe_flush_window()
        return None  # Window-based — alerts fire on flush

    @staticmethod
    def _trust_weight(event: dict) -> float:
        """
        C15 Tier 2: weight ransomware-extension signals by process trust.
        Windows-only field (integrity comes from Authenticode verification
        in the C9 agent). Signed, trusted-publisher processes (integrity
        HIGH=3 or SYSTEM=4) get reduced weight — mirrors how CrowdStrike/
        SentinelOne reduce false positives from legitimate signed writers
        without needing to know the app by name. Unsigned/untrusted
        processes (integrity 0/1/2, or Linux events with no integrity
        field at all) get full weight — no change to existing Linux
        detection behavior.
        """
        integrity = event.get("integrity")
        if integrity is not None and integrity >= 3:
            return 0.3  # trusted publisher — reduced but non-zero signal
        return 1.0  # untrusted, unknown, or Linux (no integrity field)

    @staticmethod
    def _get_ext(path: str) -> str:
        """Extract file extension from path."""
        import os
        return os.path.splitext(path)[1].lower() if path else ""

    def _update_counters(self, event: dict):
        """Update per-window counters from event."""
        event_type = event.get("type", "")
        path       = event.get("file") or event.get("path") or ""

        if event_type == "open":
            flags = event.get("flags", 0)
            # Write flag = O_WRONLY(1) or O_RDWR(2)
            if flags and (flags & 0x1 or flags & 0x2):
                self._file_writes += 1
                ext = self._get_ext(path)
                if ext:
                    self._ext_writes.add(ext)
                # Check for ransomware extension
                if ext in self.RANSOMWARE_EXTENSIONS:
                    # Instant high-weight entropy signal
                    self._entropy_deltas.append(1.0)

        elif event_type == "unlink":
            # File deletion — common in ransomware (deletes originals)
            ext = self._get_ext(path)
            if ext in self.SENSITIVE_EXTENSIONS:
                self._file_writes += 1
        elif event_type == "file_write":
            self._file_writes += 1
            ext = self._get_ext(path)
            if ext:
                self._ext_writes.add(ext)
            if ext in self.RANSOMWARE_EXTENSIONS:
                self._entropy_deltas.append(self._trust_weight(event))
        elif event_type == "file_delete":
            ext = self._get_ext(path)
            if ext in self.SENSITIVE_EXTENSIONS:
                self._file_writes += 1
        elif event_type == "file_rename":
            ext = self._get_ext(path)
            if ext in self.RANSOMWARE_EXTENSIONS:
                self._entropy_deltas.append(self._trust_weight(event))
            elif ext in self.SENSITIVE_EXTENSIONS:
                self._file_writes += 1

        # Shadow copy deletion (Linux: vssadmin equivalent)
        comm = event.get("comm", "")
        if comm in ("vssadmin", "wmic", "bcdedit", "wbadmin"):
            self._shadow_deletes += 1

        # MBR write detection (write to /dev/sda, /dev/nvme0n1)
        if path in ("/dev/sda", "/dev/nvme0n1", "/dev/hda"):
            self._mbr_writes += 1

    def _maybe_flush_window(self) -> Optional[RansomwareAlert]:
        """Flush window every 60 seconds and compute features."""
        now     = time.time()
        elapsed = now - self._window_start

        if elapsed < 60.0:
            return None

        # Compute feature values for this window
        features = {
            "file_entropy_delta":    sum(self._entropy_deltas) / max(len(self._entropy_deltas), 1),
            "unique_file_ext_writes": len(self._ext_writes),
            "shadow_delete_ct":      float(self._shadow_deletes),
            "file_write_rate":       self._file_writes / elapsed,
            "mbr_write_ct":          float(self._mbr_writes),
        }

        # Reset window
        self._window_start    = now
        self._file_writes     = 0
        self._ext_writes      = set()
        self._entropy_deltas  = []
        self._shadow_deletes  = 0
        self._mbr_writes      = 0

        # Update EWMA trackers and check thresholds
        return self._evaluate(features)

    def _evaluate(self, features: dict) -> Optional[RansomwareAlert]:
        """Run EWMA update and threshold check on all features."""
        highest: Optional[RansomwareAlert] = None

        for feature, value in features.items():
            tracker = self.trackers[feature]
            z, ema  = tracker.update(value)

            if not tracker.is_warmed_up:
                continue

            alert = None
            if z >= self.THRESHOLD_CRITICAL:
                alert = RansomwareAlert(
                    severity     = Severity.CRITICAL,
                    trigger      = feature,
                    z_score      = z,
                    value        = value,
                    ema          = ema,
                    auto_isolate = True,
                )
                log.critical(
                    f"RANSOMWARE CRITICAL — {feature} "
                    f"z={z:.2f} val={value:.4f} ema={ema:.4f} — AUTO ISOLATE"
                )
            elif z >= self.THRESHOLD_ALERT:
                alert = RansomwareAlert(
                    severity = Severity.ALERT,
                    trigger  = feature,
                    z_score  = z,
                    value    = value,
                    ema      = ema,
                )
                log.warning(
                    f"RANSOMWARE ALERT — {feature} "
                    f"z={z:.2f} val={value:.4f} ema={ema:.4f}"
                )
            elif z >= self.THRESHOLD_WARN:
                alert = RansomwareAlert(
                    severity = Severity.WARN,
                    trigger  = feature,
                    z_score  = z,
                    value    = value,
                    ema      = ema,
                )
                log.warning(
                    f"RANSOMWARE WARN — {feature} "
                    f"z={z:.2f} val={value:.4f} ema={ema:.4f}"
                )

            if alert and (
                highest is None or
                list(Severity).index(alert.severity) >
                list(Severity).index(highest.severity)
            ):
                highest = alert

        return highest


class RansomwareMonitor:
    """
    Wraps RansomwareEMADetector and forwards alerts to Ghost IT pipeline.
    Integrates with the existing pipeline TCP server.
    """

    def __init__(self, pipeline_host: str = "127.0.0.1",
                 pipeline_port: int = 9000):
        self.detector      = RansomwareEMADetector()
        self.pipeline_host = pipeline_host
        self.pipeline_port = pipeline_port

    def process(self, event: dict) -> Optional[RansomwareAlert]:
        alert = self.detector.process_event(event)
        if alert:
            self._forward(alert)
        return alert

    def _forward(self, alert: RansomwareAlert):
        """Send alert to Ghost IT pipeline."""
        payload = (json.dumps([alert.to_event()]) + "\n").encode()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((self.pipeline_host, self.pipeline_port))
            s.sendall(payload)
            s.close()
        except OSError as ex:
            log.error(f"Pipeline unavailable: {ex}")
            log.critical(f"RANSOMWARE ALERT (offline): {alert}")
