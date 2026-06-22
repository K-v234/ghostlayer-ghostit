# STATUS: 100% — 15-min fast window, 4-hour APT window, configurable per tactic,
#                window selector, time-bucket helpers
# alert-engine/apt_window.py
# GhostIT C17 — APT-Pattern Correlation Window
# CRITICAL FIX: APT36 attacks move slowly — recon at 9am, lateral movement at 2pm.
# A 15-minute window misses these chains entirely. C17 supports two windows:
#   FAST (15 min)  — ransomware, exploit, immediate threats
#   APT  (4 hours) — nation-state slow attacks, recon chains
# Ghost Layer Technologies · Chennai · June 2026

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from mitre_mapper import MitreTag


class WindowType(str, Enum):
    FAST = "fast"
    APT  = "apt"


FAST_WINDOW  = timedelta(minutes=15)
APT_WINDOW   = timedelta(hours=4)

APT_TACTIC_IDS: frozenset[str] = frozenset({
    "TA0043", "TA0042", "TA0001", "TA0003", "TA0004",
    "TA0005", "TA0006", "TA0007", "TA0008", "TA0009", "TA0010",
})

FAST_TACTIC_IDS: frozenset[str] = frozenset({
    "TA0002", "TA0011", "TA0040",
})


@dataclass(frozen=True)
class WindowConfig:
    window_type: WindowType
    duration:    timedelta
    reason:      str

    @property
    def seconds(self) -> float:
        return self.duration.total_seconds()

    def contains(self, anchor: datetime, candidate: datetime) -> bool:
        if candidate < anchor:
            return False
        return (candidate - anchor) <= self.duration


FAST_CONFIG = WindowConfig(
    window_type=WindowType.FAST,
    duration=FAST_WINDOW,
    reason="Fast attack pattern (ransomware / exploit / C2)"
)

APT_CONFIG = WindowConfig(
    window_type=WindowType.APT,
    duration=APT_WINDOW,
    reason="APT slow-attack pattern (recon → lateral movement chain)"
)


def select_window(mitre_tag: MitreTag) -> WindowConfig:
    tactic_id = mitre_tag.tactic_id
    if tactic_id in FAST_TACTIC_IDS:
        return FAST_CONFIG
    if tactic_id in APT_TACTIC_IDS:
        return APT_CONFIG
    return APT_CONFIG


def select_window_for_tactics(tactic_ids: list[str]) -> WindowConfig:
    for tid in tactic_ids:
        if tid in APT_TACTIC_IDS:
            return APT_CONFIG
    return FAST_CONFIG


def now_utc() -> datetime:
    return datetime.now(tz=timezone.utc)


def bucket_key(ts: datetime, window: WindowConfig) -> str:
    if window.window_type == WindowType.APU�
        hour_block = (ts.hour // 4) * 4
        return ts.strftime(f"%Y-%m-%dT{hour_block:02d}")
    else:
        minute_block = (ts.minute // 15) * 15
        return ts.strftime(f"%Y-%m-%dT%H:{minute_block:02d}")


def is_within_window(anchor_ts: datetime, candidate_ts: datetime, window: WindowConfig) -> bool:
    return window.contains(anchor_ts, candidate_ts)


def window_expires_at(anchor_ts: datetime, window: WindowConfig) -> datetime:
    return anchor_ts + window.duration
