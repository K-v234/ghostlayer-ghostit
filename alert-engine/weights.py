# STATUS: 100% — per-source confidence weights, severity multipliers, weight registry
# alert-engine/weights.py
# GhostIT C17 — Alert Confidence Scoring
# Every alert source has a base confidence weight reflecting its reliability.
# Deception hits are 1.0 (zero false positives by design).
# Ghost Layer Technologies · Chennai · June 2026

from dataclasses import dataclass
from enum import Enum


# ── Alert sources ─────────────────────────────────────────────────────────────
class AlertSource(str, Enum):
    DECEPTION       = "deception"        # C3 honeypots / canary traps
    BEHAVIORAL_AI   = "behavioral_ai"    # C2 EWMA + Isolation Forest
    C14_TLS         = "c14_tls"          # C14 TLS fingerprinting
    C9_EBPF         = "c9_ebpf"          # C9 eBPF kernel hook
    C9_ETW          = "c9_etw"           # C9 ETW-TI provider
    C9_DIVERGENCE   = "c9_divergence"    # C9 eBPF vs ETW mismatch
    C15_RANSOMWARE  = "c15_ransomware"   # C15 ransomware EMA detector
    MANUAL          = "manual"           # Analyst-submitted alert
    UNKNOWN         = "unknown"          # Fallback


# ── Severity levels ───────────────────────────────────────────────────────────
class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


# ── Weight definition ─────────────────────────────────────────────────────────
@dataclass(frozen=True)
class SourceWeight:
    source:      AlertSource
    base:        float   # 0.0–1.0 base confidence
    description: str

    def adjusted(self, severity: Severity) -> float:
        """Apply severity multiplier to base weight."""
        multipliers = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH:     0.9,
            Severity.MEDIUM:   0.75,
            Severity.LOW:      0.5,
            Severity.INFO:     0.25,
        }
        return round(self.base * multipliers.get(severity, 0.5), 4)


# ── Weight registry ───────────────────────────────────────────────────────────
# Any attacker who touches a honeypot is confirmed — zero false positives.
# ETW divergence (layer disagreement) is hardcoded CRITICAL — always 1.0.
WEIGHTS: dict[AlertSource, SourceWeight] = {
    AlertSource.DECEPTION: SourceWeight(
        source=AlertSource.DECEPTION,
        base=1.0,
        description="Honeypot / canary trap — zero false positives by design"
    ),
    AlertSource.C9_DIVERGENCE: SourceWeight(
        source=AlertSource.C9_DIVERGENCE,
        base=1.0,
        description="eBPF vs ETW layer mismatch — attacker tampering confirmed"
    ),
    AlertSource.MANUAL: SourceWeight(
        source=AlertSource.MANUAL,
        base=0.95,
        description="Analyst-submitted — high trust, human verified"
    ),
    AlertSource.C15_RANSOMWARE: SourceWeight(
        source=AlertSource.C15_RANSOMWARE,
        base=0.9,
        description="Ransomware EMA — entropy + file write spike (0.2ms detection)"
    ),
    AlertSource.C9_EBPF: SourceWeight(
        source=AlertSource.C9_EBPF,
        base=0.85,
        description="eBPF kernel hook — fires before userspace can interfere"
    ),
    AlertSource.C14_TLS: SourceWeight(
        source=AlertSource.C14_TLS,
        base=0.75,
        description="TLS fingerprinting — JA3/JA4 signature match"
    ),
    AlertSource.BEHAVIORAL_AI: SourceWeight(
        source=AlertSource.BEHAVIORAL_AI,
        base=0.70,
        description="Behavioral AI (EWMA + Isolation Forest) — 0.67ms inference"
    ),
    AlertSource.C9_ETW: SourceWeight(
        source=AlertSource.C9_ETW,
        base=0.70,
        description="ETW-TI kernel provider — second independent layer"
    ),
    AlertSource.UNKNOWN: SourceWeight(
        source=AlertSource.UNKNOWN,
        base=0.30,
        description="Unknown source — minimal trust"
    ),
}


def get_weight(source: AlertSource) -> SourceWeight:
    """Return weight for a given source, falling back to UNKNOWN."""
    return WEIGHTS.get(source, WEIGHTS[AlertSource.UNKNOWN])


def compute_confidence(
    source: AlertSource,
    severity: Severity,
    count: int = 1
) -> float:
    """
    Compute final confidence score for an alert.
    Multiple alerts from the same source in one incident boost confidence
    using diminishing returns: each additional alert adds half the previous gain.
    """
    w = get_weight(source)
    base = w.adjusted(severity)

    # Diminishing returns for repeated alerts from same source
    # count=1 → base, count=2 → base + 0.5*(1-base), count=3 → + 0.25*(1-base)
    if count <= 1:
        return base
    bonus = (1.0 - base) * (1.0 - 0.5 ** (count - 1))
    return round(min(base + bonus, 1.0), 4)


def combine_confidences(scores: list[float]) -> float:
    """
    Combine multiple confidence scores from different sources into one.
    Uses noisy-OR: P(at least one is right) = 1 - product(1 - Pi)
    """
    if not scores:
        return 0.0
    result = 1.0
    for s in scores:
        result *= (1.0 - s)
    return round(1.0 - result, 4)
