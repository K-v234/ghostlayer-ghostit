"""
Ghost IT — C17: Component Confidence Weights
Per PRD v5.0 and Tech Spec v3.0.

Higher weight = higher confidence = lower FP rate.
Deception and kernel integrity have near-zero FP by definition.

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 100% — complete
"""
from enum import Enum

class AlertSource(str, Enum):
    DECEPTION        = "deception"
    KERNEL_INTEGRITY = "kernel_integrity"
    INTEL_PT         = "intel_pt"
    RANSOMWARE_EMA   = "ransomware_ema"
    CAUSAL_ENGINE    = "causal_engine"
    C2_DETECTOR      = "c2_detector"
    BEHAVIORAL_AI    = "behavioral_ai"
    PMU_COUNTERS     = "pmu_counters"
    LOLBIN           = "lolbin"
    DNS_ANALYZER     = "dns_analyzer"
    DOH_ANALYZER     = "doh_analyzer"
    JA4_FINGERPRINT  = "ja4_fingerprint"
    CANARY           = "canary"

COMPONENT_WEIGHTS = {
    AlertSource.DECEPTION:        1.0,  # Near-zero FP — attacker must touch honeypot
    AlertSource.KERNEL_INTEGRITY: 1.0,  # Near-zero FP — LKRG
    AlertSource.INTEL_PT:         0.95, # Deterministic
    AlertSource.RANSOMWARE_EMA:   0.90, # High confidence EMA
    AlertSource.CAUSAL_ENGINE:    0.80, # GNN ensemble
    AlertSource.C2_DETECTOR:      0.75, # JA4+ reliable
    AlertSource.JA4_FINGERPRINT:  0.75, # Same as C2
    AlertSource.LOLBIN:           0.75, # Pattern matching
    AlertSource.BEHAVIORAL_AI:    0.70, # Dual baseline reduces FP
    AlertSource.DNS_ANALYZER:     0.70, # Entropy-based
    AlertSource.DOH_ANALYZER:     0.65, # Behavioral
    AlertSource.PMU_COUNTERS:     0.60, # Most statistical
    AlertSource.CANARY:           1.0,  # By definition — NeverWindow
}

def get_weight(source: str) -> float:
    """Get confidence weight for an alert source."""
    try:
        return COMPONENT_WEIGHTS.get(AlertSource(source), 0.5)
    except ValueError:
        return 0.5
