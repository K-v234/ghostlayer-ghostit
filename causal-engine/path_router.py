#!/usr/bin/env python3
"""
Ghost IT — Hot/Warm/Cold Path Router

Classifies every event into a real handling tier at ingestion:
HOT (canary hits, confirmed ransomware, kernel violations -- minimal
delay tolerance), WARM (normal correlation/scoring), COLD (retraining,
replay, reporting -- valuable but never time-critical). This is
reliability engineering: it doesn't add intelligence, it protects
existing intelligence from being starved by volume under real load --
the same class of problem already found and fixed once before
(Linux volume starving Windows signal in shared queries).
"""
from __future__ import annotations
import logging

log = logging.getLogger(__name__)

HOT_PATH_TYPES = {"canary_hit", "kernel_integrity"}
HOT_PATH_RULE_PREFIXES = ("C15_RANSOMWARE", "C19_LKRG", "R001", "R003")
COLD_PATH_OPERATIONS = {
    "model_retrain", "full_replay", "report_generation",
    "adaptive_threshold_recalibration", "temporal_memory_cleanup",
}

def classify_event(event_type: str = "", rule_id: str = "", score: float = 0) -> str:
    if event_type in HOT_PATH_TYPES:
        return "hot"
    if rule_id and any(rule_id.startswith(p) for p in HOT_PATH_RULE_PREFIXES):
        return "hot"
    if score >= 90:
        return "hot"
    if score >= 40:
        return "warm"
    return "cold"

def classify_operation(operation_name: str) -> str:
    if operation_name in COLD_PATH_OPERATIONS:
        return "cold"
    return "warm"

class PathRouter:
    def __init__(self):
        self.counts = {"hot": 0, "warm": 0, "cold": 0}

    def route(self, event_type: str = "", rule_id: str = "", score: float = 0) -> str:
        tier = classify_event(event_type, rule_id, score)
        self.counts[tier] += 1
        return tier

    def stats(self) -> dict:
        total = sum(self.counts.values()) or 1
        return {
            "total_routed": sum(self.counts.values()),
            "hot_pct": round(100 * self.counts["hot"] / total, 1),
            "warm_pct": round(100 * self.counts["warm"] / total, 1),
            "cold_pct": round(100 * self.counts["cold"] / total, 1),
            "raw_counts": dict(self.counts),
        }

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    router = PathRouter()

    test_events = [
        {"event_type": "file_open", "score": 10} for _ in range(80)
    ] + [
        {"event_type": "net_connect", "score": 20} for _ in range(15)
    ] + [
        {"event_type": "canary_hit", "score": 100},
        {"rule_id": "C15_RANSOMWARE_high_entropy", "score": 96},
        {"rule_id": "C19_LKRG_INTEGRITY", "score": 90},
    ]

    for e in test_events:
        router.route(**e)

    print("=== Routing 98 realistic mixed events through the classifier ===\n")
    print(router.stats())
    print(f"\n=== Result: {router.counts['hot']} genuinely critical events correctly isolated onto the hot path ===")
