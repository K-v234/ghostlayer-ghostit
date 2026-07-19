#!/usr/bin/env python3
"""
Ghost IT — Safety Governor

The gap this closes: Autonomous Response's five safety gates check
confidence and cross-pillar agreement, but nothing checks the actual
real-world consequence of the action. This governor sits between
Autonomous Response's decision and any real execution, consulting
the World-Model to check blast radius and business criticality
before compiling a final, deterministic verdict.
"""
from __future__ import annotations
import logging

log = logging.getLogger(__name__)

CRITICALITY_DOWNGRADE_THRESHOLD = 80
BLAST_RADIUS_DOWNGRADE_THRESHOLD = 5

def govern(proposed_tier: int, proposed_action: str, world_model_assessment: dict,
           false_positive_history_count: int = 0) -> dict:
    criticality_score = world_model_assessment.get("criticality_score", 0)
    blast_radius = world_model_assessment.get("blast_radius_count", 0)
    reasons = []
    final_tier = proposed_tier
    final_action = proposed_action

    if criticality_score >= CRITICALITY_DOWNGRADE_THRESHOLD:
        reasons.append(
            f"Target has high business criticality ({criticality_score}/100) -- "
            f"downgrading from tier {proposed_tier} to reduce business risk"
        )
        final_tier = min(final_tier, 2)
        final_action = "suspend_process" if final_tier >= 2 else "throttle_network"

    if blast_radius >= BLAST_RADIUS_DOWNGRADE_THRESHOLD:
        reasons.append(
            f"Blast radius of {blast_radius} dependent processes -- "
            f"isolating would affect {blast_radius} additional processes"
        )
        final_tier = min(final_tier, 2)

    if false_positive_history_count >= 3:
        reasons.append(
            f"This entity type has {false_positive_history_count} prior false "
            f"positives -- requiring human confirmation before proceeding"
        )
        return {
            "verdict": "requires_human_confirmation",
            "proposed_tier": proposed_tier, "proposed_action": proposed_action,
            "reasons": reasons,
        }

    if not reasons:
        reasons.append("No business-risk factors found -- proceeding as proposed")

    return {
        "verdict": "approved" if final_tier == proposed_tier else "downgraded",
        "final_tier": final_tier, "final_action": final_action,
        "original_tier": proposed_tier, "original_action": proposed_action,
        "reasons": reasons,
    }

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    print("=== Scenario 1: high-confidence ransomware detection on a THROWAWAY script ===")
    r1 = govern(3, "isolate_host", {"criticality_score": 0, "blast_radius_count": 0})
    print(f"  {r1}\n")

    print("=== Scenario 2: identical detection, but on a CRITICAL database with 5 dependents ===")
    r2 = govern(3, "isolate_host", {"criticality_score": 100, "blast_radius_count": 5})
    print(f"  {r2}\n")

    print("=== Scenario 3: same critical target, but this process TYPE has 3 prior false positives ===")
    r3 = govern(3, "isolate_host", {"criticality_score": 100, "blast_radius_count": 5}, false_positive_history_count=3)
    print(f"  {r3}\n")

    print("=== Result: identical raw detection confidence, THREE genuinely different final verdicts based on real business context ===")
