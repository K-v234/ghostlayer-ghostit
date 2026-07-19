#!/usr/bin/env python3
"""
Ghost IT — Simulation Engine (bounded prediction-vs-reality)

Honest scoping: rather than simulating unbounded branching futures
("thousands of possible futures"), this takes Predictive Inference's
actual, concrete next-stage predictions and checks whether REALITY is
converging toward one of them -- escalating on TRAJECTORY MATCH,
before the predicted final stage completes.
"""
from __future__ import annotations
import logging

log = logging.getLogger(__name__)

def check_trajectory_match(predicted_next_tactics: list, observed_recent_stages: list) -> dict:
    predicted_set = {t.lower() for t in predicted_next_tactics}
    observed_set = {s.lower() for s in observed_recent_stages}
    matches = predicted_set & observed_set
    if not matches:
        return {"trajectory_match": False,
                 "reason": "observed reality has not yet converged with any predicted next stage"}
    match_ratio = len(matches) / len(predicted_set) if predicted_set else 0
    confidence = "high" if match_ratio >= 0.5 else "moderate"
    return {
        "trajectory_match": True, "confidence": confidence,
        "matched_tactics": sorted(matches), "match_ratio": round(match_ratio, 2),
        "conclusion": f"Reality has converged with {len(matches)} of {len(predicted_set)} predicted next-stage tactic(s). Recognition that observed behavior matches an anticipated attack trajectory, warranting escalation before the predicted final stage completes.",
    }

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("=== Setup: Predictive Inference said 'watch for Lateral Movement, Collection' ===\n")
    predicted = ["Lateral Movement", "Collection"]
    print("=== Observed activity includes an SMB connection (Lateral Movement) ===\n")
    observed = ["Lateral Movement", "Discovery"]
    result = check_trajectory_match(predicted, observed)
    print(f"  {result}\n")
    print("=== Contrast: observed activity that does NOT match ===\n")
    observed2 = ["Defense Evasion"]
    result2 = check_trajectory_match(predicted, observed2)
    print(f"  {result2}")
