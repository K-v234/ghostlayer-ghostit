#!/usr/bin/env python3
"""
Ghost IT — Contradiction Engine (Cognitive Dissonance Reasoning)

The gap this closes: Cortex fuses pillar signals by summing them --
five mild suspicions add to one bigger one. This silently destroys a
specific, valuable case: near-unanimous agreement CONTRADICTED by one
highly confident, structurally un-fakeable signal (a canary) is a
fundamentally different situation than five detectors mildly agreeing.

A sophisticated attacker can plausibly evade behavioral, network, and
memory analysis. They cannot plausibly explain why a decoy with zero
legitimate purpose was touched. This engine treats DISAGREEMENT
between pillar beliefs as first-class evidence in its own right.
"""
from __future__ import annotations
import logging

log = logging.getLogger(__name__)

STRUCTURALLY_RELIABLE_PILLARS = {"C3_deception", "C19_kernel"}

def detect_contradiction(pillar_beliefs: dict) -> dict:
    if not pillar_beliefs:
        return {"contradiction_detected": False, "reason": "no beliefs provided"}

    safe_votes = {p: c for p, c in pillar_beliefs.items() if c >= 70}
    compromised_votes = {p: c for p, c in pillar_beliefs.items() if c < 30}

    if not safe_votes or not compromised_votes:
        return {"contradiction_detected": False,
                 "reason": "no genuine disagreement -- pillars broadly agree"}

    reliable_dissent = {p: c for p, c in compromised_votes.items()
                          if p in STRUCTURALLY_RELIABLE_PILLARS}

    avg_safe_confidence = sum(safe_votes.values()) / len(safe_votes)
    severity = "critical" if reliable_dissent else "moderate"

    reasoning = []
    reasoning.append(f"{len(safe_votes)} pillar(s) report high confidence of safety (avg {avg_safe_confidence:.0f}%): {list(safe_votes.keys())}")
    reasoning.append(f"{len(compromised_votes)} pillar(s) report compromise: {list(compromised_votes.keys())}")
    if reliable_dissent:
        reasoning.append(f"Dissent includes structurally reliable pillar(s) {list(reliable_dissent.keys())} -- near-zero false positive rate, so disagreement is itself strong evidence of a hidden attacker")

    return {
        "contradiction_detected": True, "severity": severity,
        "contradiction_strength": round(avg_safe_confidence, 1),
        "safe_pillars": list(safe_votes.keys()),
        "dissenting_pillars": list(compromised_votes.keys()),
        "reliable_dissent": list(reliable_dissent.keys()),
        "reasoning": reasoning,
        "conclusion": (
            "This entity's safe appearance across most detectors is likely a sign of deliberate, successful evasion -- the contradiction itself is the evidence."
            if reliable_dissent else
            "Genuine disagreement exists but no structurally reliable pillar is dissenting -- worth monitoring, less certain."
        ),
    }

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("=== Scenario: sophisticated attacker evading everything except the canary ===\n")
    r1 = detect_contradiction({"C2_behavioral": 92, "C14_network": 88, "C8_memory": 95, "C3_deception": 0})
    for k, v in r1.items():
        print(f"  {k}: {v}")
    print("\n=== Scenario: ordinary disagreement, no reliable pillar dissenting ===\n")
    r2 = detect_contradiction({"C2_behavioral": 85, "C14_network": 40, "C8_memory": 90})
    for k, v in r2.items():
        print(f"  {k}: {v}")
    print("\n=== Scenario: no contradiction, everything agrees ===\n")
    r3 = detect_contradiction({"C2_behavioral": 95, "C14_network": 90, "C3_deception": 92})
    print(f"  {r3}")
