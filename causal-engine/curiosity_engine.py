#!/usr/bin/env python3
"""
Ghost IT — Curiosity Engine

Real extension of Active Deception + Cortex sub-threshold observation:
for entities in the genuine ambiguous middle (not clean, not yet
alert-worthy), recommends extending observation and deploying
targeted decoys, before either escalating or dismissing.
"""
from __future__ import annotations
import time, logging

log = logging.getLogger(__name__)

CURIOSITY_LOW_BOUND = 25
CURIOSITY_HIGH_BOUND = 50
INVESTIGATION_WINDOW_SEC = 300

def should_investigate(cortex_score: float, distinct_pillars: int) -> bool:
    return (CURIOSITY_LOW_BOUND <= cortex_score < CURIOSITY_HIGH_BOUND) or distinct_pillars >= 2

def build_investigation_plan(entity_id: str, comm: str, cortex_score: float) -> dict:
    now = time.time()
    return {
        "entity_id": entity_id, "comm": comm, "cortex_score": cortex_score,
        "investigation_started": now,
        "investigation_expires": now + INVESTIGATION_WINDOW_SEC,
        "actions": [
            {"action": "extend_observation_window",
             "detail": f"Hold detailed logging active for this entity for {INVESTIGATION_WINDOW_SEC}s beyond normal retention"},
            {"action": "flag_children_for_inherited_scrutiny",
             "detail": "Any child process spawned during the investigation window inherits elevated baseline scrutiny"},
            {"action": "prioritize_targeted_deception",
             "detail": "If file-access pattern suggests a specific area of interest, prioritize Active Deception there"},
        ],
        "reasoning": f"Entity is in the genuine ambiguous zone (score {cortex_score}, not yet alert-worthy but not clean) -- proactively gathering more evidence.",
    }

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("=== Scenario: mild, ambiguous score (35) ===\n")
    if should_investigate(35, 1):
        plan = build_investigation_plan("pid:7777", "unknown_updater.exe", 35)
        print(f"Investigation triggered for {plan['entity_id']}")
        print(f"Reasoning: {plan['reasoning']}\n")
        for a in plan["actions"]:
            print(f"  - {a['action']}: {a['detail']}")
    print("\n=== Clean entity (score 5) ===")
    print(f"should_investigate: {should_investigate(5, 1)}")
    print("\n=== Already alert-worthy (score 85) ===")
    print(f"should_investigate: {should_investigate(85, 1)}")
