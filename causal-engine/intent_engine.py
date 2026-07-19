#!/usr/bin/env python3
"""
Ghost IT — Intent Engine

Translates a real, observed sequence of attack stages into a stated
ATTACKER GOAL -- "the objective is destructive encryption" rather
than "ransomware detected" -- inferred from the shape of the
sequence. This is a reasoning/output layer over Predictive Inference
and Attack Replay, not a new detector.
"""
from __future__ import annotations
import logging

log = logging.getLogger(__name__)

INTENT_SIGNATURES = [
    {
        "name": "destructive_encryption",
        "required_stages": {"discovery", "privilege_escalation", "backup_discovery",
                              "service_stopping", "shadow_copy_deletion"},
        "min_match": 3,
        "stated_intent": "The objective of this process is destructive encryption "
                          "(ransomware) -- it is systematically removing recovery "
                          "options before encrypting, not merely exploring the system.",
    },
    {
        "name": "data_exfiltration",
        "required_stages": {"discovery", "collection", "archive_creation", "outbound_transfer"},
        "min_match": 3,
        "stated_intent": "The objective of this process is data theft -- it is "
                          "gathering and packaging specific data for removal from "
                          "the network, not causing local damage.",
    },
    {
        "name": "persistent_access",
        "required_stages": {"privilege_escalation", "credential_access",
                              "scheduled_task_creation", "registry_modification"},
        "min_match": 3,
        "stated_intent": "The objective of this process is establishing long-term, "
                          "covert access -- it is building persistence mechanisms "
                          "rather than pursuing immediate impact.",
    },
    {
        "name": "lateral_reconnaissance",
        "required_stages": {"discovery", "network_enumeration", "credential_access"},
        "min_match": 2,
        "stated_intent": "The objective of this process is mapping the network for "
                          "further movement -- it is preparing to spread, not acting "
                          "on this host alone.",
    },
]

def infer_intent(observed_stages: set) -> dict:
    observed_stages = {s.lower().replace(" ", "_") for s in observed_stages}
    matches = []
    for sig in INTENT_SIGNATURES:
        overlap = sig["required_stages"] & observed_stages
        if len(overlap) >= sig["min_match"]:
            confidence = len(overlap) / len(sig["required_stages"])
            matches.append({
                "intent": sig["name"], "stated_intent": sig["stated_intent"],
                "confidence": round(confidence * 100, 1),
                "matched_stages": sorted(overlap),
                "total_stages_in_signature": len(sig["required_stages"]),
            })
    matches.sort(key=lambda m: m["confidence"], reverse=True)
    if not matches:
        return {"intent_inferred": False,
                 "reason": "observed stages do not yet form a recognized intent pattern"}
    return {"intent_inferred": True, "top_intent": matches[0], "all_candidate_intents": matches}

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("=== Scenario: real observed stages before encryption actually begins ===\n")
    observed = {"discovery", "privilege_escalation", "backup_discovery", "service_stopping"}
    result = infer_intent(observed)
    print(f"Top inferred intent: {result['top_intent']['intent']}")
    print(f"Confidence: {result['top_intent']['confidence']}%")
    print(f"Stated: {result['top_intent']['stated_intent']}")
