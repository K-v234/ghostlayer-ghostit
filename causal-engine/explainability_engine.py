#!/usr/bin/env python3
"""
Ghost IT — Explainability Engine: "Why Did I Decide This?"

Breakthrough #3: every system built today logs WHAT it decided, but
nothing synthesizes WHY across all of them at once into a genuinely
human-readable story. A real analyst (or a pilot customer's IT admin
who isn't a security expert) shouldn't have to manually cross-
reference six different databases to understand what actually
happened -- they should get one coherent narrative.

This engine pulls evidence from every pillar (Cortex fusion,
Temporal Memory, Adaptive Thresholds, Predictive Inference,
Autonomous Response, Threat Mesh, Behavioral DNA, Active Deception)
for a given entity and synthesizes it into a genuine, plain-English
incident narrative -- this is what actually makes a sophisticated
system TRUSTWORTHY and USABLE, not just technically impressive.
"""
from __future__ import annotations
import os
import time
import logging

log = logging.getLogger(__name__)

def _humanize_age(seconds: float) -> str:
    if seconds < 60:
        return f"{int(seconds)} seconds ago"
    if seconds < 3600:
        return f"{int(seconds/60)} minutes ago"
    if seconds < 86400:
        return f"{seconds/3600:.1f} hours ago"
    return f"{seconds/86400:.1f} days ago"

def build_narrative(entity_id: str, cortex_data: dict = None,
                     temporal_data: dict = None, mesh_data: dict = None,
                     prediction_data: dict = None, dna_data: dict = None,
                     response_decision: dict = None) -> dict:
    """
    Synthesize evidence from every available pillar into one coherent,
    human-readable incident narrative. Every input is optional -- this
    genuinely degrades gracefully, building the best story it can from
    whatever evidence actually exists, rather than requiring every
    single pillar to have fired.
    """
    story_parts = []
    evidence_summary = []

    if cortex_data and cortex_data.get("distinct_pillars", 0) >= 2:
        pillars = cortex_data["pillars"]
        score = cortex_data["score"]
        story_parts.append(
            f"This process was flagged by {cortex_data['distinct_pillars']} "
            f"independent detection systems ({', '.join(pillars)}), producing "
            f"a combined confidence score of {score}/100"
        )
        for c in cortex_data.get("contributions", [])[:3]:
            evidence_summary.append(f"{c['pillar']}: {c['reason']} ({_humanize_age(c['age_sec'])})")
    elif cortex_data and cortex_data.get("distinct_pillars", 0) == 1:
        # Genuinely different, calibrated language for single-pillar
        # cases -- still real, worth reporting, but explicitly NOT
        # claiming cross-pillar confirmation, which single-pillar
        # evidence never provides.
        pillar = cortex_data["pillars"][0]
        score = cortex_data["score"]
        story_parts.append(
            f"This process has a score of {score}/100 from a single detection "
            f"system ({pillar}) -- worth monitoring, but not yet confirmed by "
            f"any independent source"
        )
        for c in cortex_data.get("contributions", [])[:3]:
            evidence_summary.append(f"{c['pillar']}: {c['reason']} ({_humanize_age(c['age_sec'])})")

    if dna_data and dna_data.get("masquerade_suspected"):
        story_parts.append(
            f"it is masquerading as a trusted process -- it claims to be "
            f"'{dna_data['comm']}' but was launched by '{dna_data['observed_parent']}', "
            f"which is NOT how this process normally starts on this machine "
            f"(normally started by {dna_data['typical_parents']})"
        )
        evidence_summary.append(f"Behavioral DNA: identity mismatch detected")

    if temporal_data and temporal_data.get("is_returning_actor"):
        story_parts.append(
            f"this is not the first time this exact pattern has been seen -- "
            f"it has occurred {temporal_data['sighting_count']} times over the "
            f"past {temporal_data['days_since_first_seen']:.1f} days, suggesting "
            f"a persistent or returning threat rather than an isolated incident"
        )
        evidence_summary.append(f"Temporal Memory: {temporal_data['sighting_count']} sightings")

    if mesh_data and mesh_data.get("immune_hit"):
        story_parts.append(
            f"this specific pattern was already confirmed malicious on another "
            f"connected deployment ({mesh_data['origin_deployment']}), with "
            f"{mesh_data['confirmations']} independent confirmation(s) across "
            f"the network -- this is a known, actively spreading threat"
        )
        evidence_summary.append(f"Threat Mesh: {mesh_data['confirmations']} cross-deployment confirmations")

    if prediction_data and prediction_data.get("predicted_next"):
        next_tactics = [p["tactic"] for p in prediction_data["predicted_next"]]
        story_parts.append(
            f"based on the attack stage already observed ({prediction_data['current_tactic']}), "
            f"the likely next moves are {next_tactics} -- specifically watch for: "
            + "; ".join(p["watch_action"] for p in prediction_data["predicted_next"][:2])
        )
        evidence_summary.append(f"Predictive Inference: anticipating {next_tactics}")

    if response_decision and response_decision.get("decision") in ("action_taken", "action_simulated"):
        mode = "took" if response_decision["decision"] == "action_taken" else "would have taken (simulation mode)"
        story_parts.append(
            f"the system {mode} a tier-{response_decision['tier']} response: "
            f"{response_decision['action']} -- {response_decision['description']}"
        )
        evidence_summary.append(f"Autonomous Response: tier {response_decision['tier']} decision")

    if not story_parts:
        narrative = f"Entity {entity_id}: no significant cross-pillar evidence currently available."
    else:
        narrative = f"Entity {entity_id} is under investigation because " + "; and ".join(story_parts) + "."

    return {
        "entity_id": entity_id,
        "narrative": narrative,
        "evidence_summary": evidence_summary,
        "pillars_consulted": sum(1 for x in [cortex_data, temporal_data, mesh_data,
                                               prediction_data, dna_data, response_decision] if x),
        "generated_at": time.time(),
    }

if __name__ == "__main__":
    print("=== Synthesizing a realistic, complete multi-pillar incident ===\n")

    narrative = build_narrative(
        entity_id="pid:9999",
        cortex_data={
            "score": 89.5, "distinct_pillars": 3,
            "pillars": ["C2_behavioral", "C3_deception", "C14_lolbin"],
            "contributions": [
                {"pillar": "C3_deception", "reason": "canary file accessed", "age_sec": 12},
                {"pillar": "C2_behavioral", "reason": "unusual process spawn rate", "age_sec": 45},
            ],
        },
        dna_data={
            "masquerade_suspected": True, "comm": "svchost.exe",
            "observed_parent": "winword.exe", "typical_parents": ["services.exe"],
        },
        temporal_data={"is_returning_actor": True, "sighting_count": 4, "days_since_first_seen": 6.2},
        mesh_data={"immune_hit": True, "confirmations": 3, "origin_deployment": "customer-B-endpoint-02"},
        prediction_data={
            "current_tactic": "Defense Evasion",
            "predicted_next": [
                {"tactic": "Credential Access", "watch_action": "Watch for /etc/shadow reads, LSASS access"},
                {"tactic": "Discovery", "watch_action": "Watch for network/system enumeration commands"},
            ],
        },
        response_decision={
            "decision": "action_simulated", "tier": 2, "action": "suspend_process",
            "description": "Suspend (not kill) the process -- fully reversible",
        },
    )

    print(narrative["narrative"])
    print(f"\nEvidence summary ({narrative['pillars_consulted']} pillars consulted):")
    for e in narrative["evidence_summary"]:
        print(f"  - {e}")
