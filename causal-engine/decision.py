
"""

Ghost IT -- Decision and action (Week 2 Cortex split, part 3 of 3)



Wraps everything that acts on a risk score: Autonomous Response's

decide(), Safety Governor's pre-action review, Contradiction Engine's

belief-consistency check, Threat Mesh's cross-deployment broadcast,

and Active Deception's below-threshold decoy injection. All of the

real side effects (network broadcasts, simulated/real autonomous

actions) live in exactly one place now, instead of being interleaved

with scoring and correlation logic.

"""

from __future__ import annotations

import os

import logging



log = logging.getLogger(__name__)





def decide_and_act(pid: int, pillar: str, reason: str, result: dict) -> None:

    try:

        from autonomous_response import AutonomousResponseEngine

        engine = AutonomousResponseEngine()

        decision = engine.decide(

            f"pid:{pid}", result["score"], result["pillars"],

            f"triggered by new contribution from {pillar}: {reason}"

        )

        if decision.get("tier"):

            _run_safety_governor(pid, decision)

        if result["distinct_pillars"] >= 2:

            _run_contradiction_check(pid, result)

        if decision.get("tier", 0) >= 2:

            _broadcast_threat_mesh(pillar, reason, result)

    except Exception as ex:

        log.debug(f"Autonomous response decision error: {ex}")

    _inject_active_deception(pid, reason, result)





def _run_safety_governor(pid: int, decision: dict) -> None:

    from world_model import WorldModel

    from safety_governor import govern

    try:

        assessment = WorldModel().what_breaks_if_isolated(f"pid:{pid}")

        verdict = govern(decision["tier"], decision.get("action", ""), assessment)

        if verdict["verdict"] != "approved":

            log.warning(f"[Governor] Decision for pid:{pid} {verdict['verdict']}: {verdict['reasons']}")

            decision["governor_verdict"] = verdict

    except Exception as ex:

        log.debug(f"Safety governor error: {ex}")





def _run_contradiction_check(pid: int, result: dict) -> None:

    from contradiction_engine import detect_contradiction

    try:

        beliefs = {c["pillar"]: max(0, 100 - c["current_weight"]) for c in result.get("contributions", [])}

        contradiction = detect_contradiction(beliefs)

        if contradiction.get("contradiction_detected") and contradiction.get("severity") == "critical":

            log.warning(f"[Contradiction] CRITICAL contradiction for pid:{pid}: {contradiction['conclusion']}")

    except Exception as ex:

        log.debug(f"Contradiction engine error: {ex}")





def _broadcast_threat_mesh(pillar: str, reason: str, result: dict) -> None:

    from threat_mesh import ThreatMesh

    import hashlib

    fp = hashlib.sha256(f"{pillar}:{reason}".lower().encode()).hexdigest()[:16]

    ThreatMesh().broadcast_immunity(

        origin_deployment=os.environ.get("GHOSTIT_DEPLOYMENT_ID", "unknown-deployment"),

        fingerprint=fp, tactic="", technique="",

        comm_pattern=pillar, resource_pattern=reason[:100],

        confidence=result["score"],

    )





def _inject_active_deception(pid: int, reason: str, result: dict) -> None:

    from active_deception import ActiveDeception

    try:

        ActiveDeception().generate_injection(f"pid:{pid}", reason, result["score"])

    except Exception as ex:

        log.debug(f"Active deception injection error: {ex}")

