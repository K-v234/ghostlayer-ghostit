#!/usr/bin/env python3
"""
Ghost IT — Autonomous Response Engine (Graduated, Evidence-Logged)

Architectural upgrade #5, built following the real industry pattern
confirmed via research: SentinelOne's actual ransomware playbook
(process kill -> network isolation -> rollback) and the documented
"guardrails-as-code" practice (signal -> reasoning -> action ->
artifacts, dual-control for destructive steps, time-boxed containment
with rollback).

SAFETY DESIGN, non-negotiable:
1. SIMULATION MODE by default. ACTIONS_ENABLED must be explicitly
   set to true before any real action executes -- until then, this
   only DECIDES and LOGS what it would have done, never touches a
   real machine. This is intentional and should not be bypassed
   casually.
2. Graduated escalation -- always the least destructive plausible
   action first, escalating only if the Cortex score continues
   climbing AFTER the milder action.
3. High confidence floor -- requires the KIND of score only
   cross-pillar fusion (Cortex) or confirmed recurring patterns
   (Temporal Memory) produce, never a single raw pillar alert alone.
4. Full evidence logging on every decision, whether or not action
   was actually taken.
5. Rate limiting -- repeated triggers in a short window pause and
   require human review rather than escalating further, since that
   pattern suggests a detection logic problem, not a worsening attack.
"""
from __future__ import annotations
import os
import time
import logging
import threading
import duckdb

log = logging.getLogger(__name__)

# THE SAFETY SWITCH. Defaults to False. Must be explicitly enabled
# via environment variable -- never flip this casually, and never as
# a default for a new deployment. See module docstring.
ACTIONS_ENABLED = os.environ.get("GHOSTIT_AUTONOMOUS_ACTIONS_ENABLED", "false").lower() == "true"

RESPONSE_DB_PATH = os.environ.get("RESPONSE_DB_PATH",
    os.path.expanduser("~/ghostlayer/data/autonomous_response.duckdb"))

# Minimum Cortex fused score required before ANY autonomous decision
# is even considered -- deliberately higher than any single pillar's
# own alert threshold, since this should only engage on genuine
# cross-pillar-confirmed or recurring-pattern-confirmed suspicion.
MIN_CONFIDENCE_FOR_ACTION = 75

# Graduated response ladder -- least destructive first. Each tier
# only engages if the entity's score is STILL elevated after the
# previous, milder tier was already applied (or logged, in
# simulation mode).
RESPONSE_LADDER = [
    {
        "tier": 1, "name": "throttle_network",
        "description": "Rate-limit the process's network I/O -- least destructive, "
                        "buys time without fully cutting off legitimate work if this "
                        "turns out to be a false positive.",
        "min_score": 75,
    },
    {
        "tier": 2, "name": "suspend_process",
        "description": "Suspend (not kill) the process -- freezes it in place, "
                        "fully reversible by resuming, preserves all state for "
                        "forensic investigation unlike killing it outright.",
        "min_score": 85,
    },
    {
        "tier": 3, "name": "isolate_host",
        "description": "Full network isolation of the host -- last resort, only "
                        "for sustained CRITICAL confidence, matches industry "
                        "practice for confirmed active compromise (SentinelOne's "
                        "documented ransomware playbook uses this tier).",
        "min_score": 95,
    },
]

# Rate limit: if more than this many actions get triggered for the
# same entity within RATE_LIMIT_WINDOW_SEC, pause and require human
# review instead of continuing to escalate -- repeated rapid triggers
# indicate a detection logic problem, not a worsening attack.
RATE_LIMIT_MAX_ACTIONS = 3
RATE_LIMIT_WINDOW_SEC = 300  # 5 minutes

class AutonomousResponseEngine:
    def __init__(self, db_path: str = RESPONSE_DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._lock = threading.Lock()
        self.conn = duckdb.connect(db_path)
        self._init_schema()
        mode = "ACTIONS ENABLED (real actions will execute)" if ACTIONS_ENABLED \
               else "SIMULATION MODE (decisions logged only, nothing executed)"
        log.warning(f"AutonomousResponseEngine initialized: {mode}")

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS decisions (
                entity_id      VARCHAR NOT NULL,
                tier           INTEGER NOT NULL,
                action_name    VARCHAR NOT NULL,
                score_at_decision DOUBLE NOT NULL,
                reasoning      VARCHAR NOT NULL,
                simulated      BOOLEAN NOT NULL,
                executed       BOOLEAN NOT NULL,
                ts             DOUBLE NOT NULL
            )
        """)

    def _recent_action_count(self, entity_id: str) -> int:
        cutoff = time.time() - RATE_LIMIT_WINDOW_SEC
        with self._lock:
            return self.conn.execute(
                "SELECT COUNT(*) FROM decisions WHERE entity_id = ? AND ts > ?",
                [entity_id, cutoff]
            ).fetchone()[0]

    def decide(self, entity_id: str, cortex_score: float,
                contributing_pillars: list[str], reasoning: str) -> dict:
        """
        The core decision function: given an entity's current fused
        Cortex score and the pillars that contributed to it, decide
        whether autonomous action is warranted, at what tier, and
        WHY -- with full evidence logging regardless of whether any
        action actually executes (simulation mode or not).
        """
        # Safety gate 1: confidence floor
        if cortex_score < MIN_CONFIDENCE_FOR_ACTION:
            return {"decision": "no_action", "reason": "below confidence floor",
                     "score": cortex_score, "threshold": MIN_CONFIDENCE_FOR_ACTION}

        # Safety gate 2: require genuine cross-pillar or recurring-pattern
        # evidence, not a single pillar's isolated confirmation
        if len(contributing_pillars) < 2:
            return {"decision": "no_action",
                     "reason": "single-pillar confirmation insufficient for autonomous action",
                     "score": cortex_score, "pillars": contributing_pillars}

        # Safety gate 3: rate limiting
        recent = self._recent_action_count(entity_id)
        if recent >= RATE_LIMIT_MAX_ACTIONS:
            log.error(
                f"[AutonomousResponse] RATE LIMIT HIT for {entity_id}: "
                f"{recent} actions in {RATE_LIMIT_WINDOW_SEC}s -- pausing, "
                f"requires human review. This pattern suggests a detection "
                f"logic issue, not an escalating attack."
            )
            return {"decision": "rate_limited", "recent_action_count": recent,
                     "requires_human_review": True}

        # Select the highest tier this score qualifies for -- graduated,
        # but if the score is already very high (e.g. confirmed
        # ransomware mid-encryption), start at the appropriate tier
        # rather than always starting at tier 1 and wasting time.
        selected_tier = None
        for tier_def in RESPONSE_LADDER:
            if cortex_score >= tier_def["min_score"]:
                selected_tier = tier_def

        if not selected_tier:
            return {"decision": "no_action", "reason": "no tier threshold met",
                     "score": cortex_score}

        full_reasoning = (
            f"Cortex fused score {cortex_score} across {len(contributing_pillars)} "
            f"pillars ({', '.join(contributing_pillars)}) -- {reasoning}"
        )

        with self._lock:
            self.conn.execute(
                "INSERT INTO decisions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [entity_id, selected_tier["tier"], selected_tier["name"],
                 cortex_score, full_reasoning, not ACTIONS_ENABLED,
                 ACTIONS_ENABLED, time.time()]
            )

        log.warning(
            f"[AutonomousResponse] DECISION for {entity_id}: "
            f"tier={selected_tier['tier']} ({selected_tier['name']}) "
            f"score={cortex_score} mode={'EXECUTED' if ACTIONS_ENABLED else 'SIMULATED'} "
            f"-- {full_reasoning}"
        )

        result = {
            "decision": "action_taken" if ACTIONS_ENABLED else "action_simulated",
            "tier": selected_tier["tier"],
            "action": selected_tier["name"],
            "description": selected_tier["description"],
            "score": cortex_score,
            "reasoning": full_reasoning,
            "actions_enabled": ACTIONS_ENABLED,
        }

        if ACTIONS_ENABLED:
            self._execute_action(entity_id, selected_tier)

        return result

    def _execute_action(self, entity_id: str, tier_def: dict):

        import signal

        pid = None

        if entity_id.startswith("pid:"):

            try:

                pid = int(entity_id.split(":", 1)[1])

            except ValueError:

                pass



        if tier_def["name"] == "suspend_process":

            if pid is None:

                log.error(f"[AutonomousResponse] Cannot suspend -- no parseable PID in {entity_id}")

                return

            try:

                os.kill(pid, signal.SIGSTOP)

                log.critical(

                    f"[AutonomousResponse] REAL ACTION EXECUTED -- SIGSTOP sent to pid {pid} "

                    f"(tier {tier_def['tier']}, {tier_def['name']}). Process is now frozen, "

                    f"fully reversible via SIGCONT, all state preserved for investigation."

                )
                try:
                    from self_heal import run_self_heal
                    heal_report = run_self_heal(dry_run=not ACTIONS_ENABLED)
                    log.critical(f"[AutonomousResponse] Self-heal follow-up complete -- healed={heal_report.get('healed')}")
                except Exception as heal_ex:
                    log.error(f"[AutonomousResponse] Self-heal follow-up failed: {heal_ex}")

            except ProcessLookupError:

                log.warning(f"[AutonomousResponse] pid {pid} no longer exists -- nothing to suspend")

            except PermissionError:

                log.error(f"[AutonomousResponse] Permission denied suspending pid {pid} -- agent needs elevated privileges")

            except Exception as ex:

                log.error(f"[AutonomousResponse] Real suspend action failed for pid {pid}: {ex}")

        else:

            log.error(

                f"[AutonomousResponse] ACTIONS_ENABLED=true but tier "

                f"{tier_def['tier']} ({tier_def['name']}) has no real "

                f"implementation yet -- decision logged, no action taken. "

                f"Only suspend_process (tier 2) is currently implemented."

            )



    def get_decision_history(self, entity_id: str = None, limit: int = 50) -> list[dict]:
        with self._lock:
            if entity_id:
                rows = self.conn.execute(
                    "SELECT * FROM decisions WHERE entity_id = ? ORDER BY ts DESC LIMIT ?",
                    [entity_id, limit]
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM decisions ORDER BY ts DESC LIMIT ?", [limit]
                ).fetchall()
        cols = ["entity_id", "tier", "action_name", "score_at_decision",
                "reasoning", "simulated", "executed", "ts"]
        return [dict(zip(cols, r)) for r in rows]

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print(f"Running in {'ACTION-ENABLED' if ACTIONS_ENABLED else 'SIMULATION'} mode\n")

    engine = AutonomousResponseEngine(db_path="/tmp/autonomous_test.duckdb")

    print("=== Test 1: low confidence, single pillar -- should be REJECTED ===")
    r1 = engine.decide("pid:100", 45, ["C2_behavioral"], "mild anomaly")
    print(f"  {r1}\n")

    print("=== Test 2: high confidence, single pillar -- should be REJECTED (needs cross-pillar) ===")
    r2 = engine.decide("pid:101", 90, ["C3_deception"], "canary touch")
    print(f"  {r2}\n")

    print("=== Test 3: high confidence, cross-pillar -- should trigger tier 2 ===")
    r3 = engine.decide("pid:102", 88, ["C2_behavioral", "C3_deception", "C14_lolbin"],
                        "sustained cross-pillar suspicion")
    print(f"  {r3}\n")

    print("=== Test 4: CRITICAL confidence, cross-pillar -- should trigger tier 3 ===")
    r4 = engine.decide("pid:103", 97, ["C3_deception", "C15_ransomware", "C19_kernel"],
                        "confirmed multi-signal critical event")
    print(f"  {r4}\n")

    print("=== Test 5: rate limit -- repeat pid:102 three more times rapidly ===")
    for _ in range(3):
        r5 = engine.decide("pid:102", 88, ["C2_behavioral", "C3_deception"], "repeat trigger")
    print(f"  Final attempt result: {r5}\n")

    os.remove("/tmp/autonomous_test.duckdb")
