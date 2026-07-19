#!/usr/bin/env python3
"""
Ghost IT — Self-Evolving Architecture (recommendation-only, human-gated)

Deliberate safety design: this does NOT silently reweight pillars.
Observes each pillar's real, historical contribution value and
produces a genuine, reasoned RECOMMENDATION for weight changes --
never applying them automatically. A human must review and approve
before any actual reweighting takes effect.
"""
from __future__ import annotations
import os, time, logging, threading, duckdb

log = logging.getLogger(__name__)

EVOLUTION_DB_PATH = os.environ.get("EVOLUTION_DB_PATH",
    os.path.expanduser("~/ghostlayer/data/self_evolution.duckdb"))
MIN_SAMPLES_FOR_RECOMMENDATION = 20

class SelfEvolvingArchitecture:
    def __init__(self, db_path: str = EVOLUTION_DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._lock = threading.Lock()
        self.conn = duckdb.connect(db_path)
        self._init_schema()
        log.info(f"SelfEvolvingArchitecture initialized (RECOMMENDATION-ONLY MODE): {db_path}")

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS pillar_outcomes (
                pillar VARCHAR NOT NULL, outcome VARCHAR NOT NULL, ts DOUBLE NOT NULL
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS pending_recommendations (
                recommendation_id VARCHAR NOT NULL, pillar VARCHAR NOT NULL,
                current_weight DOUBLE, recommended_weight DOUBLE,
                reasoning VARCHAR NOT NULL, status VARCHAR NOT NULL DEFAULT 'pending_human_review',
                created_ts DOUBLE NOT NULL, reviewed_ts DOUBLE, reviewed_by VARCHAR
            )
        """)

    def record_outcome(self, pillar: str, outcome: str):
        with self._lock:
            self.conn.execute("INSERT INTO pillar_outcomes VALUES (?, ?, ?)", [pillar, outcome, time.time()])

    def generate_recommendation(self, pillar: str, current_weight: float) -> dict:
        with self._lock:
            rows = self.conn.execute("SELECT outcome FROM pillar_outcomes WHERE pillar = ?", [pillar]).fetchall()
        outcomes = [r[0] for r in rows]
        if len(outcomes) < MIN_SAMPLES_FOR_RECOMMENDATION:
            return {"recommendation": None, "reason": f"insufficient real evidence ({len(outcomes)} samples, need {MIN_SAMPLES_FOR_RECOMMENDATION})"}

        confirmed = outcomes.count("confirmed_incident")
        false_pos = outcomes.count("false_positive")
        reliability = confirmed / len(outcomes)

        if reliability >= 0.8:
            recommended_weight = min(60, current_weight * 1.3)
            direction = "increase"
        elif reliability <= 0.3:
            recommended_weight = max(5, current_weight * 0.6)
            direction = "decrease"
        else:
            return {"recommendation": None, "reason": f"reliability ({reliability:.0%}) is within normal range"}

        rec_id = f"rec-{pillar}-{int(time.time())}"
        reasoning = (f"Pillar '{pillar}' has a {reliability:.0%} real confirmed-incident rate over {len(outcomes)} outcomes "
                     f"({confirmed} confirmed, {false_pos} false positive) -- recommending weight {direction} from "
                     f"{current_weight} to {round(recommended_weight, 1)}. THIS IS A RECOMMENDATION ONLY. "
                     f"No weight has been changed. Human review and explicit approval required.")
        with self._lock:
            self.conn.execute(
                "INSERT INTO pending_recommendations VALUES (?, ?, ?, ?, ?, 'pending_human_review', ?, NULL, NULL)",
                [rec_id, pillar, current_weight, round(recommended_weight, 1), reasoning, time.time()]
            )
        log.warning(f"[SelfEvolving] RECOMMENDATION (not applied): {reasoning}")
        return {"recommendation_id": rec_id, "pillar": pillar, "current_weight": current_weight,
                 "recommended_weight": round(recommended_weight, 1), "reasoning": reasoning,
                 "status": "pending_human_review"}

    def approve_recommendation(self, recommendation_id: str, reviewed_by: str) -> dict:
        with self._lock:
            row = self.conn.execute(
                "SELECT pillar, recommended_weight, status FROM pending_recommendations WHERE recommendation_id = ?",
                [recommendation_id]
            ).fetchone()
            if not row:
                return {"approved": False, "reason": "recommendation not found"}
            if row[2] != "pending_human_review":
                return {"approved": False, "reason": f"already {row[2]}"}
            self.conn.execute(
                "UPDATE pending_recommendations SET status = 'approved', reviewed_ts = ?, reviewed_by = ? WHERE recommendation_id = ?",
                [time.time(), reviewed_by, recommendation_id]
            )
        log.warning(f"[SelfEvolving] Recommendation {recommendation_id} APPROVED by {reviewed_by} -- pillar {row[0]} weight change to {row[1]} now authorized")
        return {"approved": True, "pillar": row[0], "new_weight": row[1]}

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sea = SelfEvolvingArchitecture(db_path="/tmp/evolution_test.duckdb")

    print("=== Recording 25 real outcomes for a highly reliable pillar ===\n")
    for _ in range(22):
        sea.record_outcome("C3_deception", "confirmed_incident")
    for _ in range(3):
        sea.record_outcome("C3_deception", "false_positive")

    rec = sea.generate_recommendation("C3_deception", current_weight=40)
    print(f"  {rec}\n")

    print("=== Human reviews and approves ===\n")
    approval = sea.approve_recommendation(rec["recommendation_id"], reviewed_by="keerthivahanan")
    print(f"  {approval}")
    os.remove("/tmp/evolution_test.duckdb")
