#!/usr/bin/env python3
"""
Ghost IT — Cortex: Cross-Pillar Live Fusion Layer

The architectural gap this closes: every detection pillar (C2
behavioral, C3 deception, C4 causal, C14 LOLBin/C2, C15 ransomware,
C19 kernel integrity) currently decides independently whether
something crosses ITS OWN alert threshold, in isolation. Two mild,
individually-forgivable signals from two different pillars on the
SAME entity never compound -- an attacker who stays just under each
individual pillar's threshold walks through undetected, even though
the combination is genuinely suspicious.

The Cortex is a continuously-updated, persistent per-entity confidence
score that every pillar writes to and reads from. A pillar doesn't
just decide "is this bad enough to alert on its own" -- it also asks
"what does the Cortex already know about this entity from every other
pillar" before deciding, and contributes its own finding regardless of
whether it crosses its own threshold alone.

Score decays over time if not reinforced (an old, isolated flicker of
suspicion shouldn't stay maximally suspicious forever), but compounds
quickly when multiple pillars agree close together in time.
"""
from __future__ import annotations
import os
import time
import math
import logging
import threading
import duckdb
from dataclasses import dataclass

log = logging.getLogger(__name__)

CORTEX_DB_PATH = os.environ.get("CORTEX_DB_PATH",
    os.path.expanduser("~/ghostlayer/data/cortex.duckdb"))

# Half-life for score decay, in seconds. A contribution's influence
# halves every DECAY_HALFLIFE_SEC if not reinforced -- old, isolated
# signals fade, but anything reinforced within this window compounds.
DECAY_HALFLIFE_SEC = 600  # 10 minutes

# Per-pillar base weights. Deception (C3) and kernel integrity (C19)
# have the lowest false-positive rates of any pillar (a canary touch
# or a kernel tamper event has essentially no legitimate explanation),
# so they contribute the most to the fused score. Behavioral (C2) and
# LOLBin (C14) are noisier signals individually, so they contribute
# less per-hit but compound meaningfully when combined with others.
PILLAR_WEIGHTS = {
    "C2_behavioral":     15,
    "C3_deception":      40,
    "C4_causal":         25,
    "C14_lolbin":        15,
    "C15_ransomware":    30,
    "C19_kernel":        40,
}

ESCALATION_THRESHOLD = 60  # Cortex score at which cross-pillar fusion itself becomes alert-worthy

@dataclass
class CortexContribution:
    entity_id: str      # typically f"pid:{pid}" or f"host:{hostname}" for host-wide signals
    pillar: str          # one of PILLAR_WEIGHTS keys
    reason: str          # short human-readable reason
    ts: float = None

    def __post_init__(self):
        if self.ts is None:
            self.ts = time.time()

class Cortex:
    def __init__(self, db_path: str = CORTEX_DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._lock = threading.Lock()
        self.conn = duckdb.connect(db_path)
        self._init_schema()
        log.info(f"Cortex initialized: {db_path}")

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS contributions (
                entity_id VARCHAR NOT NULL,
                pillar    VARCHAR NOT NULL,
                reason    VARCHAR NOT NULL,
                weight    DOUBLE NOT NULL,
                ts        DOUBLE NOT NULL
            )
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_entity ON contributions(entity_id)
        """)

    def contribute(self, contribution: CortexContribution) -> dict:
        """
        A pillar reports a finding about an entity, REGARDLESS of
        whether the pillar's own threshold was crossed. Returns the
        entity's current fused score and whether cross-pillar
        escalation is now warranted.
        """
        weight = PILLAR_WEIGHTS.get(contribution.pillar, 10)
        with self._lock:
            self.conn.execute(
                "INSERT INTO contributions VALUES (?, ?, ?, ?, ?)",
                [contribution.entity_id, contribution.pillar,
                 contribution.reason, weight, contribution.ts]
            )
        result = self.get_score(contribution.entity_id)
        if result["score"] >= ESCALATION_THRESHOLD and result["distinct_pillars"] >= 2:
            log.warning(
                f"[Cortex] ESCALATION: {contribution.entity_id} "
                f"fused_score={result['score']:.1f} "
                f"pillars={result['pillars']} -- no single pillar alone "
                f"crossed its own threshold, but combined signal warrants attention"
            )
        return result

    def get_score(self, entity_id: str) -> dict:
        """
        Compute the current, time-decayed fused score for an entity.
        Each historical contribution's weight decays exponentially
        based on age (DECAY_HALFLIFE_SEC), so recent, reinforcing
        signals dominate while old isolated flickers fade naturally.
        """
        now = time.time()
        with self._lock:
            rows = self.conn.execute(
                "SELECT pillar, reason, weight, ts FROM contributions "
                "WHERE entity_id = ? ORDER BY ts DESC LIMIT 200",
                [entity_id]
            ).fetchall()
        if not rows:
            return {"entity_id": entity_id, "score": 0.0, "distinct_pillars": 0,
                     "pillars": [], "contributions": []}
        total = 0.0
        pillars_seen = set()
        contributions = []
        for pillar, reason, weight, ts in rows:
            age = now - ts
            decay = 0.5 ** (age / DECAY_HALFLIFE_SEC)
            decayed_weight = weight * decay
            total += decayed_weight
            pillars_seen.add(pillar)
            if decay > 0.05:  # only report contributions still meaningfully influencing the score
                contributions.append({
                    "pillar": pillar, "reason": reason,
                    "original_weight": weight, "current_weight": round(decayed_weight, 1),
                    "age_sec": round(age, 1),
                })
        # Cross-pillar bonus: agreement across MULTIPLE distinct pillars
        # is qualitatively stronger evidence than the same pillar firing
        # repeatedly -- reward diversity of signal sources, not just volume.
        diversity_bonus = (len(pillars_seen) - 1) * 10 if len(pillars_seen) > 1 else 0
        final_score = min(100.0, total + diversity_bonus)
        return {
            "entity_id": entity_id,
            "score": round(final_score, 1),
            "distinct_pillars": len(pillars_seen),
            "pillars": sorted(pillars_seen),
            "contributions": contributions,
        }

    def top_entities(self, limit: int = 20) -> list[dict]:
        """Return the highest-scoring entities right now -- the Cortex's
        own 'most suspicious right now' view, useful for a dashboard
        widget or as C4's prioritization queue."""
        with self._lock:
            entity_ids = self.conn.execute(
                "SELECT DISTINCT entity_id FROM contributions "
                "WHERE ts > ? ", [time.time() - DECAY_HALFLIFE_SEC * 4]
            ).fetchall()
        scored = [self.get_score(row[0]) for row in entity_ids]
        scored.sort(key=lambda s: s["score"], reverse=True)
        return scored[:limit]

    def cleanup_old(self, max_age_sec: float = 86400):
        """Purge contributions old enough to have fully decayed and be
        analytically irrelevant, keeping the table from growing unbounded."""
        with self._lock:
            self.conn.execute(
                "DELETE FROM contributions WHERE ts < ?",
                [time.time() - max_age_sec]
            )

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    cortex = Cortex(db_path="/tmp/cortex_test.duckdb")

    entity = "pid:99999"
    print("=== Simulating an attacker who stays under each pillar's own threshold ===\n")

    print("C2 (behavioral): mild anomaly, not alert-worthy alone")
    r = cortex.contribute(CortexContribution(entity, "C2_behavioral", "slight deviation from baseline"))
    print(f"  Fused score: {r['score']} (pillars: {r['pillars']})\n")

    time.sleep(1)
    print("C3 (deception): touched a canary file")
    r = cortex.contribute(CortexContribution(entity, "C3_deception", "canary file accessed"))
    print(f"  Fused score: {r['score']} (pillars: {r['pillars']})\n")

    time.sleep(1)
    print("C14 (LOLBin): minor suspicious chain, below own threshold")
    r = cortex.contribute(CortexContribution(entity, "C14_lolbin", "explorer->powershell, low confidence"))
    print(f"  Fused score: {r['score']} (pillars: {r['pillars']})\n")

    print(f"=== Result: no single pillar alone would have alerted, but the Cortex escalated at score {r['score']} across {r['distinct_pillars']} distinct pillars ===")
    print(f"\nFull contribution breakdown: {r['contributions']}")

    os.remove("/tmp/cortex_test.duckdb")
