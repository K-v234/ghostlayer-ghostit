#!/usr/bin/env python3
"""
Ghost IT — Adaptive Threshold Calibration

Architectural gap this closes: detection thresholds (C15's entropy
delta, C2's z-scores, C14's confidence cutoffs) are fixed constants
chosen once, globally, for every deployment. A quiet accounting
firm and a noisy dev shop running constant compilers/build tools have
wildly different baseline activity levels -- a fixed threshold is
either too sensitive (drowns the quiet deployment in false positives)
or too blind (misses real signal on the noisy one, since its "normal"
already looks like what the fixed threshold was tuned to catch).

This module continuously observes each deployment's own event-score
distribution and computes a locally-appropriate threshold using
percentile-based calibration -- the threshold that would have flagged
only the top N% most unusual events THIS SPECIFIC DEPLOYMENT actually
produced, rather than a number chosen in the abstract.
"""
from __future__ import annotations
import os
import time
import logging
import threading
import statistics
import duckdb

log = logging.getLogger(__name__)

THRESHOLDS_DB_PATH = os.environ.get("THRESHOLDS_DB_PATH",
    os.path.expanduser("~/ghostlayer/data/adaptive_thresholds.duckdb"))

# How many recent score observations to keep per pillar for
# calibration -- large enough for statistical stability, small enough
# that the baseline adapts to genuinely new normal behavior (e.g. a
# new backup tool being installed) within a reasonable window.
WINDOW_SIZE = 2000

# Target percentile: the threshold is set so that roughly this
# fraction of a deployment's OWN observed activity would be flagged
# -- i.e. "the top 2% most unusual things THIS deployment does."
# Tunable per pillar since some (deception) should have near-zero
# tolerance while others (behavioral) genuinely need more headroom.
DEFAULT_TARGET_PERCENTILE = 98.0

# Hard floor/ceiling so a deployment's own noise can't calibrate the
# threshold into something nonsensical (e.g. a deployment that's
# ALREADY compromised and constantly noisy shouldn't calibrate its
# own threshold up to "normal").
MIN_THRESHOLD = 30
MAX_THRESHOLD = 95

class AdaptiveThresholds:
    def __init__(self, db_path: str = THRESHOLDS_DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._lock = threading.Lock()
        self.conn = duckdb.connect(db_path)
        self._init_schema()
        log.info(f"AdaptiveThresholds initialized: {db_path}")

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS observations (
                pillar VARCHAR NOT NULL,
                score  DOUBLE NOT NULL,
                ts     DOUBLE NOT NULL
            )
        """)
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_pillar ON observations(pillar)")

    def observe(self, pillar: str, score: float):
        """
        Record a raw score observation for this pillar, regardless of
        whether it crossed any threshold -- calibration needs to see
        the FULL distribution of normal activity, not just the
        already-flagged tail.
        """
        with self._lock:
            self.conn.execute(
                "INSERT INTO observations VALUES (?, ?, ?)",
                [pillar, score, time.time()]
            )
            count = self.conn.execute(
                "SELECT COUNT(*) FROM observations WHERE pillar = ?", [pillar]
            ).fetchone()[0]
            if count > WINDOW_SIZE * 1.2:
                # Trim to keep only the most recent WINDOW_SIZE, keeping
                # the calibration responsive to recent behavior rather
                # than accumulating unbounded history.
                self.conn.execute("""
                    DELETE FROM observations WHERE pillar = ? AND ts < (
                        SELECT ts FROM observations WHERE pillar = ?
                        ORDER BY ts DESC LIMIT 1 OFFSET ?
                    )
                """, [pillar, pillar, WINDOW_SIZE])

    def get_threshold(self, pillar: str,
                        target_percentile: float = DEFAULT_TARGET_PERCENTILE) -> dict:
        """
        Compute the current, locally-calibrated threshold for a
        pillar based on its own observed score distribution. Falls
        back to a sensible default if too few observations exist yet
        to calibrate reliably (a brand-new deployment has no history
        to learn from -- it should use conservative global defaults
        until it accumulates enough real activity).
        """
        with self._lock:
            rows = self.conn.execute(
                "SELECT score FROM observations WHERE pillar = ? ORDER BY ts DESC LIMIT ?",
                [pillar, WINDOW_SIZE]
            ).fetchall()
        scores = [r[0] for r in rows]
        if len(scores) < 100:
            return {
                "pillar": pillar, "threshold": 70, "calibrated": False,
                "sample_size": len(scores),
                "reason": "insufficient observations, using conservative default",
            }
        scores.sort()
        idx = int(len(scores) * (target_percentile / 100.0))
        idx = min(idx, len(scores) - 1)
        raw_threshold = scores[idx]
        clamped = max(MIN_THRESHOLD, min(MAX_THRESHOLD, raw_threshold))
        return {
            "pillar": pillar, "threshold": round(clamped, 1), "calibrated": True,
            "sample_size": len(scores), "raw_percentile_value": round(raw_threshold, 1),
            "mean": round(statistics.mean(scores), 1),
            "stddev": round(statistics.stdev(scores), 1) if len(scores) > 1 else 0,
        }

if __name__ == "__main__":
    import random
    logging.basicConfig(level=logging.INFO)
    at = AdaptiveThresholds(db_path="/tmp/thresholds_test.duckdb")

    print("=== Simulating a QUIET deployment (low, tight score distribution) ===")
    for _ in range(500):
        at.observe("C2_behavioral", random.gauss(15, 5))
    quiet_result = at.get_threshold("C2_behavioral")
    print(f"Quiet deployment threshold: {quiet_result}\n")

    print("=== Simulating a NOISY deployment (higher, wider score distribution) ===")
    at2 = AdaptiveThresholds(db_path="/tmp/thresholds_test2.duckdb")
    for _ in range(500):
        at2.observe("C2_behavioral", random.gauss(40, 15))
    noisy_result = at2.get_threshold("C2_behavioral")
    print(f"Noisy deployment threshold: {noisy_result}\n")

    print(f"=== Result: same pillar, two different deployments, two genuinely different calibrated thresholds ({quiet_result['threshold']} vs {noisy_result['threshold']}) -- each tuned to its OWN normal, not one global fixed constant ===")

    os.remove("/tmp/thresholds_test.duckdb")
    os.remove("/tmp/thresholds_test2.duckdb")
