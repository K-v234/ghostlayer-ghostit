"""
Ghost IT — C2: EWMA Baseline Tracker

Per-entity exponentially weighted moving average baseline.
Alpha=0.05 — slow adaptation, resistant to short-term poisoning.

Ghost Layer Technologies — CONFIDENTIAL
"""
from __future__ import annotations
import math
import json
import os
import logging
import time
from dataclasses import dataclass, field
from typing import Optional
from .features import BEHAVIORAL_FEATURES

log = logging.getLogger(__name__)

# 8 role archetypes per spec
ROLE_ARCHETYPES = [
    "Developer", "SysAdmin", "Finance", "HR",
    "Executive", "ServiceAccount", "Workstation", "Server"
]

# Population baselines — P10/P90 per archetype
# These are initial estimates — updated as data accumulates
POPULATION_BASELINES = {
    "Developer": {
        "p10": [0.1, 0.05, 0.05, 0.02, 50, 0.5, 0.0, 0.0, 0.0, 0.5, 0.1, 0.5, 0.0, 0.0, 0.1, 0.1, 0.0],
        "p90": [5.0, 10.0, 2.0, 5.0, 5000, 5.0, 0.3, 0.1, 0.5, 5.0, 2.0, 5.0, 1.0, 1.0, 1.0, 3.0, 0.0],
    },
    "SysAdmin": {
        "p10": [0.2, 0.1, 0.1, 0.05, 100, 1.0, 0.0, 0.0, 0.1, 1.0, 0.2, 1.0, 0.0, 0.0, 0.2, 0.2, 0.0],
        "p90": [10.0, 20.0, 5.0, 10.0, 10000, 10.0, 0.5, 0.5, 2.0, 10.0, 5.0, 10.0, 2.0, 2.0, 2.0, 5.0, 0.0],
    },
    "ServiceAccount": {
        "p10": [0.0, 0.0, 0.0, 0.0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "p90": [0.5, 1.0, 1.0, 2.0, 2000, 1.0, 0.0, 0.0, 0.0, 0.5, 0.1, 0.5, 0.0, 0.0, 0.1, 0.0, 0.0],
    },
    "Workstation": {
        "p10": [0.05, 0.02, 0.02, 0.01, 20, 0.2, 0.0, 0.0, 0.0, 0.1, 0.05, 0.2, 0.0, 0.0, 0.05, 0.05, 0.0],
        "p90": [2.0, 5.0, 1.0, 3.0, 3000, 3.0, 0.2, 0.1, 0.2, 2.0, 1.0, 3.0, 1.0, 1.0, 0.5, 1.0, 0.0],
    },
}

# Default baseline for unknown archetypes
for archetype in ROLE_ARCHETYPES:
    if archetype not in POPULATION_BASELINES:
        POPULATION_BASELINES[archetype] = POPULATION_BASELINES["Workstation"]


@dataclass
class EWMAFeatureTracker:
    """
    Tracks EWMA mean and variance for a single feature.
    alpha=0.05 — slow, poisoning-resistant adaptation.
    """
    alpha:  float = 0.05
    ema:    Optional[float] = None
    var:    float = 0.0
    n:      int   = 0

    def update(self, value: float) -> tuple[float, float]:
        """Update and return (z_score, ema)."""
        if self.ema is None:
            self.ema = value
            self.n   = 1
            return 0.0, value

        prev_ema = self.ema
        self.ema = self.alpha * value + (1 - self.alpha) * self.ema
        self.var = self.alpha * (value - prev_ema) ** 2 + \
                   (1 - self.alpha) * self.var
        self.n  += 1

        std = max(math.sqrt(self.var), 1e-6)
        z   = abs(value - self.ema) / std
        return z, self.ema

    @property
    def is_warmed_up(self) -> bool:
        return self.n >= 20  # 20 windows = 5 minutes of data


class EntityBaseline:
    """
    Per-entity EWMA baseline for all 17 features.
    Persists to disk for survival across restarts.
    """

    def __init__(self, entity_id: str, role_archetype: str = "Workstation",
                 state_dir: str = None):
        self.entity_id      = entity_id
        self.role_archetype = role_archetype
        self.state_dir      = state_dir or os.path.expanduser(
            "~/ghostlayer/data/baselines"
        )
        self.trackers = {
            f: EWMAFeatureTracker() for f in BEHAVIORAL_FEATURES
        }
        self.created_at = time.time()
        self._load()

    def update(self, feature_vector: dict[str, float]) -> dict[str, float]:
        """
        Update baseline with new feature vector.
        Returns dict of z-scores per feature.
        """
        z_scores = {}
        for feature, value in feature_vector.items():
            if feature in self.trackers:
                z, _ = self.trackers[feature].update(value)
                z_scores[feature] = z
        self._save()
        return z_scores

    def anomaly_score(self, feature_vector: dict[str, float]) -> float:
        """
        Compute combined anomaly score (0-1).
        Combines entity EWMA score (60%) + population range score (40%).
        """
        entity_score = self._entity_score(feature_vector)
        pop_score    = self._population_score(feature_vector)
        return 0.6 * entity_score + 0.4 * pop_score

    def _entity_score(self, fv: dict[str, float]) -> float:
        """Entity-level z-score normalized to 0-1."""
        scores = []
        for f, v in fv.items():
            tracker = self.trackers.get(f)
            if tracker and tracker.is_warmed_up:
                z, _ = tracker.update(v)
                # Normalize: z=3 → 1.0, z=0 → 0.0
                scores.append(min(z / 3.0, 1.0))
        return sum(scores) / max(len(scores), 1)

    def _population_score(self, fv: dict[str, float]) -> float:
        """Population range violation score (0-1)."""
        baseline = POPULATION_BASELINES.get(
            self.role_archetype,
            POPULATION_BASELINES["Workstation"]
        )
        p10 = baseline["p10"]
        p90 = baseline["p90"]

        violations = 0
        total      = 0
        for i, feature in enumerate(BEHAVIORAL_FEATURES):
            val = fv.get(feature, 0.0)
            if val > p90[i] * 2:   # 2x above P90 = clear violation
                violations += 1
            elif val < p10[i] / 2: # 2x below P10 = also anomalous
                violations += 0.5
            total += 1

        return violations / max(total, 1)

    def _save(self):
        """Persist baseline state to disk."""
        os.makedirs(self.state_dir, exist_ok=True)
        path = os.path.join(self.state_dir, f"{self.entity_id}.json")
        state = {
            f: {"ema": t.ema, "var": t.var, "n": t.n}
            for f, t in self.trackers.items()
        }
        try:
            with open(path, "w") as fp:
                json.dump(state, fp)
        except OSError as e:
            log.warning(f"Cannot save baseline for {self.entity_id}: {e}")

    def _load(self):
        """Load persisted baseline state from disk."""
        path = os.path.join(self.state_dir, f"{self.entity_id}.json")
        if not os.path.exists(path):
            return
        try:
            with open(path) as fp:
                state = json.load(fp)
            for f, s in state.items():
                if f in self.trackers:
                    self.trackers[f].ema = s.get("ema")
                    self.trackers[f].var = s.get("var", 0.0)
                    self.trackers[f].n   = s.get("n", 0)
            log.info(f"Loaded baseline for entity {self.entity_id}")
        except Exception as e:
            log.warning(f"Cannot load baseline for {self.entity_id}: {e}")
