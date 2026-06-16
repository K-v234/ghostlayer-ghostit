"""
Ghost IT — C2: Isolation Forest Anomaly Scorer

Trains incrementally on behavioral feature vectors.
Exported to ONNX for <5ms inference (C8 requirement).

Ghost Layer Technologies — CONFIDENTIAL
"""
from __future__ import annotations
import os
import logging
import numpy as np
from typing import Optional
from sklearn.ensemble import IsolationForest
from .features import BEHAVIORAL_FEATURES

log = logging.getLogger(__name__)

MODEL_PATH = os.path.expanduser("~/ghostlayer/data/models/isolation_forest.pkl")


class GhostIsolationForest:
    """
    Isolation Forest wrapper for Ghost IT behavioral anomaly detection.

    Training: batch mode on accumulated windows.
    Inference: single vector, target <5ms.
    """

    def __init__(self, contamination: float = 0.05,
                 n_estimators: int = 100):
        self.contamination = contamination
        self.n_estimators  = n_estimators
        self.model: Optional[IsolationForest] = None
        self.training_data: list[list[float]] = []
        self.min_samples = 50  # Need 50 windows before training
        self._load()

    def add_sample(self, feature_vector: dict[str, float]):
        """Add a feature vector to training buffer."""
        vec = [feature_vector.get(f, 0.0) for f in BEHAVIORAL_FEATURES]
        self.training_data.append(vec)

        # Auto-train when enough samples
        if len(self.training_data) >= self.min_samples and \
           len(self.training_data) % 10 == 0:
            self.train()

    def train(self):
        """Train Isolation Forest on accumulated data."""
        if len(self.training_data) < self.min_samples:
            log.debug(f"Not enough samples ({len(self.training_data)}/{self.min_samples})")
            return

        X = np.array(self.training_data, dtype=np.float32)
        self.model = IsolationForest(
            n_estimators  = self.n_estimators,
            contamination = self.contamination,
            random_state  = 42,
            n_jobs        = -1,
        )
        self.model.fit(X)
        log.info(f"Isolation Forest trained on {len(X)} samples")
        self._save()

    def score_onnx(self, feature_vector: dict[str, float]) -> float:
        """Score via ONNX runtime if available — faster, signed model."""
        try:
            import sys
            sys.path.insert(0, '/home/keerthivahanan/ghostlayer')
            from inference.runtime import GhostONNXRuntime
            if not hasattr(self, '_onnx_runtime'):
                self._onnx_runtime = GhostONNXRuntime("isolation_forest")
            vec = [feature_vector.get(f, 0.0) for f in __import__(
                'detection.behavioral.features',
                fromlist=['BEHAVIORAL_FEATURES']
            ).BEHAVIORAL_FEATURES]
            result = self._onnx_runtime.infer(vec)
            if result["available"]:
                return result["score"]
        except Exception:
            pass
        return self.score(feature_vector)

    def score(self, feature_vector: dict[str, float]) -> float:
        """
        Score a feature vector.
        Returns anomaly score 0-1 (higher = more anomalous).
        Returns 0.0 if model not trained yet.
        """
        if self.model is None:
            return 0.0

        vec = np.array(
            [[feature_vector.get(f, 0.0) for f in BEHAVIORAL_FEATURES]],
            dtype=np.float32
        )

        # sklearn returns negative scores: -1 = outlier, +1 = normal
        raw = self.model.score_samples(vec)[0]

        # Normalize to 0-1: more negative = more anomalous = higher score
        score = 1.0 - (raw + 0.5)
        return float(max(0.0, min(1.0, score)))

    def _save(self):
        import pickle
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        with open(MODEL_PATH, "wb") as f:
            pickle.dump(self.model, f)

    def _load(self):
        if not os.path.exists(MODEL_PATH):
            return
        try:
            import pickle
            with open(MODEL_PATH, "rb") as f:
                self.model = pickle.load(f)
            log.info("Isolation Forest model loaded from disk")
        except Exception as e:
            log.warning(f"Cannot load model: {e}")
