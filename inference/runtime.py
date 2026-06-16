"""
Ghost IT — C8: ONNX Inference Runtime

Loads signed ONNX models, verifies before use.
Target: <5ms per inference call.
Falls back to previous verified model if new model fails verification.

Ghost Layer Technologies — CONFIDENTIAL
"""
from __future__ import annotations
import os
import time
import logging
import numpy as np
from typing import Optional
import onnxruntime as ort
from .signing import verify_model, SecurityError

log = logging.getLogger(__name__)

MODELS_DIR = os.path.expanduser("~/ghostlayer/data/models")


class GhostONNXRuntime:
    """
    Secure ONNX inference runtime.

    - Verifies Ed25519 signature before loading any model
    - Keeps previous model as fallback
    - Measures inference latency
    - Target: <5ms per call
    """

    def __init__(self, model_name: str):
        self.model_name   = model_name
        self.model_path   = os.path.join(MODELS_DIR, f"{model_name}.onnx")
        self.session: Optional[ort.InferenceSession] = None
        self._fallback:   Optional[ort.InferenceSession] = None
        self._load()

    def _load(self):
        """Load and verify model. Fall back to previous if verification fails."""
        if not os.path.exists(self.model_path):
            log.warning(f"Model not found: {self.model_path}")
            return

        try:
            verify_model(self.model_path)
            new_session = ort.InferenceSession(
                self.model_path,
                providers=["CPUExecutionProvider"],
            )
            # Keep current as fallback before replacing
            if self.session:
                self._fallback = self.session
            self.session = new_session
            log.info(f"Model loaded: {self.model_name}")

        except SecurityError as ex:
            log.critical(f"MODEL SECURITY VIOLATION: {ex}")
            if self._fallback:
                log.warning("Falling back to previous verified model")
                self.session = self._fallback
            else:
                log.critical("No fallback model available — inference disabled")
                self.session = None

        except Exception as ex:
            log.error(f"Model load error: {ex}")

    def infer(self, feature_vector: list[float]) -> dict:
        """
        Run inference on a 17-feature vector.
        Returns dict with score and latency.
        Target: <5ms.
        """
        if self.session is None:
            return {"score": 0.0, "latency_ms": 0.0, "available": False}

        X = np.array([feature_vector], dtype=np.float32)

        t0 = time.perf_counter()
        outputs = self.session.run(None, {"X": X})
        latency_ms = (time.perf_counter() - t0) * 1000

        # Isolation Forest outputs: [labels, scores]
        # score_samples returns negative values — more negative = more anomalous
        if len(outputs) >= 2:
            raw_score = float(outputs[1][0])
        else:
            raw_score = float(outputs[0][0])

        # Normalize to 0-1
        score = float(max(0.0, min(1.0, 1.0 - (raw_score + 0.5))))

        if latency_ms > 5.0:
            log.warning(f"Inference latency {latency_ms:.2f}ms exceeds 5ms target")

        return {
            "score":      score,
            "latency_ms": latency_ms,
            "available":  True,
        }

    def reload(self):
        """Reload model — called by C16 when new signed model arrives."""
        log.info(f"Reloading model: {self.model_name}")
        self._load()
