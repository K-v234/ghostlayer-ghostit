"""
Ghost IT — C2: Behavioral AI Engine

Combines:
  - 17-feature EWMA per-entity baseline
  - Isolation Forest anomaly scoring
  - Dual baseline (entity 60% + population 40%)
  - Behavioral anchor invariants (override ML)
  - Per-entity 15-second sliding windows

Ghost Layer Technologies — CONFIDENTIAL
"""
from __future__ import annotations
import time
import json
import socket
import logging
import threading
from dataclasses import dataclass
from typing import Optional
from collections import defaultdict

from .features    import FeatureWindow, BEHAVIORAL_FEATURES
from .baseline    import EntityBaseline
from .isolation_forest import GhostIsolationForest
from .anchors     import AnchorChecker, InvariantViolation
from .cade        import CADEDriftDetector, DriftType

log = logging.getLogger(__name__)

# Thresholds
ANOMALY_SCORE_ALERT    = 0.65  # Alert
ANOMALY_SCORE_CRITICAL = 0.85  # Critical


@dataclass
class BehavioralAlert:
    entity_id:      str
    score:          float
    severity:       str   # medium | high | critical
    feature_scores: dict
    top_features:   list[str]
    source:         str   # "ml" | "invariant"
    invariant_name: Optional[str] = None
    rationale:      Optional[str] = None

    def to_event(self) -> dict:
        return {
            "ts":      int(time.time_ns()),
            "pid":     0,
            "ppid":    0,
            "uid":     0,
            "gid":     0,
            "comm":    f"behavioral-ai:{self.entity_id}",
            "type":    "behavioral_anomaly",
            "score":   int(self.score * 100),
            "alert":   self.severity in ("high", "critical"),
            "reasons": [
                f"behavioral:{self.severity}",
                f"source:{self.source}",
                f"score:{self.score:.3f}",
            ] + (
                [f"invariant:{self.invariant_name}"] if self.invariant_name else []
            ) + [f"top:{f}" for f in self.top_features[:3]],
            "file":    self.rationale or f"Behavioral anomaly score={self.score:.3f}",
            "daddr":   None,
            "dport":   None,
        }


class BehavioralAIEngine:
    """
    C2 — Behavioral AI Engine.

    One instance handles all entities.
    Thread-safe — can be called from multiple threads.
    """

    def __init__(self, pipeline_host: str = "127.0.0.1",
                 pipeline_port: int = 9000,
                 window_sec: float = 15.0):
        self.pipeline_host = pipeline_host
        self.pipeline_port = pipeline_port
        self.window_sec    = window_sec

        # Per-entity state
        self._windows:   dict[str, FeatureWindow]   = {}
        self._baselines: dict[str, EntityBaseline]  = {}
        self._checkers:  dict[str, AnchorChecker]   = {}
        self._cade:      dict[str, CADEDriftDetector] = {}
        self._lock       = threading.Lock()

        # Shared Isolation Forest (global model)
        self._iso_forest = GhostIsolationForest()

        log.info("C2 Behavioral AI Engine initialized")

    def process_event(self, event: dict) -> Optional[BehavioralAlert]:
        """
        Process a single event.
        Returns BehavioralAlert if anomaly detected, None otherwise.
        """
        entity_id = self._entity_id(event)

        with self._lock:
            # Ensure entity state exists
            if entity_id not in self._windows:
                self._windows[entity_id]   = FeatureWindow(
                    entity_id=entity_id,
                    window_sec=self.window_sec,
                )
                self._baselines[entity_id] = EntityBaseline(entity_id)
                self._checkers[entity_id]  = AnchorChecker(entity_id)
                self._cade[entity_id]      = CADEDriftDetector(
                    entity_id,
                    feature_names=BEHAVIORAL_FEATURES,
                )

            window   = self._windows[entity_id]
            baseline = self._baselines[entity_id]
            checker  = self._checkers[entity_id]

            # Check invariants first — override ML
            violations = checker.check(event)
            if violations:
                v     = violations[0]
                alert = BehavioralAlert(
                    entity_id      = entity_id,
                    score          = 1.0,
                    severity       = "critical",
                    feature_scores = {},
                    top_features   = [],
                    source         = "invariant",
                    invariant_name = v.invariant_name,
                    rationale      = v.rationale,
                )
                self._forward(alert)
                return alert

            # Add to window
            window.add_event(event)

            # Flush window if expired
            if window.is_expired:
                alert = self._flush_window(entity_id, window, baseline)
                self._windows[entity_id] = FeatureWindow(
                    entity_id=entity_id,
                    window_sec=self.window_sec,
                )
                if alert:
                    self._forward(alert)
                return alert

        return None

    def _flush_window(
        self,
        entity_id: str,
        window: FeatureWindow,
        baseline: EntityBaseline,
    ) -> Optional[BehavioralAlert]:
        """Compute features, score, and return alert if threshold crossed."""
        fv = window.compute()

        # C2 CADE: check for adversarial drift
        cade = self._cade.get(entity_id)
        if cade:
            drift = cade.add_window(fv)
            if drift and drift.type == DriftType.ADVERSARIAL:
                alert = BehavioralAlert(
                    entity_id      = entity_id,
                    score          = 1.0,
                    severity       = "critical",
                    feature_scores = {},
                    top_features   = drift.drifting_features,
                    source         = "cade",
                    rationale      = drift.recommendation,
                )
                self._forward(alert)
                return alert

        # Add to Isolation Forest training buffer
        self._iso_forest.add_sample(fv)

        # Combined anomaly score
        combined_score = baseline.anomaly_score(fv)
        iso_score      = self._iso_forest.score(fv)

        # Weighted combination per spec
        if iso_score > 0:
            final_score = 0.7 * combined_score + 0.3 * iso_score
        else:
            final_score = combined_score

        # Update baseline
        z_scores = baseline.update(fv)

        if final_score < ANOMALY_SCORE_ALERT:
            return None

        # Find top anomalous features
        top = sorted(z_scores.items(), key=lambda x: x[1], reverse=True)
        top_features = [f for f, _ in top[:5]]

        severity = "critical" if final_score >= ANOMALY_SCORE_CRITICAL else "high"

        log.warning(
            f"BEHAVIORAL ANOMALY [{severity.upper()}] "
            f"entity={entity_id} score={final_score:.3f} "
            f"top={top_features[:3]}"
        )

        return BehavioralAlert(
            entity_id      = entity_id,
            score          = final_score,
            severity       = severity,
            feature_scores = z_scores,
            top_features   = top_features,
            source         = "ml",
            rationale      = f"Behavioral anomaly: {', '.join(top_features[:3])}",
        )

    def _entity_id(self, event: dict) -> str:
        """Entity ID = comm:uid for now. Will be enriched in V1."""
        comm = event.get("comm", "unknown")
        uid  = event.get("uid", 0)
        return f"{comm}:{uid}"

    def _forward(self, alert: BehavioralAlert):
        """Forward alert to Ghost IT pipeline."""
        payload = (json.dumps([alert.to_event()]) + "\n").encode()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((self.pipeline_host, self.pipeline_port))
            s.sendall(payload)
            s.close()
        except OSError as ex:
            log.error(f"Pipeline unavailable: {ex}")
