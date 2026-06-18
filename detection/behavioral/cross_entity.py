"""
Ghost IT — C2: Cross-Entity Consistency Audit + PSI Drift Detection

Cross-entity audit: detects coordinated spikes across multiple PIDs/UIDs
that no single-entity baseline would catch (e.g. worm spreading).

PSI drift: Population Stability Index monitors feature distribution shift
week-over-week — flags when the model's training distribution drifts.

Ghost Layer Technologies — CONFIDENTIAL
"""

import math
import time
import logging
import threading
from collections import defaultdict, deque
from typing import Dict, List, Optional

log = logging.getLogger("cross_entity")

# ------------------------------------------------------------------ #
# Cross-Entity Consistency Audit                                      #
# ------------------------------------------------------------------ #

AUDIT_WINDOW_SEC  = 60      # look-back window
SPIKE_THRESHOLD   = 0.7     # fraction of entities that must spike together
MIN_ENTITIES      = 3       # need at least 3 entities to call coordinated

class CrossEntityAuditor:
    """
    Tracks anomaly scores per entity over time.
    If >= SPIKE_THRESHOLD fraction of active entities spike within
    AUDIT_WINDOW_SEC, raises a coordinated-attack alert.
    """

    def __init__(self):
        # entity_id -> deque of (timestamp, score)
        self._scores: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._lock = threading.Lock()
        self._alert_cb = None

    def set_alert_callback(self, cb):
        """cb(alert_dict) called when coordinated spike detected."""
        self._alert_cb = cb

    def record(self, entity_id: str, score: float):
        """Record an anomaly score for an entity (call from behavioral engine)."""
        with self._lock:
            self._scores[entity_id].append((time.time(), score))

    def audit(self) -> Optional[dict]:
        """
        Run consistency audit. Returns alert dict if coordinated spike found,
        else None.
        """
        now = time.time()
        cutoff = now - AUDIT_WINDOW_SEC

        with self._lock:
            active_entities = {}
            for eid, dq in self._scores.items():
                # Get scores within window
                recent = [(t, s) for t, s in dq if t >= cutoff]
                if recent:
                    max_score = max(s for _, s in recent)
                    active_entities[eid] = max_score

        if len(active_entities) < MIN_ENTITIES:
            return None

        # Count how many entities have high anomaly scores
        spiking = {eid: s for eid, s in active_entities.items() if s >= 0.6}
        fraction = len(spiking) / len(active_entities)

        if fraction >= SPIKE_THRESHOLD:
            alert = {
                "type":        "cross_entity_spike",
                "alert":       True,
                "score":       100,
                "fraction":    round(fraction, 3),
                "spiking":     len(spiking),
                "total":       len(active_entities),
                "entities":    list(spiking.keys())[:10],
                "ts":          int(now),
                "comm":        "cross_entity_audit",
                "pid":         0,
                "description": (
                    f"Coordinated anomaly: {len(spiking)}/{len(active_entities)} "
                    f"entities spiked ({fraction*100:.0f}%) — possible worm/lateral movement"
                )
            }
            log.critical(
                f"[CROSS-ENTITY] Coordinated spike: "
                f"{len(spiking)}/{len(active_entities)} entities ({fraction*100:.0f}%)"
            )
            if self._alert_cb:
                self._alert_cb(alert)
            return alert

        return None

    def run_periodic(self, interval_sec: int = 60):
        """Start background audit thread."""
        def _loop():
            while True:
                time.sleep(interval_sec)
                try:
                    self.audit()
                except Exception as e:
                    log.error(f"Cross-entity audit error: {e}")
        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        log.info("Cross-entity auditor started (60s interval)")


# ------------------------------------------------------------------ #
# PSI Drift Detection                                                 #
# ------------------------------------------------------------------ #

PSI_THRESHOLD_WARN     = 0.1   # minor drift
PSI_THRESHOLD_CRITICAL = 0.25  # significant drift — retrain needed
N_BINS                 = 10

class PSIDriftDetector:
    """
    Population Stability Index drift detection.
    Compares current feature distribution against baseline (training week).
    PSI < 0.1  → no significant change
    PSI 0.1-0.25 → moderate change, monitor
    PSI > 0.25 → significant drift, retrain model
    """

    def __init__(self, n_features: int = 17):
        self.n_features  = n_features
        self._baseline: Optional[List[List[float]]] = None   # per-feature bins
        self._current:  List[List[float]] = [[] for _ in range(n_features)]
        self._lock = threading.Lock()
        self._week_start = time.time()

    def add_sample(self, feature_vector: List[float]):
        """Add a feature vector to the current window."""
        if len(feature_vector) != self.n_features:
            return
        with self._lock:
            for i, v in enumerate(feature_vector):
                self._current[i].append(v)

    def set_baseline(self, samples: List[List[float]]):
        """Set baseline distribution from training data."""
        with self._lock:
            self._baseline = [[] for _ in range(self.n_features)]
            for vec in samples:
                for i, v in enumerate(vec[:self.n_features]):
                    self._baseline[i].append(v)
        log.info(f"PSI baseline set: {len(samples)} samples")

    def _psi_single(self, baseline: List[float], current: List[float]) -> float:
        """Compute PSI for a single feature."""
        if not baseline or not current:
            return 0.0

        # Build bins from baseline
        mn = min(baseline)
        mx = max(baseline)
        if mx == mn:
            return 0.0

        edges = [mn + (mx - mn) * i / N_BINS for i in range(N_BINS + 1)]

        def bin_counts(data):
            counts = [0] * N_BINS
            for v in data:
                idx = min(int((v - mn) / (mx - mn) * N_BINS), N_BINS - 1)
                counts[idx] += 1
            total = len(data)
            return [max(c / total, 1e-4) for c in counts]

        base_pct = bin_counts(baseline)
        curr_pct = bin_counts(current)

        psi = sum(
            (c - b) * math.log(c / b)
            for b, c in zip(base_pct, curr_pct)
        )
        return psi

    def compute_psi(self) -> Optional[dict]:
        """Compute PSI across all features. Returns result dict."""
        with self._lock:
            if not self._baseline:
                return None
            if not any(self._current):
                return None
            baseline = [list(b) for b in self._baseline]
            current  = [list(c) for c in self._current]

        psi_scores = []
        for i in range(self.n_features):
            psi_scores.append(self._psi_single(baseline[i], current[i]))

        avg_psi = sum(psi_scores) / len(psi_scores)
        max_psi = max(psi_scores)
        max_feat = psi_scores.index(max_psi)

        level = "ok"
        if avg_psi >= PSI_THRESHOLD_CRITICAL:
            level = "critical"
        elif avg_psi >= PSI_THRESHOLD_WARN:
            level = "warn"

        result = {
            "type":      "psi_drift",
            "avg_psi":   round(avg_psi, 4),
            "max_psi":   round(max_psi, 4),
            "max_feat":  max_feat,
            "level":     level,
            "alert":     level == "critical",
            "score":     min(int(avg_psi * 400), 100),
            "ts":        int(time.time()),
            "comm":      "psi_drift",
            "pid":       0,
        }

        if level == "critical":
            log.critical(f"[PSI] Significant drift: avg={avg_psi:.3f} max={max_psi:.3f} feat={max_feat} — RETRAIN NEEDED")
        elif level == "warn":
            log.warning(f"[PSI] Moderate drift: avg={avg_psi:.3f} max={max_psi:.3f} feat={max_feat}")
        else:
            log.info(f"[PSI] No significant drift: avg={avg_psi:.3f}")

        return result

    def run_weekly(self, interval_sec: int = 604800):
        """Run PSI check weekly (default) or on custom interval."""
        def _loop():
            while True:
                time.sleep(interval_sec)
                try:
                    result = self.compute_psi()
                    if result:
                        log.info(f"[PSI] Weekly check: {result}")
                    # Rotate: current becomes new baseline
                    with self._lock:
                        if any(self._current):
                            self._baseline = [list(c) for c in self._current]
                        self._current = [[] for _ in range(self.n_features)]
                except Exception as e:
                    log.error(f"PSI drift check error: {e}")
        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        log.info(f"PSI drift detector started ({interval_sec}s interval)")


# ------------------------------------------------------------------ #
# Singleton instances                                                 #
# ------------------------------------------------------------------ #
cross_entity_auditor = CrossEntityAuditor()
psi_detector         = PSIDriftDetector(n_features=17)
