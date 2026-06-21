"""
Ghost IT — C17: Alert Correlation Engine
Fuses alerts from all components into coherent incidents.
Supports 15-minute (ransomware) and 4-hour (APT) windows.

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 100% — complete
"""
from __future__ import annotations
import time
import logging
import threading
from typing import Dict, List, Optional
from datetime import timedelta

from .weights import get_weight, AlertSource
from .incidents import Alert, Incident
from .apt_window import detect_attack_mode, get_window, AttackMode

log = logging.getLogger(__name__)

class AlertCorrelationEngine:
    """
    Cross-component alert fusion engine.
    Groups related alerts into incidents within correlation window.
    Multiple independent components agreeing → higher confidence.
    Each additional agreeing source adds 5% confidence.
    """

    def __init__(self):
        self._incidents: Dict[str, Incident] = {}  # incident_id → Incident
        self._entity_map: Dict[str, str] = {}      # entity → incident_id
        self._lock = threading.Lock()
        log.info("C17 Alert Correlation Engine initialized")

    def correlate(self, alert: Alert) -> Incident:
        """
        Correlate an alert into an existing or new incident.
        Returns the incident this alert belongs to.
        """
        with self._lock:
            # Find existing open incident for same entity
            existing = self._find_incident(alert)

            if existing:
                existing.add_alert(alert)
                existing.confidence = self._compute_confidence(existing)
                log.info(
                    f"[C17] Alert added to incident {existing.incident_id} "
                    f"— {len(existing.alerts)} alerts, "
                    f"confidence={existing.confidence:.2f}, "
                    f"severity={existing.severity}"
                )
                return existing
            else:
                # Create new incident
                incident = Incident(
                    entity=alert.entity,
                    severity=alert.severity.upper(),
                )
                incident.add_alert(alert)
                incident.confidence = get_weight(alert.source)
                self._incidents[incident.incident_id] = incident
                self._entity_map[alert.entity] = incident.incident_id
                log.info(
                    f"[C17] New incident {incident.incident_id} "
                    f"— source={alert.source}, severity={alert.severity}"
                )
                return incident

    def _find_incident(self, alert: Alert) -> Optional[Incident]:
        """Find open incident for same entity within correlation window."""
        incident_id = self._entity_map.get(alert.entity)
        if not incident_id:
            return None

        incident = self._incidents.get(incident_id)
        if not incident:
            return None

        # Determine correlation window from first alert's MITRE tactic
        first_mitre = incident.mitre_tactics[0] if incident.mitre_tactics else ""
        mode   = detect_attack_mode(first_mitre)
        window = get_window(mode)

        # Check if incident is still within window
        elapsed = time.time() - incident.updated_at
        if elapsed > window.total_seconds():
            # Incident expired — close it
            log.info(
                f"[C17] Incident {incident_id} expired "
                f"({mode.value} window={window})"
            )
            del self._entity_map[alert.entity]
            return None

        return incident

    def _compute_confidence(self, incident: Incident) -> float:
        """
        Compute ensemble confidence score.
        Base = highest component weight.
        Each additional unique source adds 5%.
        """
        sources = list(set(a.source for a in incident.alerts))
        if not sources:
            return 0.0

        base_score = max(get_weight(s) for s in sources)
        agreement_bonus = 0.05 * (len(sources) - 1)
        return min(1.0, base_score + agreement_bonus)

    def get_open_incidents(self) -> List[dict]:
        """Return all open incidents as dicts."""
        with self._lock:
            return [i.to_dict() for i in self._incidents.values()]

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        with self._lock:
            return self._incidents.get(incident_id)

    def close_incident(self, incident_id: str):
        with self._lock:
            incident = self._incidents.pop(incident_id, None)
            if incident:
                # Remove from entity map
                for entity, iid in list(self._entity_map.items()):
                    if iid == incident_id:
                        del self._entity_map[entity]
                log.info(f"[C17] Incident {incident_id} closed")

    def stats(self) -> dict:
        with self._lock:
            return {
                "open_incidents": len(self._incidents),
                "tracked_entities": len(self._entity_map),
            }

# Singleton
correlation_engine = AlertCorrelationEngine()
