"""
Ghost IT — C17: Incident Data Model
Groups related alerts into coherent incidents.

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 100% — complete
"""
from __future__ import annotations
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class Alert:
    alert_id:   str
    source:     str
    severity:   str
    score:      float
    entity:     str          # PID, IP, or hostname
    description: str
    mitre:      str
    ts:         float = field(default_factory=time.time)
    raw:        dict  = field(default_factory=dict)

@dataclass
class Incident:
    incident_id:  str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    alerts:       List[Alert] = field(default_factory=list)
    confidence:   float = 0.0
    severity:     str = "LOW"
    entity:       str = ""
    started_at:   float = field(default_factory=time.time)
    updated_at:   float = field(default_factory=time.time)
    mitre_tactics: List[str] = field(default_factory=list)
    escalating:   bool = False

    def add_alert(self, alert: Alert):
        self.alerts.append(alert)
        self.updated_at = time.time()
        # Update severity — take highest
        severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        current = severity_order.get(self.severity, 0)
        new     = severity_order.get(alert.severity.upper(), 0)
        if new > current:
            self.severity = alert.severity.upper()
        # Add MITRE tactic if new
        if alert.mitre and alert.mitre not in self.mitre_tactics:
            self.mitre_tactics.append(alert.mitre)
        # Check escalating — 2+ components agreeing
        sources = set(a.source for a in self.alerts)
        self.escalating = len(sources) >= 2

    def duration_seconds(self) -> float:
        return self.updated_at - self.started_at

    def to_dict(self) -> dict:
        return {
            "incident_id":   self.incident_id,
            "severity":      self.severity,
            "confidence":    round(self.confidence, 3),
            "entity":        self.entity,
            "alert_count":   len(self.alerts),
            "sources":       list(set(a.source for a in self.alerts)),
            "mitre_tactics": self.mitre_tactics,
            "escalating":    self.escalating,
            "started_at":    self.started_at,
            "updated_at":    self.updated_at,
            "duration_s":    round(self.duration_seconds(), 1),
        }
