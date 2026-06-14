"""
Ghost IT — Attack Chain Tracker
Links multiple detections into coherent attack stories.
Tracks kill chain progression in real time.
"""
from __future__ import annotations
import time
import uuid
import logging
from dataclasses import dataclass, field
from typing import Optional
from .mitre import get_mitre_tag, KillChainStage

log = logging.getLogger(__name__)

# Max seconds between detections to consider them part of same chain
CHAIN_TIMEOUT = 300  # 5 minutes


@dataclass
class ChainEvent:
    rule_id:     str
    title:       str
    tactic:      str
    technique:   str
    stage:       KillChainStage
    timestamp:   float
    confidence:  int


@dataclass
class AttackChain:
    chain_id:   str
    started_at: float
    events:     list[ChainEvent] = field(default_factory=list)

    @property
    def stages(self) -> list[KillChainStage]:
        return sorted({e.stage for e in self.events})

    @property
    def current_stage(self) -> Optional[KillChainStage]:
        return max(self.stages) if self.stages else None

    @property
    def severity(self) -> str:
        s = self.current_stage
        if not s:
            return "low"
        if s >= KillChainStage.COMMAND_CONTROL:
            return "critical"
        if s >= KillChainStage.CREDENTIAL_ACCESS:
            return "high"
        if s >= KillChainStage.EXECUTION:
            return "medium"
        return "low"

    @property
    def is_escalating(self) -> bool:
        """True if attack is moving to higher kill chain stages."""
        if len(self.events) < 2:
            return False
        return self.events[-1].stage > self.events[-2].stage

    def last_seen(self) -> float:
        return self.events[-1].timestamp if self.events else self.started_at

    def summary(self) -> dict:
        return {
            "chain_id":      self.chain_id,
            "started_at":    self.started_at,
            "duration_s":    int(time.time() - self.started_at),
            "event_count":   len(self.events),
            "current_stage": self.current_stage.label() if self.current_stage else "unknown",
            "severity":      self.severity,
            "escalating":    self.is_escalating,
            "stages":        [s.label() for s in self.stages],
            "tactics":       list({e.tactic for e in self.events}),
            "techniques":    list({e.technique for e in self.events}),
        }


class ChainTracker:
    """
    Maintains active attack chains.
    Each new detection either extends an existing chain or starts a new one.
    Chains expire after CHAIN_TIMEOUT seconds of inactivity.
    """

    def __init__(self):
        self.chains: dict[str, AttackChain] = {}

    def process(self, rule_id: str, title: str, confidence: int) -> AttackChain:
        """Add a detection to the appropriate chain."""
        tag = get_mitre_tag(rule_id)
        if not tag:
            return None

        now = time.time()
        event = ChainEvent(
            rule_id    = rule_id,
            title      = title,
            tactic     = tag.tactic,
            technique  = tag.technique_id,
            stage      = tag.kill_chain,
            timestamp  = now,
            confidence = confidence,
        )

        # Find active chain or create new one
        active = self._find_active_chain(now)
        if active:
            active.events.append(event)
            chain = active
        else:
            chain = AttackChain(
                chain_id   = str(uuid.uuid4())[:8],
                started_at = now,
                events     = [event],
            )
            self.chains[chain.chain_id] = chain

        # Log chain status
        summary = chain.summary()
        if chain.is_escalating:
            log.warning(
                f"CHAIN [{chain.chain_id}] ESCALATING → {summary['current_stage']} "
                f"| {summary['event_count']} events | {summary['severity'].upper()}"
            )
        else:
            log.info(
                f"CHAIN [{chain.chain_id}] {summary['current_stage']} "
                f"| {summary['event_count']} events"
            )

        # Expire old chains
        self._expire_chains(now)
        return chain

    def _find_active_chain(self, now: float) -> Optional[AttackChain]:
        """Find most recently active chain within timeout window."""
        candidates = [
            c for c in self.chains.values()
            if now - c.last_seen() < CHAIN_TIMEOUT
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda c: c.last_seen())

    def _expire_chains(self, now: float):
        expired = [
            cid for cid, c in self.chains.items()
            if now - c.last_seen() > CHAIN_TIMEOUT * 2
        ]
        for cid in expired:
            log.info(f"CHAIN [{cid}] expired")
            del self.chains[cid]

    def active_chains(self) -> list[dict]:
        now = time.time()
        return [
            c.summary() for c in self.chains.values()
            if now - c.last_seen() < CHAIN_TIMEOUT
        ]

    def highest_severity(self) -> str:
        active = self.active_chains()
        if not active:
            return "none"
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
        return max(active, key=lambda c: order.get(c["severity"], 0))["severity"]
