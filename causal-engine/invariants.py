"""
Ghost IT — C4: Semantic Invariants
Rules that ALWAYS trigger CRITICAL regardless of GNN score.
These override the ML model — no exceptions.

Based on PRD v5.0 and Tech Spec v3.0.

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 100% — complete
"""
from __future__ import annotations
import logging
from dataclasses import dataclass
from typing import Callable, Optional

log = logging.getLogger(__name__)

@dataclass
class InvariantViolation:
    name:        str
    description: str
    severity:    str = "CRITICAL"
    confidence:  float = 1.0

class SemanticInvariant:
    def __init__(self, name: str, condition: Callable, rationale: str):
        self.name      = name
        self.condition = condition
        self.rationale = rationale

    def check(self, subgraph: dict) -> Optional[InvariantViolation]:
        try:
            if self.condition(subgraph):
                log.critical(f"INVARIANT VIOLATED: {self.name} — {self.rationale}")
                return InvariantViolation(
                    name=self.name,
                    description=self.rationale
                )
        except Exception as e:
            log.error(f"Invariant check error {self.name}: {e}")
        return None

def _has_network_spawn(sg: dict) -> bool:
    """Network socket directly spawns process — always malicious."""
    net_nodes = {n["id"] for n in sg["nodes"] if n["type"] == "network"}
    for e in sg["edges"]:
        if e["src"] in net_nodes and e["type"] == "spawned":
            return True
    return False

def _has_tmp_exec(sg: dict) -> bool:
    """Executable loaded from /tmp/ — malware staging."""
    for n in sg["nodes"]:
        if n["type"] == "file":
            path = n.get("attrs", {}).get("path", "")
            if path.startswith("/tmp/"):
                for e in sg["edges"]:
                    if e["src"] == n["id"] and e["type"] == "loaded":
                        return True
    return False

def _has_lsass_access(sg: dict) -> bool:
    """LSASS access via injection or direct read — credential dump."""
    for n in sg["nodes"]:
        attrs = n.get("attrs", {})
        comm  = attrs.get("comm", "").lower()
        if "lsass" in comm:
            for e in sg["edges"]:
                if e["dst"] == n["id"] and e["type"] in ("injected", "read"):
                    return True
    return False

def _has_rapid_lateral(sg: dict) -> bool:
    """Network connections to 3+ unique hosts — lateral movement."""
    net_nodes = [n for n in sg["nodes"] if n["type"] == "network"]
    unique_hosts = set()
    for n in net_nodes:
        dst = n.get("attrs", {}).get("dst", "")
        if dst:
            host = dst.split(":")[0]
            unique_hosts.add(host)
    return len(unique_hosts) >= 3

def _has_shadow_delete(sg: dict) -> bool:
    """Shadow copy deletion — ransomware pre-encryption step."""
    for n in sg["nodes"]:
        attrs = n.get("attrs", {})
        comm  = attrs.get("comm", "").lower()
        if any(k in comm for k in ["vssadmin", "wmic", "shadow"]):
            return True
    return False

# All invariants — checked in order
SEMANTIC_INVARIANTS = [
    SemanticInvariant(
        "network_socket_spawn",
        _has_network_spawn,
        "Process spawned directly from network socket — always malicious"
    ),
    SemanticInvariant(
        "exec_from_tmp",
        _has_tmp_exec,
        "Executable loaded from /tmp/ — malware staging"
    ),
    SemanticInvariant(
        "lsass_access",
        _has_lsass_access,
        "LSASS access via injection or direct read — credential dump"
    ),
    SemanticInvariant(
        "rapid_lateral_movement",
        _has_rapid_lateral,
        "Connections to 3+ hosts — confirmed lateral movement"
    ),
    SemanticInvariant(
        "shadow_copy_deletion",
        _has_shadow_delete,
        "Shadow copy deletion — ransomware pre-encryption step"
    ),
]

def check_invariants(subgraph: dict) -> Optional[InvariantViolation]:
    """
    Check all semantic invariants against a subgraph.
    Returns first violation found, or None if clean.
    These override GNN output — always CRITICAL.
    """
    for invariant in SEMANTIC_INVARIANTS:
        violation = invariant.check(subgraph)
        if violation:
            return violation
    return None
