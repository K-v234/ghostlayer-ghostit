"""
Ghost IT — Process Lineage Tracer
Builds parent→child process trees from event data.
Detects suspicious spawn chains like:
  sshd → bash → python3 → nc (reverse shell chain)
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from .rules import Detection


@dataclass
class ProcessNode:
    pid:      int
    ppid:     int
    comm:     str
    events:   list[dict] = field(default_factory=list)
    children: list["ProcessNode"] = field(default_factory=list)


# Chains that indicate compromise
SUSPICIOUS_CHAINS = [
    # Web shell: web server → shell
    ({"nginx","apache2","httpd"}, {"bash","sh","dash"}),
    # Shell → network tool (C2)
    ({"bash","sh","dash","zsh"}, {"nc","ncat","socat","curl","wget"}),
    # Shell → interpreter → network (staged payload)
    ({"bash","sh"}, {"python3","python","perl","ruby"}),
]

# Processes that should NEVER spawn children
STERILE_PROCS = {"nginx", "apache2", "sshd", "postgres", "mysql"}


class LineageTracer:
    """
    Builds and analyzes process trees.
    Call add_event() for each event, then analyze() to get detections.
    """

    def __init__(self):
        self.nodes: dict[int, ProcessNode] = {}

    def add_event(self, event: dict):
        pid  = event.get("pid", 0)
        ppid = event.get("ppid", 0)
        comm = event.get("comm", "")

        if pid not in self.nodes:
            self.nodes[pid] = ProcessNode(pid=pid, ppid=ppid, comm=comm)

        self.nodes[pid].events.append(event)

        # Link parent
        if ppid and ppid not in self.nodes:
            self.nodes[ppid] = ProcessNode(pid=ppid, ppid=0, comm="")

        if ppid and self.nodes[pid] not in self.nodes[ppid].children:
            self.nodes[ppid].children.append(self.nodes[pid])

    def _get_chain(self, pid: int) -> list[str]:
        """Walk up the tree to get ancestor comm names."""
        chain = []
        node  = self.nodes.get(pid)
        while node and len(chain) < 10:
            if node.comm:
                chain.append(node.comm)
            node = self.nodes.get(node.ppid)
        return list(reversed(chain))

    def analyze(self) -> list[Detection]:
        detections = []

        for pid, node in self.nodes.items():
            if not node.comm:
                continue

            chain = self._get_chain(pid)

            # Check suspicious spawn chains
            for parent_set, child_set in SUSPICIOUS_CHAINS:
                if (node.comm in child_set and
                    any(p in parent_set for p in chain[:-1])):
                    parent = next(
                        (p for p in chain[:-1] if p in parent_set), "unknown"
                    )
                    detections.append(Detection(
                        rule_id     = "L001",
                        severity    = "critical",
                        title       = "Suspicious Process Chain",
                        description = (
                            f"Suspicious spawn chain detected: "
                            f"{' → '.join(chain[-3:])}"
                        ),
                        confidence  = 88,
                        evidence    = node.events[:3],
                    ))
                    break

            # Check sterile process spawning children
            if node.comm in STERILE_PROCS and node.children:
                child_comms = [c.comm for c in node.children]
                detections.append(Detection(
                    rule_id     = "L002",
                    severity    = "high",
                    title       = "Unexpected Child Process",
                    description = (
                        f"{node.comm} spawned unexpected children: "
                        f"{', '.join(child_comms)}"
                    ),
                    confidence  = 82,
                    evidence    = node.events[:3],
                ))

        return detections
