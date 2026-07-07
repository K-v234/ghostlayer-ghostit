"""
Ghost IT — C4: Provenance Graph
Builds causal provenance graph from eBPF events.
Tracks process→file→network→credential relationships.

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 40% — graph structure done, GNN integration pending
"""
from __future__ import annotations
import time
import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Set

log = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Node and Edge Types                                                  #
# ------------------------------------------------------------------ #

class NodeType(Enum):
    PROCESS    = "process"
    FILE       = "file"
    NETWORK    = "network"
    CREDENTIAL = "credential"
    USER       = "user"

class EdgeType(Enum):
    SPAWNED    = "spawned"
    WROTE      = "wrote"
    READ       = "read"
    CONNECTED  = "connected"
    ACCESSED   = "accessed"
    LOADED     = "loaded"
    INJECTED   = "injected"

@dataclass
class GraphNode:
    node_id:   str
    ntype:     NodeType
    attrs:     dict = field(default_factory=dict)
    ts:        float = field(default_factory=time.time)

@dataclass
class GraphEdge:
    src_id:    str
    dst_id:    str
    etype:     EdgeType
    ts:        float = field(default_factory=time.time)
    attrs:     dict = field(default_factory=dict)

# ------------------------------------------------------------------ #
# Provenance Graph                                                     #
# ------------------------------------------------------------------ #

class ProvenanceGraph:
    """
    Incremental provenance graph built from eBPF events.
    Nodes: Process, File, Network, Credential, User
    Edges: spawned, wrote, read, connected, accessed, loaded, injected
    """

    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        self._pid_to_node: Dict[int, str] = {}

    def add_event(self, event: dict):
        """Process a single eBPF event and update graph."""
        etype = event.get("event_type", "")
        pid   = event.get("pid", 0)
        ppid  = event.get("ppid", 0)
        comm  = event.get("comm", "")
        path  = event.get("path", "")
        ts    = event.get("ts", time.time())

        if etype in ("exec", "fork", "clone", "vfork"):
            self._handle_process(pid, ppid, comm, ts)

        elif etype in ("open", "openat", "read", "write"):
            self._handle_file(pid, path, etype, ts)

        elif etype in ("connect", "tcp_connect", "tcp_accept"):
            self._handle_network(pid, path, ts)

        elif etype in ("setuid", "setgid", "cap_check"):
            self._handle_credential(pid, comm, etype, ts)

    def _handle_process(self, pid: int, ppid: int, comm: str, ts: float):
        node_id = f"proc:{pid}"
        if node_id not in self.nodes:
            self.nodes[node_id] = GraphNode(
                node_id=node_id,
                ntype=NodeType.PROCESS,
                attrs={"pid": pid, "comm": comm},
                ts=ts
            )
            self._pid_to_node[pid] = node_id

        # Add edge from parent
        parent_id = self._pid_to_node.get(ppid)
        if parent_id:
            self.edges.append(GraphEdge(
                src_id=parent_id,
                dst_id=node_id,
                etype=EdgeType.SPAWNED,
                ts=ts
            ))

    def _handle_file(self, pid: int, path: str, etype: str, ts: float):
        if not path:
            return
        file_id = f"file:{path}"
        if file_id not in self.nodes:
            self.nodes[file_id] = GraphNode(
                node_id=file_id,
                ntype=NodeType.FILE,
                attrs={"path": path},
                ts=ts
            )
        proc_id = self._pid_to_node.get(pid)
        if proc_id:
            edge_type = EdgeType.WROTE if "write" in etype else EdgeType.READ
            self.edges.append(GraphEdge(
                src_id=proc_id,
                dst_id=file_id,
                etype=edge_type,
                ts=ts
            ))

    def _handle_network(self, pid: int, dst: str, ts: float):
        if not dst:
            return
        net_id = f"net:{dst}"
        if net_id not in self.nodes:
            self.nodes[net_id] = GraphNode(
                node_id=net_id,
                ntype=NodeType.NETWORK,
                attrs={"dst": dst},
                ts=ts
            )
        proc_id = self._pid_to_node.get(pid)
        if proc_id:
            self.edges.append(GraphEdge(
                src_id=proc_id,
                dst_id=net_id,
                etype=EdgeType.CONNECTED,
                ts=ts
            ))

    def _handle_credential(self, pid: int, comm: str, etype: str, ts: float):
        cred_id = f"cred:{pid}:{etype}"
        if cred_id not in self.nodes:
            self.nodes[cred_id] = GraphNode(
                node_id=cred_id,
                ntype=NodeType.CREDENTIAL,
                attrs={"type": etype, "comm": comm},
                ts=ts
            )
        proc_id = self._pid_to_node.get(pid)
        if proc_id:
            self.edges.append(GraphEdge(
                src_id=proc_id,
                dst_id=cred_id,
                etype=EdgeType.ACCESSED,
                ts=ts
            ))

    def get_subgraph(self, root_pid: int, depth: int = 3) -> dict:
        """Get subgraph rooted at a process — for GNN input."""
        root_id = self._pid_to_node.get(root_pid)
        if not root_id:
            return {"nodes": [], "edges": []}

        visited = set()
        queue = [root_id]
        for _ in range(depth):
            next_q = []
            for nid in queue:
                if nid in visited:
                    continue
                visited.add(nid)
                for edge in self.edges:
                    if edge.src_id == nid and edge.dst_id not in visited:
                        next_q.append(edge.dst_id)
            queue = next_q

        nodes = [self.nodes[n] for n in visited if n in self.nodes]
        edges = [e for e in self.edges
                 if e.src_id in visited and e.dst_id in visited]

        return {
            "nodes": [{"id": n.node_id, "type": n.ntype.value, "attrs": n.attrs} for n in nodes],
            "edges": [{"src": e.src_id, "dst": e.dst_id, "type": e.etype.value} for e in edges]
        }

    def stats(self) -> dict:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "processes": sum(1 for n in self.nodes.values() if n.ntype == NodeType.PROCESS),
            "files": sum(1 for n in self.nodes.values() if n.ntype == NodeType.FILE),
            "network": sum(1 for n in self.nodes.values() if n.ntype == NodeType.NETWORK),
        }

# Singleton
provenance_graph = ProvenanceGraph()
