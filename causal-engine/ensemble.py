"""
Ghost IT — C4: Causal Engine Main
Polls pipeline for new events, builds provenance graph,
runs GNN ensemble, checks semantic invariants,
forwards CRITICAL alerts to pipeline.

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 100% — complete
"""
from __future__ import annotations
import os
import sys
import time
import json
import logging
import threading
import urllib.request
from typing import Optional

sys.path.insert(0, os.path.expanduser("~/ghostlayer"))

log = logging.getLogger(__name__)

_graph_mod = None
_inv_mod   = None
_gnn_mod   = None
_store_mod = None

def _load_modules():
    global _graph_mod, _inv_mod, _gnn_mod, _store_mod
    if _graph_mod:
        return
    import importlib.util
    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        mod  = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod
    base = os.path.expanduser("~/ghostlayer/causal-engine")
    _graph_mod = load("graph",      f"{base}/graph.py")
    _inv_mod   = load("invariants", f"{base}/invariants.py")
    _gnn_mod   = load("graphsage",  f"{base}/models/graphsage.py")
    _store_mod = load("store",      f"{base}/store.py")

class CausalEngine:
    PIPELINE_API  = os.environ.get("PIPELINE_API", "http://127.0.0.1:8000")
    POLL_INTERVAL = 15
    MIN_SCORE     = 40
    SUBGRAPH_SIZE = 5

    def __init__(self):
        _load_modules()
        self.graph    = _graph_mod.ProvenanceGraph()
        self.store    = _store_mod.ProvenanceStore()
        self.ensemble = _gnn_mod.GraphSAGEEnsemble()
        self._offset  = 0
        self._lock    = threading.Lock()
        log.info("C4 Causal Engine initialized")

    def _fetch_events(self) -> list:
        try:
            url = f"{self.PIPELINE_API}/events?limit=100&offset={self._offset}&min_score={self.MIN_SCORE}"
            with urllib.request.urlopen(url, timeout=10) as r:
                data = json.loads(r.read())
            events = data.get("events", [])
            if events:
                self._offset += len(events)
            return events
        except Exception as e:
            log.error(f"Pipeline fetch error: {e}")
            return []

    def _forward_alert(self, alert: dict):
        try:
            import socket
            payload = (json.dumps([alert]) + "\n").encode()
            s = socket.socket()
            s.settimeout(2)
            s.connect(("127.0.0.1", 9000))
            s.sendall(payload)
            s.close()
        except Exception as e:
            log.error(f"Alert forward error: {e}")
    def _watchlist_pid(self, pid: int):
        # Feedback loop: tell the pipeline this PID is confirmed
        # malicious so C2's downstream behavioral scoring elevates
        # suspicion on its subsequent actions, instead of scoring each
        # new event from this confirmed-bad entity from scratch.
        try:
            req = urllib.request.Request(
                f"{self.PIPELINE_API}/watchlist/{pid}", method="POST")
            urllib.request.urlopen(req, timeout=3)
        except Exception as e:
            log.error(f"Watchlist call error: {e}")

    def process_events(self, events: list):
        for event in events:
            self.graph.add_event(event)
            pid   = event.get("pid", 0)
            etype = event.get("event_type", event.get("type", ""))
            path  = event.get("path", "")
            ts    = event.get("ts", time.time() * 1e9) / 1e9
            node_id = f"proc:{pid}"
            self.store.save_node(node_id, "process",
                {"pid": pid, "comm": event.get("comm", "")}, ts)
            if path:
                fnode = f"file:{path}"
                self.store.save_node(fnode, "file", {"path": path}, ts)
                self.store.save_edge(node_id, fnode, etype, ts)

    def analyze_pid(self, pid: int) -> Optional[dict]:
        subgraph = self.graph.get_subgraph(pid)
        if len(subgraph.get("nodes", [])) < self.SUBGRAPH_SIZE:
            return None
        violation = _inv_mod.check_invariants(subgraph)
        if violation:
            alert = {
                "type": "causal_invariant", "score": 100, "alert": True,
                "pid": pid, "comm": "causal-engine", "ts": int(time.time()),
                "reasons": ["SEMANTIC_INVARIANT", violation.name,
                            violation.description, "severity:CRITICAL"]
            }
            log.critical(f"[C4] Invariant violated: {violation.name} pid={pid}")
            self._forward_alert(alert)
            self._watchlist_pid(pid)
            return alert
        result = self.ensemble.classify(subgraph)
        if result.label.name == "MALICIOUS" and result.confidence >= 0.75:
            alert = {
                "type": "causal_gnn", "score": int(result.confidence * 100),
                "alert": True, "pid": pid, "comm": "causal-engine",
                "ts": int(time.time()),
                "reasons": ["GNN_ENSEMBLE", f"confidence:{result.confidence:.2f}",
                            f"severity:{result.severity}", result.note]
            }
            log.warning(f"[C4] GNN malicious: pid={pid} confidence={result.confidence:.2f}")
            self._watchlist_pid(pid)
            self._forward_alert(alert)
            return alert
        return None

    def run(self):
        log.info(f"C4 Causal Engine running — poll={self.POLL_INTERVAL}s")
        seen_pids = set()
        while True:
            events = self._fetch_events()
            if events:
                self.process_events(events)
                for event in events:
                    pid = event.get("pid", 0)
                    if pid > 0 and pid not in seen_pids:
                        seen_pids.add(pid)
                        self.analyze_pid(pid)
            time.sleep(self.POLL_INTERVAL)

causal_engine = CausalEngine()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
        format="%(asctime)s [causal] %(levelname)s %(message)s")
    causal_engine.run()
