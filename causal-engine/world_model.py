#!/usr/bin/env python3
"""
Ghost IT — Endpoint World-Model

The gap this closes: Autonomous Response decides to suspend or
isolate a process based purely on confidence and cross-pillar
agreement -- it has no concept of what that process actually IS to
the business. This module maintains a live, continuously updated
graph of what exists on each endpoint -- processes, their
relationships, and a real, computable criticality score -- so any
response decision can ask "what actually breaks if I act on this,
right now" before acting.
"""
from __future__ import annotations
import os, time, logging, threading, duckdb

log = logging.getLogger(__name__)

WORLDMODEL_DB_PATH = os.environ.get("WORLDMODEL_DB_PATH",
    os.path.expanduser("~/ghostlayer/data/world_model.duckdb"))

CRITICAL_PROCESS_PATTERNS = {
    "sql", "postgres", "mysql", "oracle", "mongod",
    "sshd", "rdp", "winrm",
    "nginx", "apache", "iis", "httpd",
    "exchange", "outlook",
}

class WorldModel:
    def __init__(self, db_path: str = WORLDMODEL_DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._lock = threading.Lock()
        self.conn = duckdb.connect(db_path)
        self._init_schema()
        log.info(f"WorldModel initialized: {db_path}")

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS entities (
                entity_id     VARCHAR NOT NULL,
                host          VARCHAR NOT NULL,
                comm          VARCHAR NOT NULL,
                parent_id     VARCHAR,
                first_seen    DOUBLE NOT NULL,
                last_seen     DOUBLE NOT NULL,
                child_count   INTEGER NOT NULL DEFAULT 0,
                network_conn_count INTEGER NOT NULL DEFAULT 0,
                file_touch_count INTEGER NOT NULL DEFAULT 0
            )
        """)
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_wm_entity ON entities(entity_id)")

    def observe(self, entity_id: str, host: str, comm: str, parent_id: str = None, event_type: str = ""):
        now = time.time()
        with self._lock:
            existing = self.conn.execute(
                "SELECT entity_id FROM entities WHERE entity_id = ?", [entity_id]
            ).fetchone()
            if existing:
                inc_net = 1 if event_type in ("net_connect", "connect") else 0
                inc_file = 1 if event_type in ("file_write", "file_open") else 0
                self.conn.execute(
                    "UPDATE entities SET last_seen = ?, "
                    "network_conn_count = network_conn_count + ?, "
                    "file_touch_count = file_touch_count + ? WHERE entity_id = ?",
                    [now, inc_net, inc_file, entity_id]
                )
            else:
                self.conn.execute(
                    "INSERT INTO entities VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0)",
                    [entity_id, host, comm, parent_id, now, now]
                )
            if parent_id:
                self.conn.execute(
                    "UPDATE entities SET child_count = child_count + 1 WHERE entity_id = ?",
                    [parent_id]
                )

    def compute_criticality(self, entity_id: str) -> dict:
        with self._lock:
            row = self.conn.execute(
                "SELECT comm, first_seen, last_seen, child_count, "
                "network_conn_count, file_touch_count FROM entities WHERE entity_id = ?",
                [entity_id]
            ).fetchone()
        if not row:
            return {"entity_id": entity_id, "criticality": "unknown",
                     "criticality_score": 0, "reasoning": "entity not observed in world-model"}

        comm, first_seen, last_seen, child_count, net_count, file_count = row
        now = time.time()
        age_hours = (now - first_seen) / 3600
        score = 0
        reasons = []
        comm_lower = comm.lower()
        if any(pat in comm_lower for pat in CRITICAL_PROCESS_PATTERNS):
            score += 50
            reasons.append(f"process name matches known-critical pattern ('{comm}')")
        if child_count >= 3:
            score += min(30, child_count * 5)
            reasons.append(f"{child_count} dependent child processes would be affected")
        if age_hours >= 24:
            score += 15
            reasons.append(f"long-running ({age_hours:.1f}h) -- likely load-bearing, not transient")
        if net_count >= 10 or file_count >= 50:
            score += 10
            reasons.append(f"high real activity volume ({net_count} connections, {file_count} file touches)")

        tier = "critical" if score >= 60 else "elevated" if score >= 30 else "low"
        return {
            "entity_id": entity_id, "comm": comm, "criticality": tier,
            "criticality_score": min(100, score), "child_count": child_count,
            "age_hours": round(age_hours, 1), "reasoning": reasons,
        }

    def what_breaks_if_isolated(self, entity_id: str) -> dict:
        criticality = self.compute_criticality(entity_id)
        with self._lock:
            children = self.conn.execute(
                "SELECT entity_id, comm FROM entities WHERE parent_id = ?", [entity_id]
            ).fetchall()
        return {
            **criticality,
            "direct_dependents": [{"entity_id": c[0], "comm": c[1]} for c in children],
            "blast_radius_count": len(children),
        }

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    wm = WorldModel(db_path="/tmp/worldmodel_test.duckdb")

    print("=== Scenario: a real production database process, long-running, with dependents ===\n")
    wm.observe("pid:500", "linux", "postgres", parent_id=None, event_type="process_exec")
    wm.conn.execute("UPDATE entities SET first_seen = ? WHERE entity_id = 'pid:500'", [time.time() - 86400 * 3])
    for i in range(5):
        wm.observe(f"pid:{600+i}", "linux", "postgres_worker", parent_id="pid:500", event_type="process_exec")
    for _ in range(60):
        wm.observe("pid:500", "linux", "postgres", event_type="net_connect")

    result = wm.what_breaks_if_isolated("pid:500")
    print(f"Criticality: {result['criticality']} (score: {result['criticality_score']})")
    print(f"Blast radius: {result['blast_radius_count']} dependent processes")
    for r in result["reasoning"]:
        print(f"  - {r}")

    print("\n=== Scenario: a brand-new, isolated, throwaway script ===\n")
    wm.observe("pid:9999", "linux", "temp_script.sh", parent_id=None, event_type="process_exec")
    result2 = wm.what_breaks_if_isolated("pid:9999")
    print(f"Criticality: {result2['criticality']} (score: {result2['criticality_score']})")
    print(f"Blast radius: {result2['blast_radius_count']} dependent processes")

    print(f"\n=== Result: same isolation ACTION, genuinely different real-world consequence ===")
    os.remove("/tmp/worldmodel_test.duckdb")
