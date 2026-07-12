"""
Ghost IT — C4: Provenance Graph Store
Persists provenance graph nodes and edges in DuckDB.
Enables historical attack chain queries.

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 100% — complete
"""
from __future__ import annotations
import os
import json
import logging
import duckdb
from typing import List, Optional

log = logging.getLogger(__name__)

# Configurable via env var for container compatibility -- same pattern
# as CHAIN_STATE_PATH in detection/engine.py. Docker mounts data at
# /data (see docker-compose.yml volumes), not ~/ghostlayer/data which
# only exists on developer machines.
DB_PATH = os.environ.get("PROVENANCE_DB_PATH",
    os.path.expanduser("~/ghostlayer/data/provenance.db"))

class ProvenanceStore:
    """
    DuckDB-backed storage for provenance graph.
    Separate from main events.db to keep schemas clean.
    """

    def __init__(self, db_path: str = DB_PATH):
        self.conn = duckdb.connect(db_path)
        self._init_schema()
        log.info(f"ProvenanceStore initialized: {db_path}")

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS prov_nodes (
                node_id   VARCHAR NOT NULL,
                ntype     VARCHAR NOT NULL,
                attrs     VARCHAR,
                ts        DOUBLE,
                PRIMARY KEY (node_id)
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS prov_edges (
                edge_id   VARCHAR NOT NULL,
                src_id    VARCHAR NOT NULL,
                dst_id    VARCHAR NOT NULL,
                etype     VARCHAR NOT NULL,
                ts        DOUBLE,
                attrs     VARCHAR,
                PRIMARY KEY (edge_id)
            )
        """)
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_prov_src ON prov_edges(src_id)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_prov_dst ON prov_edges(dst_id)")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_prov_ts  ON prov_nodes(ts)")

    def save_node(self, node_id: str, ntype: str, attrs: dict, ts: float):
        try:
            self.conn.execute("""
                INSERT OR REPLACE INTO prov_nodes VALUES (?, ?, ?, ?)
            """, [node_id, ntype, json.dumps(attrs), ts])
        except Exception as e:
            log.error(f"Failed to save node {node_id}: {e}")

    def save_edge(self, src_id: str, dst_id: str, etype: str, ts: float, attrs: dict = {}):
        edge_id = f"{src_id}:{etype}:{dst_id}:{ts}"
        try:
            self.conn.execute("""
                INSERT OR IGNORE INTO prov_edges VALUES (?, ?, ?, ?, ?, ?)
            """, [edge_id, src_id, dst_id, etype, ts, json.dumps(attrs)])
        except Exception as e:
            log.error(f"Failed to save edge {src_id}→{dst_id}: {e}")

    def get_subgraph(self, root_id: str, depth: int = 3) -> dict:
        """Retrieve subgraph from DuckDB for GNN input."""
        visited = {root_id}
        frontier = {root_id}

        for _ in range(depth):
            if not frontier:
                break
            placeholders = ",".join(["?" for _ in frontier])
            rows = self.conn.execute(f"""
                SELECT dst_id FROM prov_edges
                WHERE src_id IN ({placeholders})
            """, list(frontier)).fetchall()
            new_nodes = {r[0] for r in rows} - visited
            visited.update(new_nodes)
            frontier = new_nodes

        # Fetch nodes
        placeholders = ",".join(["?" for _ in visited])
        nodes = self.conn.execute(f"""
            SELECT node_id, ntype, attrs, ts FROM prov_nodes
            WHERE node_id IN ({placeholders})
        """, list(visited)).fetchall()

        # Fetch edges
        edges = self.conn.execute(f"""
            SELECT src_id, dst_id, etype FROM prov_edges
            WHERE src_id IN ({placeholders})
            AND dst_id IN ({placeholders})
        """, list(visited) + list(visited)).fetchall()

        return {
            "nodes": [{"id": r[0], "type": r[1], "attrs": json.loads(r[2] or "{}")} for r in nodes],
            "edges": [{"src": r[0], "dst": r[1], "type": r[2]} for r in edges]
        }

    def stats(self) -> dict:
        nodes = self.conn.execute("SELECT COUNT(*) FROM prov_nodes").fetchone()[0]
        edges = self.conn.execute("SELECT COUNT(*) FROM prov_edges").fetchone()[0]
        return {"nodes": nodes, "edges": edges}

    def cleanup_old(self, days: int = 30):
        """Remove provenance data older than N days."""
        import time
        cutoff = time.time() - (days * 86400)
        self.conn.execute("DELETE FROM prov_nodes WHERE ts < ?", [cutoff])
        self.conn.execute("DELETE FROM prov_edges WHERE ts < ?", [cutoff])
        log.info(f"Provenance store cleaned: removed data older than {days} days")

# Singleton
provenance_store = ProvenanceStore()
