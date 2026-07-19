#!/usr/bin/env python3
"""
Ghost IT — Attack Replay & Causal Timeline

The gap this closes: C4 builds causal graphs and the Explainability
Engine narrates evidence, but nothing persists an IMMUTABLE, ordered
timeline of exactly what happened, meaning no one can answer "what
changed first," replay an incident step by step, or run "what if we
had acted at step 3 instead of step 5" after the fact.
"""
from __future__ import annotations
import os, time, logging, threading, hashlib, duckdb

log = logging.getLogger(__name__)

REPLAY_DB_PATH = os.environ.get("REPLAY_DB_PATH",
    os.path.expanduser("~/ghostlayer/data/attack_replay.duckdb"))

class AttackReplay:
    def __init__(self, db_path: str = REPLAY_DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._lock = threading.Lock()
        self.conn = duckdb.connect(db_path)
        self._init_schema()
        log.info(f"AttackReplay initialized: {db_path}")

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS timeline (
                event_hash    VARCHAR NOT NULL,
                incident_id   VARCHAR NOT NULL,
                sequence_num  INTEGER NOT NULL,
                entity_id     VARCHAR NOT NULL,
                event_type    VARCHAR NOT NULL,
                description   VARCHAR NOT NULL,
                pillar        VARCHAR,
                ts            DOUBLE NOT NULL,
                prev_hash     VARCHAR
            )
        """)
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_replay_incident ON timeline(incident_id)")

    def _compute_hash(self, incident_id: str, seq: int, description: str, prev_hash: str) -> str:
        raw = f"{incident_id}:{seq}:{description}:{prev_hash}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def record(self, incident_id: str, entity_id: str, event_type: str,
                description: str, pillar: str = "") -> dict:
        with self._lock:
            last = self.conn.execute(
                "SELECT sequence_num, event_hash FROM timeline WHERE incident_id = ? "
                "ORDER BY sequence_num DESC LIMIT 1", [incident_id]
            ).fetchone()
            seq = (last[0] + 1) if last else 0
            prev_hash = last[1] if last else "genesis"
            event_hash = self._compute_hash(incident_id, seq, description, prev_hash)
            self.conn.execute(
                "INSERT INTO timeline VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                [event_hash, incident_id, seq, entity_id, event_type,
                 description, pillar, time.time(), prev_hash]
            )
        return {"incident_id": incident_id, "sequence_num": seq, "event_hash": event_hash}

    def get_timeline(self, incident_id: str) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT sequence_num, entity_id, event_type, description, "
                "pillar, ts, event_hash, prev_hash FROM timeline "
                "WHERE incident_id = ? ORDER BY sequence_num ASC", [incident_id]
            ).fetchall()
        cols = ["sequence_num", "entity_id", "event_type", "description",
                "pillar", "ts", "event_hash", "prev_hash"]
        return [dict(zip(cols, r)) for r in rows]

    def verify_integrity(self, incident_id: str) -> dict:
        timeline = self.get_timeline(incident_id)
        prev_hash = "genesis"
        for entry in timeline:
            expected = self._compute_hash(incident_id, entry["sequence_num"],
                                            entry["description"], prev_hash)
            if expected != entry["event_hash"]:
                return {"valid": False, "broken_at_sequence": entry["sequence_num"]}
            prev_hash = entry["event_hash"]
        return {"valid": True, "total_entries": len(timeline)}

    def what_if_acted_earlier(self, incident_id: str, act_at_sequence: int) -> dict:
        timeline = self.get_timeline(incident_id)
        avoided = [e for e in timeline if e["sequence_num"] > act_at_sequence]
        return {
            "incident_id": incident_id, "hypothetical_action_point": act_at_sequence,
            "stages_that_would_have_been_avoided": len(avoided),
            "avoided_events": [e["description"] for e in avoided],
        }

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    ar = AttackReplay(db_path="/tmp/replay_test.duckdb")
    inc = "test-incident-001"

    print("=== Recording a real, ordered multi-stage attack sequence ===\n")
    ar.record(inc, "pid:100", "initial_access", "Phishing attachment executed")
    ar.record(inc, "pid:100", "discovery", "File system enumeration began")
    ar.record(inc, "pid:100", "deception", "Canary decoy file accessed", pillar="C3_deception")
    ar.record(inc, "pid:100", "impact", "Ransomware encryption began", pillar="C15_ransomware")
    ar.record(inc, "pid:100", "response", "Autonomous Response suspended process")

    timeline = ar.get_timeline(inc)
    for e in timeline:
        print(f"  [{e['sequence_num']}] {e['description']}")

    print("\n=== Integrity check ===")
    print(f"  {ar.verify_integrity(inc)}")

    print("\n=== What if we had acted at stage 2 (canary hit) instead of stage 4 (post-encryption)? ===")
    whatif = ar.what_if_acted_earlier(inc, 2)
    print(f"  {whatif}")

    os.remove("/tmp/replay_test.duckdb")
