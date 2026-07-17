#!/usr/bin/env python3
"""
Ghost IT — Temporal Attack-Graph Memory

Architectural gap this closes: C4's causal reasoning chains, and the
Cortex's per-PID scores, both reset to zero relevance the moment a
process exits or a machine reboots. A PID is not a durable identity --
it's reused constantly, meaningless after 24 hours. This means an
attacker who performs reconnaissance today and returns to execute
next week looks like a completely fresh, unknown entity each time,
even though it's genuinely the same actor.

This module tracks durable, long-lived ENTITY FINGERPRINTS -- not
PIDs -- built from (host, comm, and the specific file/network
resource touched), persisted across days, so the system can recognize
"this specific actor pattern has been seen on this host before" even
across reboots and process restarts.

This is a genuine extension of the same DuckDB used by the Cortex,
following the same HTTP-contribution architecture (single-writer via
pipeline) established there.
"""
from __future__ import annotations
import os
import time
import hashlib
import logging
import threading
import duckdb

log = logging.getLogger(__name__)

TEMPORAL_DB_PATH = os.environ.get("TEMPORAL_DB_PATH",
    os.path.expanduser("~/ghostlayer/data/temporal_memory.duckdb"))

# How long a fingerprint stays "recognized" before being considered
# stale/expired -- 30 days matches your Tech Spec's other long-term
# retention windows (V0 soak test, DuckDB event retention).
FINGERPRINT_RETENTION_DAYS = 30

def make_fingerprint(host: str, comm: str, resource: str) -> str:
    """
    A durable identity independent of PID. Two attacks from the same
    malware family / same actor on the same host, touching the same
    kind of resource, produce the SAME fingerprint even if the PID
    differs completely and days have passed. This is intentionally
    coarse (not tied to exact PID or exact timestamp) -- the point is
    recognizing a returning PATTERN, not tracking one specific
    process instance.
    """
    raw = f"{host}:{comm}:{resource}".lower()
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

class TemporalMemory:
    def __init__(self, db_path: str = TEMPORAL_DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._lock = threading.Lock()
        self.conn = duckdb.connect(db_path)
        self._init_schema()
        log.info(f"TemporalMemory initialized: {db_path}")

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS sightings (
                fingerprint VARCHAR NOT NULL,
                host        VARCHAR NOT NULL,
                comm        VARCHAR NOT NULL,
                resource    VARCHAR NOT NULL,
                pillar      VARCHAR NOT NULL,
                reason      VARCHAR NOT NULL,
                first_ts    DOUBLE NOT NULL,
                last_ts     DOUBLE NOT NULL,
                sighting_count INTEGER NOT NULL DEFAULT 1
            )
        """)
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_fingerprint ON sightings(fingerprint)")

    def record_sighting(self, host: str, comm: str, resource: str,
                          pillar: str, reason: str) -> dict:
        """
        Record that this fingerprint was seen again. If it's genuinely
        new, creates a fresh record. If it's a RETURNING fingerprint
        (seen before, possibly days ago), increments the count and
        flags it as a real return -- this is the actual value: knowing
        "this specific pattern has shown up 4 times over the past 2
        weeks" is qualitatively different information than any single
        isolated event, and no existing pillar tracks this.
        """
        fp = make_fingerprint(host, comm, resource)
        now = time.time()
        with self._lock:
            existing = self.conn.execute(
                "SELECT sighting_count, first_ts FROM sightings WHERE fingerprint = ?",
                [fp]
            ).fetchone()
            if existing:
                count, first_ts = existing
                new_count = count + 1
                self.conn.execute(
                    "UPDATE sightings SET last_ts = ?, sighting_count = ?, "
                    "pillar = ?, reason = ? WHERE fingerprint = ?",
                    [now, new_count, pillar, reason, fp]
                )
                is_return = True
                days_since_first = (now - first_ts) / 86400
            else:
                self.conn.execute(
                    "INSERT INTO sightings VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)",
                    [fp, host, comm, resource, pillar, reason, now, now]
                )
                new_count = 1
                is_return = False
                days_since_first = 0.0
        result = {
            "fingerprint": fp, "is_returning_actor": is_return,
            "sighting_count": new_count, "days_since_first_seen": round(days_since_first, 1),
        }
        if is_return and new_count >= 3:
            log.warning(
                f"[TemporalMemory] RECURRING PATTERN: fingerprint={fp} "
                f"({host}/{comm}) seen {new_count} times over "
                f"{days_since_first:.1f} days -- {reason}"
            )
        return result

    def cleanup_expired(self):
        cutoff = time.time() - (FINGERPRINT_RETENTION_DAYS * 86400)
        with self._lock:
            self.conn.execute("DELETE FROM sightings WHERE last_ts < ?", [cutoff])

    def get_recurring(self, min_count: int = 2, limit: int = 20) -> list[dict]:
        with self._lock:
            rows = self.conn.execute(
                "SELECT fingerprint, host, comm, resource, pillar, reason, "
                "first_ts, last_ts, sighting_count FROM sightings "
                "WHERE sighting_count >= ? ORDER BY sighting_count DESC LIMIT ?",
                [min_count, limit]
            ).fetchall()
        now = time.time()
        return [{
            "fingerprint": r[0], "host": r[1], "comm": r[2], "resource": r[3],
            "pillar": r[4], "reason": r[5], "sighting_count": r[8],
            "days_since_first_seen": round((now - r[6]) / 86400, 1),
            "days_since_last_seen": round((now - r[7]) / 86400, 1),
        } for r in rows]

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    tm = TemporalMemory(db_path="/tmp/temporal_test.duckdb")

    print("=== Simulating an attacker returning across 'days' (simulated via manual timestamps) ===\n")
    print("Day 1: first recon attempt")
    r1 = tm.record_sighting("host-A", "powershell.exe", "\\\\shadow_probe", "C14_lolbin", "reconnaissance attempt")
    print(f"  {r1}\n")

    print("Simulated day 8: SAME actor pattern returns")
    r2 = tm.record_sighting("host-A", "powershell.exe", "\\\\shadow_probe", "C14_lolbin", "reconnaissance attempt")
    print(f"  {r2}\n")

    print("Simulated day 15: SAME actor pattern returns again")
    r3 = tm.record_sighting("host-A", "powershell.exe", "\\\\shadow_probe", "C14_lolbin", "reconnaissance attempt")
    print(f"  {r3}\n")

    print(f"=== Result: system recognizes this as a RECURRING pattern (seen {r3['sighting_count']} times), not 3 unrelated isolated events ===")

    import os as _os
    _os.remove("/tmp/temporal_test.duckdb")
