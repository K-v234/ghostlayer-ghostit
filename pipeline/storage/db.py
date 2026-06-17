"""
Ghost IT — DuckDB Storage Layer
Handles all database operations for the event pipeline.
Schema designed for fast time-series queries + detection engine access.
"""
from __future__ import annotations
import duckdb
import logging
import os
from typing import Optional

log = logging.getLogger(__name__)

DB_PATH = os.environ.get("GHOSTIT_DB_PATH", "/var/lib/ghostit/events.db")


class EventStore:
    """
    Thread-safe DuckDB event store.
    Single writer, multiple readers via DuckDB's MVCC.
    """

    def __init__(self, db_path: str = DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.conn = duckdb.connect(db_path)
        self._init_schema()
        log.info(f"EventStore initialized at {db_path}")

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id          UBIGINT PRIMARY KEY,
                ts          UBIGINT NOT NULL,        -- nanoseconds since boot
                received_at TIMESTAMP DEFAULT now(), -- wall clock insert time
                pid         UINTEGER NOT NULL,
                ppid        UINTEGER NOT NULL,
                uid         UINTEGER NOT NULL,
                gid         UINTEGER NOT NULL,
                comm        VARCHAR  NOT NULL,
                type        VARCHAR  NOT NULL,
                score       USMALLINT NOT NULL,
                alert       BOOLEAN  NOT NULL,
                reasons     VARCHAR[],               -- array of reason strings
                file        VARCHAR,
                args        VARCHAR,
                flags       INTEGER,
                daddr       VARCHAR,
                dport       USMALLINT,
                family      USMALLINT,
                clone_flags UBIGINT
            )
        """)

        # Indexes for common query patterns
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_ts
            ON events (ts DESC)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_alert
            ON events (alert, ts DESC)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_pid
            ON events (pid, ts DESC)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_comm
            ON events (comm, ts DESC)
        """)

        # Sequence for auto-increment IDs
        self.conn.execute("""
            CREATE SEQUENCE IF NOT EXISTS event_id_seq START 1
        """)

        log.info("Schema ready")

    def insert_batch(self, events: list[dict]) -> int:
        """
        Bulk insert a batch of events. Returns number inserted.
        Uses prepared statement for performance.
        """
        if not events:
            return 0

        rows = []
        for e in events:
            rows.append((
                e.get("ts", 0),
                e.get("pid", 0),
                e.get("ppid", 0),
                e.get("uid", 0),
                e.get("gid", 0),
                e.get("comm", ""),
                e.get("type", ""),
                e.get("score", 0),
                bool(e.get("alert", False)),
                e.get("reasons", []),
                e.get("file"),
                e.get("args"),
                e.get("flags"),
                e.get("daddr"),
                e.get("dport"),
                e.get("family"),
                e.get("clone_flags"),
            ))

        self.conn.executemany("""
            INSERT INTO events (
                id, ts, pid, ppid, uid, gid, comm, type,
                score, alert, reasons,
                file, args, flags, daddr, dport, family, clone_flags
            ) VALUES (
                nextval('event_id_seq'), ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?
            )
        """, rows)

        log.debug(f"Inserted {len(rows)} events")
        return len(rows)

    def query_alerts(self, limit: int = 100) -> list[dict]:
        """Return most recent alert-level events."""
        result = self.conn.execute("""
            SELECT * FROM events
            WHERE alert = true
            ORDER BY ts DESC
            LIMIT ?
        """, [limit]).fetchdf()
        return result.to_dict(orient="records")

    def query_by_pid(self, pid: int) -> list[dict]:
        """Return all events for a specific process."""
        result = self.conn.execute("""
            SELECT * FROM events
            WHERE pid = ?
            ORDER BY ts ASC
        """, [pid]).fetchdf()
        return result.to_dict(orient="records")

    def query_recent(self, seconds: int = 60, limit: int = 500) -> list[dict]:
        """Return events from the last N seconds."""
        result = self.conn.execute("""
            SELECT * FROM events
            WHERE received_at >= now() - INTERVAL (? || ' seconds')
            ORDER BY ts DESC
            LIMIT ?
        """, [str(seconds), limit]).fetchdf()
        return result.to_dict(orient="records")

    def stats(self) -> dict:
        """Return summary statistics for dashboard."""
        row = self.conn.execute("""
            SELECT
                COUNT(*)                             AS total,
                COUNT(*) FILTER (WHERE alert = true) AS alerts,
                COUNT(DISTINCT pid)                  AS unique_pids,
                COUNT(DISTINCT comm)                 AS unique_procs,
                MIN(received_at)                     AS first_seen,
                MAX(received_at)                     AS last_seen
            FROM events
        """).fetchone()

        return {
            "total":        row[0],
            "alerts":       row[1],
            "unique_pids":  row[2],
            "unique_procs": row[3],
            "first_seen":   str(row[4]),
            "last_seen":    str(row[5]),
        }

    def close(self):
        self.conn.close()
        log.info("EventStore closed")


def setup_retention_policy(conn):
    """
    90-day retention — DPDP compliant.
    Called on startup and daily via scheduler.
    """
    conn.execute("""
        CREATE OR REPLACE MACRO cleanup_old_events() AS TABLE
        SELECT COUNT(*) FROM events
        WHERE received_at < now() - INTERVAL '90 days'
    """)


def run_cleanup(conn) -> int:
    """Delete events older than 90 days. Returns count deleted."""
    result = conn.execute("""
        DELETE FROM events
        WHERE received_at < now() - INTERVAL '90 days'
        RETURNING COUNT(*)
    """)
    deleted = result.fetchone()
    return deleted[0] if deleted else 0
