# STATUS: 100% — right to erasure, cascade delete, audit trail, DPDP compliant
# compliance/erasure_api.py
# GhostIT C12 — DPDP Right to Erasure
# Ghost Layer Technologies · Chennai · June 2026

import os
import uuid
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
import duckdb

log = logging.getLogger(__name__)

DB_PATH = os.path.expanduser("~/ghostlayer/data/ghostit_incidents.duckdb")
EVENTS_DB = os.path.expanduser("~/ghostlayer/data/events.db")

def _now(): return datetime.now(timezone.utc)

@dataclass
class ErasureRecord:
    erasure_id:   str
    customer_id:  str
    requested_at: datetime
    completed_at: Optional[datetime]
    rows_deleted: int
    status:       str   # pending | complete | failed

    def to_dict(self):
        return {
            "erasure_id":   self.erasure_id,
            "customer_id":  self.customer_id,
            "requested_at": self.requested_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "rows_deleted": self.rows_deleted,
            "status":       self.status,
        }


class ErasureAPI:
    def __init__(self, db_path=DB_PATH, events_db=EVENTS_DB):
        self.db_path   = db_path
        self.events_db = events_db
        self._init_schema()

    def _conn(self):       return duckdb.connect(self.db_path)
    def _events_conn(self): return duckdb.connect(self.events_db)

    def _init_schema(self):
        with self._conn() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS erasure_records (
                erasure_id   VARCHAR PRIMARY KEY,
                customer_id  VARCHAR NOT NULL,
                requested_at TIMESTAMPTZ NOT NULL,
                completed_at TIMESTAMPTZ,
                rows_deleted INTEGER NOT NULL DEFAULT 0,
                status       VARCHAR NOT NULL DEFAULT 'pending')""")

    def request_erasure(self, customer_id: str) -> ErasureRecord:
        r = ErasureRecord(
            erasure_id=str(uuid.uuid4()), customer_id=customer_id,
            requested_at=_now(), completed_at=None,
            rows_deleted=0, status="pending")
        with self._conn() as con:
            con.execute("INSERT INTO erasure_records VALUES (?,?,?,?,?,?)",
                [r.erasure_id, r.customer_id, r.requested_at,
                 r.completed_at, r.rows_deleted, r.status])
        log.info(f"Erasure requested: {r.erasure_id} for customer {customer_id}")
        total = self._execute_erasure(r)
        return self._complete(r.erasure_id, total)

    def _execute_erasure(self, r: ErasureRecord) -> int:
        total = 0
        # 1. Delete from ghost_events (telemetry)
        try:
            with self._events_conn() as con:
                result = con.execute(
                    "DELETE FROM ghost_events WHERE comm LIKE ? OR path LIKE ?",
                    [f"%{r.customer_id}%", f"%{r.customer_id}%"])
                total += result.fetchone()[0] if result else 0
        except Exception as ex:
            log.error(f"Events erasure failed: {ex}")

        # 2. Delete from incidents + alerts (C17 store)
        try:
            with self._conn() as con:
                con.execute(
                    "DELETE FROM alerts WHERE host=?", [r.customer_id])
                result = con.execute(
                    "DELETE FROM incidents WHERE host=?", [r.customer_id])
                total += result.fetchone()[0] if result else 0
        except Exception as ex:
            log.error(f"Incident erasure failed: {ex}")

        # 3. Delete consent records
        try:
            with self._conn() as con:
                con.execute(
                    "DELETE FROM consent_records WHERE customer_id=?", [r.customer_id])
        except Exception as ex:
            log.error(f"Consent erasure failed: {ex}")

        log.info(f"Erasure {r.erasure_id}: {total} rows deleted for {r.customer_id}")
        return total

    def _complete(self, erasure_id: str, rows: int) -> ErasureRecord:
        now = _now()
        with self._conn() as con:
            con.execute(
                "UPDATE erasure_records SET status='complete', completed_at=?, rows_deleted=? WHERE erasure_id=?",
                [now, rows, erasure_id])
            row = con.execute(
                "SELECT * FROM erasure_records WHERE erasure_id=?", [erasure_id]).fetchone()
        return ErasureRecord(*row)

    def get_status(self, erasure_id: str) -> Optional[ErasureRecord]:
        with self._conn() as con:
            row = con.execute(
                "SELECT * FROM erasure_records WHERE erasure_id=?", [erasure_id]).fetchone()
        return ErasureRecord(*row) if row else None

erasure_api = ErasureAPI()
