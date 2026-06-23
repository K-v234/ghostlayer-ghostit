# STATUS: 100% — consent records CRUD, DuckDB storage, REST-ready
# compliance/consent_api.py
# GhostIT C12 — DPDP Consent Management
# Ghost Layer Technologies · Chennai · June 2026

import json
import uuid
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
import duckdb

DB_PATH = os.path.expanduser("~/ghostlayer/data/ghostit_incidents.duckdb")

def _now() -> datetime:
    return datetime.now(timezone.utc)

@dataclass
class ConsentRecord:
    consent_id:   str
    customer_id:  str
    entity:       str        # endpoint hostname or user
    purpose:      str        # "endpoint_monitoring" | "behavioral_ai" | "federated_learning"
    granted:      bool
    granted_at:   datetime
    expires_at:   Optional[datetime]
    revoked_at:   Optional[datetime] = None

    def to_dict(self):
        return {
            "consent_id":  self.consent_id,
            "customer_id": self.customer_id,
            "entity":      self.entity,
            "purpose":     self.purpose,
            "granted":     self.granted,
            "granted_at":  self.granted_at.isoformat(),
            "expires_at":  self.expires_at.isoformat() if self.expires_at else None,
            "revoked_at":  self.revoked_at.isoformat() if self.revoked_at else None,
        }


class ConsentStore:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_schema()

    def _conn(self): return duckdb.connect(self.db_path)

    def _init_schema(self):
        with self._conn() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS consent_records (
                consent_id  VARCHAR PRIMARY KEY,
                customer_id VARCHAR NOT NULL,
                entity      VARCHAR NOT NULL,
                purpose     VARCHAR NOT NULL,
                granted     BOOLEAN NOT NULL,
                granted_at  TIMESTAMPTZ NOT NULL,
                expires_at  TIMESTAMPTZ,
                revoked_at  TIMESTAMPTZ)""")

    def grant(self, customer_id: str, entity: str, purpose: str,
              expires_at: Optional[datetime] = None) -> ConsentRecord:
        r = ConsentRecord(
            consent_id=str(uuid.uuid4()), customer_id=customer_id,
            entity=entity, purpose=purpose, granted=True,
            granted_at=_now(), expires_at=expires_at)
        with self._conn() as con:
            con.execute(
                "INSERT INTO consent_records VALUES (?,?,?,?,?,?,?,?)",
                [r.consent_id, r.customer_id, r.entity, r.purpose,
                 r.granted, r.granted_at, r.expires_at, r.revoked_at])
        return r

    def revoke(self, consent_id: str) -> bool:
        with self._conn() as con:
            con.execute(
                "UPDATE consent_records SET granted=FALSE, revoked_at=? WHERE consent_id=?",
                [_now(), consent_id])
        return True

    def is_active(self, customer_id: str, purpose: str) -> bool:
        with self._conn() as con:
            row = con.execute("""SELECT granted, expires_at FROM consent_records
                WHERE customer_id=? AND purpose=? AND revoked_at IS NULL
                ORDER BY granted_at DESC LIMIT 1""",
                [customer_id, purpose]).fetchone()
        if not row: return False
        granted, expires_at = row
        if not granted: return False
        if expires_at and expires_at < _now(): return False
        return True

    def get_all(self, customer_id: str) -> list[ConsentRecord]:
        with self._conn() as con:
            rows = con.execute(
                "SELECT * FROM consent_records WHERE customer_id=? ORDER BY granted_at DESC",
                [customer_id]).fetchall()
        return [ConsentRecord(*r) for r in rows]

consent_store = ConsentStore()
