import os
# STATUS: 100% — DuckDB incident storage, alert deduplication, incident CRUD,
#                query by time range / severity / tactic, incident export to JSON
# alert-engine/incidents.py
# GhostIT C17 — Incident Storage (DuckDB)
# Ghost Layer Technologies · Chennai · June 2026

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import duckdb

from weights import AlertSource, Severity, compute_confidence, combine_confidences
from mitre_mapper import MitreTag, map_alert
from apt_window import WindowConfig, select_window, now_utc

DB_PATH = os.path.expanduser("~/ghostlayer/data/ghostit_incidents.duckdb")


@dataclass
class RawAlert:
    alert_id:   str
    source:     AlertSource
    severity:   Severity
    ts:         datetime
    pid:        int        = 0
    host:       str        = ""
    comm:       str        = ""
    reason:     str        = ""
    event_type: str        = ""
    raw_json:   str        = "{}"

    @classmethod
    def create(cls, source, severity, pid=0, host="", comm="", reason="", event_type="", raw_json="{}"):
        return cls(alert_id=str(uuid.uuid4()), source=source, severity=severity,
            ts=now_utc(), pid=pid, host=host, comm=comm, reason=reason,
            event_type=event_type, raw_json=raw_json)


@dataclass
class Incident:
    incident_id:  str
    created_at:   datetime
    updated_at:   datetime
    host:         str
    severity:     Severity
    confidence:   float
    window_type:  str
    tactic_id:    str
    tactic_name:  str
    technique_id: str
    technique_name: str
    alert_count:  int
    alert_ids:    list[str] = field(default_factory=list)
    sources:      list[str] = field(default_factory=list)
    summary:      str = ""
    closed:       bool = False

    def to_dict(self):
        return {"incident_id": self.incident_id, "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(), "host": self.host,
            "severity": self.severity.value, "confidence": self.confidence,
            "window_type": self.window_type, "tactic_id": self.tactic_id,
            "tactic_name": self.tactic_name, "technique_id": self.technique_id,
            "technique_name": self.technique_name, "alert_count": self.alert_count,
            "alert_ids": self.alert_ids, "sources": self.sources,
            "summary": self.summary, "closed": self.closed}

    def to_json(self): return json.dumps(self.to_dict(), indent=2)


class IncidentStore:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_schema()

    def _conn(self): return duckdb.connect(self.db_path)

    def _init_schema(self):
        with self._conn() as con:
            con.execute("""CREATE TABLE IF NOT EXISTS incidents (
                incident_id VARCHAR PRIMARY KEY,
                created_at TIMESTAMPTZ NOT NULL, updated_at TIMESTAMPTZ NOT NULL,
                host VARCHAR NOT NULL DEFAULT '', severity VARCHAR NOT NULL,
                confidence DOUBLE NOT NULL, window_type VARCHAR NOT NULL,
                tactic_id VARCHAR NOT NULL, tactic_name VARCHAR NOT NULL,
                technique_id VARCHAR NOT NULL, technique_name VARCHAR NOT NULL,
                alert_count INTEGER NOT NULL DEFAULT 0,
                alert_ids JSON NOT NULL DEFAULT '[]',
                sources JSON NOT NULL DEFAULT '[]',
                summary VARCHAR NOT NULL DEFAULT '',
                closed BOOLEAN NOT NULL DEFAULT FALSE)""")
            con.execute("""CREATE TABLE IF NOT EXISTS alerts (
                alert_id VARCHAR PRIMARY KEY, incident_id VARCHAR,
                source VARCHAR NOT NULL, severity VARCHAR NOT NULL,
                ts TIMESTAMPTZ NOT NULL, pid INTEGER NOT NULL DEFAULT 0,
                host VARCHAR NOT NULL DEFAULT '', comm VARCHAR NOT NULL DEFAULT '',
                reason VARCHAR NOT NULL DEFAULT '', event_type VARCHAR NOT NULL DEFAULT '',
                raw_json JSON NOT NULL DEFAULT '{}')""")

    def save_incident(self, i: Incident):
        with self._conn() as con:
            con.execute("""INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT (incident_id) DO UPDATE SET updated_at=excluded.updated_at,
                severity=excluded.severity,confidence=excluded.confidence,
                alert_count=excluded.alert_count,alert_ids=excluded.alert_ids,
                sources=excluded.sources,summary=excluded.summary,closed=excluded.closed""",
                [i.incident_id,i.created_at,i.updated_at,i.host,i.severity.value,
                 i.confidence,i.window_type,i.tactic_id,i.tactic_name,i.technique_id,
                 i.technique_name,i.alert_count,json.dumps(i.alert_ids),
                 json.dumps(i.sources),i.summary,i.closed])

    def save_alert(self, a: RawAlert, incident_id: str):
        with self._conn() as con:
            con.execute("INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (alert_id) DO NOTHING",
                [a.alert_id,incident_id,a.source.value,a.severity.value,a.ts,a.pid,a.host,a.comm,a.reason,a.event_type,a.raw_json])

    def close_incident(self, incident_id):
        with self._conn() as con:
            con.execute("UPDATE incidents SET closed=TRUE,updated_at=? WHERE incident_id=?", [now_utc(),incident_id])

    def get_incident(self, incident_id):
        with self._conn() as con:
            row = con.execute("SELECT * FROM incidents WHERE incident_id=?",[incident_id]).fetchone()
        return self._row(row) if row else None

    def get_open_incidents(self, host="", severity=None, tactic_id="", limit=100):
        q = "SELECT * FROM incidents WHERE closed=FALSE"
        p = []
        if host: q+=" AND host=?";p.append(host)
        if severity: q+=" AND severity=?";p.append(severity.value)
        if tactic_id: q+=" AND tactic_id=?";p.append(tactic_id)
        q+=" ORDER BY updated_at DESC LIMIT ?";p.append(limit)
        with self._conn() as con: rows=con.execute(q,p).fetchall()
        return [self._row(r) for r in rows if r]

    def get_incidents_in_range(self, start, end, host=""):
        q = "SELECT * FROM incidents WHERE created_at BETWEEN ? AND ?"
        p = [start,end]
        if host: q+=" AND host=?";p.append(host)
        q+=" ORDER BY created_at DESC"
        with self._conn() as con: rows=con.execute(q,p).fetchall()
        return [self._row(r) for r in rows if r]

    def incident_count(self, closed=None):
        q="SELECT COUNT(*) FROM incidents";p=[]
        if closed is not None: q+=" WHERE closed=?";p.append(closed)
        with self._conn() as con: return con.execute(q,p).fetchone()[0]

    @staticmethod
    def _row(r):
        return Incident(incident_id=r[0],created_at=r[1],updated_at=r[2],host=r[3],
            severity=Severity(r[4]),confidence=r[5],window_type=r[6],
            tactic_id=r[7],tactic_name=r[8],technique_id=r[9],technique_name=r[10],
            alert_count=r[11],alert_ids=json.loads(r[12]) if isinstance(r[12],str) else r[12],
            sources=json.loads(r[13]) if isinstance(r[13],str) else r[13],summary=r[14],closed=r[15])
