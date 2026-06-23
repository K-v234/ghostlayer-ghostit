# STATUS: 100% — FastAPI dashboard server, bcrypt session auth, REST + WebSocket
# dashboard/api/server.py
# GhostIT C13 — Management Dashboard API
# Ghost Layer Technologies · Chennai · June 2026

import os
import sys
import json
import time
import asyncio
import logging
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional

import bcrypt
import duckdb
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

sys.path.insert(0, os.path.expanduser("~/ghostlayer"))

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [dashboard] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S")

EVENTS_DB   = os.path.expanduser("~/ghostlayer/data/events.db")
INCIDENT_DB = os.path.expanduser("~/ghostlayer/data/ghostit_incidents.duckdb")
PIPELINE_API = "http://127.0.0.1:8000"

app = FastAPI(title="Ghost IT Dashboard API", version="1.0.0")
app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Serve React frontend
_build = os.path.expanduser("~/ghostlayer/dashboard/frontend/build")
if os.path.isdir(_build):
    app.mount("/app", StaticFiles(directory=_build, html=True), name="frontend")

# ── Session store (in-memory, bcrypt-protected) ───────────────────────────────
_SESSIONS: dict[str, dict] = {}
SESSION_TTL = timedelta(hours=8)

# Default admin — change password on first login
_USERS = {
    "admin": bcrypt.hashpw(b"ghostit-admin-2026", bcrypt.gensalt()).decode()
}

security = HTTPBearer(auto_error=False)

def _verify_session(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = credentials.credentials
    session = _SESSIONS.get(token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")
    if datetime.now(timezone.utc) > session["expires"]:
        del _SESSIONS[token]
        raise HTTPException(status_code=401, detail="Session expired")
    return session

def _events_conn(): return duckdb.connect(EVENTS_DB, read_only=True)
def _incident_conn(): return duckdb.connect(INCIDENT_DB, read_only=True)

# ── Auth endpoints ────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
async def login(request: Request):
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "").encode()
    hashed = _USERS.get(username, "").encode()
    if not hashed or not bcrypt.checkpw(password, hashed):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = secrets.token_hex(32)
    _SESSIONS[token] = {
        "username": username,
        "expires": datetime.now(timezone.utc) + SESSION_TTL,
    }
    log.info(f"Login: {username}")
    return {"token": token, "expires_in": int(SESSION_TTL.total_seconds())}

@app.post("/api/auth/logout")
async def logout(session=Depends(_verify_session),
                 credentials: HTTPAuthorizationCredentials = Depends(security)):
    _SESSIONS.pop(credentials.credentials, None)
    return {"status": "logged out"}

# ── Alert endpoints ───────────────────────────────────────────────────────────
@app.get("/api/alerts")
def get_alerts(limit: int = 100, session=Depends(_verify_session)):
    try:
        with _events_conn() as con:
            rows = con.execute("""
                SELECT id, ts, pid, comm, type, score, reasons, file, daddr, dport, dpdp_pii_flag
                FROM events WHERE alert=true
                ORDER BY ts DESC LIMIT ?
            """, [limit]).fetchall()
        alerts = [{"id": r[0], "ts": r[1], "pid": r[2], "comm": r[3],
                   "type": r[4], "score": r[5], "reasons": r[6],
                   "file": r[7], "daddr": r[8], "dport": r[9],
                   "dpdp_pii_flag": r[10]} for r in rows]
        return {"total": len(alerts), "alerts": alerts}
    except Exception as ex:
        return {"total": 0, "alerts": [], "error": str(ex)}

# ── Incident endpoints ────────────────────────────────────────────────────────
@app.get("/api/incidents")
def get_incidents(limit: int = 50, session=Depends(_verify_session)):
    try:
        with _incident_conn() as con:
            rows = con.execute("""
                SELECT incident_id, created_at, updated_at, host, severity,
                       confidence, tactic_id, tactic_name, technique_id,
                       technique_name, alert_count, sources, summary, closed
                FROM incidents ORDER BY updated_at DESC LIMIT ?
            """, [limit]).fetchall()
        incidents = [{"incident_id": r[0], "created_at": str(r[1]),
                      "updated_at": str(r[2]), "host": r[3],
                      "severity": r[4], "confidence": r[5],
                      "tactic_id": r[6], "tactic_name": r[7],
                      "technique_id": r[8], "technique_name": r[9],
                      "alert_count": r[10], "sources": r[11],
                      "summary": r[12], "closed": r[13]} for r in rows]
        return {"total": len(incidents), "incidents": incidents}
    except Exception as ex:
        return {"total": 0, "incidents": [], "error": str(ex)}

# ── Endpoint status ───────────────────────────────────────────────────────────
@app.get("/api/endpoints")
def get_endpoints(session=Depends(_verify_session)):
    try:
        with _events_conn() as con:
            rows = con.execute("""
                SELECT comm, pid, MAX(ts) as last_seen, COUNT(*) as event_count
                FROM events
                WHERE ts > (epoch_ns(now()) - 300000000000)
                GROUP BY comm, pid
                ORDER BY last_seen DESC LIMIT 50
            """).fetchall()
        endpoints = [{"comm": r[0], "pid": r[1],
                      "last_seen": r[2], "event_count": r[3]} for r in rows]
        return {"total": len(endpoints), "endpoints": endpoints}
    except Exception as ex:
        return {"total": 0, "endpoints": [], "error": str(ex)}

# ── Stats endpoint ────────────────────────────────────────────────────────────
@app.get("/api/stats")
def get_stats(session=Depends(_verify_session)):
    import urllib.request
    try:
        with urllib.request.urlopen(f"{PIPELINE_API}/stats", timeout=5) as r:
            pipeline_stats = json.loads(r.read())
    except Exception:
        pipeline_stats = {}
    try:
        with _incident_conn() as con:
            open_incidents = con.execute(
                "SELECT COUNT(*) FROM incidents WHERE closed=FALSE").fetchone()[0]
            critical = con.execute(
                "SELECT COUNT(*) FROM incidents WHERE severity='critical' AND closed=FALSE").fetchone()[0]
    except Exception:
        open_incidents = 0
        critical = 0
    return {
        "pipeline": pipeline_stats,
        "open_incidents": open_incidents,
        "critical_incidents": critical,
        "active_sessions": len(_SESSIONS),
    }

# ── DPDP compliance endpoints ─────────────────────────────────────────────────
@app.post("/api/compliance/erasure/{customer_id}")
def request_erasure(customer_id: str, session=Depends(_verify_session)):
    from compliance.erasure_api import erasure_api
    r = erasure_api.request_erasure(customer_id)
    return r.to_dict()

@app.get("/api/compliance/audit/{customer_id}")
def get_audit_report(customer_id: str, session=Depends(_verify_session)):
    from compliance.audit_report import generate_report
    return generate_report(customer_id)

@app.post("/api/compliance/consent")
async def grant_consent(request: Request, session=Depends(_verify_session)):
    from compliance.consent_api import consent_store
    body = await request.json()
    r = consent_store.grant(
        customer_id=body["customer_id"],
        entity=body["entity"],
        purpose=body["purpose"])
    return r.to_dict()

# ── WebSocket — real-time alert feed ─────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket):
        self.active.remove(ws)

    async def broadcast(self, msg: dict):
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.active.remove(ws)

ws_manager = ConnectionManager()

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await ws_manager.connect(websocket)
    last_id = 0
    try:
        while True:
            try:
                with _events_conn() as con:
                    rows = con.execute("""
                        SELECT id, ts, pid, comm, type, score, reasons, daddr
                        FROM events WHERE alert=true AND id > ?
                        ORDER BY ts DESC LIMIT 20
                    """, [last_id]).fetchall()
                if rows:
                    last_id = max(r[0] for r in rows)
                    for r in rows:
                        await websocket.send_json({
                            "id": r[0], "ts": r[1], "pid": r[2],
                            "comm": r[3], "type": r[4], "score": r[5],
                            "reasons": r[6], "daddr": r[7],
                        })
            except Exception:
                pass
            await asyncio.sleep(5)
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")
