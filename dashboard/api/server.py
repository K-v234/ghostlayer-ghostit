# STATUS: 100% — FastAPI dashboard API — SSE real-time push, industry-level
# dashboard/api/server.py
# GhostIT C13 — Management Dashboard API
# Ghost Layer Technologies · Chennai · June 2026

import os, sys, json, time, asyncio, logging, secrets
from datetime import datetime, timezone, timedelta
from typing import AsyncGenerator

import bcrypt, duckdb
from fastapi import FastAPI, HTTPException, Depends, Request, Query
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import urllib.request as _ur

sys.path.insert(0, os.path.expanduser("~/ghostlayer"))

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [dashboard] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S")

EVENTS_DB    = os.path.expanduser("~/ghostlayer/data/events.db")
INCIDENT_DB  = os.path.expanduser("~/ghostlayer/data/ghostit_incidents.duckdb")
PIPELINE_API = "http://127.0.0.1:8000"

NOISE_COMMS   = {"ghost-agent", "ghostit-agent-l", "ghost-agent-lin", ""}
NOISE_REASONS = {"file_close_write", "file_modify", "file_close_read"}

app = FastAPI(title="Ghost IT Dashboard API", version="1.0.0")
app.add_middleware(CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
    expose_headers=["Last-Event-ID"])

_build = os.path.expanduser("~/ghostlayer/dashboard/frontend/build")
if os.path.isdir(_build):
    app.mount("/app", StaticFiles(directory=_build, html=True), name="frontend")

SESSION_FILE = os.path.expanduser("~/.ghostit_sessions.json")

def _load_sessions() -> dict:
    try:
        with open(SESSION_FILE) as f:
            raw = json.load(f)
        # Re-hydrate datetime objects
        return {k: {**v, "expires": datetime.fromisoformat(v["expires"])} for k,v in raw.items()}
    except Exception:
        return {}

def _save_sessions(sessions: dict):
    try:
        serialisable = {k: {**v, "expires": v["expires"].isoformat()} for k,v in sessions.items()}
        with open(SESSION_FILE, "w") as f:
            json.dump(serialisable, f)
    except Exception:
        pass

_SESSIONS: dict[str, dict] = _load_sessions()
SESSION_TTL = timedelta(hours=8)
_USERS = {"admin": bcrypt.hashpw(b"ghostit-admin-2026", bcrypt.gensalt()).decode()}
security = HTTPBearer(auto_error=False)

def _verify_session(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(401, "Not authenticated")
    s = _SESSIONS.get(credentials.credentials)
    if not s:
        raise HTTPException(401, "Invalid session")
    if datetime.now(timezone.utc) > s["expires"]:
        del _SESSIONS[credentials.credentials]
        raise HTTPException(401, "Session expired")
    return s

def _verify_token(token: str) -> bool:
    s = _SESSIONS.get(token)
    if not s:
        return False
    if datetime.now(timezone.utc) > s["expires"]:
        _SESSIONS.pop(token, None)
        return False
    return True

def _incident_conn(): return duckdb.connect(INCIDENT_DB, read_only=True)

@app.post("/api/auth/login")
async def login(request: Request):
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "").encode()
    hashed = _USERS.get(username, "").encode()
    if not hashed or not bcrypt.checkpw(password, hashed):
        raise HTTPException(401, "Invalid credentials")
    token = secrets.token_hex(32)
    _SESSIONS[token] = {"username": username,
                        "expires": datetime.now(timezone.utc) + SESSION_TTL}
    log.info(f"Login: {username}")
    _save_sessions(_SESSIONS)
    return {"token": token, "expires_in": int(SESSION_TTL.total_seconds())}

@app.post("/api/auth/logout")
async def logout(session=Depends(_verify_session),
                 credentials: HTTPAuthorizationCredentials = Depends(security)):
    _SESSIONS.pop(credentials.credentials, None)
    _save_sessions(_SESSIONS)
    return {"status": "logged out"}

def _fetch_alerts(limit: int = 50) -> list[dict]:
    try:
        with _ur.urlopen(f"{PIPELINE_API}/alerts?limit={limit}", timeout=3) as r:
            data = json.loads(r.read())
        cutoff = int(time.time()) - 86400
        return [
            a for a in data.get("alerts", [])
            if a.get("comm", "") not in NOISE_COMMS
            and a.get("received_at", 0) > cutoff
            and not any(n in str(a.get("reasons", "")) for n in NOISE_REASONS)
            and not str(a.get("file", "")).startswith("python3 made outbound TCP connection to 1.")
            and not str(a.get("file", "")).startswith("python3 made outbound TCP connection to 127.")
            and not str(a.get("file", "")).startswith("python3 made outbound TCP connection to 11.")
        ]
    except Exception:
        return []

async def _sse_generator(last_id: int) -> AsyncGenerator[str, None]:
    POLL_INTERVAL  = 2
    HEARTBEAT_INTERVAL = 15
    seen_id  = last_id
    last_hb  = time.time()
    yield f"event: sync\ndata: {json.dumps({'ts': int(time.time()), 'resumed_from': last_id})}\n\n"
    while True:
        now = time.time()
        if now - last_hb >= HEARTBEAT_INTERVAL:
            yield f": heartbeat {int(now)}\n\n"
            last_hb = now
        alerts = _fetch_alerts(50)
        new_alerts = sorted(
            [a for a in alerts if a.get("id", 0) > seen_id],
            key=lambda a: a.get("id", 0)
        )
        # Industry-standard alert aggregation:
        # Group by (type+comm) within this batch — send ONE alert with count
        # All individual alerts still stored in backend for investigation
        from collections import defaultdict
        groups = defaultdict(list)
        for a in new_alerts:
            fingerprint = f"{a.get('type','')}:{a.get('comm','')}"
            groups[fingerprint].append(a)

        for fingerprint, grouped in groups.items():
            # Use highest-scored alert as representative
            representative = max(grouped, key=lambda a: a.get("score", 0))
            event_id = max(a.get("id", 0) for a in grouped)
            seen_id  = max(seen_id, event_id)
            # Add count to alert data
            if len(grouped) > 1:
                representative = dict(representative)
                representative["count"] = len(grouped)
                representative["suppressed"] = len(grouped) - 1
            severity = ("critical" if representative.get("score", 0) >= 90
                        else "high" if representative.get("score", 0) >= 70
                        else "alert")
            yield f"id: {event_id}\nevent: {severity}\ndata: {json.dumps(representative)}\n\n"
            log.info(f"SSE pushed id={event_id} score={representative.get('score')} comm={representative.get('comm')} count={len(grouped)}")
        await asyncio.sleep(POLL_INTERVAL)

@app.get("/api/stream/alerts")
async def stream_alerts(
    request: Request,
    token: str = Query(""),
    lastEventId: int = Query(0),
):
    header_last_id = request.headers.get("last-event-id", "")
    if header_last_id.isdigit():
        lastEventId = int(header_last_id)

    if not token or not _verify_token(token):
        async def _auth_err():
            yield "event: auth_error\ndata: {\"error\": \"Invalid token\"}\n\n"
        return StreamingResponse(_auth_err(), media_type="text/event-stream")

    return StreamingResponse(
        _sse_generator(lastEventId),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        }
    )

@app.get("/api/alerts")
def get_alerts(limit: int = 100, session=Depends(_verify_session)):
    return {"total": 0, "alerts": _fetch_alerts(limit)}

@app.get("/api/incidents")
def get_incidents(limit: int = 50, session=Depends(_verify_session)):
    try:
        with _incident_conn() as con:
            rows = con.execute(f"""
                SELECT incident_id, created_at, updated_at, host, severity,
                       confidence, tactic_id, tactic_name, technique_id,
                       technique_name, alert_count, sources, summary, closed
                FROM incidents
                ORDER BY updated_at DESC LIMIT {int(limit)}
            """).fetchall()
        incidents = [
            {"incident_id": r[0], "created_at": str(r[1]), "updated_at": str(r[2]),
             "host": r[3], "severity": r[4], "confidence": r[5],
             "tactic_id": r[6], "tactic_name": r[7],
             "technique_id": r[8], "technique_name": r[9],
             "alert_count": r[10],
             "sources": json.loads(r[11]) if isinstance(r[11], str) else (r[11] or []),
             "summary": r[12], "closed": r[13]}
            for r in rows
        ]
        return {"total": len(incidents), "incidents": incidents}
    except Exception as ex:
        log.error(f"incidents error: {ex}")
        return {"total": 0, "incidents": [], "error": str(ex)}

@app.get("/api/endpoints")
def get_endpoints(session=Depends(_verify_session)):
    try:
        with _ur.urlopen(f"{PIPELINE_API}/top/detailed?limit=50", timeout=5) as r:
            data = json.loads(r.read())
        procs = data.get("processes", [])
        return {"total": len(procs), "endpoints": [
            {"comm": p.get("comm"), "pid": p.get("pid", 0),
             "event_count": p.get("total", 0), "alerts": p.get("alerts", 0),
             "max_score": p.get("max_score", 0), "last_seen": p.get("last_seen", "")}
            for p in procs
        ]}
    except Exception as ex:
        return {"total": 0, "endpoints": [], "error": str(ex)}

@app.get("/api/stats")
def get_stats(session=Depends(_verify_session)):
    try:
        with _ur.urlopen(f"{PIPELINE_API}/stats", timeout=5) as r:
            pipeline_stats = json.loads(r.read())
    except Exception:
        pipeline_stats = {}
    try:
        with duckdb.connect(INCIDENT_DB, read_only=True) as con:
            open_inc = con.execute("SELECT COUNT(*) FROM incidents WHERE closed=FALSE").fetchone()[0]
            critical = con.execute("SELECT COUNT(*) FROM incidents WHERE severity='critical' AND closed=FALSE").fetchone()[0]
    except Exception:
        open_inc = critical = 0
    return {"pipeline": pipeline_stats, "open_incidents": open_inc,
            "critical_incidents": critical, "active_sessions": len(_SESSIONS)}

@app.post("/api/compliance/erasure/{customer_id}")
def request_erasure(customer_id: str, session=Depends(_verify_session)):
    from compliance.erasure_api import erasure_api
    return erasure_api.request_erasure(customer_id).to_dict()

@app.get("/api/compliance/audit/{customer_id}")
def get_audit_report(customer_id: str, session=Depends(_verify_session)):
    from compliance.audit_report import generate_report
    return generate_report(customer_id)

@app.post("/api/compliance/consent")
async def grant_consent(request: Request, session=Depends(_verify_session)):
    from compliance.consent_api import consent_store
    body = await request.json()
    return consent_store.grant(customer_id=body["customer_id"],
        entity=body["entity"], purpose=body["purpose"]).to_dict()

@app.post("/api/causal/analyze")
async def causal_analyze(request: Request, session=Depends(_verify_session)):
    body = await request.json()
    chain = body.get("chain", {})
    prompt = f"""You are a cybersecurity analyst for an Indian SME. Explain this attack chain to a non-technical business owner.
Attack Chain: Severity={chain.get('severity','unknown').upper()}, Stage={chain.get('current_stage','unknown')}, Duration={chain.get('duration_s',0)}s, Events={chain.get('event_count',0)}, Tactics={', '.join(chain.get('tactics',[]))}, Techniques={', '.join(chain.get('techniques',[]))}, Escalating={'YES' if chain.get('escalating') else 'No'}
3 short paragraphs: what happened, what attacker wanted, what to do now. Under 150 words."""
    try:
        payload = json.dumps({"model": "claude-sonnet-4-6", "max_tokens": 1000,
            "messages": [{"role": "user", "content": prompt}]}).encode()
        req = _ur.Request("https://api.anthropic.com/v1/messages", data=payload,
            headers={"Content-Type": "application/json"}, method="POST")
        with _ur.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
        return {"analysis": data.get("content", [{}])[0].get("text", "Unavailable")}
    except Exception as ex:
        log.error(f"Claude API error: {ex}")
        return {"analysis": f"API error: {ex}"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")
