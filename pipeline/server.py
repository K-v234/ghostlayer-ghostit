#!/usr/bin/env python3
"""
Ghost IT — Unified Pipeline Server
Single process: TCP ingestion + FastAPI query API + DuckDB.
One DuckDB connection shared across both — no lock conflicts.

Ports:
  9000 TCP — receives events from eBPF agent
  8000 HTTP — query API for dashboard + detection engine
"""
import time
import hashlib
import collections
import sys
import os
import json
import logging
import argparse
import threading
import socket
import duckdb
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detection.ransomware import RansomwareEMADetector
from detection.behavioral import BehavioralAIEngine

# Global detectors
_ransomware_detector = RansomwareEMADetector()
_behavioral_engine   = BehavioralAIEngine()
from processor.enricher import enrich_batch

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ghost-pipeline] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Shared DuckDB connection + lock                                     #
# ------------------------------------------------------------------ #
DB_CONN: duckdb.DuckDBPyConnection = None
DB_LOCK = threading.Lock()


def init_db(db_path: str):
    global DB_CONN
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    DB_CONN = duckdb.connect(db_path)

    DB_CONN.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id          UBIGINT PRIMARY KEY,
            ts          UBIGINT NOT NULL,
            received_at TIMESTAMP DEFAULT now(),
            pid         UINTEGER NOT NULL,
            ppid        UINTEGER NOT NULL,
            uid         UINTEGER NOT NULL,
            gid         UINTEGER NOT NULL,
            comm        VARCHAR  NOT NULL,
            type        VARCHAR  NOT NULL,
            score       USMALLINT NOT NULL,
            alert       BOOLEAN  NOT NULL,
            reasons     VARCHAR[],
            file        VARCHAR,
            args        VARCHAR,
            flags       INTEGER,
            daddr       VARCHAR,
            dport       USMALLINT,
            family      USMALLINT,
            clone_flags UBIGINT,
            dpdp_pii_flag BOOLEAN DEFAULT FALSE
        )
    """)
    DB_CONN.execute("CREATE INDEX IF NOT EXISTS idx_ts    ON events (ts DESC)")
    DB_CONN.execute("CREATE INDEX IF NOT EXISTS idx_alert ON events (alert, ts DESC)")
    DB_CONN.execute("CREATE INDEX IF NOT EXISTS idx_pid   ON events (pid, ts DESC)")
    DB_CONN.execute("CREATE INDEX IF NOT EXISTS idx_comm  ON events (comm, ts DESC)")
    DB_CONN.execute("CREATE SEQUENCE IF NOT EXISTS event_id_seq START 1")

    log.info(f"DB ready: {db_path}")

    # 90-day retention cleanup on startup (DPDP compliant)
    try:
        deleted = DB_CONN.execute(
            "DELETE FROM events WHERE received_at < now() - INTERVAL '90 days'"
        ).rowcount
        if deleted:
            log.info(f"Retention cleanup: deleted {deleted} events older than 90 days")
    except Exception as ex:
        log.warning(f"Retention cleanup error: {ex}")


def insert_batch(events: list[dict]) -> int:
    if not events:
        return 0
    rows = [(
        e.get("ts", 0), e.get("pid", 0), e.get("ppid", 0),
        e.get("uid", 0), e.get("gid", 0),
        e.get("comm", ""), e.get("type", ""),
        e.get("score", 0), bool(e.get("alert", False)),
        e.get("reasons", []),
        e.get("file"), e.get("args"), e.get("flags"),
        e.get("daddr"), e.get("dport"), e.get("family"),
        e.get("clone_flags"), bool(e.get("dpdp_pii_flag", False)),
    ) for e in events]

    with DB_LOCK:
        DB_CONN.executemany("""
            INSERT INTO events (
                id, ts, pid, ppid, uid, gid, comm, type,
                score, alert, reasons, file, args, flags,
                daddr, dport, family, clone_flags, dpdp_pii_flag
            ) VALUES (
                nextval('event_id_seq'), ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
        """, rows)
    return len(rows)


def query(sql: str, params=None):
    with DB_LOCK:
        result = DB_CONN.execute(sql, params or [])
        return result


def df_to_json(df):
    return json.loads(df.to_json(orient="records", default_handler=str))


# ------------------------------------------------------------------ #
# TCP Ingestion Server                                                #
# ------------------------------------------------------------------ #
def handle_client(conn: socket.socket, addr: tuple):
    BATCH_SIZE = 1000
    FLUSH_MS   = 0.100
    log.info(f"Agent connected: {addr}")
    buf        = b""
    pending    = []
    stats      = {"batches": 0, "events": 0, "errors": 0}
    last_flush = time.monotonic()
    conn.settimeout(FLUSH_MS)

    def flush():
        if not pending:
            return
        try:
            enriched = enrich_batch(pending[:])
            n = insert_batch(enriched)
            stats["batches"] += 1
            stats["events"]  += n
            alerts = sum(1 for e in enriched if e.get("alert"))
            if alerts:
                log.warning(f"[{addr}] {alerts} ALERT events in batch of {n}")
            else:
                log.debug(f"[{addr}] flushed {n} events")
        except Exception as ex:
            stats["errors"] += 1
            log.error(f"[{addr}] Flush error: {ex}")
        pending.clear()

    try:
        while True:
            try:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk
            except TimeoutError:
                chunk = None

            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    batch = json.loads(line)
                    if not isinstance(batch, list):
                        batch = [batch]
                    pending.extend(batch)
                except Exception as ex:
                    stats["errors"] += 1
                    log.error(f"[{addr}] Parse error: {ex}")

            now = time.monotonic()
            if len(pending) >= BATCH_SIZE or (now - last_flush) >= FLUSH_MS:
                flush()
                last_flush = time.monotonic()

    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        flush()
        conn.close()
        log.info(f"Agent disconnected: {addr} | {stats}")


def run_tcp_server(host: str, port: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(16)
    log.info(f"TCP ingestion on {host}:{port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


# ------------------------------------------------------------------ #
# FastAPI Query API                                                   #
# ------------------------------------------------------------------ #
app = FastAPI(title="Ghost IT Query API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["GET"], allow_headers=["*"])


@app.get("/health")
def health():
    with DB_LOCK:
        DB_CONN.execute("SELECT 1").fetchone()
    return {"status": "ok", "time": datetime.utcnow().isoformat()}


@app.get("/stats")
def stats():
    with DB_LOCK:
        row = DB_CONN.execute("""
            SELECT COUNT(*),
                   COUNT(*) FILTER (WHERE alert=true),
                   COUNT(DISTINCT pid),
                   COUNT(DISTINCT comm),
                   MIN(received_at),
                   MAX(received_at)
            FROM events
        """).fetchone()
    return {
        "total": row[0], "alerts": row[1],
        "unique_pids": row[2], "unique_procs": row[3],
        "first_seen": str(row[4]), "last_seen": str(row[5]),
    }


@app.get("/events")
def list_events(
    limit:     int            = Query(50,  ge=1, le=500),
    offset:    int            = Query(0,   ge=0),
    comm:      Optional[str]  = Query(None),
    type:      Optional[str]  = Query(None),
    alert:     Optional[bool] = Query(None),
    min_score: int            = Query(0,   ge=0, le=100),
):
    where  = ["score >= ?"]
    params = [min_score]
    if comm:  where.append("comm = ?");  params.append(comm)
    if type:  where.append("type = ?");  params.append(type)
    if alert is not None: where.append("alert = ?"); params.append(alert)

    where_sql    = "WHERE " + " AND ".join(where)
    count_params = list(params)
    params      += [limit, offset]

    with DB_LOCK:
        rows  = DB_CONN.execute(f"""
            SELECT id, ts, received_at, pid, ppid, uid, comm, type,
                   score, alert, reasons, file, args, daddr, dport, dpdp_pii_flag
            FROM events {where_sql}
            ORDER BY ts DESC LIMIT ? OFFSET ?
        """, params).fetchdf()
        total = DB_CONN.execute(f"""
            SELECT COUNT(*) FROM events {where_sql}
        """, count_params).fetchone()[0]

    return JSONResponse({"total": total, "limit": limit,
                         "offset": offset, "events": df_to_json(rows)})


@app.get("/events/since")
def events_since(since_id: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500)):
    """Fetch events with id > since_id, ordered by id ASC — for detection engine cursor."""
    with DB_LOCK:
        rows = DB_CONN.execute("""
            SELECT id, ts, received_at, pid, ppid, uid, comm, type,
                   score, alert, reasons, file, args, daddr, dport, dpdp_pii_flag
            FROM events WHERE id > ?
            ORDER BY id ASC LIMIT ?
        """, [since_id, limit]).fetchdf()
    return JSONResponse({"events": df_to_json(rows), "max_id": int(rows["id"].max()) if len(rows) > 0 else since_id})


@app.get("/alerts")
def list_alerts(limit: int = Query(100, ge=1, le=500)):
    with DB_LOCK:
        rows = DB_CONN.execute("""
            SELECT id, ts, received_at, pid, ppid, comm, type,
                   score, reasons, file, daddr, dport
            FROM events WHERE alert=true
            ORDER BY ts DESC LIMIT ?
        """, [limit]).fetchdf()
    return JSONResponse({"total": len(rows), "alerts": df_to_json(rows)})


@app.get("/top")
def top_processes(limit: int = Query(10, ge=1, le=50)):
    with DB_LOCK:
        rows = DB_CONN.execute("""
            SELECT comm,
                   COUNT(*)                             AS total,
                   COUNT(*) FILTER (WHERE alert=true)   AS alerts,
                   MAX(score)                           AS max_score,
                   COUNT(DISTINCT type)                 AS event_types
            FROM events GROUP BY comm
            ORDER BY total DESC LIMIT ?
        """, [limit]).fetchdf()
    return JSONResponse({"processes": df_to_json(rows)})


@app.get("/timeline")
def event_timeline(minutes: int = Query(60, ge=1, le=1440)):
    """Event rate per minute for the last N minutes — for dashboard graphs."""
    with DB_LOCK:
        rows = DB_CONN.execute("""
            SELECT
                strftime(received_at, '%Y-%m-%dT%H:%M:00') AS minute,
                COUNT(*) AS events,
                COUNT(*) FILTER (WHERE alert=true) AS alerts
            FROM events
            WHERE received_at > (current_timestamp - INTERVAL '{minutes}' MINUTE)
            GROUP BY minute
            ORDER BY minute ASC
        """.format(minutes=int(minutes))).fetchdf()
    return JSONResponse({"timeline": df_to_json(rows)})

@app.get("/top/detailed")
def top_processes_detailed(limit: int = Query(50, ge=1, le=200)):
    """Top processes with PID, last seen, alert count."""
    with DB_LOCK:
        rows = DB_CONN.execute("""
            SELECT comm, pid,
                   COUNT(*) AS total,
                   COUNT(*) FILTER (WHERE alert=true) AS alerts,
                   MAX(score) AS max_score,
                   MAX(received_at) AS last_seen,
                   COUNT(DISTINCT type) AS event_types
            FROM events
            GROUP BY comm, pid
            ORDER BY total DESC LIMIT ?
        """, [limit]).fetchdf()
    return JSONResponse({"processes": df_to_json(rows)})

@app.get("/events/pid/{pid}")
def events_by_pid(pid: int):
    with DB_LOCK:
        rows = DB_CONN.execute("""
            SELECT id, ts, received_at, pid, ppid, comm, type,
                   score, alert, reasons, file, args, daddr, dport
            FROM events WHERE pid=? ORDER BY ts ASC
        """, [pid]).fetchdf()
    if rows.empty:
        raise HTTPException(404, f"No events for PID {pid}")
    return JSONResponse({"pid": pid, "total": len(rows), "events": df_to_json(rows)})


@app.get("/events/comm/{comm}")
def events_by_comm(comm: str, limit: int = Query(100, ge=1, le=500)):
    with DB_LOCK:
        rows = DB_CONN.execute("""
            SELECT id, ts, received_at, pid, ppid, comm, type,
                   score, alert, reasons, file, daddr, dport
            FROM events WHERE comm=? ORDER BY ts DESC LIMIT ?
        """, [comm, limit]).fetchdf()
    return JSONResponse({"comm": comm, "total": len(rows), "events": df_to_json(rows)})


# ------------------------------------------------------------------ #
# Main                                                               #
# ------------------------------------------------------------------ #


# ------------------------------------------------------------------ #
# Chain state endpoint                                               #
# ------------------------------------------------------------------ #
import pathlib as _pathlib

CHAIN_STATE_FILE = _pathlib.Path.home() / "ghostlayer/data/chain_state.json"

@app.get("/chains")
def get_chains():
    """Active attack chains from detection engine."""
    try:
        if CHAIN_STATE_FILE.exists():
            return json.loads(CHAIN_STATE_FILE.read_text())
        return {"chains": [], "highest_severity": "none"}
    except Exception as e:
        return {"chains": [], "error": str(e)}



# ------------------------------------------------------------------ #
# Heartbeat Listener (C6 Layer 4)                                    #
# ------------------------------------------------------------------ #
_hb_registry: dict = {}          # pubkey -> last_seen timestamp
_hb_missed:   dict = {}          # pubkey -> missed count
HB_TIMEOUT_SEC = 180             # 3 missed x 60s = alert

def _handle_heartbeat(conn: socket.socket, addr: tuple):
    try:
        data = b""
        while b"\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        line = data.split(b"\n")[0].strip()
        if not line:
            return
        msg = json.loads(line)
        payload_str = msg.get("payload", "")
        sig_hex     = msg.get("sig", "")
        payload     = json.loads(payload_str)
        pubkey_hex  = payload.get("pubkey", "")
        seq         = payload.get("seq", 0)
        ts          = payload.get("ts", 0)
        pid         = payload.get("pid", 0)
        # Register / update last seen
        _hb_registry[pubkey_hex] = time.time()
        _hb_missed[pubkey_hex]   = 0
        log.info(f"[HB] seq={seq} pid={pid} ts={ts} from {addr} — OK")
    except Exception as ex:
        log.warning(f"[HB] Bad heartbeat from {addr}: {ex}")
    finally:
        conn.close()

def _heartbeat_watchdog():
    """Check for missed heartbeats every 60s."""
    while True:
        time.sleep(60)
        now = time.time()
        for pubkey, last_seen in list(_hb_registry.items()):
            elapsed = now - last_seen
            if elapsed > HB_TIMEOUT_SEC:
                missed = int(elapsed // 60)
                _hb_missed[pubkey] = missed
                log.critical(
                    f"[HB] TAMPER ALERT — agent silent for {int(elapsed)}s "
                    f"({missed} missed heartbeats) pubkey={pubkey[:16]}..."
                )
                # Inject tamper alert into pipeline
                alert_event = [{
                    "type": "heartbeat_miss",
                    "score": 100,
                    "alert": True,
                    "pubkey": pubkey[:16],
                    "missed": missed,
                    "ts": int(now),
                    "comm": "ghost-agent",
                    "pid": 0,
                }]
                try:
                    insert_batch(alert_event)
                except Exception as e:
                    log.error(f"[HB] Failed to insert tamper alert: {e}")

def run_heartbeat_server(host: str, port: int):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(8)
    log.info(f"Heartbeat listener on {host}:{port} (C6 Layer 4)")
    # Start watchdog thread
    threading.Thread(target=_heartbeat_watchdog, daemon=True).start()
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=_handle_heartbeat, args=(conn, addr), daemon=True).start()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tcp-host",  default="127.0.0.1")
    ap.add_argument("--tcp-port",  default=9000, type=int)
    ap.add_argument("--http-host", default="127.0.0.1")
    ap.add_argument("--http-port", default=8000, type=int)
    ap.add_argument("--db-path",   default=os.path.expanduser("~/ghostlayer/data/events.db"))
    args = ap.parse_args()

    init_db(args.db_path)

    # TCP ingestion in background thread
    tcp_thread = threading.Thread(
        target=run_tcp_server,
        args=(args.tcp_host, args.tcp_port),
        daemon=True,
    )
    tcp_thread.start()

    # Heartbeat listener (C6 Layer 4)
    hb_thread = threading.Thread(
        target=run_heartbeat_server,
        args=(args.tcp_host, 9001),
        daemon=True,
    )
    hb_thread.start()

    # HTTP API in main thread
    log.info(f"HTTP API on {args.http_host}:{args.http_port}")
    uvicorn.run(app, host=args.http_host, port=args.http_port, log_level="warning")


if __name__ == "__main__":
    main()

