#!/usr/bin/env python3
"""
Ghost IT — Unified Pipeline Server
Single process: TCP ingestion + FastAPI query API + DuckDB.
One DuckDB connection shared across both — no lock conflicts.

Ports:
  9000 TCP — receives events from eBPF agent
  8000 HTTP — query API for dashboard + detection engine
"""
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

# Global ransomware detector (C15)
_ransomware_detector = RansomwareEMADetector()
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
            clone_flags UBIGINT
        )
    """)
    DB_CONN.execute("CREATE INDEX IF NOT EXISTS idx_ts    ON events (ts DESC)")
    DB_CONN.execute("CREATE INDEX IF NOT EXISTS idx_alert ON events (alert, ts DESC)")
    DB_CONN.execute("CREATE INDEX IF NOT EXISTS idx_pid   ON events (pid, ts DESC)")
    DB_CONN.execute("CREATE INDEX IF NOT EXISTS idx_comm  ON events (comm, ts DESC)")
    DB_CONN.execute("CREATE SEQUENCE IF NOT EXISTS event_id_seq START 1")
    log.info(f"DB ready: {db_path}")


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
        e.get("clone_flags"),
    ) for e in events]

    with DB_LOCK:
        DB_CONN.executemany("""
            INSERT INTO events (
                id, ts, pid, ppid, uid, gid, comm, type,
                score, alert, reasons, file, args, flags,
                daddr, dport, family, clone_flags
            ) VALUES (
                nextval('event_id_seq'), ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
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
    log.info(f"Agent connected: {addr}")
    buf = b""
    stats = {"batches": 0, "events": 0, "errors": 0}

    try:
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    batch = json.loads(line)
                    if not isinstance(batch, list):
                        batch = [batch]
                    enriched = enrich_batch(batch)
                    n = insert_batch(enriched)
                    stats["batches"] += 1
                    stats["events"]  += n
                    alerts = sum(1 for e in enriched if e.get("alert"))
                    if alerts:
                        log.warning(f"[{addr}] {alerts} ALERT events")
                    else:
                        log.debug(f"[{addr}] {n} events stored")
                except Exception as ex:
                    stats["errors"] += 1
                    log.error(f"[{addr}] Bad batch: {ex}")
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
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
                   score, alert, reasons, file, args, daddr, dport
            FROM events {where_sql}
            ORDER BY ts DESC LIMIT ? OFFSET ?
        """, params).fetchdf()
        total = DB_CONN.execute(f"""
            SELECT COUNT(*) FROM events {where_sql}
        """, count_params).fetchone()[0]

    return JSONResponse({"total": total, "limit": limit,
                         "offset": offset, "events": df_to_json(rows)})


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

    # HTTP API in main thread
    log.info(f"HTTP API on {args.http_host}:{args.http_port}")
    uvicorn.run(app, host=args.http_host, port=args.http_port, log_level="warning")


if __name__ == "__main__":
    main()

