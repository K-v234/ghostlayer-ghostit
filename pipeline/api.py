#!/usr/bin/env python3
"""
Ghost IT — Query API
FastAPI REST server over DuckDB.
"""
import sys
import os
import json
import argparse
import logging
import duckdb
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [api] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

app = FastAPI(title="Ghost IT Query API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

DB_PATH = os.environ.get("GHOSTIT_DB_PATH",
          os.path.expanduser("~/ghostlayer/data/events.db"))


def get_conn():
    return duckdb.connect(DB_PATH, read_only=True)


def df_to_json(df):
    """Convert DataFrame to JSON-safe list of dicts."""
    return json.loads(df.to_json(orient="records", default_handler=str))


@app.get("/health")
def health():
    try:
        conn = get_conn()
        conn.execute("SELECT 1").fetchone()
        conn.close()
        return {"status": "ok", "db": DB_PATH, "time": datetime.utcnow().isoformat()}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.get("/stats")
def stats():
    conn = get_conn()
    try:
        row = conn.execute("""
            SELECT
                COUNT(*)                              AS total,
                COUNT(*) FILTER (WHERE alert = true)  AS alerts,
                COUNT(DISTINCT pid)                   AS unique_pids,
                COUNT(DISTINCT comm)                  AS unique_procs,
                MIN(received_at)                      AS first_seen,
                MAX(received_at)                      AS last_seen
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
    finally:
        conn.close()


@app.get("/events")
def list_events(
    limit:     int           = Query(50,  ge=1, le=500),
    offset:    int           = Query(0,   ge=0),
    comm:      Optional[str] = Query(None),
    type:      Optional[str] = Query(None),
    alert:     Optional[bool]= Query(None),
    min_score: int           = Query(0,   ge=0, le=100),
):
    conn = get_conn()
    try:
        where  = ["score >= ?"]
        params = [min_score]

        if comm:
            where.append("comm = ?")
            params.append(comm)
        if type:
            where.append("type = ?")
            params.append(type)
        if alert is not None:
            where.append("alert = ?")
            params.append(alert)

        where_sql  = "WHERE " + " AND ".join(where)
        count_params = list(params)
        params += [limit, offset]

        rows = conn.execute(f"""
            SELECT id, ts, received_at, pid, ppid, uid, comm, type,
                   score, alert, reasons, file, args, daddr, dport
            FROM events
            {where_sql}
            ORDER BY ts DESC
            LIMIT ? OFFSET ?
        """, params).fetchdf()

        total = conn.execute(f"""
            SELECT COUNT(*) FROM events {where_sql}
        """, count_params).fetchone()[0]

        return JSONResponse(content={
            "total":  total,
            "limit":  limit,
            "offset": offset,
            "events": df_to_json(rows),
        })
    finally:
        conn.close()


@app.get("/alerts")
def list_alerts(limit: int = Query(100, ge=1, le=500)):
    conn = get_conn()
    try:
        rows = conn.execute("""
            SELECT id, ts, received_at, pid, ppid, comm, type,
                   score, reasons, file, daddr, dport
            FROM events
            WHERE alert = true
            ORDER BY ts DESC
            LIMIT ?
        """, [limit]).fetchdf()
        return JSONResponse(content={
            "total":  len(rows),
            "alerts": df_to_json(rows),
        })
    finally:
        conn.close()


@app.get("/events/pid/{pid}")
def events_by_pid(pid: int):
    conn = get_conn()
    try:
        rows = conn.execute("""
            SELECT id, ts, received_at, pid, ppid, comm, type,
                   score, alert, reasons, file, args, daddr, dport
            FROM events
            WHERE pid = ?
            ORDER BY ts ASC
        """, [pid]).fetchdf()
        if rows.empty:
            raise HTTPException(status_code=404, detail=f"No events for PID {pid}")
        return JSONResponse(content={
            "pid":    pid,
            "total":  len(rows),
            "events": df_to_json(rows),
        })
    finally:
        conn.close()


@app.get("/events/comm/{comm}")
def events_by_comm(comm: str, limit: int = Query(100, ge=1, le=500)):
    conn = get_conn()
    try:
        rows = conn.execute("""
            SELECT id, ts, received_at, pid, ppid, comm, type,
                   score, alert, reasons, file, daddr, dport
            FROM events
            WHERE comm = ?
            ORDER BY ts DESC
            LIMIT ?
        """, [comm, limit]).fetchdf()
        return JSONResponse(content={
            "comm":   comm,
            "total":  len(rows),
            "events": df_to_json(rows),
        })
    finally:
        conn.close()


@app.get("/top")
def top_processes(limit: int = Query(10, ge=1, le=50)):
    conn = get_conn()
    try:
        rows = conn.execute("""
            SELECT
                comm,
                COUNT(*)                              AS total,
                COUNT(*) FILTER (WHERE alert = true)  AS alerts,
                MAX(score)                            AS max_score,
                COUNT(DISTINCT type)                  AS event_types
            FROM events
            GROUP BY comm
            ORDER BY total DESC
            LIMIT ?
        """, [limit]).fetchdf()
        return JSONResponse(content={
            "processes": df_to_json(rows),
        })
    finally:
        conn.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host",    default="127.0.0.1")
    ap.add_argument("--port",    default=8000, type=int)
    ap.add_argument("--db-path", default=None)
    args = ap.parse_args()
    if args.db_path:
        os.environ["GHOSTIT_DB_PATH"] = os.path.expanduser(args.db_path)
    log.info(f"Ghost IT Query API starting on {args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
