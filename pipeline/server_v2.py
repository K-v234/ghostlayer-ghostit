#!/usr/bin/env python3
"""
Ghost IT — High-Performance Pipeline Server v2.0
Architecture: Hot Buffer + Parquet Partitioned Files + DuckDB Query Layer

Write path: TCP -> Hot Buffer (in-memory deque, 100K events) -> Parquet files (hourly)
Read path:  DuckDB queries Parquet glob + Hot Buffer union (microseconds, columnar)

Ghost Layer Technologies — CONFIDENTIAL
"""
import time, os, json, logging, argparse, threading, socket, duckdb, pathlib
from datetime import datetime, timezone
from collections import deque, defaultdict, Counter
from typing import Optional
from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn, sys
import pyarrow as pa
import pyarrow.parquet as pq

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [pipeline-v2] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S")
log = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Global State                                                        #
# ------------------------------------------------------------------ #
PARQUET_DIR  = None
LEGACY_DB    = None
HOT_BUFFER   = deque(maxlen=100_000)
HOT_LOCK     = threading.Lock()

# C4 feedback loop: PIDs C4 has confirmed malicious (via invariant
# violation or high-confidence GNN classification) get added here.
# Subsequent events from the same PID get an elevated score boost,
# closing the loop between causal reasoning and behavioral scoring --
# previously C4's confirmed findings never influenced C2's downstream
# scoring of the same entity's later actions.
WATCHLIST      = {}  # {pid: expiry_timestamp}
WATCHLIST_LOCK = threading.Lock()
WATCHLIST_TTL_SEC = 600  # 10 minutes elevated scrutiny after confirmation
EVENT_SEQ    = 0
SEQ_LOCK     = threading.Lock()
_flush_pending = []
_flush_lock    = threading.Lock()
FLUSH_INTERVAL = 300
FLUSH_COUNT    = 50_000

# Per-host hot buffers (CrowdStrike/SentinelOne pattern)
# Each sensor gets its own ring buffer — prevents Linux eBPF flood
# from crowding out Windows C9 events
HOST_BUFFERS = {
    "linux":   deque(maxlen=90_000),
    "windows": deque(maxlen=10_000),
}
HOST_LOCK = threading.Lock()


SCHEMA = pa.schema([
    pa.field("id",            pa.int64()),
    pa.field("ts",            pa.int64()),
    pa.field("received_at",   pa.int64()),
    pa.field("pid",           pa.int32()),
    pa.field("ppid",          pa.int32()),
    pa.field("uid",           pa.int32()),
    pa.field("gid",           pa.int32()),
    pa.field("comm",          pa.string()),
    pa.field("type",          pa.string()),
    pa.field("score",         pa.int16()),
    pa.field("alert",         pa.bool_()),
    pa.field("reasons",       pa.string()),
    pa.field("file",          pa.string()),
    pa.field("args",          pa.string()),
    pa.field("flags",         pa.int32()),
    pa.field("daddr",         pa.string()),
    pa.field("dport",         pa.int32()),
    pa.field("family",        pa.int32()),
    pa.field("clone_flags",   pa.int64()),
    pa.field("dpdp_pii_flag", pa.bool_()),
    pa.field("integrity",     pa.int32()),
])

def _extract_daddr(path):
    if not path or ":" not in path:
        return None
    try:
        ip = path.rsplit(":", 1)[0]
        if all(p.isdigit() for p in ip.split(".")) and len(ip.split(".")) == 4:
            return ip
    except Exception:
        pass
    return None

def _extract_dport(path):
    if not path or ":" not in path:
        return None
    try:
        port = int(path.rsplit(":", 1)[1])
        return port if 0 < port < 65536 else None
    except Exception:
        return None

def next_id():
    global EVENT_SEQ
    with SEQ_LOCK:
        if EVENT_SEQ == 0:
            EVENT_SEQ = int(time.time() * 1000) << 10
        EVENT_SEQ += 1
        return EVENT_SEQ

def parquet_path_for_now():
    now = datetime.now(timezone.utc)
    return os.path.join(PARQUET_DIR, now.strftime("%Y/%m/%d/%H"), f"batch_{int(time.time()*1000)}_{os.getpid()}.parquet")

def flush_to_parquet(events):
    if not events:
        return
    # Each flush writes its OWN small file (unique timestamp+pid in
    # filename) instead of read-modify-write of one growing per-hour
    # file. The old pattern re-read and rewrote the entire hour's
    # accumulated data on every single flush -- O(n^2) cost over the
    # course of each hour, and the real scale ceiling under real
    # multi-endpoint load, not DuckDB itself (DuckDB only reads
    # Parquet via glob, it never writes). DuckDB's glob-based query
    # path already reads across multiple files natively, so this
    # requires no read-path changes.
    path = parquet_path_for_now()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    rows = {f.name: [] for f in SCHEMA}
    for e in events:
        rows["id"].append(e.get("id", 0))
        rows["ts"].append(int(e.get("ts", 0)))
        rows["received_at"].append(int(e.get("received_at", time.time())))
        rows["pid"].append(int(e.get("pid", 0)))
        rows["ppid"].append(int(e.get("ppid", 0)))
        rows["uid"].append(int(e.get("uid", 0)))
        rows["gid"].append(int(e.get("gid", 0)))
        rows["comm"].append(str(e.get("comm", "")))
        rows["type"].append(str(e.get("type") or e.get("event_type") or ""))
        rows["score"].append(int(e.get("score", 0)))
        rows["alert"].append(bool(e.get("alert", False)))
        rows["reasons"].append(json.dumps(e.get("reasons", [])))
        rows["file"].append(e.get("file") or e.get("path"))
        rows["args"].append(e.get("args"))
        rows["flags"].append(int(e.get("flags") or 0))
        rows["daddr"].append(e.get("daddr") or _extract_daddr(e.get("path")))
        rows["dport"].append(int(e.get("dport") or _extract_dport(e.get("path")) or 0))
        rows["family"].append(int(e.get("family") or 0))
        rows["clone_flags"].append(int(e.get("clone_flags") or 0))
        rows["dpdp_pii_flag"].append(bool(e.get("dpdp_pii_flag", False)))
        rows["integrity"].append(int(e.get("integrity") or 0))
    table = pa.table(rows, schema=SCHEMA)
    # No read-modify-write: each flush has a unique filename now (see
    # parquet_path_for_now), so there's never an existing file at this
    # exact path to merge with. Atomic write still applies -- temp file
    # + rename prevents a half-written file from being read mid-write.
    tmp_path = path + ".tmp"
    pq.write_table(table, tmp_path, compression="snappy", row_group_size=10_000)
    os.replace(tmp_path, path)

def _flush_loop():
    last_flush = time.monotonic()
    while True:
        time.sleep(1)
        now = time.monotonic()
        with _flush_lock:
            count = len(_flush_pending)
        if count >= FLUSH_COUNT or (now - last_flush) >= FLUSH_INTERVAL:
            with _flush_lock:
                batch = list(_flush_pending)
                _flush_pending.clear()
            if batch:
                try:
                    flush_to_parquet(batch)
                    log.info(f"Parquet flush: {len(batch)} events")
                except Exception as ex:
                    log.error(f"Parquet flush error: {ex}")
            last_flush = time.monotonic()

# Ghost IT trusted process paths — events from these are never scored
# Identified by /proc/PID/cmdline at deploy time — survives restarts unlike PID-based exclusion
GHOST_IT_PATHS = {
    "/home/keerthivahanan/ghostlayer/detection/engine.py",
    "/home/keerthivahanan/ghostlayer/pipeline/server_v2.py",
    "/home/keerthivahanan/ghostlayer/ghostit-agent-linux-amd64",
    "/home/keerthivahanan/ghostlayer/canary/canary_server.py",
    "/home/keerthivahanan/ghostlayer/causal/engine.py",
    "/home/keerthivahanan/ghostlayer/alert-engine/correlator.py",
    "/home/keerthivahanan/ghostlayer/dashboard/api/server.py",
}

def _is_ghost_it_process(pid: int) -> bool:
    """Check if pid belongs to a Ghost IT service by reading /proc/PID/cmdline."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmdline = f.read().decode("utf-8", errors="replace").replace("\x00", " ")
        return any(p in cmdline for p in GHOST_IT_PATHS)
    except Exception:
        return False

def enrich_batch(events):
    enriched = []
    for e in events:
        # Layer 1 self-exclusion: Ghost IT own processes never scored (CrowdStrike pattern)
        # EXCEPT detection alerts forwarded by the detection engine — those must pass through
        # Self-exclusion: only suppress raw eBPF telemetry from Ghost IT processes
        # Detection alerts (type=detection) always pass through unchanged — filtered at display layer
        if e.get("type") != "detection" and _is_ghost_it_process(int(e.get("pid", 0) or 0)):
            e = {**e, "score": 0, "alert": False, "reasons": [], "_ghost_internal": True}
        # Default scoring for agents that don't self-score (Windows C9
        # sends no score field on raw file/process/network events --
        # only C15/other detectors re-score and forward specific
        # alerts). Without this, score stays None forever for most
        # Windows telemetry, making it invisible to any score-filtered
        # consumer (C4's min_score=40, /events min_score queries, etc.)
        # -- confirmed root cause of C4 never seeing Windows ransomware
        # test events despite them being genuinely present. Matches the
        # Linux agent's own priority-based default (60 for critical-ring
        # events, 10 otherwise) so both platforms are scored consistently.
        if e.get("score") is None:
            e["score"] = 60 if e.get("priority") == 1 else 10
        e["id"] = next_id()
        e["received_at"] = int(time.time())
        # C4 feedback loop: if this PID was recently confirmed malicious
        # by causal reasoning, boost its score so C2's downstream
        # behavioral scoring treats its subsequent actions with elevated
        # suspicion instead of scoring each new event from scratch.
        pid = int(e.get("pid", 0) or 0)
        if pid:
            with WATCHLIST_LOCK:
                expiry = WATCHLIST.get(pid)
                if expiry and time.time() < expiry:
                    original_score = e.get("score") or 0
                    e["score"] = min(100, original_score + 30)
                    e["watchlisted"] = True
                elif expiry:
                    del WATCHLIST[pid]  # expired, clean up
        # Tag host based on agent field
        agent = e.get("agent", "")
        if agent == "windows-c9":
            e["host"] = "windows"
            # Windows agent sends command-line arguments via the path
            # field (out.path in ghost_event_t, reused since it's empty
            # for real ProcessStart events) rather than a dedicated args
            # field. Map it here so LOLBinDetector.check_event(), which
            # reads event.get("args"), actually sees it.
            if e.get("type") == "process_exec" and not e.get("args"):
                candidate = e.get("path") or e.get("file")
                if candidate:
                    e["args"] = candidate
        else:
            e["host"] = "linux"
        path = e.get("file") or e.get("path") or ""
        e["dpdp_pii_flag"] = any(p in path for p in (
            "/etc/passwd", "/etc/shadow", "id_rsa", ".ssh", "credential", "password"))
        enriched.append(e)
    return enriched

def insert_batch(events):
    if not events:
        return 0
    enriched = enrich_batch(events)
    with HOT_LOCK:
        HOT_BUFFER.extend(enriched)
    # Per-host buffers — separate ring per sensor (CrowdStrike pattern)
    with HOST_LOCK:
        for e in enriched:
            host = e.get("host", "linux")
            buf = HOST_BUFFERS.get(host, HOST_BUFFERS["linux"])
            buf.append(e)
    with _flush_lock:
        _flush_pending.extend(enriched)
    return len(enriched)

def get_duckdb():
    conn = duckdb.connect(":memory:")
    parquet_glob = os.path.join(PARQUET_DIR, "**/*.parquet")
    has_parquet = any(True for _ in pathlib.Path(PARQUET_DIR).rglob("*.parquet"))
    if has_parquet:
        conn.execute(f"""
            CREATE VIEW IF NOT EXISTS parquet_events AS
            SELECT * FROM read_parquet("{parquet_glob}", hive_partitioning=false)
        """)
    if LEGACY_DB and os.path.exists(LEGACY_DB):
        try:
            conn.execute(f"ATTACH '{LEGACY_DB}' AS legacy (READ_ONLY)")
            if has_parquet:
                conn.execute("""
                    CREATE VIEW events_all AS
                    SELECT id, ts, CAST(received_at AS BIGINT) AS received_at,
                           pid, ppid, uid, gid, comm, type, score, alert,
                           CAST(reasons AS VARCHAR) AS reasons,
                           file, args, CAST(flags AS INT) AS flags,
                           daddr, CAST(dport AS INT) AS dport,
                           CAST(family AS INT) AS family,
                           CAST(clone_flags AS BIGINT) AS clone_flags, dpdp_pii_flag
                    FROM legacy.events
                    UNION ALL SELECT * FROM parquet_events
                """)
            else:
                conn.execute("""
                    CREATE VIEW events_all AS
                    SELECT * FROM legacy.events
                """)
        except Exception as ex:
            log.warning(f"Legacy DB attach failed: {ex}")
            if has_parquet:
                conn.execute("CREATE VIEW events_all AS SELECT * FROM parquet_events")
            else:
                conn.execute("CREATE VIEW events_all AS SELECT 1 AS id LIMIT 0")
    elif has_parquet:
        conn.execute("CREATE VIEW events_all AS SELECT * FROM parquet_events")
    else:
        conn.execute("CREATE VIEW events_all AS SELECT 1 AS id LIMIT 0")
    return conn

def hot_to_result(events):
    result = []
    for e in events:
        result.append({
            "id": e.get("id"), "ts": e.get("ts"),
            "received_at": e.get("received_at"),
            "pid": e.get("pid"), "ppid": e.get("ppid"), "uid": e.get("uid"),
            "comm": e.get("comm"),
            "type": e.get("type") or e.get("event_type"),
            "score": e.get("score"), "alert": e.get("alert"),
            "reasons": e.get("reasons", []),
            "file": e.get("file") or e.get("path"),
            "args": e.get("args"),
            "daddr": e.get("daddr") or _extract_daddr(e.get("path")),
            "dport": e.get("dport") or _extract_dport(e.get("path")),
            "dpdp_pii_flag": e.get("dpdp_pii_flag", False),
            "host": e.get("host", "linux"),
            "agent": e.get("agent", "linux-c1"),
            "integrity": e.get("integrity"),
            "source_ip": e.get("source_ip"),
        })
    return result

def df_to_json(df):
    return json.loads(df.to_json(orient="records", default_handler=str))

# ------------------------------------------------------------------ #
# TCP Ingestion                                                       #
# ------------------------------------------------------------------ #
def handle_client(conn, addr):
    BATCH_SIZE = 1000
    FLUSH_MS   = 0.100
    buf, pending = b"", []
    stats = {"batches": 0, "events": 0, "errors": 0}
    last_flush = time.monotonic()
    conn.settimeout(FLUSH_MS)
    def flush():
        if not pending: return
        try:
            n = insert_batch(list(pending))
            stats["batches"] += 1; stats["events"] += n
        except Exception as ex:
            stats["errors"] += 1; log.error(f"[{addr}] Flush: {ex}")
        pending.clear()
    try:
        while True:
            try:
                chunk = conn.recv(65536)
                if not chunk: break
                buf += chunk
            except TimeoutError:
                chunk = None
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                line = line.strip()
                if not line: continue
                try:
                    batch = json.loads(line)
                    if not isinstance(batch, list): batch = [batch]
                    # Tag each event with the connecting machine's real
                    # source IP -- "host" field only distinguishes
                    # platform (windows/linux), not individual machines,
                    # so multiple Windows or Linux boxes were previously
                    # indistinguishable in the data. source_ip gives
                    # genuine per-machine identity for free, using the
                    # TCP connection's own address, no agent-side changes needed.
                    for ev in batch:
                        ev["source_ip"] = addr[0]
                    pending.extend(batch)
                except Exception as ex:
                    stats["errors"] += 1
            now = time.monotonic()
            if len(pending) >= BATCH_SIZE or (now - last_flush) >= FLUSH_MS:
                flush(); last_flush = time.monotonic()
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        flush(); conn.close()
        log.info(f"Agent disconnected: {addr} | {stats}")

def run_tcp_server(host, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port)); srv.listen(16)
    log.info(f"TCP ingestion on {host}:{port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

# ------------------------------------------------------------------ #
# FastAPI                                                             #
# ------------------------------------------------------------------ #
app = FastAPI(title="Ghost IT Pipeline v2", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"],
                   allow_methods=["GET"], allow_headers=["*"])

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat(),
            "hot_buffer": len(HOT_BUFFER), "version": "2.0"}

@app.get("/stats")
def stats_endpoint():
    with HOT_LOCK:
        hot = list(HOT_BUFFER)
    try:
        conn = get_duckdb()
        row = conn.execute("SELECT COUNT(*) FROM events_all").fetchone()
        total = row[0] + len(hot)
        conn.close()
    except Exception:
        total = len(hot)
    return {
        "total": total,
        "alerts": sum(1 for e in hot if e.get("alert")),
        "unique_pids": len(set(e.get("pid") for e in hot)),
        "unique_procs": len(set(e.get("comm") for e in hot)),
        "hot_buffer": len(hot),
        "first_seen": None,
        "last_seen": datetime.now(timezone.utc).astimezone().isoformat(),
    }

@app.get("/events")
def list_events(
    limit:     int           = Query(50, ge=1, le=500),
    offset:    int           = Query(0, ge=0),
    comm:      Optional[str] = Query(None),
    type:      Optional[str] = Query(None, alias="type"),
    alert:     Optional[bool]= Query(None),
    min_score: int           = Query(0, ge=0, le=100),
):
    with HOT_LOCK:
        events = list(HOT_BUFFER)
    events = [e for e in events if e.get("score", 0) >= min_score]
    if type:    events = [e for e in events if (e.get("type") or e.get("event_type")) == type]
    if comm:    events = [e for e in events if e.get("comm") == comm]
    if alert is not None: events = [e for e in events if bool(e.get("alert")) == alert]
    events.sort(key=lambda x: x.get("id", 0), reverse=True)
    total = len(events)
    events = events[offset:offset+limit]
    return JSONResponse({"total": total, "limit": limit, "offset": offset,
                         "events": hot_to_result(events)})

@app.post("/watchlist/{pid}")
def add_to_watchlist(pid: int):
    # C4 feedback loop endpoint: causal engine calls this when it
    # confirms a PID is malicious (invariant violation or high-confidence
    # GNN classification). Subsequent events from this PID get elevated
    # scoring for WATCHLIST_TTL_SEC, closing the loop so C2's downstream
    # scoring benefits from C4's confirmed finding instead of treating
    # each new event from the same confirmed-bad entity as fresh/unknown.
    with WATCHLIST_LOCK:
        WATCHLIST[pid] = time.time() + WATCHLIST_TTL_SEC
    log.info(f"[C4-feedback] PID {pid} added to watchlist for {WATCHLIST_TTL_SEC}s")
    return {"status": "watchlisted", "pid": pid, "ttl_sec": WATCHLIST_TTL_SEC}
@app.get("/watchlist")
def get_watchlist():
    now = time.time()
    with WATCHLIST_LOCK:
        active = {pid: round(exp - now, 1) for pid, exp in WATCHLIST.items() if exp > now}
    return {"watchlisted_pids": active}
@app.get("/events/since")
def events_since(since_id: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500),
                  host: str = Query(None)):
    # Reading from HOT_BUFFER alone drops Windows events: it's a single
    # shared deque and high-volume Linux eBPF telemetry evicts them before
    # they can be polled. Reading per-host buffers (already populated
    # correctly at insert_batch time) and merging preserves both streams.
    with HOT_LOCK:
        base = list(HOT_BUFFER)
    with HOST_LOCK:
        for buf in HOST_BUFFERS.values():
            base.extend(buf)
    seen_ids = set()
    events = []
    for e in base:
        eid = e.get("id", 0)
        if eid > since_id and eid not in seen_ids:
            seen_ids.add(eid)
            if host is None or e.get("host") == host:
                events.append(e)
    events.sort(key=lambda x: x.get("id", 0))
    # Per-host fetch quota: without this, a single high-volume source
    # (Linux eBPF telemetry, confirmed ~50,000 events/minute) statistically
    # crowds out lower-volume sources (Windows ETW, comparatively rare)
    # from every poll cycle's shared limit -- confirmed root cause of the
    # detection engine (and C4) never seeing Windows ransomware test data
    # despite it genuinely reaching the pipeline. Splitting the limit
    # evenly per distinct host guarantees each platform gets fetch
    # bandwidth regardless of how noisy any other platform is.
    if host is None and len(events) > limit:
        hosts_present = sorted(set(e.get("host", "unknown") for e in events))
        per_host_limit = max(1, limit // len(hosts_present))
        balanced = []
        for h in hosts_present:
            h_events = [e for e in events if e.get("host") == h]
            balanced.extend(h_events[-per_host_limit:])
        balanced.sort(key=lambda x: x.get("id", 0))
        events = balanced[:limit]
    else:
        events = events[:limit]
    max_id = max((e.get("id", 0) for e in events), default=since_id)
    return JSONResponse({"events": hot_to_result(events), "max_id": max_id})

@app.get("/alerts")
def list_alerts(limit: int = Query(100, ge=1, le=500)):
    with HOT_LOCK:
        events = [e for e in HOT_BUFFER if e.get("alert")]
    events.sort(key=lambda x: x.get("id", 0), reverse=True)
    events = events[:limit]
    result = hot_to_result(events)
    return JSONResponse({"total": len(result), "alerts": result})

@app.get("/top")
def top_processes(limit: int = Query(10, ge=1, le=50)):
    with HOT_LOCK:
        events = list(HOT_BUFFER)
    counts = Counter(e.get("comm", "") for e in events)
    alert_counts = Counter(e.get("comm", "") for e in events if e.get("alert"))
    max_scores, type_counts = {}, {}
    for e in events:
        c = e.get("comm", "")
        max_scores[c] = max(max_scores.get(c, 0), e.get("score", 0))
        type_counts.setdefault(c, set()).add(e.get("type") or e.get("event_type"))
    processes = [{"comm": c, "total": n, "alerts": alert_counts.get(c, 0),
                  "max_score": max_scores.get(c, 0),
                  "event_types": len(type_counts.get(c, set()))}
                 for c, n in counts.most_common(limit)]
    return JSONResponse({"processes": processes})

@app.get("/top/detailed")
def top_processes_detailed(limit: int = Query(50, ge=1, le=200)):
    with HOT_LOCK:
        events = list(HOT_BUFFER)
    groups = defaultdict(list)
    for e in events:
        groups[(e.get("comm",""), e.get("pid",0))].append(e)
    processes = []
    for (comm, pid), evts in sorted(groups.items(), key=lambda x: -len(x[1]))[:limit]:
        host = evts[0].get("host", "linux") if evts else "linux"
        processes.append({"comm": comm, "pid": pid, "total": len(evts),
            "alerts": sum(1 for e in evts if e.get("alert")),
            "max_score": max((e.get("score",0) for e in evts), default=0),
            "last_seen": max((e.get("received_at",0) for e in evts), default=0),
            "event_types": len(set(e.get("type") or e.get("event_type") for e in evts)),
            "host": host})
    return JSONResponse({"processes": processes})

@app.get("/timeline")
def event_timeline(minutes: int = Query(60, ge=1, le=1440)):
    cutoff = time.time() - minutes * 60
    with HOT_LOCK:
        events = [e for e in HOT_BUFFER if e.get("received_at", 0) >= cutoff]
    buckets = defaultdict(lambda: {"events": 0, "alerts": 0})
    for e in events:
        minute = datetime.fromtimestamp(e.get("received_at", 0)).strftime("%Y-%m-%dT%H:%M:00")
        buckets[minute]["events"] += 1
        if e.get("alert"): buckets[minute]["alerts"] += 1
    return JSONResponse({"timeline": [{"minute": k, **v} for k, v in sorted(buckets.items())]})

@app.get("/events/pid/{pid}")
def events_by_pid(pid: int):
    with HOT_LOCK:
        events = [e for e in HOT_BUFFER if e.get("pid") == pid]
    if not events:
        try:
            conn = get_duckdb()
            rows = conn.execute("SELECT * FROM events_all WHERE pid=? ORDER BY id ASC", [pid]).fetchdf()
            conn.close()
            if rows.empty:
                raise HTTPException(404, f"No events for PID {pid}")
            return JSONResponse({"pid": pid, "total": len(rows), "events": df_to_json(rows)})
        except HTTPException: raise
        except Exception: raise HTTPException(404, f"No events for PID {pid}")
    events.sort(key=lambda x: x.get("id", 0))
    return JSONResponse({"pid": pid, "total": len(events), "events": hot_to_result(events)})

@app.get("/events/comm/{comm}")
def events_by_comm(comm: str, limit: int = Query(100, ge=1, le=500)):
    with HOT_LOCK:
        events = [e for e in HOT_BUFFER if e.get("comm") == comm]
    events.sort(key=lambda x: x.get("id", 0), reverse=True)
    events = events[:limit]
    return JSONResponse({"comm": comm, "total": len(events), "events": hot_to_result(events)})

@app.get("/top/by-host")
def top_by_host():
    """Return top processes grouped by host using per-host ring buffers."""
    from collections import defaultdict
    result = {}
    with HOST_LOCK:
        host_snapshots = {h: list(buf) for h, buf in HOST_BUFFERS.items()}
    for host, events in host_snapshots.items():
        if not events:
            continue
        groups = defaultdict(list)
        for e in events:
            groups[(e.get("comm",""), e.get("pid",0))].append(e)
        procs = []
        for (comm, pid), evts in sorted(groups.items(), key=lambda x: -len(x[1]))[:25]:
            procs.append({
                "comm": comm, "pid": pid, "total": len(evts),
                "alerts": sum(1 for e in evts if e.get("alert")),
                "max_score": max((e.get("score",0) for e in evts), default=0),
                "last_seen": max((e.get("received_at",0) for e in evts), default=0),
                "host": host,
            })
        result[host] = procs
    return result

@app.get("/events/file-opens")
def events_file_opens(
    path_prefix: str = Query(...),
    comm: str = Query(None),
    since_id: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200)
):
    with HOT_LOCK:
        events = list(HOT_BUFFER)
    events = [e for e in events
              if (e.get("type") == "open" or e.get("event_type") == "open")
              and (e.get("file") or e.get("path") or "").startswith(path_prefix)
              and e.get("id", 0) > since_id]
    if comm: events = [e for e in events if e.get("comm") == comm]
    events.sort(key=lambda x: x.get("id", 0), reverse=True)
    return {"events": hot_to_result(events[:limit]), "total": len(events)}

CHAIN_STATE_FILE = pathlib.Path("/data/chain_state.json")

@app.get("/chains")
def get_chains():
    try:
        if CHAIN_STATE_FILE.exists():
            return json.loads(CHAIN_STATE_FILE.read_text())
        return {"chains": [], "highest_severity": "none"}
    except Exception as e:
        return {"chains": [], "error": str(e)}

# ------------------------------------------------------------------ #
# Heartbeat (C6 Layer 4)                                             #
# ------------------------------------------------------------------ #
_hb_registry, _hb_missed = {}, {}
HB_TIMEOUT_SEC = 180

def _handle_heartbeat(conn, addr):
    try:
        data = b""
        while b"\n" not in data:
            chunk = conn.recv(4096)
            if not chunk: break
            data += chunk
        line = data.split(b"\n")[0].strip()
        if not line: return
        msg = json.loads(line)
        payload = json.loads(msg.get("payload", "{}"))
        pubkey = payload.get("pubkey", "")
        _hb_registry[pubkey] = time.time()
        _hb_missed[pubkey] = 0
        log.info(f"[HB] seq={payload.get('seq',0)} pid={payload.get('pid',0)} from {addr} — OK")
    except Exception as ex:
        log.warning(f"[HB] Bad heartbeat from {addr}: {ex}")
    finally:
        conn.close()

def _heartbeat_watchdog():
    while True:
        time.sleep(60)
        now = time.time()
        for pubkey, last_seen in list(_hb_registry.items()):
            elapsed = now - last_seen
            if elapsed > HB_TIMEOUT_SEC:
                missed = int(elapsed // 60)
                _hb_missed[pubkey] = missed
                log.critical(f"[HB] TAMPER ALERT — agent silent {int(elapsed)}s")
                insert_batch([{"type": "heartbeat_miss", "score": 100, "alert": True,
                               "comm": "ghost-agent", "pid": 0, "ts": int(now * 1e9)}])

def run_heartbeat_server(host, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port)); srv.listen(8)
    log.info(f"Heartbeat listener on {host}:{port}")
    threading.Thread(target=_heartbeat_watchdog, daemon=True).start()
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=_handle_heartbeat, args=(conn, addr), daemon=True).start()

def _retention_cleanup():
    while True:
        time.sleep(3600)
        cutoff = time.time() - 90 * 86400
        for root, dirs, files in os.walk(PARQUET_DIR or ""):
            for f in files:
                if f.endswith(".parquet"):
                    path = os.path.join(root, f)
                    if os.path.getmtime(path) < cutoff:
                        os.remove(path)
                        log.info(f"Retention: deleted {path}")

def main():
    global PARQUET_DIR, LEGACY_DB, EVENT_SEQ
    ap = argparse.ArgumentParser()
    ap.add_argument("--tcp-host",    default="127.0.0.1")
    ap.add_argument("--tcp-port",    default=9000, type=int)
    ap.add_argument("--http-host",   default="127.0.0.1")
    ap.add_argument("--http-port",   default=8000, type=int)
    ap.add_argument("--parquet-dir", default=os.path.expanduser("~/ghostlayer/data/parquet"))
    ap.add_argument("--legacy-db",   default=os.path.expanduser("~/ghostlayer/data/events.db"))
    ap.add_argument("--db-path",     default=None)
    args = ap.parse_args()
    PARQUET_DIR = args.parquet_dir
    LEGACY_DB = args.legacy_db if os.path.exists(args.legacy_db) else None
    os.makedirs(PARQUET_DIR, exist_ok=True)
    if LEGACY_DB:
        try:
            conn = duckdb.connect(LEGACY_DB, read_only=True)
            row = conn.execute("SELECT MAX(id) FROM events").fetchone()
            if row and row[0]:
                EVENT_SEQ = int(row[0]) + 1
                log.info(f"Event ID seeded: {EVENT_SEQ}")
            conn.close()
        except Exception as ex:
            log.warning(f"Legacy DB seed failed: {ex}")
    log.info(f"Parquet dir: {PARQUET_DIR}")
    log.info(f"Legacy DB: {LEGACY_DB or 'none'}")
    threading.Thread(target=_flush_loop, daemon=True).start()
    threading.Thread(target=_retention_cleanup, daemon=True).start()
    threading.Thread(target=run_tcp_server, args=(args.tcp_host, args.tcp_port), daemon=True).start()
    threading.Thread(target=run_heartbeat_server, args=(args.tcp_host, 9001), daemon=True).start()
    log.info(f"Ghost IT Pipeline v2 — HTTP {args.http_host}:{args.http_port}")
    uvicorn.run(app, host=args.http_host, port=args.http_port, log_level="warning")

if __name__ == "__main__":
    main()

