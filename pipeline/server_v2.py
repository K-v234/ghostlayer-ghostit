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
from fastapi import FastAPI, Query, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
import uvicorn, sys
import pyarrow as pa
import pyarrow.parquet as pq



# ------------------------------------------------------------------ #

# Redis Streams publish (Week 2 -- replaces polling for consumers)   #

# Two streams by priority, matching the existing eBPF ring-buffer    #

# pattern: critical events (alerts, deception hits) go to their own  #

# stream so a burst of low-priority telemetry can never starve them. #

# Publish failures are logged and swallowed -- Redis is an           #

# acceleration path, not the durability path (WAL + Parquet already  #

# own that). A consumer that only reads Redis and never falls back   #

# to /events/since would be a regression; this is additive.          #

# ------------------------------------------------------------------ #

import redis as _redis



REDIS_HOST = os.environ.get("GHOST_REDIS_HOST", "redis")

REDIS_PORT = int(os.environ.get("GHOST_REDIS_PORT", "6379"))

STREAM_CRITICAL = "ghost:events:critical"

STREAM_STANDARD = "ghost:events:standard"

STREAM_MAXLEN = 50_000  # approx trim, keeps memory bounded



_redis_client = None



def get_redis():

    global _redis_client

    if _redis_client is None:

        try:

            _redis_client = _redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True, socket_connect_timeout=2)

            _redis_client.ping()

        except Exception as ex:

            log.warning(f"Redis unavailable at startup, will retry lazily: {ex}")

            _redis_client = None

    return _redis_client



def redis_publish(events):

    r = get_redis()

    if r is None:

        return

    try:

        for e in events:

            is_critical = bool(e.get("alert")) or e.get("score", 0) >= 80

            stream = STREAM_CRITICAL if is_critical else STREAM_STANDARD

            r.xadd(stream, {"payload": json.dumps(e, default=str)}, maxlen=STREAM_MAXLEN, approximate=True)

    except Exception as ex:

        log.warning(f"Redis publish failed (event still safe in WAL/Parquet): {ex}")

        global _redis_client

        _redis_client = None  # force reconnect attempt next time


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



# ------------------------------------------------------------------ #

# Write-Ahead Log for the hot buffer (R-04 fix)                       #

# Events are appended here BEFORE being added to _flush_pending, so   #

# a crash between insert and the next Parquet flush (up to           #

# FLUSH_INTERVAL=300s) doesn't silently lose data. Truncated after    #

# each successful flush; replayed into a recovery Parquet file on     #

# startup if anything's left over from an unclean shutdown.           #

# ------------------------------------------------------------------ #

_WAL_LOCK = threading.Lock()

_WAL_PATH = None  # set in main()



def _wal_path() -> str:

    global _WAL_PATH

    if _WAL_PATH is None:

        _WAL_PATH = os.path.join(PARQUET_DIR or "/tmp", "hot_buffer.wal")

    return _WAL_PATH



def wal_append(events):

    if not events:

        return

    try:

        with _WAL_LOCK:

            with open(_wal_path(), "a") as f:

                for e in events:

                    f.write(json.dumps(e, default=str) + "\n")

    except Exception as ex:

        log.error(f"WAL append failed -- events NOT durably persisted: {ex}")




def wal_size() -> int:

    try:

        return os.path.getsize(_wal_path())

    except Exception:

        return 0



def wal_trim_to(offset: int):

    """Removes only the first `offset` bytes of the WAL -- anything

    appended after that offset (i.e. after the flush snapshot was

    taken) is preserved, since those events aren't in Parquet yet."""

    try:

        with _WAL_LOCK:

            path = _wal_path()

            if not os.path.exists(path):

                return

            with open(path, "rb") as f:

                f.seek(offset)

                remainder = f.read()

            if remainder:

                tmp = path + ".trim"

                with open(tmp, "wb") as f:

                    f.write(remainder)

                os.replace(tmp, path)

            else:

                os.remove(path)

    except Exception as ex:

        log.warning(f"WAL trim failed: {ex}")



def wal_recover():

    """Called once at startup. Replays any leftover WAL entries from an

    unclean shutdown directly into a dedicated recovery Parquet file,

    so nothing is lost even if the process died before the normal

    flush cycle ran."""

    path = _wal_path()

    if not os.path.exists(path):

        return 0

    events = []

    try:

        with open(path) as f:

            for line in f:

                line = line.strip()

                if not line:

                    continue

                try:

                    events.append(json.loads(line))

                except Exception:

                    continue

    except Exception as ex:

        log.error(f"WAL read failed during recovery: {ex}")

        return 0

    if events:

        try:

            flush_to_parquet(events)

            log.warning(f"WAL recovery: replayed {len(events)} events lost from previous session into Parquet")

        except Exception as ex:

            log.error(f"WAL recovery flush failed: {ex}")

            return 0

    wal_trim_to(wal_size())

    return len(events)



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

                wal_trim_offset = wal_size()

            if batch:

                try:

                    flush_to_parquet(batch)

                    log.info(f"Parquet flush: {len(batch)} events")

                    wal_trim_to(wal_trim_offset)

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
    try:
        import sys as _sys_pr
        _sys_pr.path.insert(0, "/app/causal-engine")
        try:
            from path_router import classify_event
        except ImportError:
            _sys_pr.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
            from path_router import classify_event
        for e in enriched:
            e["_tier"] = classify_event(
                e.get("type") or e.get("event_type") or "",
                e.get("comm", "") if str(e.get("comm", "")).startswith(("C1", "C2", "C3", "R0")) else "",
                e.get("score", 0)
            )
    except Exception as _ex_pr:
        log.debug(f"Path router classification error: {_ex_pr}")
    with HOT_LOCK:
        HOT_BUFFER.extend(enriched)
    # Per-host buffers — separate ring per sensor (CrowdStrike pattern)
    with HOST_LOCK:
        for e in enriched:
            host = e.get("host", "linux")
            buf = HOST_BUFFERS.get(host, HOST_BUFFERS["linux"])
            buf.append(e)
    with _flush_lock:
        wal_append(enriched)
        _flush_pending.extend(enriched)
    redis_publish(enriched)
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
            "_tier": e.get("_tier"),
            "machine_id": e.get("machine_id"),
            "customer_id": e.get("customer_id"),
        })
    return result

def df_to_json(df):
    return json.loads(df.to_json(orient="records", default_handler=str))

# ------------------------------------------------------------------ #
# TCP Ingestion                                                       #
# ------------------------------------------------------------------ #
API_KEYS_PATH = os.environ.get("GHOST_API_KEYS_PATH",
    "/home/ubuntu/ghostlayer/agent-releases/api_keys.json")

def load_api_keys():
    try:
        with open(API_KEYS_PATH) as f:
            return json.load(f)
    except Exception:
        return {}

def handle_client(conn, addr):
    BATCH_SIZE = 1000
    FLUSH_MS   = 0.100
    buf, pending = b"", []
    stats = {"batches": 0, "events": 0, "errors": 0}
    last_flush = time.monotonic()
    conn.settimeout(5.0)
    auth_buf = b""
    authenticated_customer_id = None
    api_keys = load_api_keys()
    try:
        while b"\n" not in auth_buf:
            chunk = conn.recv(4096)
            if not chunk:
                conn.close()
                return
            auth_buf += chunk
        auth_line, buf = auth_buf.split(b"\n", 1)
        submitted_key = auth_line.decode("utf-8", errors="replace").strip()
        authenticated_customer_id = api_keys.get(submitted_key)
        if not authenticated_customer_id:
            log.warning(f"[{addr}] REJECTED -- invalid or missing API key")
            conn.close()
            return
        log.info(f"[{addr}] Authenticated as customer_id={authenticated_customer_id}")
    except (TimeoutError, ConnectionResetError, BrokenPipeError, OSError):
        conn.close()
        return
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
                        ev["customer_id"] = authenticated_customer_id
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



INTERNAL_SECRET = os.environ.get("GHOST_INTERNAL_SECRET")

if not INTERNAL_SECRET:

    raise RuntimeError("GHOST_INTERNAL_SECRET not set -- refusing to start without internal auth")



PUBLIC_PATHS = {"/health", "/metrics"}



@app.middleware("http")

async def require_internal_auth(request, call_next):

    if request.url.path not in PUBLIC_PATHS:

        if request.headers.get("X-Internal-Auth") != INTERNAL_SECRET:

            return JSONResponse(status_code=401, content={"error": "unauthorized"})

    return await call_next(request)


@app.get("/metrics")
def metrics_endpoint():
    """
    Real, genuine Prometheus-format metrics endpoint. Exposes the
    same real, already-computed stats as /stats, in the standard
    Prometheus text exposition format so a real Prometheus server can
    scrape this directly with zero custom parsing.
    """
    with HOT_LOCK:
        hot = list(HOT_BUFFER)
    try:
        conn = get_duckdb()
        row = conn.execute("SELECT COUNT(*) FROM events_all").fetchone()
        total = row[0] + len(hot)
        conn.close()
    except Exception:
        total = len(hot)

    alert_count = sum(1 for e in hot if e.get("alert"))
    unique_pids = len(set(e.get("pid") for e in hot))
    unique_procs = len(set(e.get("comm") for e in hot))

    lines = [
        "# HELP ghostit_events_total Real, genuine total events ever received",
        "# TYPE ghostit_events_total counter",
        f"ghostit_events_total {total}",
        "",
        "# HELP ghostit_hot_buffer_size Real, current in-memory hot buffer size",
        "# TYPE ghostit_hot_buffer_size gauge",
        f"ghostit_hot_buffer_size {len(hot)}",
        "",
        "# HELP ghostit_alerts_current Real alerts currently in the hot buffer",
        "# TYPE ghostit_alerts_current gauge",
        f"ghostit_alerts_current {alert_count}",
        "",
        "# HELP ghostit_unique_pids_current Real unique PIDs in the hot buffer",
        "# TYPE ghostit_unique_pids_current gauge",
        f"ghostit_unique_pids_current {unique_pids}",
        "",
        "# HELP ghostit_unique_processes_current Real unique process names in the hot buffer",
        "# TYPE ghostit_unique_processes_current gauge",
        f"ghostit_unique_processes_current {unique_procs}",
        "",
    ]
    return Response(content="\n".join(lines), media_type="text/plain")

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
    customer_id: Optional[str] = Query(None),
):
    with HOT_LOCK:
        events = list(HOT_BUFFER)
    events = [e for e in events if e.get("score", 0) >= min_score]
    if type:    events = [e for e in events if (e.get("type") or e.get("event_type")) == type]
    if comm:    events = [e for e in events if e.get("comm") == comm]
    if alert is not None: events = [e for e in events if bool(e.get("alert")) == alert]
    if customer_id: events = [e for e in events if e.get("customer_id") == customer_id]
    events.sort(key=lambda x: x.get("id", 0), reverse=True)
    total = len(events)
    events = events[offset:offset+limit]
    return JSONResponse({"total": total, "limit": limit, "offset": offset,
                         "events": hot_to_result(events)})

@app.post("/threat-mesh/broadcast")
def threat_mesh_broadcast(origin_deployment: str, fingerprint: str, tactic: str,
                            technique: str, comm_pattern: str, resource_pattern: str,
                            confidence: float):
    """
    Threat Mesh: broadcast a confirmed threat pattern to every
    connected deployment (currently: every customer/machine reporting
    to this shared pipeline -- the real, honest scope right now,
    architected to scale as more independent firms/customers connect).
    Called automatically when Autonomous Response makes a real
    tier-2+ decision anywhere in the fleet.
    """
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from threat_mesh import ThreatMesh
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from threat_mesh import ThreatMesh
    mesh = ThreatMesh()
    result = mesh.broadcast_immunity(origin_deployment, fingerprint, tactic,
                                       technique, comm_pattern, resource_pattern, confidence)
    return JSONResponse(result)
@app.get("/threat-mesh/check")
def threat_mesh_check(comm: str, resource: str):
    """Check if an event matches any active mesh-confirmed threat
    pattern -- lets ANY connected deployment benefit instantly from
    what ANY OTHER connected deployment already confirmed, before its
    own local pillars would independently figure it out."""
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from threat_mesh import ThreatMesh
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from threat_mesh import ThreatMesh
    mesh = ThreatMesh()
    return JSONResponse(mesh.check_immunity(comm, resource))
@app.post("/behavioral-dna/observe")
def dna_observe(comm: str, parent_comm: str, event_type: str, path: str = ""):
    """Record a real behavioral observation, building this comm's
    trusted profile from genuine local activity."""
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from behavioral_dna import BehavioralDNA
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from behavioral_dna import BehavioralDNA
    BehavioralDNA().observe(comm, parent_comm, event_type, path)
    return JSONResponse({"status": "observed"})
@app.get("/insurance-report")
def insurance_report():
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from insurance_report import generate_readiness_report
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from insurance_report import generate_readiness_report
    with HOT_LOCK:
        events = list(HOT_BUFFER)
    alerts = [e for e in events if e.get("alert")]
    incidents = [{"severity": "critical" if a.get("score",0)>=90 else "high", "closed": True, "response_time_sec": 60} for a in alerts[:50]]
    return JSONResponse(generate_readiness_report({}, incidents, 99.5))
@app.get("/guided-action/{rule_id}")
def guided_action(rule_id: str, score: float = Query(0)):
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from guided_response import get_guided_action
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from guided_response import get_guided_action
    return JSONResponse(get_guided_action(rule_id, score))
@app.get("/identity-risk")
def identity_risk(username: str, login_hour: int, is_new_device: bool = Query(False), mfa_used: bool = Query(True)):
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from identity_correlation import score_login_anomaly
        from cortex import Cortex, CortexContribution
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from identity_correlation import score_login_anomaly
        from cortex import Cortex, CortexContribution
    result = score_login_anomaly(username, login_hour, is_new_device, mfa_used)
    if result["identity_risk_score"] > 0:
        try:
            Cortex().contribute(CortexContribution(
                f"user:{username}", "identity_risk", "; ".join(result["reasons"])))
        except Exception as _ex:
            log.debug(f"Identity Cortex feed error: {_ex}")
    return JSONResponse(result)
@app.post("/rollback")
def rollback(affected_paths: str):
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from ransomware_rollback import rollback_from_ransomware
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from ransomware_rollback import rollback_from_ransomware
    paths = affected_paths.split(",")
    return JSONResponse(rollback_from_ransomware(paths))
@app.get("/behavioral-dna/check")
def dna_check(comm: str, parent_comm: str, event_type: str = "", path: str = ""):
    """Check if this process instance's behavior (esp. parent lineage)
    is consistent with comm's established trusted profile -- detects
    masquerading regardless of how convincing the filename is."""
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from behavioral_dna import BehavioralDNA
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from behavioral_dna import BehavioralDNA
    return JSONResponse(BehavioralDNA().check_masquerade(comm, parent_comm, event_type, path))
@app.post("/active-deception/inject")
def deception_inject(entity_id: str, context_hint: str, cortex_score: float):
    """Generate fresh, contextually-relevant fake data for a
    suspicious entity -- actively wastes attacker reconnaissance
    effort rather than just passively detecting."""
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from active_deception import ActiveDeception
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from active_deception import ActiveDeception
    return JSONResponse(ActiveDeception().generate_injection(entity_id, context_hint, cortex_score))
@app.get("/explain/{pid}")
def explain_entity(pid: int):
    """
    The Explainability Engine: pulls real evidence from every pillar
    for this entity and synthesizes it into one coherent, human-
    readable incident narrative -- the actual answer to 'why is this
    process suspicious,' explained the way a human analyst would.
    """
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    for mod_name in ["cortex", "temporal_memory", "threat_mesh",
                       "behavioral_dna", "autonomous_response", "explainability_engine"]:
        pass
    try:
        from cortex import Cortex
        from temporal_memory import TemporalMemory
        from autonomous_response import AutonomousResponseEngine
        from explainability_engine import build_narrative
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from cortex import Cortex
        from temporal_memory import TemporalMemory
        from autonomous_response import AutonomousResponseEngine
        from explainability_engine import build_narrative
    entity_id = f"pid:{pid}"
    cortex_data = Cortex().get_score(entity_id)
    # Pull real recent decision history for this specific entity, if
    # Autonomous Response has ever made one -- gives the narrative
    # real "what action was taken" evidence, not just detection scores.
    response_history = AutonomousResponseEngine().get_decision_history(entity_id, limit=1)
    response_decision = None
    if response_history:
        d = response_history[0]
        response_decision = {
            "decision": "action_taken" if d["executed"] else "action_simulated",
            "tier": d["tier"], "action": d["action_name"],
            "description": d["reasoning"],
        }
    narrative = build_narrative(entity_id, cortex_data=cortex_data,
                                  response_decision=response_decision)
    return JSONResponse(narrative)
@app.get("/threat-mesh/signals")
def threat_mesh_signals(limit: int = Query(50, ge=1, le=200)):
    """All currently active mesh immunity signals -- the real,
    live 'collective knowledge' every connected deployment shares."""
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from threat_mesh import ThreatMesh
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from threat_mesh import ThreatMesh
    mesh = ThreatMesh()
    return JSONResponse({"active_signals": mesh.get_active_signals(limit)})
@app.get("/autonomous-response/history")
def autonomous_response_history(entity_id: str = Query(None), limit: int = Query(50, ge=1, le=200)):
    """Decision history from the Autonomous Response Engine -- every
    decision made (simulated or real) with full evidence: score,
    contributing pillars, reasoning, tier, and whether it was actually
    executed or just simulated."""
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from autonomous_response import AutonomousResponseEngine
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from autonomous_response import AutonomousResponseEngine
    engine = AutonomousResponseEngine()
    return JSONResponse({"decisions": engine.get_decision_history(entity_id, limit)})
@app.get("/predict/{tactic}")
def predict_next(tactic: str):
    """
    Predictive Next-Step Inference: given a MITRE ATT&CK tactic just
    observed in a confirmed detection, predicts the statistically
    likely next tactic(s) per real, documented kill-chain progression,
    with concrete watch-guidance -- turns detection from purely
    reactive into genuinely anticipatory.
    """
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from predictive_inference import predict_next_tactics
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from predictive_inference import predict_next_tactics
    return JSONResponse(predict_next_tactics(tactic))
@app.post("/adaptive-thresholds/observe")
def adaptive_threshold_observe(pillar: str, score: float):
    """HTTP-based score observation for Adaptive Threshold Calibration
    -- same single-writer-via-pipeline pattern as Cortex/temporal
    memory."""
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from adaptive_thresholds import AdaptiveThresholds
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from adaptive_thresholds import AdaptiveThresholds
    AdaptiveThresholds().observe(pillar, score)
    return JSONResponse({"status": "observed", "pillar": pillar})
@app.get("/adaptive-thresholds/{pillar}")
def adaptive_threshold_get(pillar: str):
    """Current, locally-calibrated threshold for a pillar, based on
    this deployment's own observed activity distribution."""
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from adaptive_thresholds import AdaptiveThresholds
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from adaptive_thresholds import AdaptiveThresholds
    return JSONResponse(AdaptiveThresholds().get_threshold(pillar))
@app.post("/temporal-memory/sighting")
def temporal_memory_sighting(host: str, comm: str, resource: str, pillar: str, reason: str):
    """HTTP-based sighting recorder for Temporal Attack-Graph Memory --
    same single-writer-via-pipeline pattern as /cortex/contribute."""
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from temporal_memory import TemporalMemory
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from temporal_memory import TemporalMemory
    tm = TemporalMemory()
    result = tm.record_sighting(host, comm, resource, pillar, reason)
    return JSONResponse(result)
@app.get("/temporal-memory/recurring")
def temporal_memory_recurring(min_count: int = Query(2, ge=1), limit: int = Query(20, ge=1, le=100)):
    """Recurring attack patterns across time -- fingerprints seen
    multiple times, possibly days apart, indicating a returning
    actor rather than isolated unrelated events."""
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from temporal_memory import TemporalMemory
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from temporal_memory import TemporalMemory
    tm = TemporalMemory()
    return JSONResponse({"recurring_patterns": tm.get_recurring(min_count, limit)})
@app.post("/cortex/contribute")
def cortex_contribute(pid: int, pillar: str, reason: str):
    """
    HTTP-based Cortex contribution endpoint. Fixes a real concurrency
    bug: DuckDB only allows one process to hold a write lock on a
    database file at a time, but pipeline/detection/canary are three
    SEPARATE Docker containers -- each independently opening
    causal-engine/cortex.py's DuckDB file directly caused
    'Conflicting lock is held' errors. The fix: only the pipeline
    process (which already owns this DuckDB connection and has a
    public HTTP API) touches the Cortex DB directly; every other
    service now contributes via this HTTP endpoint instead of
    importing cortex.py and opening the file itself.
    """
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from cortex import Cortex, CortexContribution
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from cortex import Cortex, CortexContribution
    cortex = Cortex()
    result = cortex.contribute(CortexContribution(f"pid:{pid}", pillar, reason))
    # Curiosity Engine: check on EVERY contribution whether this
    # entity has entered the genuine ambiguous middle.
    try:
        from curiosity_engine import should_investigate, build_investigation_plan
    except ImportError:
        import sys as _sys_cur
        _sys_cur.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from curiosity_engine import should_investigate, build_investigation_plan
    try:
        if should_investigate(result["score"], result["distinct_pillars"]):
            plan = build_investigation_plan(f"pid:{pid}", pillar, result["score"])
            log.info(f"[Curiosity] Investigation triggered for pid:{pid}: {plan['reasoning']}")
    except Exception as _ex_cur:
        log.debug(f"Curiosity engine error: {_ex_cur}")
    # World-Model: every real contribution is real evidence this
    # entity exists and is active.
    try:
        from world_model import WorldModel
    except ImportError:
        import sys as _sys_wm
        _sys_wm.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from world_model import WorldModel
    try:
        WorldModel().observe(f"pid:{pid}", "unknown", pillar, event_type="cortex_contribution")
    except Exception as _ex_wm:
        log.debug(f"World-model observe error: {_ex_wm}")
    # Autonomous Response Engine: every Cortex contribution is a real
    # opportunity for the fused score to have crossed the action
    # threshold -- check on every contribution, not on a separate
    # poll cycle, so decisions happen in real time as suspicion
    # genuinely accumulates. SIMULATION MODE by default (see
    # causal-engine/autonomous_response.py's safety design) --
    # decisions are computed and logged, no real action taken unless
    # GHOSTIT_AUTONOMOUS_ACTIONS_ENABLED is explicitly set.
    try:
        from autonomous_response import AutonomousResponseEngine
        engine = AutonomousResponseEngine()
        decision = engine.decide(
            f"pid:{pid}", result["score"], result["pillars"],
            f"triggered by new contribution from {pillar}: {reason}"
        )
        # Safety Governor: automatically consulted the instant a real
        # decision is proposed, BEFORE any real action or Threat Mesh
        # broadcast -- checks World-Model blast radius/criticality and
        # may downgrade the proposed tier for genuine business reasons.
        if decision.get("tier"):
            try:
                from world_model import WorldModel
                from safety_governor import govern
            except ImportError:
                import sys as _sys_gov
                _sys_gov.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
                from world_model import WorldModel
                from safety_governor import govern
            try:
                assessment = WorldModel().what_breaks_if_isolated(f"pid:{pid}")
                verdict = govern(decision["tier"], decision.get("action", ""), assessment)
                if verdict["verdict"] != "approved":
                    log.warning(f"[Governor] Decision for pid:{pid} {verdict['verdict']}: {verdict['reasons']}")
                    decision["governor_verdict"] = verdict
            except Exception as _ex_gov:
                log.debug(f"Safety governor error: {_ex_gov}")
        # Contradiction Engine: check if this entity's pillar mix shows
        # majority-safe contradicted by a structurally reliable pillar.
        if result["distinct_pillars"] >= 2:
            try:
                from contradiction_engine import detect_contradiction
            except ImportError:
                import sys as _sys_con
                _sys_con.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
                from contradiction_engine import detect_contradiction
            try:
                beliefs = {c["pillar"]: max(0, 100 - c["current_weight"]) for c in result.get("contributions", [])}
                contradiction = detect_contradiction(beliefs)
                if contradiction.get("contradiction_detected") and contradiction.get("severity") == "critical":
                    log.warning(f"[Contradiction] CRITICAL contradiction for pid:{pid}: {contradiction['conclusion']}")
            except Exception as _ex_con:
                log.debug(f"Contradiction engine error: {_ex_con}")
        # Threat Mesh: a real tier-2+ decision is confirmed-enough
        # evidence to broadcast to every other connected deployment --
        # this is the actual moment collective immunity kicks in.
        if decision.get("tier", 0) >= 2:
            try:
                from threat_mesh import ThreatMesh
            except ImportError:
                import sys as _sys2
                _sys2.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
                from threat_mesh import ThreatMesh
            import hashlib as _hashlib
            fp = _hashlib.sha256(f"{pillar}:{reason}".lower().encode()).hexdigest()[:16]
            ThreatMesh().broadcast_immunity(
                origin_deployment=os.environ.get("GHOSTIT_DEPLOYMENT_ID", "unknown-deployment"),
                fingerprint=fp, tactic="", technique="",
                comm_pattern=pillar, resource_pattern=reason[:100],
                confidence=result["score"],
            )
    except Exception as _ex:
        log.debug(f"Autonomous response decision error: {_ex}")
    # Active Deception: below the autonomous-action threshold but
    # above the (deliberately lower) injection threshold, generate
    # fresh fake data targeted at this suspicious entity -- lower
    # risk than suspending/isolating, so it engages earlier.
    try:
        from active_deception import ActiveDeception
    except ImportError:
        import sys as _sys3
        _sys3.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from active_deception import ActiveDeception
    try:
        ActiveDeception().generate_injection(f"pid:{pid}", reason, result["score"])
    except Exception as _ex2:
        log.debug(f"Active deception injection error: {_ex2}")
    return JSONResponse(result)
@app.post("/worldmodel/observe")
def worldmodel_observe(entity_id: str, host: str, comm: str, parent_id: str = Query(None), event_type: str = Query("")):
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from world_model import WorldModel
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from world_model import WorldModel
    WorldModel().observe(entity_id, host, comm, parent_id, event_type)
    return {"status": "observed"}
@app.get("/worldmodel/blast-radius/{entity_id}")
def worldmodel_blast_radius(entity_id: str):
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from world_model import WorldModel
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from world_model import WorldModel
    return JSONResponse(WorldModel().what_breaks_if_isolated(entity_id))
@app.post("/governor/evaluate")
def governor_evaluate(proposed_tier: int, proposed_action: str, entity_id: str, false_positive_history_count: int = Query(0)):
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from world_model import WorldModel
        from safety_governor import govern
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from world_model import WorldModel
        from safety_governor import govern
    assessment = WorldModel().what_breaks_if_isolated(entity_id)
    verdict = govern(proposed_tier, proposed_action, assessment, false_positive_history_count)
    return JSONResponse({**verdict, "world_model_assessment": assessment})
@app.post("/replay/record")
def replay_record(incident_id: str, entity_id: str, event_type: str, description: str, pillar: str = Query("")):
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from attack_replay import AttackReplay
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from attack_replay import AttackReplay
    ar = AttackReplay()
    result = ar.record(incident_id, entity_id, event_type, description, pillar)
    try:
        from intent_engine import infer_intent
    except ImportError:
        import sys as _sys_int
        _sys_int.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from intent_engine import infer_intent
    try:
        timeline = ar.get_timeline(incident_id)
        observed_stages = {e["event_type"] for e in timeline}
        intent_result = infer_intent(observed_stages)
        if intent_result.get("intent_inferred"):
            log.warning(f"[Intent] {incident_id}: inferred intent {intent_result['top_intent']['intent']} ({intent_result['top_intent']['confidence']}% confidence)")
            result["inferred_intent"] = intent_result["top_intent"]
    except Exception as _ex_int:
        log.debug(f"Intent engine error: {_ex_int}")
    return JSONResponse(result)
@app.get("/replay/{incident_id}")
def replay_get(incident_id: str):
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from attack_replay import AttackReplay
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from attack_replay import AttackReplay
    ar = AttackReplay()
    return JSONResponse({"timeline": ar.get_timeline(incident_id), "integrity": ar.verify_integrity(incident_id)})
@app.get("/replay/{incident_id}/what-if/{sequence_num}")
def replay_what_if(incident_id: str, sequence_num: int):
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from attack_replay import AttackReplay
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from attack_replay import AttackReplay
    return JSONResponse(AttackReplay().what_if_acted_earlier(incident_id, sequence_num))
@app.post("/contradiction/check")
def contradiction_check(pillar_beliefs: str):
    import sys as _sys, json as _json
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from contradiction_engine import detect_contradiction
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from contradiction_engine import detect_contradiction
    beliefs = _json.loads(pillar_beliefs)
    return JSONResponse(detect_contradiction(beliefs))
@app.post("/intent/infer")
def intent_infer(observed_stages: str):
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from intent_engine import infer_intent
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from intent_engine import infer_intent
    stages = set(s.strip() for s in observed_stages.split(","))
    return JSONResponse(infer_intent(stages))
@app.get("/curiosity/evaluate")
def curiosity_evaluate(entity_id: str, comm: str, cortex_score: float, distinct_pillars: int = Query(1)):
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from curiosity_engine import should_investigate, build_investigation_plan
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from curiosity_engine import should_investigate, build_investigation_plan
    if should_investigate(cortex_score, distinct_pillars):
        return JSONResponse(build_investigation_plan(entity_id, comm, cortex_score))
    return {"investigation_triggered": False}
@app.post("/simulation/check-trajectory")
def simulation_check(predicted: str, observed: str):
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from simulation_engine import check_trajectory_match
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from simulation_engine import check_trajectory_match
    pred_list = [s.strip() for s in predicted.split(",")]
    obs_list = [s.strip() for s in observed.split(",")]
    return JSONResponse(check_trajectory_match(pred_list, obs_list))
@app.post("/evolution/record-outcome")
def evolution_record(pillar: str, outcome: str):
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from self_evolving_architecture import SelfEvolvingArchitecture
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from self_evolving_architecture import SelfEvolvingArchitecture
    SelfEvolvingArchitecture().record_outcome(pillar, outcome)
    return {"status": "recorded"}
@app.post("/evolution/generate-recommendation")
def evolution_recommend(pillar: str, current_weight: float):
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from self_evolving_architecture import SelfEvolvingArchitecture
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from self_evolving_architecture import SelfEvolvingArchitecture
    return JSONResponse(SelfEvolvingArchitecture().generate_recommendation(pillar, current_weight))
@app.post("/evolution/approve/{recommendation_id}")
def evolution_approve(recommendation_id: str, reviewed_by: str):
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from self_evolving_architecture import SelfEvolvingArchitecture
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from self_evolving_architecture import SelfEvolvingArchitecture
    return JSONResponse(SelfEvolvingArchitecture().approve_recommendation(recommendation_id, reviewed_by))
@app.get("/path-router/classify")
def path_router_classify(event_type: str = Query(""), rule_id: str = Query(""), score: float = Query(0)):
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from path_router import classify_event
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from path_router import classify_event
    return {"tier": classify_event(event_type, rule_id, score)}
@app.get("/cortex/{pid}")
def get_cortex_score(pid: int):
    """
    Query the Cortex's current, live-decayed fused suspicion score for
    a specific PID, showing exactly which pillars contributed and why
    -- this is the real, working answer to 'is this process suspicious
    when you consider everything every pillar has seen about it, not
    just whether any single pillar's threshold fired.'
    """
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from cortex import Cortex
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from cortex import Cortex
    cortex = Cortex()
    return JSONResponse(cortex.get_score(f"pid:{pid}"))
@app.get("/cortex")
def get_cortex_top(limit: int = Query(20, ge=1, le=100)):
    """Top currently-most-suspicious entities per the Cortex's live
    fused scoring -- a real-time 'watch this' priority queue."""
    import sys as _sys
    _sys.path.insert(0, "/app/causal-engine")
    try:
        from cortex import Cortex
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/causal-engine"))
        from cortex import Cortex
    cortex = Cortex()
    return JSONResponse({"top_entities": cortex.top_entities(limit)})
@app.get("/threat-intel/stix")
def export_stix_bundle(limit: int = Query(100, ge=1, le=1000)):
    """
    V3: Export current confirmed alerts as a STIX 2.1 Bundle -- the
    OASIS-standard format for threat intelligence sharing used by
    CISA, India-CERT, and TAXII-based sharing communities. Technical
    prep for eventual India-CERT partnership integration: the data
    format is ready now, independent of when the actual government
    relationship exists.
    """
    import sys as _sys
    _sys.path.insert(0, "/app/integrations/threat_intel")
    try:
        from stix_formatter import to_stix_bundle
    except ImportError:
        _sys.path.insert(0, os.path.expanduser("~/ghostlayer/integrations/threat_intel"))
        from stix_formatter import to_stix_bundle
    with HOT_LOCK:
        events = list(HOT_BUFFER)
    alerts = [e for e in events if e.get("alert")]
    alerts.sort(key=lambda x: x.get("id", 0), reverse=True)
    alerts = alerts[:limit]
    bundle = to_stix_bundle(hot_to_result(alerts))
    return JSONResponse(bundle)
@app.get("/hunt")
def threat_hunt(
    file_pattern:  Optional[str] = Query(None, description="Substring match on file/path field"),
    comm_pattern:  Optional[str] = Query(None, description="Substring match on process name"),
    event_type:    Optional[str] = Query(None),
    host:          Optional[str] = Query(None, description="windows | linux"),
    min_score:     int           = Query(0, ge=0, le=100),
    since_id:      int           = Query(0, ge=0, description="Only events after this ID"),
    since_minutes: Optional[int] = Query(None, ge=1, description="Only events from the last N minutes (real time range, not just ID)"),
    watchlist_only: bool          = Query(False, description="Only PIDs currently on C4's watchlist -- cross-reference confirmed-malicious entities"),
    limit:         int           = Query(200, ge=1, le=2000),
):
    """
    V3 Threat Hunting: flexible, multi-criteria historical search.
    Unlike /events (single-field exact matches, recent buffer only),
    this supports substring pattern matching across file paths and
    process names, combined with type/host/score filters -- the
    actual query shape a real investigation needs ("show me anything
    touching /etc/shadow", "find all mshta activity", "what did this
    host do in the last hour"). Searches across both HOT_BUFFER and
    per-host buffers (same merge pattern as /events/since) to avoid
    missing events evicted from the shared hot buffer under high
    Linux eBPF volume.
    """
    with HOT_LOCK:
        base = list(HOT_BUFFER)
    with HOST_LOCK:
        for buf in HOST_BUFFERS.values():
            base.extend(buf)
    seen_ids = set()
    results = []
    cutoff_sec = None
    if since_minutes:
        cutoff_sec = (time.time() - since_minutes * 60)
    watchlisted_pids = set()
    if watchlist_only:
        with WATCHLIST_LOCK:
            now = time.time()
            watchlisted_pids = {pid for pid, exp in WATCHLIST.items() if exp > now}
    for e in base:
        eid = e.get("id", 0)
        if eid in seen_ids or eid <= since_id:
            continue
        seen_ids.add(eid)
        if e.get("score", 0) < min_score:
            continue
        if host and e.get("host") != host:
            continue
        if event_type and (e.get("type") or e.get("event_type")) != event_type:
            continue
        if file_pattern and file_pattern.lower() not in str(e.get("file", "")).lower():
            continue
        if comm_pattern and comm_pattern.lower() not in str(e.get("comm", "")).lower():
            continue
        if cutoff_sec is not None and e.get("received_at", 0) < cutoff_sec:
            continue
        if watchlist_only and e.get("pid") not in watchlisted_pids:
            continue
        results.append(e)
    results.sort(key=lambda x: x.get("id", 0), reverse=True)
    total = len(results)
    results = results[:limit]
    return JSONResponse({
        "total": total, "limit": limit,
        "query": {
            "file_pattern": file_pattern, "comm_pattern": comm_pattern,
            "event_type": event_type, "host": host, "min_score": min_score,
        },
        "events": hot_to_result(results),
    })
@app.get("/events/history")

def events_history(

    file_pattern:  Optional[str] = Query(None),

    comm_pattern:  Optional[str] = Query(None),

    event_type:    Optional[str] = Query(None),

    customer_id:   Optional[str] = Query(None),

    min_score:     int           = Query(0, ge=0, le=100),

    days_back:     int           = Query(7, ge=1, le=90),

    limit:         int           = Query(200, ge=1, le=5000),

):

    conn = get_duckdb()

    try:

        has_parquet = any(True for _ in pathlib.Path(PARQUET_DIR).rglob("*.parquet"))

        if not has_parquet:

            return {"total": 0, "events": [], "note": "no historical parquet data yet"}


        cutoff_sec = int(time.time() - days_back * 86400)

        conditions = ["received_at >= ?"]

        params = [cutoff_sec]

        if min_score:

            conditions.append("score >= ?")

            params.append(min_score)

        if event_type:

            conditions.append("(type = ? OR event_type = ?)")

            params.append(event_type); params.append(event_type)

        if customer_id:

            conditions.append("customer_id = ?")

            params.append(customer_id)

        if comm_pattern:

            conditions.append("comm ILIKE ?")

            params.append(f"%{comm_pattern}%")

        if file_pattern:

            conditions.append("file ILIKE ?")

            params.append(f"%{file_pattern}%")

        where_clause = " AND ".join(conditions)

        query = f"""

            SELECT * FROM parquet_events

            WHERE {where_clause}

            ORDER BY ts DESC

            LIMIT ?

        """

        params.append(limit)

        df = conn.execute(query, params).fetchdf()


        events = df_to_json(df)

        return {"total": len(events), "days_searched": days_back, "events": events}

    except Exception as ex:

        log.error(f"events_history query failed: {ex}")

        return {"total": 0, "events": [], "error": str(ex)}

    finally:

        conn.close()

@app.get("/hunt/anomalies")
def hunt_anomalies(
    host:  Optional[str] = Query(None),
    limit: int           = Query(20, ge=1, le=100),
):
    """
    V3 Statistical anomaly hunting: find processes with unusually high
    event volume, WITHOUT needing a known-bad pattern to search for --
    the genuine hunting technique (vs. pattern matching) of finding
    outliers first, then investigating why. A process generating
    10x the typical event rate is worth a look regardless of whether
    it matches any existing detection rule -- this is how real
    threat hunters find genuinely novel activity that signature/rule
    -based detection would miss entirely.
    """
    with HOT_LOCK:
        base = list(HOT_BUFFER)
    with HOST_LOCK:
        for buf in HOST_BUFFERS.values():
            base.extend(buf)
    seen_ids = set()
    by_pid = {}
    for e in base:
        eid = e.get("id", 0)
        if eid in seen_ids:
            continue
        seen_ids.add(eid)
        if host and e.get("host") != host:
            continue
        pid = e.get("pid", 0)
        if not pid:
            continue
        key = (pid, e.get("comm", "unknown"))
        by_pid.setdefault(key, {"count": 0, "types": set(), "max_score": 0, "host": e.get("host")})
        by_pid[key]["count"] += 1
        by_pid[key]["types"].add(e.get("type") or e.get("event_type"))
        by_pid[key]["max_score"] = max(by_pid[key]["max_score"], e.get("score", 0))
    if not by_pid:
        return JSONResponse({"total": 0, "anomalies": []})
    counts = [v["count"] for v in by_pid.values()]
    mean = sum(counts) / len(counts)
    variance = sum((c - mean) ** 2 for c in counts) / len(counts)
    stddev = variance ** 0.5 or 1.0
    anomalies = []
    for (pid, comm), stats in by_pid.items():
        z_score = (stats["count"] - mean) / stddev
        if z_score >= 2.0:  # 2+ standard deviations above the mean = statistical outlier
            anomalies.append({
                "pid": pid, "comm": comm, "event_count": stats["count"],
                "z_score": round(z_score, 2), "distinct_event_types": len(stats["types"]),
                "max_score_seen": stats["max_score"], "host": stats["host"],
            })
    anomalies.sort(key=lambda a: a["z_score"], reverse=True)
    return JSONResponse({
        "total": len(anomalies), "baseline_mean_events_per_pid": round(mean, 1),
        "baseline_stddev": round(stddev, 1), "anomalies": anomalies[:limit],
    })
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
    # Priority tiers: within each host's slice, rare high-signal event
    # types (renames, deletes, process spawns -- the actual attack
    # signals) get guaranteed bandwidth ahead of routine, high-volume
    # noise (writes, opens -- background sync, DLL loads, etc.). Matches
    # the industry-standard priority-queue telemetry pattern (rare,
    # high-value events reserved a lane so they are never starved out by
    # volume, regardless of how much routine traffic competes for the
    # same budget). Confirmed real-world need: OneDrive sync alone
    # generates ~100 file_write events per fetch window on a single
    # machine, which would otherwise crowd out the handful of
    # file_rename/.locked events a real ransomware attack produces.
    HIGH_SIGNAL_TYPES = {"file_rename", "file_delete", "process_exec", "net_connect"}
    def _split_by_priority(evts):
        high = [e for e in evts if (e.get("type") or "") in HIGH_SIGNAL_TYPES]
        low  = [e for e in evts if (e.get("type") or "") not in HIGH_SIGNAL_TYPES]
        return high, low
    if host is None and len(events) > limit:
        hosts_present = sorted(set(e.get("host", "unknown") for e in events))
        per_host_limit = max(1, limit // len(hosts_present))
        balanced = []
        for h in hosts_present:
            h_events = [e for e in events if e.get("host") == h]
            high, low = _split_by_priority(h_events)
            # High-signal events always included in full (up to the
            # host's whole quota if needed); low-signal fills whatever
            # room remains.
            take_high = high[-per_host_limit:]
            remaining = max(0, per_host_limit - len(take_high))
            take_low  = low[-remaining:] if remaining else []
            balanced.extend(take_high + take_low)
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
                log.critical(f"[HB] TAMPER ALERT — agent silent {int(elapsed)}s")
                insert_batch([{"type": "heartbeat_miss", "score": 100, "alert": True,
                               "comm": "ghost-agent", "pid": 0, "ts": int(now * 1e9)}])
                # Real fix: alert ONCE per dead session, then stop
                # tracking this pubkey -- a real agent restart always
                # generates a fresh ephemeral key by design, so the
                # OLD key genuinely never comes back. Without this,
                # every past session's abandoned key fires this same
                # alert forever, every 60s, permanently -- a real,
                # honest bug, not a real, ongoing tamper signal.
                _hb_registry.pop(pubkey, None)
                _hb_missed.pop(pubkey, None)

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
    recovered = wal_recover()
    if recovered:
        log.warning(f"Startup WAL recovery: {recovered} events recovered from previous session")
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

    if EVENT_SEQ == 0:

        try:

            has_parquet_files = any(True for _ in pathlib.Path(PARQUET_DIR).rglob("*.parquet"))

            if has_parquet_files:

                seed_conn = duckdb.connect(":memory:")

                parquet_glob = os.path.join(PARQUET_DIR, "**/*.parquet")

                row = seed_conn.execute(

                    f'SELECT MAX(id) FROM read_parquet("{parquet_glob}", hive_partitioning=false)'

                ).fetchone()

                if row and row[0]:

                    EVENT_SEQ = int(row[0]) + 1

                    log.info(f"Event ID seeded from Parquet: {EVENT_SEQ}")

                seed_conn.close()

        except Exception as ex:

            log.warning(f"Parquet-based event ID seed failed: {ex}")

    threading.Thread(target=_flush_loop, daemon=True).start()
    threading.Thread(target=_retention_cleanup, daemon=True).start()
    threading.Thread(target=run_tcp_server, args=(args.tcp_host, args.tcp_port), daemon=True).start()
    threading.Thread(target=run_heartbeat_server, args=(args.tcp_host, 9001), daemon=True).start()
    log.info(f"Ghost IT Pipeline v2 — HTTP {args.http_host}:{args.http_port}")
    uvicorn.run(app, host=args.http_host, port=args.http_port, log_level="warning")

import hashlib as _hashlib

AGENT_BINARY_PATH = os.environ.get(
    "GHOST_AGENT_BINARY_PATH",
    "/home/ubuntu/ghostlayer/agent-releases/ghostit-agent-linux-amd64"
)
AGENT_VERSION_FILE = os.environ.get(
    "GHOST_AGENT_VERSION_FILE",
    "/home/ubuntu/ghostlayer/agent-releases/VERSION"
)

@app.get("/agent/version")
async def agent_version():
    if not os.path.exists(AGENT_BINARY_PATH):
        return {"available": False, "reason": "no release published"}
    with open(AGENT_BINARY_PATH, "rb") as f:
        real_hash = _hashlib.sha256(f.read()).hexdigest()
    version = "unknown"
    if os.path.exists(AGENT_VERSION_FILE):
        with open(AGENT_VERSION_FILE) as f:
            version = f.read().strip()
    return {
        "available": True,
        "version": version,
        "sha256": real_hash,
        "download_url": "/agent/download",
        "size_bytes": os.path.getsize(AGENT_BINARY_PATH),
    }

@app.get("/agent/download")
async def agent_download():
    if not os.path.exists(AGENT_BINARY_PATH):
        return JSONResponse(status_code=404, content={"error": "no release published"})
    return FileResponse(AGENT_BINARY_PATH, media_type="application/octet-stream",
                         filename="ghostit-agent-linux-amd64")

AGENT_BPF_OBJ_PATH = os.environ.get(

    "GHOST_AGENT_BPF_OBJ_PATH",

    "/home/ubuntu/ghostlayer/agent-releases/ghost_agent.bpf.o"

)



@app.get("/agent/ebpf-object")

async def agent_ebpf_object():

    if not os.path.exists(AGENT_BPF_OBJ_PATH):

        return JSONResponse(status_code=404, content={"error": "no eBPF object published"})

    return FileResponse(AGENT_BPF_OBJ_PATH, media_type="application/octet-stream",

                         filename="ghost_agent.bpf.o")



AGENT_INSTALL_SCRIPT_PATH = os.environ.get(

    "GHOST_AGENT_INSTALL_SCRIPT_PATH",

    "/home/ubuntu/ghostlayer/agent-releases/install.sh"

)



@app.get("/install.sh")

async def install_script():

    if not os.path.exists(AGENT_INSTALL_SCRIPT_PATH):

        return JSONResponse(status_code=404, content={"error": "install script not published"})

    return FileResponse(AGENT_INSTALL_SCRIPT_PATH, media_type="text/plain")



if __name__ == "__main__":

    main()

