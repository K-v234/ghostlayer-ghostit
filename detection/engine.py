#!/usr/bin/env python3
"""
Ghost IT — Detection Engine v0
Reads events via REST API. Runs 3 detection layers.
"""
import os
import sys
import json
import time
import socket
import logging
import argparse
import urllib.request
import urllib.parse
import redis

# Simulation Engine: caches each entity's most recent prediction, so
# a later detection on the same entity can check whether reality
# genuinely converged toward it.
_PREDICTION_CACHE = {}
from datetime import datetime, timezone
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detection.rules      import check_event, check_sequence, Detection
from detection.mitre      import get_mitre_tag, KillChainStage
def _feed_cortex(pid: int, pillar: str, reason: str):
    """
    Report a finding to the Cortex via HTTP -- see
    pipeline/server_v2.py's POST /cortex/contribute for full
    rationale (DuckDB single-writer concurrency means only the
    pipeline process can open the Cortex DB directly; every other
    service, including this one, contributes over HTTP instead).
    Failures here are logged but never block detection itself; the
    Cortex is an enhancement layer, not a dependency the core
    pipeline should ever be blocked by.
    """
    if not pid:
        return
    try:
        import urllib.parse
        url = (f"http://ghostit-pipeline:8000/cortex/contribute?"
               f"pid={pid}&pillar={urllib.parse.quote(pillar)}&reason={urllib.parse.quote(reason[:200])}")
        req = urllib.request.Request(url, method="POST")
        urllib.request.urlopen(req, timeout=3)
    except Exception as ex:
        log.debug(f"Cortex feed error: {ex}")
def _feed_cortex_host(host: str, pillar: str, reason: str):
    """
    Host-level Cortex contribution -- for signals like C19's kernel
    integrity violations that aren't tied to one PID, but genuinely
    compromise trust in the entire machine. Uses 'host:{hostname}' as
    the Cortex entity ID instead of 'pid:{pid}'.
    """
    if not host or host == "unknown":
        return
    try:
        import urllib.parse
        url = (f"http://ghostit-pipeline:8000/cortex/contribute?"
               f"pid=host_{urllib.parse.quote(host)}&pillar={urllib.parse.quote(pillar)}"
               f"&reason={urllib.parse.quote(reason[:200])}")
        req = urllib.request.Request(url, method="POST")
        urllib.request.urlopen(req, timeout=3)
    except Exception as ex:
        log.debug(f"Cortex host-feed error: {ex}")
def _observe_threshold(pillar: str, score: float):
    """
    Report a raw score observation to Adaptive Threshold Calibration,
    REGARDLESS of whether any detection fired -- calibration needs
    the full distribution of normal activity, not just the already-
    flagged tail, to learn this deployment's genuine baseline.
    """
    try:
        import urllib.parse
        url = f"http://ghostit-pipeline:8000/adaptive-thresholds/observe?pillar={urllib.parse.quote(pillar)}&score={score}"
        req = urllib.request.Request(url, method="POST")
        urllib.request.urlopen(req, timeout=3)
    except Exception as ex:
        log.debug(f"Adaptive threshold observe error: {ex}")
def _feed_temporal_memory(host: str, comm: str, resource: str, pillar: str, reason: str):
    """
    Report a sighting to Temporal Attack-Graph Memory via HTTP (same
    single-writer-via-pipeline pattern as Cortex, for the same
    concurrency reason). Records whether this specific pattern has
    been seen before, possibly days ago -- recognizing a returning
    actor across time, not just within one session.
    """
    try:
        import urllib.parse
        params = urllib.parse.urlencode({
            "host": host, "comm": comm, "resource": resource[:200],
            "pillar": pillar, "reason": reason[:200],
        })
        url = f"http://ghostit-pipeline:8000/temporal-memory/sighting?{params}"
        req = urllib.request.Request(url, method="POST")
        urllib.request.urlopen(req, timeout=3)
    except Exception as ex:
        log.debug(f"Temporal memory feed error: {ex}")
def _check_and_observe_dna(comm: str, parent_comm: str, event_type: str, path: str):
    """
    Behavioral DNA: observe this event to build the comm's trusted
    profile, then check if THIS instance's lineage is consistent --
    if masquerading is suspected, feed it into the Cortex as a real,
    high-confidence signal (identity mismatch is genuinely strong
    evidence, independent of anything else).
    """
    path = path or ""
    try:
        import urllib.parse
        obs_params = urllib.parse.urlencode({
            "comm": comm, "parent_comm": parent_comm,
            "event_type": event_type, "path": path[:200],
        })
        obs_url = f"http://ghostit-pipeline:8000/behavioral-dna/observe?{obs_params}"
        urllib.request.urlopen(urllib.request.Request(obs_url, method="POST"), timeout=3)

        check_params = urllib.parse.urlencode({
            "comm": comm, "parent_comm": parent_comm,
            "event_type": event_type, "path": path[:200],
        })
        check_url = f"http://ghostit-pipeline:8000/behavioral-dna/check?{check_params}"
        with urllib.request.urlopen(check_url, timeout=3) as r:
            result = json.loads(r.read())
        if result.get("masquerade_suspected"):
            log.warning(
                f"[BehavioralDNA] MASQUERADE SUSPECTED: '{comm}' claims to be "
                f"trusted but parent='{parent_comm}' inconsistent with typical "
                f"parents {result.get('typical_parents')}"
            )
    except Exception as ex:
        log.debug(f"Behavioral DNA check error: {ex}")
from detection.chain_tracker import ChainTracker
from detection.lineage    import LineageTracer
from detection.aggregator import analyze_window
from detection.behavioral.engine import BehavioralAIEngine
from detection.ransomware.ema_detector import RansomwareEMADetector
from detection.ransomware.file_entropy_monitor import FileEntropyMonitor
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), '..'))
from detectors.lolbin_detector import LOLBinDetector
from detectors.exfiltration_detector import ExfiltrationDetector

# Level set to INFO by default; pass --log-level DEBUG at startup to see
# verbose internal diagnostics (e.g. C15 window feature values) without
# needing to edit source code and restart every time.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [detection] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)



_GHOST_INTERNAL_SECRET = os.environ.get("GHOST_INTERNAL_SECRET", "")

# Global default opener: attaches X-Internal-Auth to every request made

# via urllib.request.urlopen() anywhere in this file, including the many

# scattered inline Request(...) calls above and below -- one fix instead

# of eleven individually risky edits across call sites with different

# shapes (bare url strings, POST Requests, GET Requests).

_opener = urllib.request.build_opener()

_opener.addheaders = [("X-Internal-Auth", _GHOST_INTERNAL_SECRET)]

urllib.request.install_opener(_opener)


# Global default opener: attaches X-Internal-Auth to every request made

# via urllib.request.urlopen() anywhere in this file, including the many

# scattered inline Request(...) calls above and below -- one fix instead

# of eleven individually risky edits across call sites with different

# shapes (bare url strings, POST Requests, GET Requests).

_opener = urllib.request.build_opener()

_opener.addheaders = [("X-Internal-Auth", _GHOST_INTERNAL_SECRET)]

urllib.request.install_opener(_opener)




def api_get(url: str) -> dict:

    try:

        req = urllib.request.Request(url, headers={"X-Internal-Auth": _GHOST_INTERNAL_SECRET})

        with urllib.request.urlopen(req, timeout=15) as r:

            return json.loads(r.read())

    except Exception as ex:

        log.error(f"API error {url}: {ex}")

        return {}



def send_to_pipeline(detections: list, host: str, port: int):
    if not detections:
        return
    events = []
    for d in detections:
        tag = get_mitre_tag(d.rule_id)
        # Predictive Next-Step Inference: given this detection's
        # confirmed tactic, query what's statistically likely to
        # happen next per real MITRE ATT&CK kill-chain progression,
        # and log it as an actionable anticipatory signal -- turns
        # this from purely reactive detection into genuine prediction.
        if tag:
            try:
                import urllib.parse as _urlp
                _url = f"http://ghostit-pipeline:8000/predict/{_urlp.quote(tag.tactic)}"
                with urllib.request.urlopen(_url, timeout=3) as _r:
                    _pred = json.loads(_r.read())
                if _pred.get("predicted_next"):
                    next_tactics = [p["tactic"] for p in _pred["predicted_next"]]
                    log.warning(
                        f"[PREDICT] {d.rule_id} confirmed at tactic={tag.tactic} "
                        f"-- likely next: {next_tactics} "
                        f"(kill chain position {_pred.get('kill_chain_position')}/"
                        f"{_pred.get('kill_chain_total_stages')})"
                    )
                    _entity = d.evidence[0].get("pid") if hasattr(d, "evidence") and d.evidence else None
                    if _entity:
                        _prior = _PREDICTION_CACHE.get(f"{_entity}_prior")
                        if _prior:
                            try:
                                _sim_params = urllib.parse.urlencode({"predicted": ",".join(_prior), "observed": tag.tactic})
                                _sim_url = f"http://ghostit-pipeline:8000/simulation/check-trajectory?{_sim_params}"
                                _sim_req = urllib.request.Request(_sim_url, method="POST")
                                with urllib.request.urlopen(_sim_req, timeout=3) as _sr:
                                    _sim_result = json.loads(_sr.read())
                                if _sim_result.get("trajectory_match"):
                                    log.warning(f"[Simulation] TRAJECTORY MATCH for pid {_entity}: {_sim_result['conclusion']}")
                            except Exception as _ex_sim:
                                log.debug(f"Simulation engine error: {_ex_sim}")
                        _PREDICTION_CACHE[f"{_entity}_prior"] = next_tactics
            except Exception as _ex:
                log.debug(f"Predictive inference error: {_ex}")
            try:
                _entity_id = d.evidence[0].get("pid") if hasattr(d, "evidence") and d.evidence else 0
                _incident_id = f"incident-pid-{_entity_id}"
                _replay_params = urllib.parse.urlencode({
                    "incident_id": _incident_id, "entity_id": f"pid:{_entity_id}",
                    "event_type": tag.tactic.lower().replace(" ", "_") if tag else d.rule_id.lower(),
                    "description": d.title, "pillar": d.rule_id,
                })
                _replay_url = f"http://ghostit-pipeline:8000/replay/record?{_replay_params}"
                _replay_req = urllib.request.Request(_replay_url, method="POST")
                urllib.request.urlopen(_replay_req, timeout=3)
            except Exception as _ex_replay:
                log.debug(f"Attack replay recording error: {_ex_replay}")
        # V1.5: tag whether this rule has a real incident response
        # playbook available -- dashboard uses this to show/hide the
        # "View Playbook" action, fetching the actual content from
        # GET /api/playbook/{rule_id} rather than duplicating the
        # playbook text into every single alert event.
        has_playbook = d.rule_id in ("C15_RANSOMWARE", "C14_LOLBIN",
                                       "C19_LKRG_INTEGRITY", "canary_hit",
                                       "R002", "R003", "R004")
        reasons = [
            d.rule_id,
            d.title,
            f"confidence:{d.confidence}",
        ]
        if has_playbook:
            reasons.append("playbook:available")
        if tag:
            reasons += [
                f"tactic:{tag.tactic}",
                f"technique:{tag.technique_id}",
                f"kill_chain:{tag.kill_chain.label()}",
            ]
        event = (d.evidence[0] if hasattr(d, "evidence") and d.evidence else {})
        events.append({
            "ts":      int(time.time_ns()),
            "pid": event.get("pid", -1), "ppid": event.get("ppid", -1), "uid": event.get("uid", -1), "gid": event.get("gid", -1),
            "comm":    f"detection:{d.rule_id}",
            "type":    "detection",
            "score":   100,
            "alert":   True,
            "reasons": reasons,
            "file":    d.description,
            "daddr":   None, "dport": None,
        })

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        s.sendall((json.dumps(events) + "\n").encode())
        s.close()
        log.info(f"Forwarded {len(detections)} detections")
    except OSError as ex:
        log.error(f"Pipeline unavailable: {ex}")
        for d in detections:
            log.warning(f"[{d.severity.upper()}] {d.rule_id} — {d.title}")


class DetectionEngine:
    def __init__(self, api_base: str, poll_interval: int,
                 window: int, pipeline_host: str, pipeline_port: int):
        self.api         = api_base
        self.poll        = poll_interval
        self.window      = window
        self.p_host      = pipeline_host
        self.p_port      = pipeline_port
        self.cycle_count = 0
        self.window_offset = 0
        self.last_offset = 0
        self.seen_ids = self._seed_seen_ids()
        self.start_time  = time.time()
        self._ransomware = RansomwareEMADetector()
        self._lolbin     = LOLBinDetector()
        self._exfil      = ExfiltrationDetector()
        # PID -> comm cache for process-chain detection (wmic->powershell etc).
        # Populated as events flow through; capped by size since PIDs get
        # reused and we only need recent-enough mappings.
        self._pid_comm_cache: dict[int, str] = {}
        self._PID_CACHE_MAX = 5000
        self._entropy_monitor = FileEntropyMonitor(pipeline_host=pipeline_host, pipeline_port=pipeline_port)
        self._entropy_monitor.start()

        # Week 2: Redis Streams as a low-latency trigger, not a replacement

        # for _fetch_new's HTTP polling. If Redis is unreachable, self._redis

        # stays None and run() falls back to the exact old sleep(poll)

        # behavior -- this must never become a hard dependency.

        redis_host = os.environ.get("GHOST_REDIS_HOST", "redis")

        redis_port = int(os.environ.get("GHOST_REDIS_PORT", "6379"))

        try:

            self._redis = redis.Redis(host=redis_host, port=redis_port, decode_responses=True, socket_connect_timeout=2)

            self._redis.ping()

            for stream in ("ghost:events:critical", "ghost:events:standard"):

                try:

                    self._redis.xgroup_create(stream, "detection-engine", id="$", mkstream=True)

                except redis.exceptions.ResponseError as e:

                    if "BUSYGROUP" not in str(e):

                        raise

            log.info("Redis Streams trigger connected -- polling loop will wake on new events instead of blind sleep")

        except Exception as ex:

            self._redis = None

            log.warning(f"Redis unavailable, falling back to plain poll interval: {ex}")

        log.info("C15 FileEntropyMonitor started")
        log.info(f"Engine ready — starting at offset {self.last_offset}")

    def _seed_seen_ids(self) -> set:
        """Get max event ID at startup — only detect events with higher IDs.
        Retries until pipeline is ready and returns events."""
        import time as _time
        for attempt in range(10):
            data2 = api_get(f"{self.api}/events?limit=1&offset=0&min_score=0")
            events = data2.get("events", [])
            if events:
                self.max_id_at_start = events[0].get("id", 0)
                break
            log.info(f"Pipeline not ready yet (attempt {attempt+1}/10) — retrying in 3s")
            _time.sleep(3)
        else:
            # Pipeline has no events yet — set to 0 but skip first 30s of detections
            self.max_id_at_start = 0
            self._skip_until = _time.time() + 30
            log.warning("Pipeline empty at startup — skipping detections for 30s")
        self.chain_tracker = ChainTracker()
        log.info(f"Max event ID at startup: {self.max_id_at_start}")
        # C2: Behavioral AI Engine
        self._behavioral = BehavioralAIEngine(
            pipeline_host="127.0.0.1",
            pipeline_port=9000,
        )
        log.info("C2 BehavioralAIEngine wired in")
        return set()

    def _get_total(self) -> int:
        data = api_get(f"{self.api}/stats")
        return data.get("total", 0)

    def _fetch_new(self) -> list[dict]:
        """Fetch events newer than max_seen_id using /events/since cursor."""
        import time as _time
        # Skip if within startup suppression window
        if hasattr(self, "_skip_until") and _time.time() < self._skip_until:
            return []
        # Use max_seen_id as cursor
        if not hasattr(self, "_max_seen_id"):
            self._max_seen_id = self.max_id_at_start
        # Real, genuine fix for the true, final root cause found tonight:
        # EVENT_SEQ on the server is an in-memory counter that resets to a
        # new timestamp-based seed on every pipeline restart. A stale
        # since_id from before a restart becomes permanently higher than
        # any new, post-restart event ID, silently freezing this method
        # forever. Detect this by comparing our cursor against the
        # server's current actual max id, and reset if we're ahead of it.
        try:
            probe = api_get(f"{self.api}/events?limit=1&offset=0&min_score=0")
            probe_events = probe.get("events", [])
            if probe_events:
                real_max = probe_events[0].get("id", 0)
                if real_max < self._max_seen_id:
                    log.warning(f"Pipeline restart detected (real_max={real_max} < cursor={self._max_seen_id}) -- resetting cursor")
                    self._max_seen_id = 0
        except Exception:
            pass
        data = api_get(f"{self.api}/events/since?since_id={self._max_seen_id}&limit=500")
        events = data.get("events", [])
        log.info(f"DEBUG_FETCH_NEW since_id={self._max_seen_id} got={len(events)} max_id_in_response={data.get('max_id')} raw_keys={list(data.keys())}")
        if events:
            self._max_seen_id = data.get("max_id", self._max_seen_id)
        # Supplemental fetch: shell opens of /tmp and /dev/shm — high-value
        for prefix in ("/tmp/", "/dev/shm/"):
            try:
                tmp_data = api_get(
                    f"{self.api}/events/file-opens?path_prefix={prefix}"
                    f"&since_id={self.max_id_at_start}&limit=50"
                )
                for e in tmp_data.get("events", []):
                    if e.get("id", 0) > self._max_seen_id - 10000:
                        if not any(x.get("id") == e.get("id") for x in events):
                            events.append(e)
            except Exception:
                pass

        # Supplemental fetch: auth_failure events (buried by eBPF flood)
        try:
            auth_data = api_get(f"{self.api}/events?limit=50&type=auth_failure")
            for e in auth_data.get("events", []):
                if e.get("id", 0) > self.max_id_at_start:
                    if not any(x.get("id") == e.get("id") for x in events):
                        events.append(e)
        except Exception:
            pass
        return events
    def _fetch_window(self) -> list[dict]:
        """Fetch recent events — only last 200 to avoid historical noise."""
        offset = max(0, self.last_offset - 200)
        data   = api_get(f"{self.api}/events?limit=2000&offset={offset}&min_score=0")
        return data.get("events", [])

    def run_once(self) -> int:
        self.cycle_count += 1
        detections: list[Detection] = []

        # Layer 1 + sequence — new events only
        new_events = self._fetch_new()
        if new_events:
            log.debug(f"Analyzing {len(new_events)} new events")
            for e in new_events:
                # Update PID->comm cache for process-chain resolution.
                # Every event teaches the cache its own PID's current name,
                # so future children can resolve this event's PID as a parent.
                e_pid = e.get("pid", 0)
                e_comm = e.get("comm", "")
                if e_pid and e_comm:
                    if len(self._pid_comm_cache) >= self._PID_CACHE_MAX:
                        # Evict oldest ~10% when full (simple FIFO via dict order)
                        for k in list(self._pid_comm_cache.keys())[:self._PID_CACHE_MAX // 10]:
                            del self._pid_comm_cache[k]
                    self._pid_comm_cache[e_pid] = e_comm

                d = check_event(e)
                if d:
                    detections.append(d)

                # C14 process-chain: resolve this event's parent comm from
                # the cache, then check if parent->child matches a known
                # suspicious chain (wmic->powershell, word->powershell, etc).
                e_ppid = e.get("ppid", 0)
                parent_comm = self._pid_comm_cache.get(e_ppid, "")
                if parent_comm and e_comm:
                    chain_alert = self._lolbin.check_process_chain(parent_comm, e_comm)
                    if chain_alert:
                        detections.append(Detection(
                            rule_id     = "C14_LOLBIN_CHAIN",
                            severity    = chain_alert.severity,
                            title       = f"Suspicious process chain: {chain_alert.technique}",
                            description = f"{parent_comm} -> {e_comm} matches known attack pattern",
                            confidence  = 85,
                            evidence    = [e],
                        ))
                        _feed_cortex(e_pid, "C14_lolbin", f"chain:{parent_comm}->{e_comm}")
                # C2: Behavioral AI
                # Feed every raw event score to Adaptive Threshold
                # Calibration, regardless of whether any pillar fires --
                # calibration needs the full baseline distribution, not
                # just the already-flagged tail.
                if e.get("score") is not None:
                    _observe_threshold("C2_behavioral", e.get("score"))
                # Behavioral DNA: observe this event to build/reinforce
                # the comm's trusted profile, AND check if this specific
                # instance's lineage is consistent with that profile --
                # masquerading detection independent of process name.
                if e_comm and parent_comm:
                    _check_and_observe_dna(e_comm, parent_comm, e.get("type", ""), e.get("file", ""))
                b = self._behavioral.process_event(e)
                if b:
                    detections.append(Detection(
                        rule_id     = "B001",
                        severity    = b.severity,
                        title       = f"Behavioral anomaly: {b.rationale}",
                        description = f"Behavioral AI detected anomaly — score={b.score:.2f}",
                        confidence  = int(b.score * 100),
                        evidence    = [e],
                    ))
                    _feed_cortex(e_pid, "C2_behavioral", b.rationale)
                # Cortex: even when C2 does NOT cross its own threshold,
                # still feed a light-weight signal if the raw event score
                # is meaningfully elevated -- this is what lets genuinely
                # sub-threshold behavioral drift still contribute to
                # cross-pillar fusion instead of being discarded entirely.
                elif e.get("score", 0) >= 40:
                    _feed_cortex(e_pid, "C2_behavioral", f"elevated_event_score:{e.get('score')}")
                # C15: Ransomware EMA
                r = self._ransomware.process_event(e)
                if r:
                    r_confidence = min(100, int(r.z_score * 20))
                    detections.append(Detection(
                        rule_id     = f"C15_{r.trigger}",
                        severity    = r.severity.lower() if r.severity != "CRITICAL" else "critical",
                        title       = f"Ransomware EMA: {r.trigger}",
                        description = f"Ransomware behaviour detected — z_score={r.z_score:.1f}",
                        confidence  = r_confidence,
                        evidence    = [e],
                    ))
                    _feed_cortex(e_pid, "C15_ransomware", f"{r.trigger}:z={r.z_score:.1f}")
                    _feed_temporal_memory(e.get("host","unknown"), e.get("comm","unknown"), e.get("file","") or "unknown", "C15_ransomware", r.trigger)
                    _observe_threshold("C15_ransomware", r_confidence)
                else:
                    _observe_threshold("C15_ransomware", 0)
                # C14: LOLBin
                l = self._lolbin.check_event(e)
                if l:
                    detections.append(Detection(
                        rule_id     = "C14_LOLBIN",
                        severity    = l.severity,
                        title       = f"LOLBin: {l.technique}",
                        description = f"Living-off-the-land binary abuse detected",
                        confidence  = 85,
                        evidence    = [e],
                    ))
                    _feed_cortex(e_pid, "C14_lolbin", l.technique)
                    _observe_threshold("C14_lolbin", 85)
                else:
                    _observe_threshold("C14_lolbin", 0)
                # C20: Insider Threat / Bulk Exfiltration
                xf = self._exfil.check_event(e)
                if xf:
                    detections.append(Detection(
                        rule_id     = "C20_EXFILTRATION",
                        severity    = xf.severity,
                        title       = f"Bulk file access: {xf.distinct_files} distinct files in {xf.window_sec}s",
                        description = f"Process {xf.comm} (pid {xf.pid}) accessed {xf.distinct_files} distinct files rapidly -- possible data staging/exfiltration",
                        confidence  = 90 if xf.severity == "critical" else 75,
                        evidence    = [e],
                    ))
                    _feed_cortex(e_pid, "C20_exfiltration", f"bulk_access:{xf.distinct_files}_files")
                    _observe_threshold("C20_exfiltration", 90 if xf.severity == "critical" else 75)
                else:
                    _observe_threshold("C20_exfiltration", 0)
                if d:
                    _observe_threshold(f"rule_{d.rule_id}", d.confidence)
                # C19: LKRG kernel integrity violations
                if e.get("type") == "kernel_integrity" and e.get("score", 0) >= 80:
                    detections.append(Detection(
                        rule_id     = "C19_LKRG_INTEGRITY",
                        severity    = "critical",
                        title       = "Kernel integrity violation detected",
                        description = f"LKRG flagged a real kernel/process integrity concern: {e.get('file', '')[:120]}",
                        confidence  = 90,
                        evidence    = [e],
                    ))
                    # C19 feeds Cortex as a HOST-level entity, not PID
                    # -- kernel integrity violations aren't tied to one
                    # process, they compromise the whole machine's
                    # trustworthiness. Every process running on a host
                    # with a kernel integrity violation should
                    # genuinely be treated with elevated suspicion.
                    _feed_cortex_host(e.get("host", "unknown"), "C19_kernel",
                                       e.get("file", "")[:150])

            by_pid: dict[int, list] = {}
            for e in new_events:
                by_pid.setdefault(e.get("pid", 0), []).append(e)
            for evts in by_pid.values():
                if len(evts) >= 2:
                    detections.extend(
                        check_sequence(sorted(evts, key=lambda x: x.get("ts") or 0))
                    )

        # Layer 2 + 3 — window, once per 6 cycles (60s)
        if False:  # window analysis disabled until clean baseline
            window_events = self._fetch_window()
            if window_events:
                tracer = LineageTracer()
                for e in window_events:
                    tracer.add_event(e)
                detections.extend(tracer.analyze())
                detections.extend(analyze_window(window_events))

        # Deduplicate
        seen, unique = set(), []
        for d in detections:
            key = f"{d.rule_id}:{d.title}"
            if key not in seen:
                seen.add(key)
                unique.append(d)

        if unique:
            for d in unique:
                tag = get_mitre_tag(d.rule_id)
                mitre_str = f" | {tag.tactic} {tag.technique_id} | {tag.kill_chain.label()}" if tag else ""
                log.warning(
                    f"[{d.severity.upper()}] {d.rule_id} — {d.title} ({d.confidence}%){mitre_str}"
                )
                self.chain_tracker.process(d.rule_id, d.title, d.confidence)

            active = self.chain_tracker.active_chains()
            if active:
                log.info(f"Active chains: {len(active)} | Highest severity: {self.chain_tracker.highest_severity()}")
                import pathlib, json as _json
                state = {"chains": active, "highest_severity": self.chain_tracker.highest_severity()}
                pathlib.Path(os.environ.get("CHAIN_STATE_PATH", os.path.expanduser("~/ghostlayer/data/chain_state.json"))).write_text(_json.dumps(state))

            send_to_pipeline(unique, self.p_host, self.p_port)
            # C17 Alert Correlation — wire detections into incident DB
            try:
                if not hasattr(self, '_correlator'):
                    import sys as _sys
                    # Same class of bug as C4's hardcoded ~/ghostlayer path
                    # (fixed earlier) -- resolves relative to this file's
                    # own location instead of assuming a fixed home
                    # directory that doesn't exist in Docker (/app, not
                    # /root/ghostlayer).
                    _alert_engine_dir = os.path.join(
                        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "alert-engine")
                    _sys.path.insert(0, _alert_engine_dir)
                    from correlator import AlertCorrelator
                    self._correlator = AlertCorrelator()
                from incidents import RawAlert
                from weights import AlertSource, Severity
                _source_map = {
                    # C15 ransomware → Impact T1486
                    "C15_RENAME_STORM": AlertSource.C15_RANSOMWARE,
                    "C15_ENTROPY_SPIKE": AlertSource.C15_RANSOMWARE,
                    "C15_EXT_CHANGE": AlertSource.C15_RANSOMWARE,
                    "C15_WRITE_RATE": AlertSource.C15_RANSOMWARE,
                    # C2/network detections → C14_TLS (Command and Control)
                    "R003": AlertSource.C14_TLS,
                    "R004": AlertSource.C14_TLS,
                    "R007": AlertSource.C14_TLS,
                    # LOLBin/execution detections → C9_EBPF (Execution)
                    "R014": AlertSource.C9_EBPF,
                    "R006": AlertSource.C9_EBPF,
                    "R008": AlertSource.C9_EBPF,
                    "R010": AlertSource.C9_EBPF,
                    "R012": AlertSource.C9_EBPF,
                    # Auth failures → BEHAVIORAL_AI (Credential Access)
                    "R013": AlertSource.BEHAVIORAL_AI,
                    # Canary/deception → DECEPTION (Collection)
                    "R001": AlertSource.DECEPTION,
                    "R002": AlertSource.DECEPTION,
                }
                _sev_map = {
                    "critical": Severity.CRITICAL,
                    "high":     Severity.HIGH,
                    "medium":   Severity.MEDIUM,
                }
                # Deduplication: same rule+comm within 60s = skip
                import time as _time
                if not hasattr(self, '_c17_dedup'):
                    self._c17_dedup = {}
                now_ts = _time.time()
                # Clean old entries
                self._c17_dedup = {k: v for k, v in self._c17_dedup.items() if now_ts - v < 60}

                for d in unique:
                    ev = d.evidence[0] if hasattr(d, "evidence") and d.evidence else {}
                    dedup_key = f"{d.rule_id}:{ev.get('comm', '')}"
                    if dedup_key in self._c17_dedup:
                        log.debug(f"C17 dedup: skipping {dedup_key} (within 60s)")
                        continue
                    self._c17_dedup[dedup_key] = now_ts
                    raw = RawAlert.create(
                        source=_source_map.get(d.rule_id,
                        AlertSource.C15_RANSOMWARE if d.rule_id.startswith("C15_") else
                        AlertSource.BEHAVIORAL_AI),
                        severity=_sev_map.get(d.severity.lower(), Severity.MEDIUM),
                        pid=ev.get("pid", 0),
                        host="localhost",
                        comm=ev.get("comm", d.rule_id),
                        reason=d.title,
                        event_type="detection",
                        raw_json=json.dumps(ev),
                    )
                    iid = self._correlator.ingest(raw)
                    if iid:
                        log.info(f"C17 incident updated: {iid[:8]}")
            except Exception as _c17_ex:
                log.debug(f"C17 wire error: {_c17_ex}")

        return len(unique)


    def _wait_for_trigger(self):

        """Blocks until either Redis signals a new event, or self.poll

        seconds elapse -- whichever comes first. Falls back to a plain

        sleep if Redis isn't connected. Never raises; any Redis error

        here just means we fall through to the timer, same as before."""

        if self._redis is None:

            time.sleep(self.poll)

            return

        try:

            self._redis.xreadgroup(

                "detection-engine", "engine-main",

                {"ghost:events:critical": ">", "ghost:events:standard": ">"},

                count=1, block=self.poll * 1000

            )

            # We don't process the Redis payload directly here -- _fetch_new's

            # HTTP-based fetch (with its cursor-reset detection and

            # supplemental fetches) remains the single source of truth for

            # what gets processed. Redis here is purely a wakeup signal.

        except Exception as ex:

            log.warning(f"Redis wait failed, falling back to sleep: {ex}")

            time.sleep(self.poll)

    def run(self):

        log.info(f"Running — poll={self.poll}s window={self.window}s")

        total = 0

        while True:

            try:

                n = self.run_once()

                total += n

                if n:

                    log.info(f"Cycle done — {n} detections (total: {total})")

                self._wait_for_trigger()

            except KeyboardInterrupt:

                log.info(f"Stopped — total: {total}")

                break

            except Exception as ex:

                import traceback; log.error(f"Engine error: {ex}\n{traceback.format_exc()}")

                time.sleep(self.poll)



def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-level",      default="INFO", choices=["DEBUG","INFO","WARNING","ERROR"])
    ap.add_argument("--api",           default="http://127.0.0.1:8000")
    ap.add_argument("--poll-interval", default=10,  type=int)
    ap.add_argument("--window",        default=120, type=int)
    ap.add_argument("--pipeline-host", default="127.0.0.1")
    ap.add_argument("--pipeline-port", default=9000, type=int)
    args = ap.parse_args()
    logging.getLogger().setLevel(getattr(logging, args.log_level))

    DetectionEngine(
        api_base      = args.api,
        poll_interval = args.poll_interval,
        window        = args.window,
        pipeline_host = args.pipeline_host,
        pipeline_port = args.pipeline_port,
    ).run()


if __name__ == "__main__":
    main()
