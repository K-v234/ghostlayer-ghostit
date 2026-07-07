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
from datetime import datetime, timezone
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from detection.rules      import check_event, check_sequence, Detection
from detection.mitre      import get_mitre_tag, KillChainStage
from detection.chain_tracker import ChainTracker
from detection.lineage    import LineageTracer
from detection.aggregator import analyze_window
from detection.behavioral.engine import BehavioralAIEngine
from detection.ransomware.ema_detector import RansomwareEMADetector
from detection.ransomware.file_entropy_monitor import FileEntropyMonitor
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), '..'))
from detectors.lolbin_detector import LOLBinDetector

# Level set to INFO by default; pass --log-level DEBUG at startup to see
# verbose internal diagnostics (e.g. C15 window feature values) without
# needing to edit source code and restart every time.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [detection] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


def api_get(url: str) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
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
        reasons = [
            d.rule_id,
            d.title,
            f"confidence:{d.confidence}",
        ]
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
        # PID -> comm cache for process-chain detection (wmic->powershell etc).
        # Populated as events flow through; capped by size since PIDs get
        # reused and we only need recent-enough mappings.
        self._pid_comm_cache: dict[int, str] = {}
        self._PID_CACHE_MAX = 5000
        self._entropy_monitor = FileEntropyMonitor(pipeline_host=pipeline_host, pipeline_port=pipeline_port)
        self._entropy_monitor.start()
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
        data = api_get(f"{self.api}/events/since?since_id={self._max_seen_id}&limit=500")
        events = data.get("events", [])
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
        data   = api_get(f"{self.api}/events?limit=200&offset={offset}&min_score=0")
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
                # C2: Behavioral AI
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
                # C15: Ransomware EMA
                r = self._ransomware.process_event(e)
                if r:
                    detections.append(Detection(
                        rule_id     = f"C15_{r.trigger}",
                        severity    = r.severity.lower() if r.severity != "CRITICAL" else "critical",
                        title       = f"Ransomware EMA: {r.trigger}",
                        description = f"Ransomware behaviour detected — z_score={r.z_score:.1f}",
                        confidence  = min(100, int(r.z_score * 20)),
                        evidence    = [e],
                    ))
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
                pathlib.Path.home().joinpath("ghostlayer/data/chain_state.json").write_text(_json.dumps(state))

            send_to_pipeline(unique, self.p_host, self.p_port)
            # C17 Alert Correlation — wire detections into incident DB
            try:
                if not hasattr(self, '_correlator'):
                    import sys as _sys
                    _sys.path.insert(0, os.path.expanduser("~/ghostlayer/alert-engine"))
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

    def run(self):
        log.info(f"Running — poll={self.poll}s window={self.window}s")
        total = 0
        while True:
            try:
                n = self.run_once()
                total += n
                if n:
                    log.info(f"Cycle done — {n} detections (total: {total})")
                time.sleep(self.poll)
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
