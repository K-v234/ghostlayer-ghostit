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
        events.append({
            "ts":      int(time.time_ns()),
            "pid":     0, "ppid": 0, "uid": 0, "gid": 0,
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
        log.info(f"Engine ready — starting at offset {self.last_offset}")

    def _seed_seen_ids(self) -> set:
        """Get max event ID at startup — only detect events with higher IDs."""
        data = api_get(f"{self.api}/stats")
        total = data.get("total", 0)
        # Get current max ID by fetching one event
        data2 = api_get(f"{self.api}/events?limit=1&offset=0&min_score=0")
        events = data2.get("events", [])
        self.max_id_at_start = events[0].get("id", 0) if events else 0
        self.chain_tracker = ChainTracker()
        log.info(f"Max event ID at startup: {self.max_id_at_start}")
        return set()

    def _get_total(self) -> int:
        data = api_get(f"{self.api}/stats")
        return data.get("total", 0)

    def _fetch_new(self) -> list[dict]:
        """Fetch events newer than max_id_at_start."""
        data = api_get(f"{self.api}/events?limit=100&offset=0&min_score=0")
        all_events = data.get("events", [])
        new = [
            e for e in all_events
            if e.get("id", 0) > self.max_id_at_start
            and e.get("id") not in self.seen_ids
        ]
        for e in new:
            self.seen_ids.add(e.get("id"))
        return new
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
                d = check_event(e)
                if d:
                    detections.append(d)

            by_pid: dict[int, list] = {}
            for e in new_events:
                by_pid.setdefault(e.get("pid", 0), []).append(e)
            for evts in by_pid.values():
                if len(evts) >= 2:
                    detections.extend(
                        check_sequence(sorted(evts, key=lambda x: x["ts"]))
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
                log.error(f"Engine error: {ex}")
                time.sleep(self.poll)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api",           default="http://127.0.0.1:8000")
    ap.add_argument("--poll-interval", default=10,  type=int)
    ap.add_argument("--window",        default=120, type=int)
    ap.add_argument("--pipeline-host", default="127.0.0.1")
    ap.add_argument("--pipeline-port", default=9000, type=int)
    args = ap.parse_args()

    DetectionEngine(
        api_base      = args.api,
        poll_interval = args.poll_interval,
        window        = args.window,
        pipeline_host = args.pipeline_host,
        pipeline_port = args.pipeline_port,
    ).run()


if __name__ == "__main__":
    main()
