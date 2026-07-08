#!/usr/bin/env python3
"""
Ghost IT Agent — Pipeline Forwarder v3
- Scored + filtered events
- Time-based flush (every 5s) + size-based flush (every N events)
- Auto-reconnect on pipeline disconnect
"""
import sys
import json
import os
import socket
import logging
import argparse
import threading
from typing import Optional
from events import GhostEvent
from scorer import score, THRESHOLD_LOG, THRESHOLD_ALERT

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ghost-agent] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stderr,
)
log = logging.getLogger(__name__)


class PipelineForwarder:
    def __init__(self, host: str, port: int,
                 batch_size: int = 50, flush_interval: float = 5.0):
        self.host           = host
        self.port           = port
        self.batch_size     = batch_size
        self.flush_interval = flush_interval
        self.batch: list    = []
        self.lock           = threading.Lock()
        self.sock: Optional[socket.socket] = None
        self._connect()
        self._start_timer()

    def _connect(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((self.host, self.port))
            self.sock = s
            log.info(f"Connected to pipeline at {self.host}:{self.port}")
        except (ConnectionRefusedError, OSError):
            log.warning("Pipeline unavailable — stdout fallback active")
            self.sock = None

    def _start_timer(self):
        """Flush on timer regardless of batch size."""
        def _tick():
            self.flush()
            self._timer = threading.Timer(self.flush_interval, _tick)
            self._timer.daemon = True
            self._timer.start()
        self._timer = threading.Timer(self.flush_interval, _tick)
        self._timer.daemon = True
        self._timer.start()

    def forward(self, event: GhostEvent, event_score: int, reasons: list):
        payload = event.to_dict()
        payload["score"]   = event_score
        payload["reasons"] = reasons
        payload["alert"]   = event_score >= THRESHOLD_ALERT
        with self.lock:
            self.batch.append(payload)
            if len(self.batch) >= self.batch_size:
                self._flush_locked()

    def flush(self):
        with self.lock:
            self._flush_locked()

    def _flush_locked(self):
        if not self.batch:
            return
        data = (json.dumps(self.batch) + "\n").encode()
        if self.sock:
            try:
                self.sock.sendall(data)
                log.debug(f"Flushed {len(self.batch)} events")
            except OSError:
                log.warning("Pipeline connection lost — reconnecting")
                self._connect()
                if self.sock:
                    try:
                        self.sock.sendall(data)
                    except OSError:
                        sys.stdout.buffer.write(data)
                        sys.stdout.flush()
        else:
            sys.stdout.buffer.write(data)
            sys.stdout.flush()
        self.batch.clear()

    def close(self):
        if hasattr(self, "_timer"):
            self._timer.cancel()
        self.flush()
        if self.sock:
            self.sock.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host",           default="127.0.0.1")
    ap.add_argument("--port",           default=9000, type=int)
    ap.add_argument("--batch-size",     default=50,   type=int)
    ap.add_argument("--flush-interval", default=5.0,  type=float)
    ap.add_argument("--dry-run",        action="store_true")
    args = ap.parse_args()

    forwarder = None if args.dry_run else PipelineForwarder(
        args.host, args.port, args.batch_size, args.flush_interval
    )

    stats = {"total": 0, "dropped": 0, "logged": 0, "alerted": 0}
    log.info("Ghost IT Agent v3 started")

    # C6 Layer 3: Start binary hash watchdog
    try:
        import sys as _sys
        _sys.path.insert(0, os.path.dirname(__file__))
        from watchdog import start_watchdog_background
        _watchdog = start_watchdog_background(
            pipeline_host=args.host,
            pipeline_port=args.port,
        )
    except Exception as _ex:
        log.warning(f"Watchdog init failed: {_ex}")

    try:
        sys.stdin.reconfigure(errors='replace')
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                event = GhostEvent.from_dict(json.loads(line))
                stats["total"] += 1
                s, reasons = score(event)

                if s < THRESHOLD_LOG:
                    stats["dropped"] += 1
                    continue

                if s >= THRESHOLD_ALERT:
                    stats["alerted"] += 1
                else:
                    stats["logged"] += 1

                if args.dry_run:
                    out = event.to_dict()
                    out["score"]   = s
                    out["reasons"] = reasons
                    out["level"]   = "ALERT" if s >= THRESHOLD_ALERT else "LOG"
                    print(json.dumps(out), flush=True)
                else:
                    forwarder.forward(event, s, reasons)

                if stats["total"] % 500 == 0:
                    log.info(f"Stats: {stats}")

            except (json.JSONDecodeError, TypeError) as ex:
                log.error(f"Bad event: {ex} | raw: {line[:80]}")

    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        if forwarder:
            forwarder.close()
        log.info(f"Final stats: {stats}")


if __name__ == "__main__":
    main()
