#!/usr/bin/env python3
"""
Ghost IT Agent — Pipeline Forwarder (v2 — scored + filtered)

Flow:
  kernel eBPF → JSON stdin → scorer → [drop/log/alert] → pipeline TCP
"""
import sys
import json
import socket
import logging
import argparse
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
    def __init__(self, host: str, port: int, batch_size: int = 50):
        self.host       = host
        self.port       = port
        self.batch_size = batch_size
        self.batch: list = []
        self.sock: Optional[socket.socket] = None
        self._connect()

    def _connect(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((self.host, self.port))
            self.sock = s
            log.info(f"Connected to pipeline at {self.host}:{self.port}")
        except (ConnectionRefusedError, OSError):
            log.warning(f"Pipeline unavailable — stdout fallback active")
            self.sock = None

    def forward(self, event: GhostEvent, event_score: int, reasons: list):
        payload = event.to_dict()
        payload["score"]   = event_score
        payload["reasons"] = reasons
        payload["alert"]   = event_score >= THRESHOLD_ALERT
        self.batch.append(payload)
        if len(self.batch) >= self.batch_size:
            self.flush()

    def flush(self):
        if not self.batch:
            return
        data = (json.dumps(self.batch) + "\n").encode()
        if self.sock:
            try:
                self.sock.sendall(data)
            except OSError:
                self._connect()
                if self.sock:
                    self.sock.sendall(data)
        else:
            sys.stdout.buffer.write(data)
            sys.stdout.flush()
        self.batch.clear()

    def close(self):
        self.flush()
        if self.sock:
            self.sock.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host",       default="127.0.0.1")
    ap.add_argument("--port",       default=9000, type=int)
    ap.add_argument("--batch-size", default=50,   type=int)
    ap.add_argument("--dry-run",    action="store_true")
    ap.add_argument("--verbose",    action="store_true",
                    help="Print all events including low-score ones")
    args = ap.parse_args()

    forwarder = None if args.dry_run else PipelineForwarder(
        args.host, args.port, args.batch_size
    )

    stats = {"total": 0, "dropped": 0, "logged": 0, "alerted": 0}
    log.info("Ghost IT Agent v2 started")

    try:
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
                    level = "ALERT"
                else:
                    stats["logged"] += 1
                    level = "LOG"

                if args.dry_run:
                    out = event.to_dict()
                    out["score"]   = s
                    out["reasons"] = reasons
                    out["level"]   = level
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
