#!/usr/bin/env python3
"""
Ghost IT — Pipeline Ingestion Server

Listens for JSON event batches from eBPF agents via TCP.
Validates, enriches, and writes to DuckDB via EventStore.

Usage:
    python3 ingestion/server.py
    python3 ingestion/server.py --host 0.0.0.0 --port 9000
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import json
import socket
import logging
import argparse
import threading
from storage.db import EventStore
from processor.enricher import enrich_batch

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [pipeline] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)


class IngestionServer:
    """
    Multi-threaded TCP server.
    One thread per agent connection.
    Shared EventStore with thread-safe DuckDB writes.
    """

    def __init__(self, host: str, port: int, db_path: str):
        self.host  = host
        self.port  = port
        self.store = EventStore(db_path)
        self.lock  = threading.Lock()
        self._running = False
        self._stats = {"batches": 0, "events": 0, "errors": 0}

    def _handle_client(self, conn: socket.socket, addr: tuple):
        log.info(f"Agent connected: {addr}")
        buf = b""

        try:
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                buf += chunk

                # Events arrive as newline-delimited JSON batches
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

                        with self.lock:
                            n = self.store.insert_batch(enriched)
                            self._stats["batches"] += 1
                            self._stats["events"]  += n

                        alerts = sum(1 for e in enriched if e.get("alert"))
                        if alerts:
                            log.warning(f"[{addr}] {alerts} ALERT events in batch")
                        else:
                            log.debug(f"[{addr}] Inserted {n} events")

                    except (json.JSONDecodeError, Exception) as ex:
                        self._stats["errors"] += 1
                        log.error(f"[{addr}] Bad batch: {ex}")

        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            conn.close()
            log.info(f"Agent disconnected: {addr} | Stats: {self._stats}")

    def start(self):
        self._running = True
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(16)
        log.info(f"Pipeline ingestion listening on {self.host}:{self.port}")

        try:
            while self._running:
                conn, addr = srv.accept()
                t = threading.Thread(
                    target=self._handle_client,
                    args=(conn, addr),
                    daemon=True,
                )
                t.start()
        except KeyboardInterrupt:
            log.info("Shutting down...")
        finally:
            srv.close()
            self.store.close()
            log.info(f"Final stats: {self._stats}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host",    default="127.0.0.1")
    ap.add_argument("--port",    default=9000, type=int)
    ap.add_argument("--db-path", default="/var/lib/ghostit/events.db")
    args = ap.parse_args()

    server = IngestionServer(args.host, args.port, args.db_path)
    server.start()


if __name__ == "__main__":
    main()
