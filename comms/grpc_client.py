"""
Ghost IT — C7: gRPC/mTLS Agent Client

Sends events to pipeline via mutual TLS authenticated gRPC.
Features:
  - Certificate pinning
  - 72-hour offline buffer
  - Jittered exponential backoff reconnection

Ghost Layer Technologies — CONFIDENTIAL
"""
from __future__ import annotations
import os
import time
import json
import random
import logging
import threading
from typing import Iterator
from collections import deque

import grpc
import ghost_pb2
import ghost_pb2_grpc

log = logging.getLogger(__name__)

CERTS_DIR    = os.path.expanduser("~/ghostlayer/comms/certs")
OFFLINE_PATH = os.path.expanduser("~/ghostlayer/data/offline_buffer.jsonl")

# 72-hour offline buffer limit
MAX_OFFLINE_EVENTS = 72 * 3600 * 10  # ~10 events/sec for 72h


def load_mtls_credentials_client() -> grpc.ChannelCredentials:
    """Load client-side mTLS credentials with CA pinning."""
    with open(f"{CERTS_DIR}/agent.key",  "rb") as f: agent_key  = f.read()
    with open(f"{CERTS_DIR}/agent.crt",  "rb") as f: agent_cert = f.read()
    with open(f"{CERTS_DIR}/ca.crt",     "rb") as f: ca_cert    = f.read()

    return grpc.ssl_channel_credentials(
        root_certificates        = ca_cert,    # CA pinning
        private_key              = agent_key,
        certificate_chain        = agent_cert,
    )


class OfflineBuffer:
    """
    Persistent offline buffer for 72-hour resilience.
    Events written to disk when pipeline unreachable.
    """

    def __init__(self, path: str = OFFLINE_PATH):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def write(self, events: list[dict]):
        with open(self.path, "a") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

    def read_all(self) -> list[dict]:
        if not os.path.exists(self.path):
            return []
        events = []
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return events

    def clear(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def size(self) -> int:
        if not os.path.exists(self.path):
            return 0
        return sum(1 for _ in open(self.path))


class GhostGRPCClient:
    """
    mTLS gRPC client for Ghost IT agent.

    Handles:
    - Secure connection with certificate pinning
    - Automatic reconnection with jittered backoff
    - 72-hour offline buffering
    - Batch streaming to pipeline
    """

    AGENT_ID      = os.environ.get("GHOST_AGENT_ID", "ghost-agent-001")
    AGENT_VERSION = "0.1.0"

    def __init__(self, host: str = "127.0.0.1", port: int = 9443,
                 batch_size: int = 50, flush_interval: float = 5.0):
        self.host           = host
        self.port           = port
        self.batch_size     = batch_size
        self.flush_interval = flush_interval

        self._batch:   list[dict]  = []
        self._lock     = threading.Lock()
        self._channel  = None
        self._stub     = None
        self._offline  = OfflineBuffer()
        self._backoff  = 1.0   # seconds
        self._max_back = 300.0 # 5 minutes max

        self._connect()
        self._start_flush_timer()

    def _connect(self):
        """Connect with mTLS credentials."""
        try:
            creds = load_mtls_credentials_client()
            self._channel = grpc.secure_channel(
                f"{self.host}:{self.port}",
                creds,
                options=[
                    ("grpc.keepalive_time_ms",        30000),
                    ("grpc.keepalive_timeout_ms",     10000),
                    ("grpc.keepalive_permit_without_calls", True),
                ],
            )
            self._stub    = ghost_pb2_grpc.GhostPipelineStub(self._channel)

            # Test connection
            resp = self._stub.HealthCheck(
                ghost_pb2.HealthRequest(agent_id=self.AGENT_ID),
                timeout=3.0,
            )
            if resp.healthy:
                log.info(f"gRPC/mTLS connected to {self.host}:{self.port}")
                self._backoff = 1.0  # Reset backoff

                # Flush offline buffer if any
                self._flush_offline()

        except Exception as ex:
            log.warning(f"gRPC connection failed: {ex} — offline mode")
            self._stub = None

    def _reconnect_with_backoff(self):
        """Jittered exponential backoff reconnection."""
        jitter = random.uniform(0.5, 1.5)
        delay  = min(self._backoff * jitter, self._max_back)
        log.info(f"Reconnecting in {delay:.1f}s...")
        time.sleep(delay)
        self._backoff = min(self._backoff * 2, self._max_back)
        self._connect()

    def _start_flush_timer(self):
        """Timer-based flush every N seconds."""
        def tick():
            while True:
                time.sleep(self.flush_interval)
                self.flush()
        t = threading.Thread(target=tick, daemon=True)
        t.start()

    def send(self, event: dict):
        """Add event to batch."""
        with self._lock:
            self._batch.append(event)
            if len(self._batch) >= self.batch_size:
                self._send_batch(list(self._batch))
                self._batch.clear()

    def flush(self):
        """Force flush current batch."""
        with self._lock:
            if not self._batch:
                return
            batch = list(self._batch)
            self._batch.clear()
        self._send_batch(batch)

    def _send_batch(self, events: list[dict]):
        """Send batch via gRPC or write to offline buffer."""
        if not self._stub:
            self._offline.write(events)
            log.debug(f"Offline: {len(events)} events buffered")
            self._reconnect_with_backoff()
            return

        try:
            proto_batch = ghost_pb2.EventBatch(
                agent_id      = self.AGENT_ID,
                agent_version = self.AGENT_VERSION,
                batch_ts      = int(time.time_ns()),
                events        = [self._to_proto(e) for e in events],
            )

            def batch_iter():
                yield proto_batch

            resp = self._stub.IngestEvents(batch_iter(), timeout=10.0)
            log.debug(f"Sent {resp.events_received} events via gRPC")

        except grpc.RpcError as ex:
            log.warning(f"gRPC send failed: {ex.code()} — buffering offline")
            self._offline.write(events)
            self._stub = None
            threading.Thread(
                target=self._reconnect_with_backoff,
                daemon=True,
            ).start()

    def _flush_offline(self):
        """Send buffered offline events after reconnection."""
        events = self._offline.read_all()
        if not events:
            return
        log.info(f"Flushing {len(events)} offline-buffered events")
        self._send_batch(events)
        self._offline.clear()

    @staticmethod
    def _to_proto(e: dict) -> ghost_pb2.Event:
        return ghost_pb2.Event(
            ts          = int(e.get("ts", 0)),
            pid         = int(e.get("pid", 0)),
            tgid        = int(e.get("tgid", 0)),
            parent_pid  = int(e.get("ppid", e.get("parent_pid", 0))),
            uid         = int(e.get("uid", 0)),
            gid         = int(e.get("gid", 0)),
            comm        = str(e.get("comm", "")),
            event_type  = str(e.get("type", "")),
            priority    = int(e.get("priority", 0)),
            flags       = int(e.get("flags", 0)),
            path        = str(e.get("path") or e.get("file") or ""),
            score       = float(e.get("score", 0)),
            alert       = bool(e.get("alert", False)),
            reasons     = list(e.get("reasons", [])),
        )
