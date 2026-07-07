"""
Ghost IT — C7: gRPC/mTLS Pipeline Server

Receives events from agents via mutual TLS authenticated gRPC.
Replaces TCP ingestion server for production deployments.

Ghost Layer Technologies — CONFIDENTIAL
"""
from __future__ import annotations
import os
import time
import json
import logging
import threading
from concurrent import futures
from typing import Iterator

import grpc
import ghost_pb2
import ghost_pb2_grpc
from comms.pq_interceptor import pq_interceptor

log = logging.getLogger(__name__)

CERTS_DIR = os.path.expanduser("~/ghostlayer/comms/certs")


class GhostPipelineServicer(ghost_pb2_grpc.GhostPipelineServicer):
    """
    gRPC service implementation.
    Receives event batches from agents, passes to storage layer.
    """

    def __init__(self, insert_batch_fn, lock):
        self.insert_batch = insert_batch_fn
        self.lock         = lock
        self._stats       = {"batches": 0, "events": 0, "errors": 0}

    def IngestEvents(
        self,
        request_iterator: Iterator[ghost_pb2.EventBatch],
        context: grpc.ServicerContext,
    ) -> ghost_pb2.IngestResponse:
        """
        Bidirectional stream: agent sends batches, server ACKs.
        mTLS peer cert validated by gRPC framework before reaching here.
        """
        peer = context.peer()
        log.info(f"Agent connected: {peer}")
        total = 0

        try:
            for batch in request_iterator:
                events = []
                for e in batch.events:
                    events.append({
                        "ts":        e.ts,
                        "pid":       e.pid,
                        "tgid":      e.tgid,
                        "ppid":      e.parent_pid,
                        "uid":       e.uid,
                        "gid":       e.gid,
                        "comm":      e.comm,
                        "type":      e.event_type,
                        "priority":  e.priority,
                        "flags":     e.flags,
                        "path":      e.path or None,
                        "score":     int(e.score),
                        "alert":     e.alert,
                        "reasons":   list(e.reasons),
                    })

                if events:
                    # Import here to avoid circular import
                    from pipeline.server import enrich_batch, insert_batch
                    enriched = enrich_batch(events)
                    with self.lock:
                        n = insert_batch(enriched)
                    self._stats["batches"] += 1
                    self._stats["events"]  += n
                    total += n

                    alerts = sum(1 for e in enriched if e.get("alert"))
                    if alerts:
                        log.warning(f"[{peer}] {alerts} ALERT events in batch")

        except Exception as ex:
            self._stats["errors"] += 1
            log.error(f"[{peer}] Stream error: {ex}")

        log.info(f"Agent disconnected: {peer} | events={total}")
        return ghost_pb2.IngestResponse(
            success         = True,
            events_received = total,
            message         = "OK",
        )

    def HealthCheck(
        self,
        request: ghost_pb2.HealthRequest,
        context: grpc.ServicerContext,
    ) -> ghost_pb2.HealthResponse:
        return ghost_pb2.HealthResponse(
            healthy        = True,
            server_version = "0.1.0",
            server_ts      = int(time.time_ns()),
        )


def load_mtls_credentials_server() -> grpc.ServerCredentials:
    """Load server-side mTLS credentials."""
    with open(f"{CERTS_DIR}/server.key",  "rb") as f: server_key  = f.read()
    with open(f"{CERTS_DIR}/server.crt",  "rb") as f: server_cert = f.read()
    with open(f"{CERTS_DIR}/ca.crt",      "rb") as f: ca_cert     = f.read()

    return grpc.ssl_server_credentials(
        private_key_certificate_chain_pairs=[(server_key, server_cert)],
        root_certificates=ca_cert,
        require_client_auth=True,  # mTLS — client cert required
    )


def start_grpc_server(
    host: str,
    port: int,
    insert_batch_fn,
    lock,
) -> grpc.Server:
    """Start gRPC server with mTLS."""
    server = grpc.server(
        futures.ThreadPoolExecutor(max_workers=10,
        interceptors=[pq_interceptor]),
        options=[
            ("grpc.max_receive_message_length", 10 * 1024 * 1024),
            ("grpc.keepalive_time_ms",          30000),
            ("grpc.keepalive_timeout_ms",       10000),
        ],
    )

    servicer = GhostPipelineServicer(insert_batch_fn, lock)
    ghost_pb2_grpc.add_GhostPipelineServicer_to_server(servicer, server)

    credentials = load_mtls_credentials_server()
    server.add_secure_port(f"{host}:{port}", credentials)
    server.start()

    log.info(f"gRPC/mTLS server listening on {host}:{port}")
    return server
