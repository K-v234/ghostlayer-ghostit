"""
Ghost IT — Canary Alert Forwarder
Sends canary hit events to the Ghost IT pipeline.
Canary hits are ALWAYS score=100, alert=True — zero ambiguity.
"""
from __future__ import annotations
import json
import socket
import logging
import time
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class CanaryAlert:
    token_id:    str
    token_type:  str
    description: str
    hit_by:      str        # IP or process that triggered it
    hit_method:  str        # http_request | file_open | credential_use
    extra:       dict


class AlertForwarder:
    """
    Forwards canary hits to Ghost IT pipeline as score=100 events.
    Falls back to local log if pipeline unavailable.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 9000):
        self.host = host
        self.port = port

    def _make_event(self, alert: CanaryAlert) -> dict:
        return {
            "ts":          int(time.time_ns()),
            "pid":         0,
            "ppid":        0,
            "uid":         0,
            "gid":         0,
            "comm":        "canary",
            "type":        "canary_hit",
            "score":       100,
            "alert":       True,
            "reasons":     [
                f"canary_hit:{alert.token_type}",
                f"method:{alert.hit_method}",
                alert.description,
            ],
            "file":        alert.description,
            "daddr":       alert.hit_by,
            "canary_id":   alert.token_id,
            "canary_extra": alert.extra,
        }

    def send(self, alert: CanaryAlert):
        event = self._make_event(alert)
        payload = (json.dumps([event]) + "\n").encode()

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((self.host, self.port))
            s.sendall(payload)
            s.close()
            log.warning(
                f"CANARY HIT [{alert.token_type}] {alert.description} "
                f"| trigger={alert.hit_method} | by={alert.hit_by}"
            )
        except OSError:
            log.critical(
                f"CANARY HIT (pipeline down) [{alert.token_type}] "
                f"{alert.description} | by={alert.hit_by}"
            )
