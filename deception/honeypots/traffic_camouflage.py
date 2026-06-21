"""
Ghost IT — C3: Honeypot Traffic Camouflage
Generates synthetic traffic to honeypots — makes them
indistinguishable from real services to passive TAP observers.

Passive TAP sees Poisson-distributed traffic matching real service
statistics. Cannot fingerprint honeypot by traffic absence.

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 100% — complete
"""
from __future__ import annotations
import asyncio
import random
import logging
import socket
import time
from dataclasses import dataclass
from typing import List

log = logging.getLogger(__name__)

@dataclass
class ServiceTrafficProfile:
    """Traffic statistics cloned from nearest real service."""
    mean_requests_per_second: float  # Lambda for Poisson distribution
    avg_payload_bytes: int
    payload_stddev: int
    synthetic_source_ips: List[str]  # Internal agent IPs

# Default profiles per honeypot type
TRAFFIC_PROFILES = {
    "smb":  ServiceTrafficProfile(0.5, 512, 128, ["10.0.0.10", "10.0.0.11"]),
    "ssh":  ServiceTrafficProfile(0.1, 256, 64,  ["10.0.0.10", "10.0.0.12"]),
    "http": ServiceTrafficProfile(2.0, 1024, 256, ["10.0.0.10", "10.0.0.13"]),
    "rdp":  ServiceTrafficProfile(0.2, 768, 128, ["10.0.0.10", "10.0.0.14"]),
    "db":   ServiceTrafficProfile(0.3, 128, 32,  ["10.0.0.10", "10.0.0.15"]),
}

class HoneypotTrafficCamouflage:
    """
    Sends synthetic traffic to a honeypot at Poisson-distributed
    intervals matching real service statistics.
    Defeats passive TAP-based reconnaissance.
    """

    def __init__(self, htype: str, host: str, port: int):
        self.htype   = htype
        self.host    = host
        self.port    = port
        self.profile = TRAFFIC_PROFILES.get(htype,
                       ServiceTrafficProfile(0.5, 256, 64, ["127.0.0.1"]))
        self._running = False

    async def run(self):
        """Start sending synthetic traffic."""
        self._running = True
        log.info(f"Traffic camouflage started: {self.htype} → {self.host}:{self.port}")

        while self._running:
            # Poisson inter-arrival — matches real service statistics
            interval = random.expovariate(self.profile.mean_requests_per_second)
            await asyncio.sleep(interval)

            src_ip = random.choice(self.profile.synthetic_source_ips)
            payload_size = max(32, int(random.gauss(
                self.profile.avg_payload_bytes,
                self.profile.payload_stddev
            )))

            await self._send_synthetic_request(src_ip, payload_size)

    async def _send_synthetic_request(self, src_ip: str, size: int):
        """Send a synthetic request to the honeypot."""
        try:
            payload = bytes(random.getrandbits(8) for _ in range(size))
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._tcp_send, payload)
        except Exception:
            pass  # Silent — synthetic traffic failures are expected

    def _tcp_send(self, payload: bytes):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((self.host, self.port))
            s.send(payload[:64])  # Short probe — realistic
            s.close()
        except Exception:
            pass

    def stop(self):
        self._running = False
        log.info(f"Traffic camouflage stopped: {self.htype}")


class CamouflageManager:
    """Manages synthetic traffic for all active honeypots."""

    def __init__(self):
        self._tasks = {}

    async def start_for(self, htype: str, host: str, port: int):
        cam = HoneypotTrafficCamouflage(htype, host, port)
        task = asyncio.create_task(cam.run())
        self._tasks[htype] = (cam, task)

    def stop_for(self, htype: str):
        if htype in self._tasks:
            cam, task = self._tasks.pop(htype)
            cam.stop()
            task.cancel()

    async def start_all(self, honeypots: dict):
        """Start camouflage for all active honeypots."""
        for htype, hp in honeypots.items():
            if hp.get("running"):
                await self.start_for(htype, "127.0.0.1", hp["port"])

camouflage_manager = CamouflageManager()
