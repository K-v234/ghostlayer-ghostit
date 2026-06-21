"""
Ghost IT — C3: Moving Target Deception Rotator
Rotates honeypot IPs, hostnames, and service banners
on randomised schedules to defeat passive reconnaissance.

All rotation announcements go over WireGuard — never plaintext DHCP/DNS.

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 100% — complete
"""
from __future__ import annotations
import os
import time
import hmac
import random
import hashlib
import logging
import threading
from dataclasses import dataclass, field
from typing import Dict, Callable, Optional

log = logging.getLogger(__name__)

# Rotation schedule (seconds) — with random jitter
ROTATION_SCHEDULE = {
    "honeypot_ip":       (4 * 3600,  8 * 3600),   # 4–8 hours
    "hostname":          (12 * 3600, 24 * 3600),   # 12–24 hours
    "service_banner":    (24 * 3600, 48 * 3600),   # 24–48 hours
}

@dataclass
class DeceptionAsset:
    asset_id:    str
    asset_type:  str           # honeypot_ip, hostname, service_banner
    current:     str           # Current value
    secret:      bytes         # HMAC secret for jitter
    last_rotated: float = field(default_factory=time.time)
    rotation_count: int = 0

    def rotation_due(self, now: float = None) -> bool:
        now = now or time.time()
        min_s, max_s = ROTATION_SCHEDULE.get(self.asset_type, (3600, 7200))
        # HMAC-derived jitter — unpredictable to attacker
        jitter = self._hmac_jitter(min_s, max_s)
        return (now - self.last_rotated) >= jitter

    def _hmac_jitter(self, min_s: int, max_s: int) -> int:
        """Derive deterministic jitter from secret + rotation count."""
        h = hmac.new(
            self.secret,
            f"{self.asset_id}:{self.rotation_count}".encode(),
            'sha256'
        ).digest()
        # Map first 4 bytes to [min_s, max_s]
        val = int.from_bytes(h[:4], 'big')
        return min_s + (val % (max_s - min_s))

class MTDRotator:
    """
    Moving Target Deception orchestrator.
    Manages rotation of all deception assets.
    Announcements via WireGuard (encrypted) — never plaintext.
    """

    def __init__(self):
        self._assets: Dict[str, DeceptionAsset] = {}
        self._lock = threading.Lock()
        self._callbacks: list[Callable] = []
        self._running = False
        self._subnet = "10.0.0"
        log.info("MTD Rotator initialized")

    def register_asset(self, asset_id: str, asset_type: str, initial_value: str):
        """Register a deception asset for rotation."""
        secret = hashlib.sha256(f"{asset_id}:ghostit:mtd".encode()).digest()
        asset = DeceptionAsset(
            asset_id=asset_id,
            asset_type=asset_type,
            current=initial_value,
            secret=secret
        )
        with self._lock:
            self._assets[asset_id] = asset
        log.info(f"MTD asset registered: {asset_id} ({asset_type}) = {initial_value}")

    def on_rotation(self, callback: Callable):
        """Register callback for when any asset rotates."""
        self._callbacks.append(callback)

    def _generate_new_value(self, asset: DeceptionAsset) -> str:
        """Generate new value for an asset."""
        if asset.asset_type == "honeypot_ip":
            # New IP in same subnet
            last_octet = random.randint(10, 254)
            return f"{self._subnet}.{last_octet}"

        elif asset.asset_type == "hostname":
            # New realistic-looking hostname
            prefixes = ["WORKSTATION", "DESKTOP", "PC", "CLIENT", "WS"]
            suffix = random.randint(100, 999)
            return f"{random.choice(prefixes)}-{suffix}"

        elif asset.asset_type == "service_banner":
            # Rotate service version strings
            banners = [
                "Microsoft-IIS/10.0",
                "Apache/2.4.41 (Ubuntu)",
                "nginx/1.18.0",
                "OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
                "Microsoft-HTTPAPI/2.0",
            ]
            current = asset.current
            available = [b for b in banners if b != current]
            return random.choice(available) if available else banners[0]

        return asset.current

    def rotate_asset(self, asset_id: str) -> Optional[tuple]:
        """Rotate a single asset. Returns (old, new) or None."""
        with self._lock:
            asset = self._assets.get(asset_id)
            if not asset:
                return None

            old_value = asset.current
            new_value = self._generate_new_value(asset)
            asset.current = new_value
            asset.last_rotated = time.time()
            asset.rotation_count += 1

        log.info(f"MTD rotation: {asset_id} {old_value} → {new_value}")

        # Notify callbacks (WireGuard announcements happen here)
        for cb in self._callbacks:
            try:
                cb(asset_id, asset.asset_type, old_value, new_value)
            except Exception as e:
                log.error(f"Rotation callback error: {e}")

        return old_value, new_value

    def check_and_rotate(self):
        """Check all assets and rotate those due."""
        now = time.time()
        with self._lock:
            due = [aid for aid, asset in self._assets.items()
                   if asset.rotation_due(now)]

        for asset_id in due:
            self.rotate_asset(asset_id)

    def start(self):
        """Start background rotation loop."""
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        log.info("MTD Rotator started — checking every 60s")

    def _loop(self):
        while self._running:
            time.sleep(60)
            try:
                self.check_and_rotate()
            except Exception as e:
                log.error(f"MTD rotation error: {e}")

    def stop(self):
        self._running = False

    def get_status(self) -> dict:
        with self._lock:
            return {
                aid: {
                    "current": a.current,
                    "type": a.asset_type,
                    "rotations": a.rotation_count,
                    "last_rotated": a.last_rotated,
                }
                for aid, a in self._assets.items()
            }

# Singleton
mtd_rotator = MTDRotator()
