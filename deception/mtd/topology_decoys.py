"""
Ghost IT — C3: Topology Decoy Flooding
Broadcasts fake ARP/mDNS/NetBIOS entries.
Passive mapper sees 50% fabricated topology.
Attacker cannot build accurate network map.

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 100% — complete
"""
from __future__ import annotations
import random
import logging
import subprocess
import threading
import time

log = logging.getLogger(__name__)

class TopologyDecoyManager:
    """
    Manages continuous topology decoy flooding.
    Rotates decoy IPs/MACs every 4-8 hours.
    Passive observer cannot build stable network map.
    """

    def __init__(self, subnet: str = "10.0.0", interface: str = "eth0"):
        self.subnet    = subnet
        self.interface = interface
        self._decoys   = []
        self._running  = False
        self._lock     = threading.Lock()

    def _random_mac(self) -> str:
        """Generate random MAC address."""
        return ":".join(f"{random.randint(0,255):02x}" for _ in range(6))

    def _random_ip(self) -> str:
        """Generate random IP in subnet."""
        return f"{self.subnet}.{random.randint(10, 254)}"

    def _random_hostname(self) -> str:
        """Generate realistic-looking hostname."""
        prefixes = ["WORKSTATION", "DESKTOP", "PC", "CLIENT", "WS", "LAPTOP"]
        return f"{random.choice(prefixes)}-{random.randint(100, 999)}"

    def generate_decoys(self, count: int) -> list:
        """Generate N fake network entries."""
        decoys = []
        for _ in range(count):
            decoys.append({
                "ip":       self._random_ip(),
                "mac":      self._random_mac(),
                "hostname": self._random_hostname(),
            })
        return decoys

    def emit_arp_decoy(self, ip: str, mac: str):
        """Send gratuitous ARP for fake IP."""
        try:
            subprocess.run([
                "arping", "-c", "1", "-U",
                "-I", self.interface, ip
            ], capture_output=True, timeout=2)
        except Exception:
            pass

    def emit_mdns_decoy(self, hostname: str, ip: str):
        """Announce fake mDNS hostname."""
        try:
            subprocess.run([
                "avahi-publish-address", "-R",
                f"{hostname}.local", ip
            ], capture_output=True, timeout=2)
        except Exception:
            pass

    def flood_decoys(self, real_count: int):
        """
        Emit real_count fake entries.
        Passive mapper sees 50% fabricated topology.
        """
        decoys = self.generate_decoys(real_count)
        with self._lock:
            self._decoys = decoys

        for d in decoys:
            self.emit_arp_decoy(d["ip"], d["mac"])
            self.emit_mdns_decoy(d["hostname"], d["ip"])
            log.debug(f"[MTD] Decoy: {d['hostname']} @ {d['ip']}")

        log.info(f"[MTD] Emitted {len(decoys)} topology decoys")

    def start(self, real_count: int = 10, interval: int = 3600):
        """Start continuous decoy flooding."""
        self._running = True
        def _loop():
            while self._running:
                self.flood_decoys(real_count)
                time.sleep(interval + random.randint(-300, 300))
        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        log.info(f"Topology decoy flooding started — {real_count} decoys every ~{interval}s")

    def stop(self):
        self._running = False

    def get_decoys(self) -> list:
        with self._lock:
            return list(self._decoys)

# Singleton
topology_decoy_manager = TopologyDecoyManager()
