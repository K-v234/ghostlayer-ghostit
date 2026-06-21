"""
Ghost IT — C14: Honeypot Alert Suppressor
Suppresses C14 alerts for traffic going TO honeypot IPs.
C3 (honeypot) owns those alerts — C14 must not duplicate.

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 100% — complete
"""
from __future__ import annotations
import logging
from typing import Set

log = logging.getLogger(__name__)

class HoneypotSuppressor:
    """
    Checks if a destination IP is a known honeypot.
    If yes — suppress C14 alert, let C3 handle it.
    One event, one alert.
    """

    def __init__(self):
        self._honeypot_ips: Set[str] = set()
        self._load_from_orchestrator()

    def _load_from_orchestrator(self):
        """Load honeypot IPs from C3 orchestrator."""
        try:
            import sys, os
            sys.path.insert(0, os.path.expanduser("~/ghostlayer"))
            from deception.honeypots.orchestrator import get_honeypot_ips
            self._honeypot_ips = get_honeypot_ips()
            log.info(f"Honeypot suppressor loaded {len(self._honeypot_ips)} IPs")
        except Exception as e:
            log.warning(f"Cannot load honeypot IPs: {e}")

    def should_suppress(self, dst_ip: str) -> bool:
        """Return True if alert should be suppressed (C3 owns it)."""
        return dst_ip in self._honeypot_ips

    def add_honeypot_ip(self, ip: str):
        """Dynamically add a honeypot IP."""
        self._honeypot_ips.add(ip)
        log.info(f"Honeypot IP added to suppressor: {ip}")

    def refresh(self):
        """Refresh honeypot IP list from C3 orchestrator."""
        self._load_from_orchestrator()

# Singleton
honeypot_suppressor = HoneypotSuppressor()
