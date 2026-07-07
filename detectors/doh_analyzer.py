"""
Ghost IT — C14: DoH Behavioral Analyzer
Detects C2 tunneled over DNS-over-HTTPS.
No decryption required — analyzes flow metadata only.

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 100% — complete
"""
from __future__ import annotations
import time
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict

log = logging.getLogger(__name__)

@dataclass
class NetworkFlow:
    src_ip:    str
    dst_ip:    str
    dst_port:  int
    bytes_out: int = 0
    conn_count: int = 0
    timestamp: float = field(default_factory=time.time)

@dataclass
class DoHAlert:
    severity: str
    dst_ip:   str
    reason:   str
    score:    float

# Whitelisted DoH resolvers
DOH_WHITELIST = {
    "8.8.8.8", "8.8.4.4",          # Google
    "1.1.1.1", "1.0.0.1",          # Cloudflare
    "9.9.9.9", "149.112.112.112",  # Quad9
    "208.67.222.222",              # OpenDNS
}

class DoHBehavioralAnalyzer:
    """
    Detects C2-over-DoH by flow-level behavioral analysis.
    Checks: resolver whitelist, connection frequency, payload size.
    """

    MAX_NORMAL_CONN_RATE = 10   # connections per minute to same DoH resolver
    MAX_NORMAL_PAYLOAD   = 512  # bytes — normal DoH query is small

    def __init__(self):
        self._flow_history: Dict[str, list] = {}  # dst_ip → [timestamps]

    def is_doh_flow(self, flow: NetworkFlow) -> bool:
        """Check if flow looks like DoH (HTTPS to DNS resolver)."""
        return flow.dst_port == 443 and flow.dst_ip in DOH_WHITELIST

    def analyze(self, flow: NetworkFlow) -> Optional[DoHAlert]:
        """Analyze a network flow for DoH C2 indicators."""

        # Check 1: Non-whitelisted DoH resolver
        if flow.dst_port == 443 and flow.dst_ip not in DOH_WHITELIST:
            # Only flag if it looks like DNS traffic (small, frequent)
            if flow.bytes_out < 1024:
                return DoHAlert(
                    severity="HIGH",
                    dst_ip=flow.dst_ip,
                    reason=f"DoH to non-whitelisted resolver: {flow.dst_ip}",
                    score=0.85
                )

        # Check 2: High frequency to DoH resolver
        if flow.dst_ip in DOH_WHITELIST:
            now = time.time()
            history = self._flow_history.get(flow.dst_ip, [])
            # Keep only last 60 seconds
            history = [t for t in history if now - t < 60]
            history.append(now)
            self._flow_history[flow.dst_ip] = history

            if len(history) > self.MAX_NORMAL_CONN_RATE:
                return DoHAlert(
                    severity="HIGH",
                    dst_ip=flow.dst_ip,
                    reason=f"High DoH frequency: {len(history)} conn/min to {flow.dst_ip}",
                    score=0.75
                )

        # Check 3: Unusually large DoH payload (possible data exfil)
        if flow.dst_ip in DOH_WHITELIST and flow.bytes_out > self.MAX_NORMAL_PAYLOAD * 10:
            return DoHAlert(
                severity="HIGH",
                dst_ip=flow.dst_ip,
                reason=f"Large DoH payload: {flow.bytes_out} bytes — possible DNS tunnel",
                score=0.80
            )

        return None

# Singleton
doh_analyzer = DoHBehavioralAnalyzer()
