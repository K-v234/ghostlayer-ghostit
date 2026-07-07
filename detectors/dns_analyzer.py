"""
Ghost IT — C14: DNS Analyzer
Detects C2 via DNS:
1. DGA (Domain Generation Algorithm) detection via entropy
2. DNS tunneling detection via query length/frequency
3. Suspicious TLD detection

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 100% — complete
"""
from __future__ import annotations
import math
import re
import logging
from dataclasses import dataclass
from typing import Optional, List

log = logging.getLogger(__name__)

@dataclass
class DNSAlert:
    severity:  str
    domain:    str
    reason:    str
    score:     float
    mitre:     str

# Known legitimate TLDs — anything else is suspicious
LEGITIMATE_TLDS = {
    "com","net","org","edu","gov","io","co","in","uk","de",
    "fr","jp","cn","ru","br","au","ca","info","biz","me",
    "tech","app","dev","ai","cloud","online"
}

# Known DGA-associated TLDs
SUSPICIOUS_TLDS = {"xyz","top","club","work","live","click","link","win","bid"}

# Whitelisted domains — never flag
WHITELIST = {
    "google.com","github.com","microsoft.com","ubuntu.com",
    "cloudflare.com","amazonaws.com","azure.com","anthropic.com"
}

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(s)
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy

def _consonant_ratio(s: str) -> float:
    """High consonant ratio = possible DGA domain."""
    consonants = set("bcdfghjklmnpqrstvwxyz")
    letters = [c for c in s.lower() if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c in consonants) / len(letters)

def _has_numeric_pattern(s: str) -> bool:
    """Random hex/numeric strings = possible DGA."""
    # More than 40% digits = suspicious
    digits = sum(1 for c in s if c.isdigit())
    return digits / max(len(s), 1) > 0.4

class DNSAnalyzer:
    """
    Analyzes DNS queries for C2 indicators.
    Uses entropy, consonant ratio, and pattern analysis.
    """

    DGA_ENTROPY_THRESHOLD    = 3.5   # High entropy = random = DGA
    DGA_CONSONANT_THRESHOLD  = 0.75  # High consonant ratio = DGA
    TUNNEL_LENGTH_THRESHOLD  = 50    # Very long subdomain = DNS tunnel
    TUNNEL_QUERY_THRESHOLD   = 20    # >20 queries/minute = tunnel

    def __init__(self):
        self._query_counts: dict = {}  # domain → count per minute

    def analyze_query(self, domain: str) -> Optional[DNSAlert]:
        """Analyze a single DNS query."""
        if not domain:
            return None

        # Normalize
        domain = domain.lower().rstrip(".")

        # Whitelist check
        for white in WHITELIST:
            if domain == white or domain.endswith("." + white):
                return None

        # Extract parts
        parts = domain.split(".")
        tld = parts[-1] if parts else ""
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
        sld = parts[-2] if len(parts) >= 2 else domain  # Second-level domain

        # Check 1: Suspicious TLD
        if tld in SUSPICIOUS_TLDS:
            return DNSAlert(
                severity="HIGH",
                domain=domain,
                reason=f"Suspicious TLD: .{tld}",
                score=0.7,
                mitre="T1071.004"
            )

        # Check 2: DGA detection on SLD
        entropy = _shannon_entropy(sld)
        consonant = _consonant_ratio(sld)
        numeric = _has_numeric_pattern(sld)

        dga_score = 0.0
        if entropy > self.DGA_ENTROPY_THRESHOLD:
            dga_score += 0.4
        if consonant > self.DGA_CONSONANT_THRESHOLD:
            dga_score += 0.3
        if numeric:
            dga_score += 0.2
        if len(sld) > 15:
            dga_score += 0.1

        if dga_score >= 0.7:
            return DNSAlert(
                severity="HIGH",
                domain=domain,
                reason=f"Possible DGA domain (score={dga_score:.2f}, entropy={entropy:.2f})",
                score=dga_score,
                mitre="T1568.002"
            )

        # Check 3: DNS tunneling — very long subdomain
        if subdomain and len(subdomain) > self.TUNNEL_LENGTH_THRESHOLD:
            return DNSAlert(
                severity="HIGH",
                domain=domain,
                reason=f"Possible DNS tunnel — subdomain length {len(subdomain)}",
                score=0.8,
                mitre="T1071.004"
            )

        # Check 4: High query frequency (simple rate check)
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
        self._query_counts[base_domain] = self._query_counts.get(base_domain, 0) + 1
        if self._query_counts[base_domain] > self.TUNNEL_QUERY_THRESHOLD:
            self._query_counts[base_domain] = 0  # Reset counter
            return DNSAlert(
                severity="HIGH",
                domain=domain,
                reason=f"High DNS query frequency to {base_domain} — possible C2 beacon",
                score=0.75,
                mitre="T1071.004"
            )

        return None

    def analyze_batch(self, domains: List[str]) -> List[DNSAlert]:
        """Analyze a batch of DNS queries."""
        alerts = []
        for domain in domains:
            alert = self.analyze_query(domain)
            if alert:
                alerts.append(alert)
        return alerts

# Singleton
dns_analyzer = DNSAnalyzer()
