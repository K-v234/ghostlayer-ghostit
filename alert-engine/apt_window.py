"""
Ghost IT — C17: APT Correlation Window
Per Dakshin's analysis — 15-minute window misses APT36.
Recon at 9am + lateral movement at 2pm = same attack.

Configurable windows per attack type.

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 100% — complete
"""
from datetime import timedelta
from enum import Enum

class AttackMode(str, Enum):
    RANSOMWARE = "ransomware"
    APT        = "apt"
    DEFAULT    = "default"

# Correlation windows per attack mode
CORRELATION_WINDOWS = {
    AttackMode.RANSOMWARE: timedelta(minutes=15),   # Fast attack
    AttackMode.APT:        timedelta(hours=4),       # APT36 style
    AttackMode.DEFAULT:    timedelta(minutes=15),    # Default
}

# MITRE tactics that indicate APT (slow, stealthy)
APT_TACTICS = {
    "TA0043",  # Reconnaissance
    "TA0042",  # Resource Development
    "TA0001",  # Initial Access
    "TA0003",  # Persistence
    "TA0005",  # Defense Evasion
    "TA0006",  # Credential Access
    "TA0007",  # Discovery
    "TA0008",  # Lateral Movement
    "TA0009",  # Collection
    "TA0011",  # Command and Control
}

# MITRE tactics that indicate ransomware (fast)
RANSOMWARE_TACTICS = {
    "TA0040",  # Impact
    "TA0010",  # Exfiltration
}

def detect_attack_mode(mitre_tactic: str) -> AttackMode:
    """Detect attack mode from first alert's MITRE tactic."""
    if mitre_tactic in RANSOMWARE_TACTICS:
        return AttackMode.RANSOMWARE
    if mitre_tactic in APT_TACTICS:
        return AttackMode.APT
    return AttackMode.DEFAULT

def get_window(mode: AttackMode) -> timedelta:
    """Get correlation window for attack mode."""
    return CORRELATION_WINDOWS.get(mode, CORRELATION_WINDOWS[AttackMode.DEFAULT])
