"""
Ghost IT — Behavioral Aggregator
Detects anomalies across time windows.
Flags processes doing too much of one thing in a short period.
"""
from __future__ import annotations
from collections import defaultdict
from .rules import Detection


# Thresholds per 60-second window
THRESHOLDS = {
    "sensitive_reads":  15,    # >5 sensitive file reads = suspicious
    "exec_count":       25,   # >10 exec calls = suspicious
    "connect_count":    8,    # >8 outbound connections = suspicious
    "unique_ips":       5,    # >5 unique IPs = scanning
    "unlink_count":     3,    # >3 deletions = suspicious
}


def analyze_window(events: list[dict]) -> list[Detection]:
    """
    Analyze a time window of events for behavioral anomalies.
    Events should be from a single process or all processes.
    """
    detections = []

    # Group by comm
    by_comm: dict[str, list[dict]] = defaultdict(list)
    for e in events:
        by_comm[e.get("comm", "unknown")].append(e)

    for comm, evts in by_comm.items():
        if comm in ("canary", "unknown", ""):
            continue

        # Count sensitive file reads
        sensitive_reads = sum(
            1 for e in evts
            if e.get("type") == "open" and
            any(s in (e.get("file") or "") for s in
                ("/etc/passwd", "/etc/shadow", "/etc/sudoers",
                 "id_rsa", "authorized_keys", ".bash_history",
                 "/etc/crontab", ".ssh"))
        )

        if sensitive_reads >= THRESHOLDS["sensitive_reads"]:
            detections.append(Detection(
                rule_id     = "B001",
                severity    = "high",
                title       = "Sensitive File Enumeration Burst",
                description = (
                    f"{comm} read {sensitive_reads} sensitive files "
                    f"in analysis window"
                ),
                confidence  = 78,
                evidence    = evts[:5],
            ))

        # Count exec calls
        exec_count = sum(1 for e in evts if e.get("type") == "exec")
        if exec_count >= THRESHOLDS["exec_count"]:
            detections.append(Detection(
                rule_id     = "B002",
                severity    = "medium",
                title       = "Execution Burst",
                description = (
                    f"{comm} executed {exec_count} processes "
                    f"in analysis window — possible script activity"
                ),
                confidence  = 65,
                evidence    = evts[:5],
            ))

        # Count outbound connections + unique IPs
        connects    = [e for e in evts if e.get("type") == "connect"]
        unique_ips  = len({e.get("daddr") for e in connects if e.get("daddr")})

        if len(connects) >= THRESHOLDS["connect_count"]:
            detections.append(Detection(
                rule_id     = "B003",
                severity    = "high",
                title       = "Connection Burst",
                description = (
                    f"{comm} made {len(connects)} outbound connections "
                    f"to {unique_ips} unique IPs — possible C2 beacon or scan"
                ),
                confidence  = 72,
                evidence    = connects[:5],
            ))

        if unique_ips >= THRESHOLDS["unique_ips"]:
            detections.append(Detection(
                rule_id     = "B004",
                severity    = "high",
                title       = "Network Scanning Behavior",
                description = (
                    f"{comm} connected to {unique_ips} unique IPs — "
                    f"possible port scan or C2 rotation"
                ),
                confidence  = 80,
                evidence    = connects[:5],
            ))

        # Count deletions
        unlink_count = sum(1 for e in evts if e.get("type") == "unlink")
        if unlink_count >= THRESHOLDS["unlink_count"]:
            detections.append(Detection(
                rule_id     = "B005",
                severity    = "high",
                title       = "Mass File Deletion",
                description = (
                    f"{comm} deleted {unlink_count} files — "
                    f"possible ransomware or anti-forensics"
                ),
                confidence  = 85,
                evidence    = evts[:5],
            ))

    return detections
