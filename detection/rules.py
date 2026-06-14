"""
Ghost IT — Rule-Based Detector
Fast pattern matching on individual events and small windows.
Rules are ordered by severity. First match wins per event.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional


@dataclass
class Detection:
    rule_id:     str
    severity:    str        # critical | high | medium
    title:       str
    description: str
    confidence:  int        # 0-100
    evidence:    list[dict]


# ------------------------------------------------------------------ #
# Individual event rules                                             #
# ------------------------------------------------------------------ #

def check_event(event: dict) -> Optional[Detection]:
    """
    Check a single event against all rules.
    Returns Detection if a rule fires, None otherwise.
    """
    comm  = event.get("comm", "")
    type_ = event.get("type", "")
    file_ = event.get("file") or ""
    daddr = event.get("daddr") or ""
    dport = event.get("dport") or 0
    score = event.get("score", 0)

    # R001 — Canary hit (always critical)
    if type_ == "canary_hit":
        return Detection(
            rule_id     = "R001",
            severity    = "critical",
            title       = "Canary Token Triggered",
            description = f"Attacker accessed decoy asset: {file_}",
            confidence  = 100,
            evidence    = [event],
        )

    # R002 — Shell reading shadow file
    if comm in ("bash","sh","dash","zsh") and "/etc/shadow" in file_:
        return Detection(
            rule_id     = "R002",
            severity    = "critical",
            title       = "Shadow File Access",
            description = f"{comm} read /etc/shadow — credential theft attempt",
            confidence  = 95,
            evidence    = [event],
        )

    # R003 — Reverse shell ports
    if type_ == "connect" and dport in (4444,1337,31337,9001,6666,8888):
        return Detection(
            rule_id     = "R003",
            severity    = "critical",
            title       = "Reverse Shell Connection",
            description = f"{comm} connected to {daddr}:{dport} — known reverse shell port",
            confidence  = 90,
            evidence    = [event],
        )

    # R004 — Script interpreter making outbound connection
    if type_ == "connect" and comm in ("perl","ruby","php") and event.get("daddr","") != "127.0.0.1":
        return Detection(
            rule_id     = "R004",
            severity    = "high",
            title       = "Interpreter Outbound Connection",
            description = f"{comm} made outbound TCP connection to {daddr}:{dport}",
            confidence  = 75,
            evidence    = [event],
        )

    # R005 — Shell making outbound connection
    if type_ == "connect" and comm in ("bash","sh","dash","zsh"):
        return Detection(
            rule_id     = "R005",
            severity    = "high",
            title       = "Shell Network Activity",
            description = f"{comm} made outbound connection to {daddr}:{dport}",
            confidence  = 80,
            evidence    = [event],
        )

    # R006 — Known attacker tool executed
    if type_ == "exec" and any(t in file_ for t in
            ("/nmap","/nc","/netcat","/socat","/msfconsole","/sqlmap")):
        return Detection(
            rule_id     = "R006",
            severity    = "high",
            title       = "Attacker Tool Executed",
            description = f"Known offensive tool executed: {file_}",
            confidence  = 85,
            evidence    = [event],
        )

    # R007 — Log file deletion
    if type_ == "unlink" and "/var/log" in file_:
        return Detection(
            rule_id     = "R007",
            severity    = "high",
            title       = "Log Deletion",
            description = f"Log file deleted: {file_} — potential cover tracks",
            confidence  = 80,
            evidence    = [event],
        )

    # R008 — Wget/curl downloading to temp
    if type_ == "exec" and comm in ("wget","curl") and \
       any(t in (event.get("args") or "") for t in ("/tmp","/dev/shm")):
        return Detection(
            rule_id     = "R008",
            severity    = "high",
            title       = "Download to Temp Directory",
            description = f"{comm} downloading to suspicious location",
            confidence  = 85,
            evidence    = [event],
        )

    return None


# ------------------------------------------------------------------ #
# Multi-event rules (sequence patterns)                              #
# ------------------------------------------------------------------ #

def check_sequence(events: list[dict]) -> list[Detection]:
    """
    Check a sequence of events from one PID for attack patterns.
    Events must be sorted by timestamp ascending.
    """
    detections = []
    types  = [e.get("type")  for e in events]
    comms  = [e.get("comm")  for e in events]
    files  = [e.get("file")  or "" for e in events]

    # R009 — Reconnaissance pattern: open passwd + open shadow + exec shell
    if ("/etc/passwd" in files and
        any("shadow" in f for f in files) and
        "exec" in types):
        detections.append(Detection(
            rule_id     = "R009",
            severity    = "critical",
            title       = "Credential Reconnaissance",
            description = "Process accessed passwd + shadow + executed commands — credential dumping",
            confidence  = 90,
            evidence    = events[:5],
        ))

    # R010 — Download + execute pattern
    exec_files = [e.get("file","") for e in events if e.get("type") == "exec"]
    open_files = [e.get("file","") for e in events if e.get("type") == "open"]
    if any("/tmp" in f or "/dev/shm" in f for f in open_files) and \
       any("/tmp" in f or "/dev/shm" in f for f in exec_files):
        detections.append(Detection(
            rule_id     = "R010",
            severity    = "critical",
            title       = "Download and Execute",
            description = "Process wrote to /tmp then executed from /tmp — dropper behavior",
            confidence  = 92,
            evidence    = events[:5],
        ))

    # R011 — Multiple sensitive file reads in short window
    sensitive = [f for f in files if any(s in f for s in
                 ("/etc/passwd","/etc/shadow","/etc/sudoers",
                  "id_rsa","authorized_keys",".bash_history"))]
    if len(sensitive) >= 3:
        detections.append(Detection(
            rule_id     = "R011",
            severity    = "high",
            title       = "Sensitive File Enumeration",
            description = f"Process read {len(sensitive)} sensitive files in short window",
            confidence  = 80,
            evidence    = events[:5],
        ))

    return detections
