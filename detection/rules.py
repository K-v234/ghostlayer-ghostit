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
    detection_method: str = "deterministic_rule"  # deterministic_rule | statistical_ema | ml_isolation_forest | ml_graphsage | deception_trigger
    schema_version: int = 1


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
    if type_ == "connect" and comm in ("perl","ruby","php","python3","python","lua","node")             and daddr not in ("127.0.0.1", "::1", "", "1.0.0.127", "0.0.0.127", "11.0.0.127", "10.0.0.127"):
        return Detection(
            rule_id     = "R004",
            severity    = "high",
            title       = "Interpreter Outbound Connection",
            description = f"{comm} made outbound TCP connection to {daddr}:{dport}",
            confidence  = 75,
            evidence    = [event],
        )

    # R005 — Shell making outbound connection (any port, any IP)
    if type_ == "connect" and comm in ("bash","sh","dash","zsh","fish","ksh"):
        return Detection(
            rule_id     = "R005",
            severity    = "high",
            title       = "Shell Network Activity",
            description = f"{comm} made outbound connection to {daddr}:{dport}",
            confidence  = 80,
            evidence    = [event],
        )

    # R012 — Netcat/socat reverse shell tool making connection
    if type_ == "connect" and comm in ("nc","ncat","netcat","socat","nmap")             and daddr not in ("127.0.0.1", "::1", ""):
        return Detection(
            rule_id     = "R012",
            severity    = "critical",
            title       = "Reverse Shell Tool Connection",
            description = f"{comm} made outbound connection to {daddr}:{dport} — reverse shell tool",
            confidence  = 95,
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

    # R014 — Shell reading script from /tmp or /dev/shm (LOLBin dropper)
    if type_ in ("open", "lsm_open") and comm in ("bash","sh","dash","zsh","fish")             and file_ and any(p in file_ for p in ("/tmp/", "/dev/shm/")):
        return Detection(
            rule_id     = "R014",
            severity    = "high",
            title       = "Shell Reading Script from Temp Directory",
            description = f"{comm} opened {file_} — possible dropper execution",
            confidence  = 85,
            evidence    = [event],
        )

    CREDENTIAL_FILE_PATTERNS = (
        "/etc/shadow", "/etc/gshadow", ".env", "id_rsa", "id_ed25519",
        "id_ecdsa", "id_dsa", ".pem", ".ppk", "credentials.json",
        "passwords.txt", "password.txt", ".npmrc", ".pgpass",
        ".netrc", "wallet.dat", "secrets.yml", "secrets.yaml",
    )
    BROWSER_CRED_PATH_MARKERS = (
        "/.mozilla/", "/.config/google-chrome/", "/.config/chromium/",
    )
    if type_ in ("open", "lsm_open", "read") and file_:
        file_lower = file_.lower()
        is_direct_credential_file = any(
            p in file_lower for p in CREDENTIAL_FILE_PATTERNS
        )
        is_browser_credential_path = any(
            m in file_ for m in BROWSER_CRED_PATH_MARKERS
        ) and any(k in file_lower for k in ("login", "password", "cookie"))
        if is_direct_credential_file or is_browser_credential_path:
            TRUSTED_CRED_READERS = ("sshd", "ssh", "gnome-keyring-daemon",
                                      "firefox", "chrome", "systemd")
            trusted = comm in TRUSTED_CRED_READERS
            return Detection(
                rule_id     = "R015",
                severity    = "medium" if trusted else "high",
                title       = "Credential File Access",
                description = f"{comm} accessed {file_} — genuine credential-pattern file, " + ("expected reader" if trusted else "unexpected/untrusted reader"),
                confidence  = 60 if trusted else 90,
                evidence    = [event],
            )
    # R016 — T1055 Process Injection tool signature
    if any(t in (event.get("args") or "") for t in ("ptrace", "process_vm_writev", "LD_PRELOAD=")) or \
       (comm == "gdb" and "-p" in (event.get("args") or "")):
        return Detection(
            rule_id     = "R016",
            severity    = "high",
            title       = "Process Injection Tool Signature",
            description = f"{comm} used a real process-injection technique (T1055)",
            confidence  = 85,
            evidence    = [event],
        )
    # R017 — T1547 Persistence location write
    if type_ in ("open", "lsm_open", "write") and file_ and any(
        p in file_ for p in ("/etc/cron.d/", "/etc/cron.daily/", ".bashrc", ".profile",
                              "/etc/systemd/system/", "/etc/rc.local")):
        return Detection(
            rule_id     = "R017",
            severity    = "high",
            title       = "Persistence Location Write",
            description = f"{comm} wrote to known real persistence location {file_} (T1547)",
            confidence  = 85,
            evidence    = [event],
        )
    # R018 — T1490 Inhibit System Recovery
    args_lower = (event.get("args") or "").lower()
    if any(p in args_lower for p in ("vssadmin delete shadows", "wbadmin delete",
                                       "bcdedit /set", "wmic shadowcopy delete")):
        return Detection(
            rule_id     = "R018",
            severity    = "critical",
            title       = "Inhibit System Recovery",
            description = f"{comm} attempted to delete backups/shadow copies — ransomware precursor (T1490)",
            confidence  = 95,
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
    if any("/tmp" in (f or "") or "/dev/shm" in (f or "") for f in open_files) and \
       any("/tmp" in (f or "") or "/dev/shm" in (f or "") for f in exec_files):
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
