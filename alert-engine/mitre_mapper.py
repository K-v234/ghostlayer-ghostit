# STATUS: 100% — MITRE ATT&CK tactic/technique mapping, LOLBin coverage,
#                TLS fingerprint mapping, ransomware mapping, honeypot mapping
# alert-engine/mitre_mapper.py
# GhostIT C17 — MITRE ATT&CK Tactic/Technique Tagging
# Every alert gets an ATT&CK tactic + technique tag before incident grouping.
# Ghost Layer Technologies · Chennai · June 2026

from dataclasses import dataclass
from weights import AlertSource


# ── ATT&CK reference ──────────────────────────────────────────────────────────
@dataclass(frozen=True)
class MitreTag:
    tactic_id:     str   # e.g. TA0002
    tactic_name:   str   # e.g. Execution
    technique_id:  str   # e.g. T1059
    technique_name: str  # e.g. Command and Scripting Interpreter
    sub_id:        str = ""   # e.g. T1059.001
    sub_name:      str = ""   # e.g. PowerShell

    def __str__(self) -> str:
        sub = f" ({self.sub_id}: {self.sub_name})" if self.sub_id else ""
        return f"{self.tactic_name} / {self.technique_name}{sub}"


# ── Technique definitions ─────────────────────────────────────────────────────
class T:
    # Execution
    CMD             = MitreTag("TA0002", "Execution",          "T1059", "Command and Scripting Interpreter", "T1059.003", "Windows Command Shell")
    POWERSHELL      = MitreTag("TA0002", "Execution",          "T1059", "Command and Scripting Interpreter", "T1059.001", "PowerShell")
    WSCRIPT         = MitreTag("TA0002", "Execution",          "T1059", "Command and Scripting Interpreter", "T1059.005", "Visual Basic")
    MSHTA           = MitreTag("TA0002", "Execution",          "T1218", "System Binary Proxy Execution",    "T1218.005", "Mshta")
    REGSVR32        = MitreTag("TA0002", "Execution",          "T1218", "System Binary Proxy Execution",    "T1218.010", "Regsvr32")
    RUNDLL32        = MitreTag("TA0002", "Execution",          "T1218", "System Binary Proxy Execution",    "T1218.011", "Rundll32")
    MSIEXEC         = MitreTag("TA0002", "Execution",          "T1218", "System Binary Proxy Execution",    "T1218.007", "Msiexec")

    # Defense Evasion
    CERTUTIL        = MitreTag("TA0005", "Defense Evasion",    "T1105", "Ingress Tool Transfer",           "T1105",     "certutil download cradle")
    BITSADMIN       = MitreTag("TA0005", "Defense Evasion",    "T1197", "BITS Jobs",                       "T1197",     "bitsadmin transfer")
    TEMP_PATH       = MitreTag("TA0005", "Defense Evasion",    "T1036", "Masquerading",                    "T1036.005", "Match Legitimate Name or Location")
    PROCESS_INJECT  = MitreTag("TA0005", "Defense Evasion",    "T1055", "Process Injection",               "T1055.001", "Dynamic-link Library Injection")
    APC_INJECT      = MitreTag("TA0005", "Defense Evasion",    "T1055", "Process Injection",               "T1055.004", "Asynchronous Procedure Call")
    HOLLOW          = MitreTag("TA0005", "Defense Evasion",    "T1055", "Process Injection",               "T1055.012", "Process Hollowing")

    # Lateral Movement
    WMIC            = MitreTag("TA0008", "Lateral Movement",   "T1047", "Windows Management Instrumentation", "T1047", "WMI")

    # Command and Control
    TLS_C2          = MitreTag("TA0011", "Command and Control","T1071", "Application Layer Protocol",      "T1071.001", "Web Protocols")
    ENCRYPTED_C2    = MitreTag("TA0011", "Command and Control","T1573", "Encrypted Channel",               "T1573.002", "Asymmetric Cryptography")

    # Impact
    RANSOMWARE      = MitreTag("TA0040", "Impact",             "T1486", "Data Encrypted for Impact",       "T1486",     "Ransomware")
    WIPE            = MitreTag("TA0040", "Impact",             "T1485", "Data Destruction",                "T1485",     "File wipe")

    # Reconnaissance
    RECON           = MitreTag("TA0043", "Reconnaissance",     "T1595", "Active Scanning",                 "T1595",     "Active scanning")

    # Collection
    HONEYPOT_HIT    = MitreTag("TA0009", "Collection",         "T1119", "Automated Collection",            "T1119",     "Honeypot interaction — attacker confirmed")

    # Privilege Escalation
    STERILE_PARENT  = MitreTag("TA0004", "Privilege Escalation","T1134","Access Token Manipulation",       "T1134",     "Sterile parent spawn")

    # Initial Access
    PHISHING        = MitreTag("TA0001", "Initial Access",     "T1566", "Phishing",                        "T1566.001", "Spearphishing Attachment")

    # Unknown
    UNKNOWN         = MitreTag("TA0000", "Unknown",            "T0000", "Unknown Technique",               "",          "")


# ── Process name → MITRE technique ───────────────────────────────────────────
_LOLBIN_MAP: dict[str, MitreTag] = {
    "cmd.exe":            T.CMD,
    "powershell.exe":     T.POWERSHELL,
    "powershell_ise.exe": T.POWERSHELL,
    "wscript.exe":        T.WSCRIPT,
    "cscript.exe":        T.WSCRIPT,
    "certutil.exe":       T.CERTUTIL,
    "mshta.exe":          T.MSHTA,
    "regsvr32.exe":       T.REGSVR32,
    "rundll32.exe":       T.RUNDLL32,
    "msiexec.exe":        T.MSIEXEC,
    "wmic.exe":           T.WMIC,
    "bitsadmin.exe":      T.BITSADMIN,
}

# ── eBPF event type → MITRE technique ────────────────────────────────────────
_EBPF_EVENT_MAP: dict[str, MitreTag] = {
    "GHOST_EVENT_MEM_EXEC_ALLOC": T.PROCESS_INJECT,
    "GHOST_EVENT_MEM_EXEC_MAP":   T.PROCESS_INJECT,
    "GHOST_EVENT_APC_INJECT":     T.APC_INJECT,
    "GHOST_EVENT_THREAD_CTX_SET": T.HOLLOW,
}

# ── Reason string → MITRE technique ──────────────────────────────────────────
_REASON_MAP: list[tuple[str, MitreTag]] = [
    ("INV1",         T.TEMP_PATH),
    ("INV2",         T.STERILE_PARENT),
    ("INV3",         T.CMD),
    ("INV4",         T.CERTUTIL),
    ("INV5",         T.MSHTA),
    ("INV6",         T.REGSVR32),
    ("ransomware",   T.RANSOMWARE),
    ("honeypot",     T.HONEYPOT_HIT),
    ("canary",       T.HONEYPOT_HIT),
    ("tls",          T.TLS_C2),
    ("ja3",          T.TLS_C2),
    ("ja4",          T.TLS_C2),
    ("injection",    T.PROCESS_INJECT),
    ("apc",          T.APC_INJECT),
    ("hollow",       T.HOLLOW),
    ("divergence",   T.PROCESS_INJECT),
]


def map_alert(
    source: AlertSource,
    reason: str = "",
    comm: str = "",
    event_type: str = "",
) -> MitreTag:
    reason_lower  = reason.lower()
    comm_lower    = comm.lower()

    if event_type and event_type in _EBPF_EVENT_MAP:
        return _EBPF_EVENT_MAP[event_type]

    if comm_lower and comm_lower in _LOLBIN_MAP:
        return _LOLBIN_MAP[comm_lower]

    for keyword, tag in _REASON_MAP:
        if keyword in reason_lower:
            return tag

    _SOURCE_DEFAULTS: dict[AlertSource, MitreTag] = {
        AlertSource.DECEPTION:     T.HONEYPOT_HIT,
        AlertSource.C15_RANSOMWARE: T.RANSOMWARE,
        AlertSource.C14_TLS:       T.TLS_C2,
        AlertSource.C9_DIVERGENCE: T.PROCESS_INJECT,
        AlertSource.C9_EBPF:       T.CMD,
        AlertSource.C9_ETW:        T.CMD,
        AlertSource.BEHAVIORAL_AI: T.RECON,
    }
    return _SOURCE_DEFAULTS.get(source, T.UNKNOWN)
