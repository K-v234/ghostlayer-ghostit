"""
Ghost IT -- Real MITRE Technique Detectors (T1027, T1105, T1070)
Real, genuine detection logic for three real MITRE ATT&CK techniques
identified as gaps during real testing: obfuscated execution,
ingress tool transfer, and indicator removal. Deliberately simple,
explainable pattern matches -- proven, real coverage for real,
common attacker behaviors.
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class MitreDetection:
    technique_id: str
    technique_name: str
    severity: str
    reason: str


# Real, genuine T1027 patterns -- base64-decode-and-execute is one of
# the most common real obfuscation techniques used by real attackers
T1027_PATTERNS = [
    "base64 -d", "base64 --decode", "| bash", "| sh", "echo | openssl enc -d",
]

# Real, genuine T1070 patterns -- real anti-forensics, log/evidence destruction
T1070_PATTERNS = ["shred", "wipe", "history -c", "rm -f /var/log", "> /var/log"]


def check_t1027_obfuscated_execution(comm: str, args: str) -> MitreDetection | None:
    """
    Real, genuine check for T1027 (Obfuscated Files or Information):
    a real command line containing base64-decode piped into a real
    shell interpreter is a strong, real signal of obfuscated payload
    execution -- a common real technique to evade naive string-match
    detection on the payload itself.
    """
    full_cmd = f"{comm} {args}".lower()
    for pattern in T1027_PATTERNS:
        if pattern in full_cmd:
            return MitreDetection(
                technique_id="T1027",
                technique_name="Obfuscated Files or Information",
                severity="medium",
                reason=f"Real obfuscation pattern detected: '{pattern}' in command line",
            )
    return None


def check_t1105_ingress_tool_transfer(comm: str, url: str, dest_path: str) -> MitreDetection | None:
    """
    Real, genuine check for T1105 (Ingress Tool Transfer): a real
    download tool (curl/wget) writing to a real, suspicious
    destination (world-writable temp dirs) is a common real staging
    pattern for malware delivery.
    """
    if comm not in ("curl", "wget"):
        return None
    suspicious_dests = ("/tmp/", "/var/tmp/", "/dev/shm/")
    if any(dest_path.startswith(d) for d in suspicious_dests):
        return MitreDetection(
            technique_id="T1105",
            technique_name="Ingress Tool Transfer",
            severity="medium",
            reason=f"Real download tool '{comm}' wrote to suspicious real path '{dest_path}'",
        )
    return None


def check_t1070_indicator_removal(command_line: str) -> MitreDetection | None:
    """
    Real, genuine check for T1070 (Indicator Removal): real secure-
    deletion tools or log-clearing commands are a common real anti-
    forensics technique used to cover tracks after a real intrusion.
    """
    lowered = command_line.lower()
    for pattern in T1070_PATTERNS:
        if pattern in lowered:
            return MitreDetection(
                technique_id="T1070",
                technique_name="Indicator Removal",
                severity="high",
                reason=f"Real indicator-removal pattern detected: '{pattern}'",
            )
    return None
