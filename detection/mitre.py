"""
Ghost IT — MITRE ATT&CK Mapper
Maps detection rules to MITRE ATT&CK tactics and techniques.
Tracks kill chain progression across multiple detections.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional
from enum import IntEnum


class KillChainStage(IntEnum):
    RECON           = 1
    INITIAL_ACCESS  = 2
    EXECUTION       = 3
    PERSISTENCE     = 4
    PRIVILEGE_ESC   = 5
    DEFENSE_EVASION = 6
    CREDENTIAL_ACCESS = 7
    DISCOVERY       = 8
    LATERAL_MOVEMENT = 9
    COLLECTION      = 10
    EXFILTRATION    = 11
    COMMAND_CONTROL = 12
    IMPACT          = 13

    def label(self) -> str:
        return self.name.replace("_", " ").title()


@dataclass
class MITRETag:
    tactic:      str
    tactic_id:   str
    technique:   str
    technique_id: str
    kill_chain:  KillChainStage
    description: str


# Rule ID → MITRE mapping
RULE_MITRE_MAP: dict[str, MITRETag] = {
    "R001": MITRETag(
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        technique    = "Honey Token Access",
        technique_id = "T1056",
        kill_chain   = KillChainStage.DISCOVERY,
        description  = "Attacker accessed a canary/honey token asset",
    ),
    "R002": MITRETag(
        tactic       = "Credential Access",
        tactic_id    = "TA0006",
        technique    = "OS Credential Dumping",
        technique_id = "T1003",
        kill_chain   = KillChainStage.CREDENTIAL_ACCESS,
        description  = "Attempt to read shadow password file",
    ),
    "R003": MITRETag(
        tactic       = "Command and Control",
        tactic_id    = "TA0011",
        technique    = "Reverse Shell",
        technique_id = "T1059",
        kill_chain   = KillChainStage.COMMAND_CONTROL,
        description  = "Outbound connection to known reverse shell port",
    ),
    "R004": MITRETag(
        tactic       = "Execution",
        tactic_id    = "TA0002",
        technique    = "Command and Scripting Interpreter",
        technique_id = "T1059",
        kill_chain   = KillChainStage.EXECUTION,
        description  = "Script interpreter making unexpected network connection",
    ),
    "R005": MITRETag(
        tactic       = "Execution",
        tactic_id    = "TA0002",
        technique    = "Unix Shell",
        technique_id = "T1059.004",
        kill_chain   = KillChainStage.EXECUTION,
        description  = "Shell process making outbound network connection",
    ),
    "R006": MITRETag(
        tactic       = "Execution",
        tactic_id    = "TA0002",
        technique    = "Native API",
        technique_id = "T1106",
        kill_chain   = KillChainStage.EXECUTION,
        description  = "Known offensive security tool executed",
    ),
    "R007": MITRETag(
        tactic       = "Defense Evasion",
        tactic_id    = "TA0005",
        technique    = "Indicator Removal",
        technique_id = "T1070",
        kill_chain   = KillChainStage.DEFENSE_EVASION,
        description  = "Log file deleted to cover tracks",
    ),
    "R008": MITRETag(
        tactic       = "Execution",
        tactic_id    = "TA0002",
        technique    = "Ingress Tool Transfer",
        technique_id = "T1105",
        kill_chain   = KillChainStage.EXECUTION,
        description  = "File downloaded to temp directory for execution",
    ),
    "R009": MITRETag(
        tactic       = "Credential Access",
        tactic_id    = "TA0006",
        technique    = "OS Credential Dumping",
        technique_id = "T1003.008",
        kill_chain   = KillChainStage.CREDENTIAL_ACCESS,
        description  = "Credential file enumeration pattern detected",
    ),
    "R010": MITRETag(
        tactic       = "Execution",
        tactic_id    = "TA0002",
        technique    = "Ingress Tool Transfer + Execution",
        technique_id = "T1105",
        kill_chain   = KillChainStage.EXECUTION,
        description  = "Download and execute dropper pattern",
    ),
    "R011": MITRETag(
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        technique    = "File and Directory Discovery",
        technique_id = "T1083",
        kill_chain   = KillChainStage.DISCOVERY,
        description  = "Sensitive file enumeration detected",
    ),
    "L001": MITRETag(
        tactic       = "Execution",
        tactic_id    = "TA0002",
        technique    = "Unix Shell",
        technique_id = "T1059.004",
        kill_chain   = KillChainStage.EXECUTION,
        description  = "Suspicious process spawn chain detected",
    ),
    "L002": MITRETag(
        tactic       = "Privilege Escalation",
        tactic_id    = "TA0004",
        technique    = "Exploitation for Privilege Escalation",
        technique_id = "T1068",
        kill_chain   = KillChainStage.PRIVILEGE_ESC,
        description  = "Service process spawned unexpected child",
    ),
    "B001": MITRETag(
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        technique    = "File and Directory Discovery",
        technique_id = "T1083",
        kill_chain   = KillChainStage.DISCOVERY,
        description  = "Burst of sensitive file reads detected",
    ),
    "B002": MITRETag(
        tactic       = "Execution",
        tactic_id    = "TA0002",
        technique    = "Command and Scripting Interpreter",
        technique_id = "T1059",
        kill_chain   = KillChainStage.EXECUTION,
        description  = "High execution rate — possible script activity",
    ),
    "B003": MITRETag(
        tactic       = "Command and Control",
        tactic_id    = "TA0011",
        technique    = "Application Layer Protocol",
        technique_id = "T1071",
        kill_chain   = KillChainStage.COMMAND_CONTROL,
        description  = "Connection burst — possible C2 beacon",
    ),
    "B004": MITRETag(
        tactic       = "Discovery",
        tactic_id    = "TA0007",
        technique    = "Network Service Discovery",
        technique_id = "T1046",
        kill_chain   = KillChainStage.DISCOVERY,
        description  = "Multiple unique IPs contacted — possible scanning",
    ),
    "B005": MITRETag(
        tactic       = "Impact",
        tactic_id    = "TA0040",
        technique    = "Data Destruction",
        technique_id = "T1485",
        kill_chain   = KillChainStage.IMPACT,
        description  = "Mass file deletion — possible ransomware or wiper",
    ),
}


def get_mitre_tag(rule_id: str) -> Optional[MITRETag]:
    return RULE_MITRE_MAP.get(rule_id)


@dataclass
class AttackChain:
    """
    Tracks the progression of an attack across multiple detections.
    Groups related detections into a coherent attack story.
    """
    chain_id:    str
    started_at:  str
    detections:  list[dict] = field(default_factory=list)
    stages_seen: set        = field(default_factory=set)

    def add(self, detection: dict, tag: MITRETag):
        self.detections.append(detection)
        self.stages_seen.add(tag.kill_chain)

    @property
    def current_stage(self) -> Optional[KillChainStage]:
        if not self.stages_seen:
            return None
        return max(self.stages_seen)

    @property
    def severity(self) -> str:
        stage = self.current_stage
        if not stage:
            return "low"
        if stage >= KillChainStage.COMMAND_CONTROL:
            return "critical"
        if stage >= KillChainStage.CREDENTIAL_ACCESS:
            return "high"
        if stage >= KillChainStage.EXECUTION:
            return "medium"
        return "low"

    def summary(self) -> dict:
        stages = sorted(self.stages_seen)
        return {
            "chain_id":     self.chain_id,
            "started_at":   self.started_at,
            "stage_count":  len(stages),
            "current_stage": self.current_stage.label() if self.current_stage else "unknown",
            "severity":     self.severity,
            "stages":       [s.label() for s in stages],
            "detections":   len(self.detections),
            "tactics":      list({d.get("tactic","") for d in self.detections}),
        }
