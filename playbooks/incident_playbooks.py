#!/usr/bin/env python3
"""
Ghost IT — V1.5: Incident Response Playbooks
Structured, rule-specific response procedures. Maps each detection
rule_id to a concrete playbook: what happened, why it matters, and
exactly what steps an analyst (or automated MDR response, in V2)
should take. Referenced by rule_id so the dashboard/alert UI can show
the right playbook automatically when a specific alert type fires.
"""
from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class Playbook:
    rule_id: str
    title: str
    severity_baseline: str
    what_happened: str
    why_it_matters: str
    immediate_steps: list[str]
    investigation_steps: list[str]
    containment_steps: list[str]
    false_positive_checks: list[str] = field(default_factory=list)

PLAYBOOKS: dict[str, Playbook] = {

    "C15_RANSOMWARE": Playbook(
        rule_id="C15_RANSOMWARE",
        title="Ransomware Behavior Detected",
        severity_baseline="CRITICAL",
        what_happened="A process rapidly renamed multiple files to a known "
            "ransomware extension (.locked, .encrypted, etc.) and/or deleted "
            "volume shadow copies, matching the behavioral signature of an "
            "active ransomware attack.",
        why_it_matters="Ransomware causes immediate, severe business impact -- "
            "encrypted files are often unrecoverable without backups or "
            "paying the attacker. Every minute of delay increases the number "
            "of files affected.",
        immediate_steps=[
            "Isolate the affected host from the network immediately (disable "
            "network adapter or block at firewall) to stop the encryption "
            "from spreading to network shares.",
            "Do NOT power off the machine -- this can destroy evidence and "
            "sometimes trigger additional destructive payloads.",
            "Identify the source process (PID/comm in the alert) and "
            "terminate it if the host cannot be immediately isolated.",
        ],
        investigation_steps=[
            "Check the alert's file_entropy_delta and ransomware_ext_hit_count "
            "to gauge scope (how many files affected).",
            "Review the causal chain (C4) for this PID to see the full attack "
            "sequence -- how did the attacker get in?",
            "Check if shadow copies were deleted (shadow_delete_ct in alert "
            "reasons) -- this affects recovery options.",
        ],
        containment_steps=[
            "Restore affected files from backup once the host is confirmed "
            "clean.",
            "Reset credentials for any accounts used on the affected host.",
            "Review network shares the host had access to for lateral spread.",
        ],
        false_positive_checks=[
            "Check the process's Authenticode trust level (integrity field) -- "
            "signed backup/sync software (OneDrive, etc.) writing to its own "
            "sync folder is a known low-risk pattern, though still worth a "
            "quick sanity check.",
        ],
    ),

    "C14_LOLBIN": Playbook(
        rule_id="C14_LOLBIN",
        title="Living-off-the-Land Binary Abuse",
        severity_baseline="HIGH",
        what_happened="A legitimate, trusted Windows binary (mshta, certutil, "
            "regsvr32, etc.) was used in a way that matches known attacker "
            "techniques for fileless execution or payload delivery.",
        why_it_matters="Attackers use trusted system tools specifically to "
            "evade traditional signature-based antivirus, since the binary "
            "itself isn't malware -- only its usage pattern is suspicious.",
        immediate_steps=[
            "Check the full command line captured in the alert to understand "
            "what the LOLBin was actually asked to do.",
            "If it downloaded/executed remote content, block the destination "
            "IP/domain at the firewall.",
        ],
        investigation_steps=[
            "Check the parent process -- was this launched by a user, a "
            "script, or another suspicious process?",
            "Review C4's causal chain for what happened immediately before "
            "and after this event.",
        ],
        containment_steps=[
            "If confirmed malicious, isolate the host and investigate for "
            "persistence mechanisms (scheduled tasks, registry run keys).",
        ],
        false_positive_checks=[
            "Some legitimate IT automation/deployment tools use these same "
            "binaries -- check if this matches a known scheduled task or "
            "software deployment window.",
        ],
    ),

    "C19_LKRG_INTEGRITY": Playbook(
        rule_id="C19_LKRG_INTEGRITY",
        title="Kernel Integrity Violation",
        severity_baseline="CRITICAL",
        what_happened="LKRG (kernel runtime guard) detected a kernel or "
            "process integrity violation -- something modified kernel memory "
            "or process credentials in an unauthorized way.",
        why_it_matters="Kernel-level compromise is one of the most severe "
            "attack outcomes -- it can grant an attacker undetectable, "
            "persistent control over the entire system, bypassing most "
            "userspace security tools entirely.",
        immediate_steps=[
            "Treat this as a confirmed compromise until proven otherwise -- "
            "kernel integrity tools have very low false-positive rates.",
            "Isolate the host from the network immediately.",
            "Do NOT reboot -- this may be needed for forensic memory "
            "analysis, and a reboot could also trigger a persistence "
            "mechanism.",
        ],
        investigation_steps=[
            "Capture a memory image if forensic tooling is available, before "
            "any further action on the host.",
            "Review recent kernel module loads and driver installations.",
        ],
        containment_steps=[
            "This host should be considered untrusted until a full forensic "
            "rebuild -- kernel-level compromise cannot be reliably 'cleaned', "
            "only rebuilt from a known-good state.",
        ],
        false_positive_checks=[
            "Legitimate security/monitoring software (antivirus, EDR agents "
            "themselves) occasionally trigger kernel integrity tools -- check "
            "if this coincides with a known software install/update.",
        ],
    ),

    "canary_hit": Playbook(
        rule_id="canary_hit",
        title="Honeypot/Canary Triggered",
        severity_baseline="CRITICAL",
        what_happened="Something accessed a decoy asset (fake credential file "
            "or fake API endpoint) that has no legitimate business use -- any "
            "interaction with it is inherently suspicious.",
        why_it_matters="Canary tokens have an extremely low false-positive "
            "rate by design -- no legitimate process should ever touch these "
            "files. This is one of the strongest, most reliable signals Ghost "
            "IT produces.",
        immediate_steps=[
            "Identify the source (source_ip, pid if available) that "
            "triggered the canary.",
            "If external (HTTP canary from outside the network), block the "
            "source IP at the firewall immediately.",
        ],
        investigation_steps=[
            "If internal (file canary), determine what process accessed it "
            "and why -- this could indicate active reconnaissance by an "
            "attacker already inside the network.",
            "Review what other activity occurred from the same source "
            "around the same time.",
        ],
        containment_steps=[
            "Treat this as evidence of active compromise or reconnaissance -- "
            "escalate to a full incident investigation.",
        ],
        false_positive_checks=[
            "Automated vulnerability scanners (if authorized/scheduled) can "
            "sometimes trigger HTTP canaries -- confirm this isn't a known "
            "scheduled scan.",
        ],
    ),
}

def get_playbook(rule_id: str) -> Playbook | None:
    return PLAYBOOKS.get(rule_id)

def get_playbook_summary(rule_id: str) -> dict:
    """Returns a dict suitable for JSON API responses."""
    pb = get_playbook(rule_id)
    if not pb:
        return {"found": False, "rule_id": rule_id}
    return {
        "found": True,
        "rule_id": pb.rule_id,
        "title": pb.title,
        "severity_baseline": pb.severity_baseline,
        "what_happened": pb.what_happened,
        "why_it_matters": pb.why_it_matters,
        "immediate_steps": pb.immediate_steps,
        "investigation_steps": pb.investigation_steps,
        "containment_steps": pb.containment_steps,
        "false_positive_checks": pb.false_positive_checks,
    }

if __name__ == "__main__":
    import json
    for rid, pb in PLAYBOOKS.items():
        print(f"=== {rid} ===")
        print(json.dumps(get_playbook_summary(rid), indent=2))
        print()
