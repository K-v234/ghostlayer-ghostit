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

    "R002": Playbook(
        rule_id="R002",
        title="Shadow File Access (Credential Theft Attempt)",
        severity_baseline="CRITICAL",
        what_happened="A shell process (bash, sh, dash, zsh) directly read "
            "/etc/shadow, the file containing password hashes for every "
            "local user account on the system.",
        why_it_matters="/etc/shadow has no legitimate reason to be read "
            "directly by a shell -- normal authentication happens through "
            "system libraries, not manual file access. This is a strong, "
            "specific signal of an attacker attempting to extract password "
            "hashes for offline cracking.",
        immediate_steps=[
            "Identify the process (comm/pid in alert) and the user context "
            "it ran as -- was this root, or a compromised lower-privilege "
            "account that escalated?",
            "If the process is still running, terminate it and isolate the "
            "host.",
        ],
        investigation_steps=[
            "Check what shell history/commands led to this read -- was it "
            "an interactive attacker session, or an automated script?",
            "Review recent authentication logs for anomalous logins that "
            "may have preceded this.",
        ],
        containment_steps=[
            "Force a password reset for all local accounts on the affected "
            "host -- assume hashes were exfiltrated.",
            "Review sudo/root access logs for privilege escalation.",
        ],
        false_positive_checks=[
            "Legitimate system administration (user management scripts, "
            "backup tools) occasionally read this file -- verify this "
            "matches a known, authorized admin action before escalating.",
        ],
    ),

    "R003": Playbook(
        rule_id="R003",
        title="Reverse Shell Connection",
        severity_baseline="CRITICAL",
        what_happened="A process connected to a port commonly used for "
            "reverse shells (4444, 1337, 31337, 9001, 6666, or 8888) -- "
            "ports with no common legitimate service, strongly associated "
            "with attacker command-and-control channels.",
        why_it_matters="A successful reverse shell gives an attacker "
            "interactive, real-time control over the compromised host -- "
            "this is often the moment initial access becomes active "
            "exploitation.",
        immediate_steps=[
            "Isolate the host from the network immediately to cut the "
            "attacker's active connection.",
            "Identify and terminate the connecting process.",
        ],
        investigation_steps=[
            "Review the causal chain (C4) to identify how this process "
            "started -- what was the initial access vector?",
            "Check for any commands or files created during the window "
            "this connection was active.",
        ],
        containment_steps=[
            "Treat this host as actively compromised -- full forensic "
            "review before returning to service.",
            "Block the remote IP/port at the network perimeter.",
        ],
        false_positive_checks=[
            "Some legitimate services occasionally use uncommon high ports "
            "-- verify the destination IP isn't a known, trusted internal "
            "or partner service before treating as confirmed malicious.",
        ],
    ),

    "R004": Playbook(
        rule_id="R004",
        title="Interpreter Outbound Connection",
        severity_baseline="HIGH",
        what_happened="A scripting language interpreter (python, perl, "
            "ruby, php, lua, node) made an outbound network connection -- "
            "a common pattern for fileless malware, data exfiltration "
            "scripts, or command-and-control beaconing.",
        why_it_matters="Scripting interpreters are frequently used by "
            "attackers for quick, disposable tooling that doesn't require "
            "compiling a binary -- this pattern alone isn't definitive, but "
            "combined with an unexpected destination it's a meaningful "
            "signal.",
        immediate_steps=[
            "Check the destination IP/port -- is this a known, expected "
            "service the application legitimately talks to?",
            "If unexpected, block the destination and isolate the process.",
        ],
        investigation_steps=[
            "Review what script/file the interpreter was executing (check "
            "command-line args if captured).",
            "Check if this interpreter process was spawned by a normal "
            "application or something else in the process tree.",
        ],
        containment_steps=[
            "If confirmed malicious, isolate the host and search for "
            "the source script/file for removal.",
        ],
        false_positive_checks=[
            "This rule fires on ANY interpreter making ANY outbound "
            "connection except localhost -- legitimate applications "
            "(monitoring agents, package managers, API clients written in "
            "these languages) will trigger this constantly. Cross-check "
            "against known application behavior before treating as "
            "suspicious.",
        ],
    ),

    "C17_CORRELATED_INCIDENT": Playbook(
        rule_id="C17_CORRELATED_INCIDENT",
        title="Correlated Multi-Alert Incident",
        severity_baseline="CRITICAL",
        what_happened="Multiple independent alerts, from one or more "
            "detection sources, were correlated by C17 into a single "
            "incident within a 15-minute window -- indicating these "
            "aren't isolated events but likely stages of the same attack.",
        why_it_matters="A single alert might be a false positive or an "
            "isolated event. Multiple independent detection sources "
            "agreeing, in a short time window, on the same host or "
            "process, is a much stronger signal -- this is precisely why "
            "Ghost IT weights correlated incidents higher than any single "
            "alert (see COMPONENT_WEIGHTS in alert-engine/correlator.py).",
        immediate_steps=[
            "Review the incident's tactic_name/technique_name (MITRE "
            "ATT&CK mapping) to understand what stage of an attack this "
            "represents.",
            "Check alert_count and sources in the incident record -- more "
            "independent sources agreeing means higher confidence this is "
            "real.",
            "If confidence is high (multiple high-weight sources like "
            "DECEPTION or KERNEL_INTEGRITY), treat as confirmed and follow "
            "the isolation steps for the underlying alert types involved.",
        ],
        investigation_steps=[
            "Pull all individual alerts that make up this incident (via "
            "alert_ids in the incident record) and review each one's own "
            "playbook for specific guidance.",
            "Build a timeline: which alert fired first, and does the "
            "sequence match a known attack pattern (e.g. reconnaissance -> "
            "initial access -> execution -> persistence)?",
        ],
        containment_steps=[
            "Correlated incidents spanning multiple hosts indicate likely "
            "lateral movement -- isolate ALL affected hosts, not just the "
            "one where the alert first appeared.",
            "Escalate to full incident response if the incident includes "
            "any CRITICAL-severity component alert.",
        ],
        false_positive_checks=[
            "Correlated incidents have a much lower false-positive rate "
            "than any single alert by design (multiple independent sources "
            "agreeing) -- if this still seems like a false positive, check "
            "each component alert's own false_positive_checks first, since "
            "the correlation itself is unlikely to be wrong.",
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
