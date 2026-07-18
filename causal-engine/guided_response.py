#!/usr/bin/env python3
"""
Ghost IT — Guided One-Click Response

Market gap this closes (2026 research, Huntress): SMBs fail not from
lack of detection, but because 'no one responds to alerts.' This is
the human-facing bridge: for every real alert, present ONE obvious,
plain-language action a non-expert admin can click with confidence.
"""
from __future__ import annotations

GUIDED_ACTIONS = {
    "C15_RANSOMWARE": {"button_label": "Isolate This Device Now", "action": "isolate_host",
        "plain_explanation": "This device shows signs of ransomware actively encrypting files. Isolating it now stops the spread.", "urgency": "critical"},
    "canary_hit": {"button_label": "Block This Source", "action": "block_source",
        "plain_explanation": "Someone accessed a decoy file no legitimate user should ever touch. Very likely an active intruder.", "urgency": "critical"},
    "C19_LKRG_INTEGRITY": {"button_label": "Isolate This Device Now", "action": "isolate_host",
        "plain_explanation": "The core operating system may have been tampered with. Isolate and contact IT support.", "urgency": "critical"},
    "C14_LOLBIN": {"button_label": "Review This Process", "action": "review_process",
        "plain_explanation": "A normal system tool was used in a way matching known attack techniques.", "urgency": "high"},
    "R002": {"button_label": "Reset Passwords Now", "action": "reset_credentials",
        "plain_explanation": "Something tried to read password data on this device.", "urgency": "critical"},
    "R003": {"button_label": "Isolate This Device Now", "action": "isolate_host",
        "plain_explanation": "This device connected to a known attacker control channel.", "urgency": "critical"},
}

def get_guided_action(rule_id: str, score: float = 0) -> dict:
    action = GUIDED_ACTIONS.get(rule_id)
    if not action:
        return {"button_label": "Review Alert", "action": "review",
                "plain_explanation": f"This alert (score {score:.0f}/100) needs review.",
                "urgency": "medium" if score >= 50 else "low"}
    return {**action, "rule_id": rule_id, "score": score}

if __name__ == "__main__":
    print(get_guided_action("C15_RANSOMWARE", 96))
    print(get_guided_action("canary_hit", 100))
    print(get_guided_action("UNKNOWN_RULE", 45))
