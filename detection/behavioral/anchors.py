"""
Ghost IT — C2: Behavioral Anchor Invariants

Fixed rules that OVERRIDE the ML model.
Violation = CRITICAL regardless of anomaly score.
These rules can never be poisoned by adversarial baseline manipulation.

Ghost Layer Technologies — CONFIDENTIAL
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Optional

SCRIPT_RUNTIMES = {
    "python3", "python", "perl", "ruby", "php",
    "node", "nodejs", "lua", "tclsh",
}

BROWSERS = {
    "chrome", "firefox", "chromium", "brave",
    "safari", "edge", "opera",
}

PROD_DB_PORTS = {3306, 5432, 1433, 1521, 27017, 6379}


@dataclass
class Invariant:
    name:      str
    check:     Callable[[dict], bool]  # Returns True if VIOLATED
    rationale: str


@dataclass
class InvariantViolation:
    invariant_name: str
    rationale:      str
    event:          dict
    entity_id:      str


# ------------------------------------------------------------------ #
# Universal invariants — apply to ALL entities                       #
# ------------------------------------------------------------------ #
UNIVERSAL_INVARIANTS = [
    Invariant(
        name      = "no_exec_from_tmp",
        check     = lambda e: (
            e.get("type") == "exec" and
            (e.get("path") or "").startswith("/tmp/")
        ),
        rationale = "Executable loaded from /tmp — malware staging",
    ),
    Invariant(
        name      = "no_exec_from_dev_shm",
        check     = lambda e: (
            e.get("type") == "exec" and
            (e.get("path") or "").startswith("/dev/shm/")
        ),
        rationale = "Executable loaded from /dev/shm — fileless malware",
    ),
    Invariant(
        name      = "no_shadow_delete",
        check     = lambda e: (
            e.get("comm") in ("vssadmin", "wmic", "bcdedit", "wbadmin")
        ),
        rationale = "Shadow copy deletion — ransomware preparation",
    ),
    Invariant(
        name      = "no_lsass_ptrace",
        check     = lambda e: (
            e.get("type") == "ptrace" and
            e.get("comm") not in ("gdb", "strace", "ltrace")
        ),
        rationale = "Unexpected ptrace — possible process injection",
    ),
    Invariant(
        name      = "no_setuid_unexpected",
        check     = lambda e: (
            e.get("type") == "setuid" and
            e.get("uid", 1000) >= 1000 and
            int(e.get("flags", 1000)) == 0  # Setting to root
        ),
        rationale = "User process setting UID to root — privilege escalation",
    ),
    Invariant(
        name      = "no_mbr_write",
        check     = lambda e: (
            e.get("type") == "open" and
            (e.get("path") or "") in ("/dev/sda", "/dev/nvme0n1") and
            e.get("flags", 0) & 0x1
        ),
        rationale = "Direct MBR write — bootkit/ransomware",
    ),
]

# ------------------------------------------------------------------ #
# Role-specific invariants                                            #
# ------------------------------------------------------------------ #
SERVICE_ACCOUNT_INVARIANTS = [
    Invariant(
        name      = "no_interactive_login",
        check     = lambda e: (
            e.get("type") == "exec" and
            (e.get("path") or "") in ("/bin/bash", "/bin/sh", "/bin/zsh")
        ),
        rationale = "Service account spawned interactive shell — lateral movement",
    ),
    Invariant(
        name      = "no_browser_spawn",
        check     = lambda e: (
            e.get("type") == "exec" and
            e.get("comm", "").lower() in BROWSERS
        ),
        rationale = "Service account spawned browser — anomalous",
    ),
    Invariant(
        name      = "no_script_execution",
        check     = lambda e: (
            e.get("type") == "exec" and
            e.get("comm", "") in SCRIPT_RUNTIMES
        ),
        rationale = "Service account executing script runtime — suspicious",
    ),
]

ROLE_INVARIANTS = {
    "ServiceAccount": SERVICE_ACCOUNT_INVARIANTS,
}


class AnchorChecker:
    """
    Checks all applicable invariants for an entity.
    Returns list of violations (empty = clean).
    """

    def __init__(self, entity_id: str, role_archetype: str = "Workstation"):
        self.entity_id      = entity_id
        self.role_archetype = role_archetype

    def check(self, event: dict) -> list[InvariantViolation]:
        violations = []

        # Universal invariants — check all
        for inv in UNIVERSAL_INVARIANTS:
            if inv.check(event):
                violations.append(InvariantViolation(
                    invariant_name = inv.name,
                    rationale      = inv.rationale,
                    event          = event,
                    entity_id      = self.entity_id,
                ))

        # Role-specific invariants
        role_invs = ROLE_INVARIANTS.get(self.role_archetype, [])
        for inv in role_invs:
            if inv.check(event):
                violations.append(InvariantViolation(
                    invariant_name = inv.name,
                    rationale      = inv.rationale,
                    event          = event,
                    entity_id      = self.entity_id,
                ))

        return violations
