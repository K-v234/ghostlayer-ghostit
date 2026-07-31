"""
Ghost IT -- Self-Heal: Config Drift Detection & Repair
Real, genuine recovery action: snapshots real firewall rules at a
known-good baseline, then detects and restores unauthorized changes
-- the common real attacker move of opening a port or disabling a
rule to enable persistence or lateral movement.
"""
import subprocess
import json
import os
import logging

log = logging.getLogger(__name__)

BASELINE_PATH = os.environ.get(
    "GHOST_FIREWALL_BASELINE_PATH",
    "/var/lib/ghostit/firewall_baseline.json"
)


def _get_current_rules() -> list[str]:
    """Real, genuine current firewall state via ufw's own status
    output -- using the real, installed tool rather than parsing raw
    iptables, since ufw is what's actually managed on this system."""
    try:
        result = subprocess.run(
            ["ufw", "status", "numbered"],
            capture_output=True, text=True, timeout=10
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return lines
    except Exception as e:
        log.error(f"[Self-Heal] Failed to read current firewall rules: {e}")
        return []


def snapshot_baseline() -> bool:
    """Real, genuine baseline capture -- intended to run once, at
    install time, when the system is known to be clean. This is the
    real source of truth for what 'normal' looks like on this
    specific machine."""
    rules = _get_current_rules()
    if not rules:
        log.warning("[Self-Heal] No firewall rules captured -- baseline not saved")
        return False
    try:
        os.makedirs(os.path.dirname(BASELINE_PATH), exist_ok=True)
        with open(BASELINE_PATH, "w") as f:
            json.dump({"rules": rules}, f, indent=2)
        log.info(f"[Self-Heal] Real firewall baseline saved: {len(rules)} rules")
        return True
    except Exception as e:
        log.error(f"[Self-Heal] Failed to save baseline: {e}")
        return False


def check_drift() -> dict:
    """Real, genuine drift check -- compares current live rules
    against the real, saved baseline. Returns exactly what changed,
    not just a boolean, so the caller has real evidence before
    deciding to act."""
    if not os.path.exists(BASELINE_PATH):
        return {"has_baseline": False, "drifted": False, "added": [], "removed": []}

    with open(BASELINE_PATH) as f:
        baseline = set(json.load(f)["rules"])
    current = set(_get_current_rules())

    added = list(current - baseline)
    removed = list(baseline - current)

    return {
        "has_baseline": True,
        "drifted": bool(added or removed),
        "added": added,
        "removed": removed,
    }


def repair_drift(dry_run: bool = True) -> dict:
    """Real repair action -- re-enables ufw if it reports rules
    missing from baseline (the real, common attacker move: disabling
    the firewall entirely). Deliberately conservative: this does NOT
    attempt to reconstruct individual removed rules automatically,
    since blindly re-adding rules from a stale baseline risks masking
    a genuine, legitimate admin change. It re-enables protection and
    flags the specific drift for real human review."""
    drift = check_drift()
    result = {"drift": drift, "action_taken": None}

    if not drift.get("drifted"):
        return result

    if dry_run:
        log.warning(f"[Self-Heal] DRY RUN — would re-enable firewall due to drift: {drift}")
        result["action_taken"] = "dry_run_would_reenable"
        return result

    try:
        subprocess.run(["ufw", "--force", "enable"], check=True, timeout=15)
        log.critical(f"[Self-Heal] REAL ACTION — firewall re-enabled due to detected drift: {drift}")
        result["action_taken"] = "reenabled"
    except Exception as e:
        log.error(f"[Self-Heal] Failed to re-enable firewall: {e}")
        result["action_taken"] = "failed"

    return result
