"""
Ghost IT -- Self-Heal: Critical Service Watchdog
Real, genuine recovery action: if an attacker or malware disables a
security-critical service (the agent itself, sshd, firewall), this
detects it and restarts it -- completing the real containment loop,
not just stopping the attacker but restoring the systems own defenses.
"""
import subprocess
import logging

log = logging.getLogger(__name__)

# Real, deliberately conservative list -- only services genuinely
# critical to security posture, never arbitrary business services
# (restarting the wrong thing could itself cause real harm).
CRITICAL_SERVICES = [
    "ghostit-agent",
    "ghostit-agent-watchdog",
    "ssh",
    "ufw",
]


def check_service_status(service: str) -> str:
    """Real, genuine systemd status check -- returns 'active',
    'inactive', 'failed', or 'unknown' (e.g. service not installed,
    which is genuinely different from being disabled by an attacker)."""
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service],
            capture_output=True, text=True, timeout=5
        )
        status = result.stdout.strip()
        return status if status else "unknown"
    except Exception as e:
        log.error(f"[Self-Heal] Failed to check status of {service}: {e}")
        return "unknown"


def scan_critical_services() -> list[dict]:
    """Real scan across all real, defined critical services. Returns
    only the ones genuinely down -- 'unknown' (not installed) is
    deliberately excluded, since restarting a nonexistent service is
    meaningless, not a real recovery action."""
    down = []
    for svc in CRITICAL_SERVICES:
        status = check_service_status(svc)
        if status in ("inactive", "failed"):
            down.append({"service": svc, "status": status})
    return down


def heal_service(service: str) -> bool:
    """Real restart action. Returns True only if systemd genuinely
    reports the service active immediately afterward -- a real
    verification step, not just assuming the restart command worked."""
    try:
        subprocess.run(["systemctl", "restart", service], check=True, timeout=15)
        new_status = check_service_status(service)
        success = new_status == "active"
        if success:
            log.critical(f"[Self-Heal] REAL ACTION — restarted and verified {service} is active again")
        else:
            log.error(f"[Self-Heal] Restarted {service} but it is still not active (status={new_status})")
        return success
    except Exception as e:
        log.error(f"[Self-Heal] Failed to restart {service}: {e}")
        return False


def heal_all_down_services(dry_run: bool = True) -> dict:
    """Real, top-level entry point -- scans, then either reports or
    actually heals, mirroring the same dry-run safety gate used
    throughout the rest of the self-healing system."""
    down = scan_critical_services()
    results = {"down": down, "healed": [], "still_down": []}
    if not down:
        return results
    for entry in down:
        svc = entry["service"]
        if dry_run:
            log.warning(f"[Self-Heal] DRY RUN — would restart down service: {svc}")
            continue
        if heal_service(svc):
            results["healed"].append(svc)
        else:
            results["still_down"].append(svc)
    return results
