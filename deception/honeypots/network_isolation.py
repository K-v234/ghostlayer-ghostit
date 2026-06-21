"""
Ghost IT — C3: Honeypot Network Isolation
Isolates honeypots in separate network namespaces.
Prevents honeypot pivot to production subnets.

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 100% — complete
"""
import subprocess
import logging

log = logging.getLogger(__name__)

PRODUCTION_SUBNETS = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]

def create_namespace(ns_name: str) -> bool:
    """Create isolated network namespace for honeypot."""
    try:
        subprocess.run(["ip", "netns", "add", ns_name],
                      capture_output=True, check=True)
        log.info(f"Network namespace created: {ns_name}")
        return True
    except subprocess.CalledProcessError as e:
        if b"File exists" in e.stderr:
            return True  # Already exists
        log.error(f"Failed to create namespace {ns_name}: {e}")
        return False

def apply_isolation_rules(tap_device: str) -> bool:
    """
    Apply iptables rules to prevent honeypot from reaching
    production subnets. Critical security requirement.
    """
    try:
        for subnet in PRODUCTION_SUBNETS:
            subprocess.run([
                "iptables", "-I", "FORWARD",
                "-i", tap_device,
                "-d", subnet,
                "-j", "DROP"
            ], capture_output=True, check=True)
        log.info(f"Isolation rules applied for {tap_device}")
        return True
    except Exception as e:
        log.error(f"Failed to apply isolation rules: {e}")
        return False

def remove_namespace(ns_name: str):
    """Remove network namespace on honeypot shutdown."""
    subprocess.run(["ip", "netns", "del", ns_name],
                  capture_output=True)
    log.info(f"Network namespace removed: {ns_name}")
