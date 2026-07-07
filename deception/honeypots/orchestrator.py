"""
Ghost IT — C3: Honeypot Orchestrator
Manages micro-honeypots with automatic runtime selection:
  - KVM available → Firecracker microVM (production, real kernel, hardware timing)
  - KVM unavailable → gVisor container (development fallback)

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 40% — KVM detection + gVisor fallback done, honeypot types in progress
"""
from __future__ import annotations
import os
import json
import logging
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

log = logging.getLogger(__name__)

CONFIGS_DIR = Path(__file__).parent / "configs"
HONEYPOT_TYPES = ["smb", "ssh", "http", "rdp", "db"]

# ------------------------------------------------------------------ #
# KVM Detection                                                        #
# ------------------------------------------------------------------ #

def detect_runtime() -> str:
    """
    Detect available virtualisation runtime.
    Returns: 'firecracker' if KVM available, 'gvisor' as fallback.
    """
    try:
        result = subprocess.check_output(
            "egrep -c '(vmx|svm)' /proc/cpuinfo",
            shell=True, stderr=subprocess.DEVNULL
        )
        kvm_ok = int(result.strip()) > 0
    except subprocess.CalledProcessError:
        kvm_ok = False

    # Also check /dev/kvm exists
    if kvm_ok:
        kvm_ok = os.path.exists("/dev/kvm")

    mode = "firecracker" if kvm_ok else "gvisor"
    log.info(f"Honeypot runtime: {mode.upper()} ({'KVM available' if kvm_ok else 'KVM not available — using gVisor fallback'})")
    return mode

RUNTIME = detect_runtime()

# ------------------------------------------------------------------ #
# Honeypot Config                                                       #
# ------------------------------------------------------------------ #

@dataclass
class HoneypotConfig:
    name: str
    htype: str        # smb, ssh, http, rdp, db
    port: int
    image: str        # container/VM image
    network_ns: str   # network namespace name
    tap_device: str   # tap interface name
    running: bool = False
    pid: Optional[int] = None

# ------------------------------------------------------------------ #
# Orchestrator                                                          #
# ------------------------------------------------------------------ #

class HoneypotOrchestrator:
    """
    Manages all honeypot instances.
    Automatically uses Firecracker (KVM) or gVisor based on platform.
    """

    def __init__(self):
        self.runtime = RUNTIME
        self.honeypots: dict[str, HoneypotConfig] = {}
        self._lock = threading.Lock()
        log.info(f"HoneypotOrchestrator initialized — runtime={self.runtime}")

    def deploy(self, htype: str) -> bool:
        """Deploy a honeypot of the given type."""
        config_path = CONFIGS_DIR / f"{htype}.json"
        if not config_path.exists():
            log.warning(f"No config for honeypot type: {htype}")
            return False

        with open(config_path) as f:
            cfg = json.load(f)

        hp = HoneypotConfig(
            name=f"honeypot-{htype}",
            htype=htype,
            port=cfg["port"],
            image=cfg["image"],
            network_ns=f"ghosthoney-{htype}",
            tap_device=f"tap-honey-{htype}",
        )

        if self.runtime == "firecracker":
            success = self._deploy_firecracker(hp, cfg)
        else:
            success = self._deploy_gvisor(hp, cfg)

        if success:
            with self._lock:
                self.honeypots[htype] = hp
            log.info(f"Honeypot deployed: {htype} on port {hp.port} [{self.runtime}]")
        return success

    def _deploy_gvisor(self, hp: HoneypotConfig, cfg: dict) -> bool:
        """Deploy honeypot using gVisor (runsc) — development fallback."""
        try:
            # Create network namespace
            subprocess.run(["ip", "netns", "add", hp.network_ns],
                         capture_output=True)

            # Run container with gVisor runtime
            cmd = [
                "docker", "run", "-d",
                "--runtime=runsc",              # gVisor runtime
                "--name", hp.name,
                "--network", "none",            # isolated network
                "-p", f"{hp.port}:{hp.port}",
                "--restart", "unless-stopped",
                cfg["image"]
            ] + cfg.get("args", [])

            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                log.error(f"gVisor deploy failed: {result.stderr}")
                return False

            hp.running = True
            log.info(f"gVisor honeypot running: {hp.name}")
            return True

        except Exception as e:
            log.error(f"gVisor deploy error: {e}")
            return False

    def _deploy_firecracker(self, hp: HoneypotConfig, cfg: dict) -> bool:
        """Deploy honeypot using Firecracker microVM — production mode."""
        try:
            socket_path = f"/tmp/firecracker-{hp.htype}.socket"

            # Start Firecracker process
            proc = subprocess.Popen(
                ["firecracker", "--api-sock", socket_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            hp.pid = proc.pid

            import time, urllib.request
            time.sleep(0.5)  # Wait for socket

            # Configure boot source
            boot_config = json.dumps({
                "kernel_image_path": cfg.get("kernel", "/opt/ghost/kernels/vmlinux-5.15"),
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
            }).encode()

            req = urllib.request.Request(
                f"http+unix://{socket_path}/boot-source",
                data=boot_config,
                method="PUT",
                headers={"Content-Type": "application/json"}
            )
            urllib.request.urlopen(req, timeout=5)

            hp.running = True
            log.info(f"Firecracker honeypot running: {hp.name}")
            return True

        except Exception as e:
            log.error(f"Firecracker deploy error: {e}")
            return False

    def stop(self, htype: str):
        """Stop a running honeypot."""
        with self._lock:
            hp = self.honeypots.get(htype)
        if not hp:
            return

        if self.runtime == "gvisor":
            subprocess.run(["docker", "stop", hp.name], capture_output=True)
            subprocess.run(["docker", "rm", hp.name], capture_output=True)
        elif hp.pid:
            subprocess.run(["kill", str(hp.pid)], capture_output=True)

        hp.running = False
        log.info(f"Honeypot stopped: {htype}")

    def get_status(self) -> dict:
        """Return status of all honeypots."""
        with self._lock:
            return {
                "runtime": self.runtime,
                "honeypots": {
                    htype: {
                        "running": hp.running,
                        "port": hp.port,
                        "type": hp.htype,
                    }
                    for htype, hp in self.honeypots.items()
                }
            }

    def get_honeypot_ips(self) -> set:
        """Return set of all active honeypot IPs — used by C14 suppressor."""
        ips = set()
        with self._lock:
            for hp in self.honeypots.values():
                if hp.running:
                    ips.add("127.0.0.1")  # Local dev — real IPs in production
        return ips

    def deploy_all(self):
        """Deploy all configured honeypot types."""
        for htype in HONEYPOT_TYPES:
            config_path = CONFIGS_DIR / f"{htype}.json"
            if config_path.exists():
                self.deploy(htype)

# Singleton
orchestrator = HoneypotOrchestrator()

def get_honeypot_ips() -> set:
    """Used by C14 to suppress duplicate alerts."""
    return orchestrator.get_honeypot_ips()
