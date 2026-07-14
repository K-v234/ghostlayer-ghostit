#!/usr/bin/env python3
"""
Ghost IT — C19: LKRG Kernel Integrity Watcher
Tails dmesg for LKRG kernel integrity events and forwards them to the
Ghost IT pipeline as structured events. LKRG itself runs entirely in
kernel space (lkrg.ko) -- this watcher is the userspace bridge that
makes its findings visible to the rest of Ghost IT, same role as
C1's eBPF agent bridges kernel telemetry to the pipeline.
"""
import subprocess
import socket
import json
import time
import re
import sys
import logging

log = logging.getLogger("lkrg_watcher")
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [lkrg_watcher] %(levelname)s %(message)s")

PIPELINE_HOST = "127.0.0.1"
PIPELINE_PORT = 9000

# Lines that indicate a real integrity concern, not just normal
# lifecycle noise (module load/unload, routine heartbeat).
CONCERNING_PATTERNS = [
    r"kernel integrity.*violat",
    r"process integrity.*violat",
    r"unauthorized",
    r"WARNING",
    r"tainting kernel",
    r"module verification failed",
]

def send_event(event: dict):
    try:
        payload = (json.dumps([event]) + "\n").encode()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((PIPELINE_HOST, PIPELINE_PORT))
        s.sendall(payload)
        s.close()
    except Exception as e:
        log.error(f"Failed to forward event: {e}")

def classify_line(line: str) -> tuple[bool, int]:
    """Returns (is_concerning, score)."""
    for pattern in CONCERNING_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True, 80
    if "LKRG:" in line:
        return True, 20  # routine LKRG activity, low score
    return False, 0

def main():
    log.info("LKRG watcher started -- tailing dmesg for kernel integrity events")
    proc = subprocess.Popen(
        ["sudo", "dmesg", "-w"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
    )
    for line in proc.stdout:
        line = line.strip()
        is_concerning, score = classify_line(line)
        if not is_concerning:
            continue
        event = {
            "agent": "lkrg-c19",
            "type": "kernel_integrity",
            "comm": "lkrg",
            "score": score,
            "file": line,
            "host": "linux",
            "ts": int(time.time() * 1e9),
        }
        log.info(f"Forwarding: {line[:80]}")
        send_event(event)

if __name__ == "__main__":
    main()
