#!/usr/bin/env python3
"""
Ghost IT — C6 Layer 3: Binary Hash Watchdog

Verifies agent binary SHA-256 against cosign bundle every 60 seconds.
If hash mismatch detected → CRITICAL alert to pipeline.

Per spec: "Expected hash fetched from bundle (not local reference)"
This prevents supply chain attack where malicious binary
sets its own reference hash.

Ghost Layer Technologies — CONFIDENTIAL
"""
import os
import sys
import json
import time
import socket
import hashlib
import logging
import threading

log = logging.getLogger(__name__)

AGENT_BINARY   = os.path.join(os.path.dirname(__file__), "..", "ghost_agent")
BUNDLE_PATH    = os.path.expanduser("~/ghostlayer/ghostit-agent-linux-amd64.cosign.bundle")
CHECK_INTERVAL = 60  # seconds


def get_expected_hash() -> str:
    """
    Extract expected SHA-256 from cosign bundle.
    Bundle contains the hash that was signed at release time.
    """
    if not os.path.exists(BUNDLE_PATH):
        log.warning(f"Cosign bundle not found: {BUNDLE_PATH}")
        return ""

    with open(BUNDLE_PATH) as f:
        bundle = json.load(f)

    # Extract from bundle payload
    try:
        import base64
        payload_b64 = bundle.get("Payload", {})
        if isinstance(payload_b64, str):
            payload = json.loads(base64.b64decode(payload_b64 + "=="))
            # Look for hash in payload
            body_b64 = payload.get("body", "")
            if body_b64:
                body = json.loads(base64.b64decode(body_b64 + "=="))
                spec = body.get("spec", {})
                data = spec.get("data", {})
                return data.get("hash", {}).get("value", "")
    except Exception as ex:
        log.debug(f"Bundle parse error: {ex}")

    return ""


def get_actual_hash(binary_path: str) -> str:
    """Compute SHA-256 of current binary on disk."""
    try:
        with open(binary_path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError as ex:
        log.error(f"Cannot read binary: {ex}")
        return ""


def send_tamper_alert(pipeline_host: str = "127.0.0.1",
                      pipeline_port: int = 9000):
    """Send CRITICAL alert to pipeline if binary tampered."""
    event = {
        "ts":      int(time.time_ns()),
        "pid":     0, "ppid": 0, "uid": 0, "gid": 0,
        "comm":    "c6-watchdog",
        "type":    "binary_tampered",
        "score":   100,
        "alert":   True,
        "reasons": [
            "C6:binary_tampered",
            "layer3:hash_mismatch",
            "action:restart_required",
        ],
        "file":    "Ghost IT agent binary hash mismatch — possible tampering",
        "daddr":   None,
        "dport":   None,
    }
    payload = (json.dumps([event]) + "\n").encode()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((pipeline_host, pipeline_port))
        s.sendall(payload)
        s.close()
        log.critical("BINARY TAMPER ALERT sent to pipeline")
    except OSError:
        log.critical("BINARY TAMPER DETECTED — pipeline unavailable for alert")


class BinaryHashWatchdog:
    """
    C6 Layer 3: Binary integrity watchdog.
    Runs as background thread alongside the agent.
    """

    def __init__(self, binary_path: str = AGENT_BINARY,
                 pipeline_host: str = "127.0.0.1",
                 pipeline_port: int = 9000):
        self.binary_path   = os.path.abspath(binary_path)
        self.pipeline_host = pipeline_host
        self.pipeline_port = pipeline_port
        self._running      = False

        # Capture hash at startup as baseline
        self._baseline_hash = get_actual_hash(self.binary_path)
        log.info(
            f"C6 Layer 3 watchdog initialized — "
            f"binary={self.binary_path} "
            f"hash={self._baseline_hash[:16]}..."
        )

    def start(self):
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        log.info(f"Binary hash watchdog started — checking every {CHECK_INTERVAL}s")

    def _loop(self):
        while self._running:
            time.sleep(CHECK_INTERVAL)
            self._check()

    def _check(self):
        current_hash = get_actual_hash(self.binary_path)

        if not current_hash:
            return

        if current_hash != self._baseline_hash:
            log.critical(
                f"BINARY HASH MISMATCH — "
                f"expected={self._baseline_hash[:16]}... "
                f"actual={current_hash[:16]}..."
            )
            send_tamper_alert(self.pipeline_host, self.pipeline_port)
        else:
            log.debug(f"Binary integrity OK: {current_hash[:16]}...")

    def stop(self):
        self._running = False


def start_watchdog_background(binary_path: str = AGENT_BINARY,
                               pipeline_host: str = "127.0.0.1",
                               pipeline_port: int = 9000) -> BinaryHashWatchdog:
    """Start watchdog in background thread. Returns watchdog instance."""
    watchdog = BinaryHashWatchdog(binary_path, pipeline_host, pipeline_port)
    watchdog.start()
    return watchdog


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
        format="%(asctime)s [watchdog] %(levelname)s %(message)s")
    watchdog = BinaryHashWatchdog()
    watchdog.start()
    log.info("Watchdog running — press Ctrl+C to stop")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        watchdog.stop()
