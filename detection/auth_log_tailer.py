#!/usr/bin/env python3
"""
Ghost IT — Auth Log Tailer (S3 fix)
Tails /var/log/auth.log, parses SSH auth failures,
forwards as synthetic events to pipeline TCP on port 9000.

Ghost Layer Technologies — CONFIDENTIAL
"""
import re
import time
import socket
import json
import os
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [auth-tailer] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S"
)
log = logging.getLogger(__name__)

AUTH_LOG    = "/var/log/auth.log"
PIPELINE_HOST = os.environ.get("GHOST_PIPELINE_HOST", "127.0.0.1")
PIPELINE_PORT = int(os.environ.get("GHOST_PIPELINE_PORT", "9000"))
RECONNECT_INTERVAL = 5  # seconds

# Patterns to match
PATTERNS = [
    # Failed password for invalid user bob from 192.168.1.1 port 22 ssh2
    re.compile(
        r"sshd(?:-session)?\[\d+\]: Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
    ),
    # Invalid user bob from 192.168.1.1 port 22
    re.compile(
        r"sshd(?:-session)?\[\d+\]: Invalid user (\S+) from ([\d.]+) port (\d+)"
    ),
    # Connection closed by invalid user
    re.compile(
        r"sshd(?:-session)?\[\d+\]: Connection closed by invalid user (\S+) ([\d.]+) port (\d+)"
    ),
]

def make_event(username: str, src_ip: str, src_port: str) -> dict:
    return {
        "ts":         time.time_ns(),
        "pid":        0,
        "ppid":       0,
        "uid":        0,
        "gid":        0,
        "comm":       "sshd",
        "event_type": "auth_failure",
        "score":      40,
        "alert":      False,
        "reasons":    [],
        "file":       None,
        "args":       username,
        "flags":      None,
        "daddr":      src_ip,
        "dport":      int(src_port),
        "family":     None,
        "clone_flags": None,
        "dpdp_pii_flag": False,
    }

def connect_pipeline():
    while True:
        try:
            s = socket.create_connection((PIPELINE_HOST, PIPELINE_PORT), timeout=5)
            log.info(f"Connected to pipeline {PIPELINE_HOST}:{PIPELINE_PORT}")
            return s
        except Exception as e:
            log.warning(f"Pipeline unavailable: {e} — retrying in {RECONNECT_INTERVAL}s")
            time.sleep(RECONNECT_INTERVAL)

def send_event(sock: socket.socket, event: dict) -> bool:
    try:
        payload = json.dumps([event]) + "\n"
        sock.sendall(payload.encode())
        return True
    except Exception as e:
        log.warning(f"Send failed: {e}")
        return False

def tail_auth_log():
    sock = connect_pipeline()

    # Seek to end of file on startup — don't replay old events
    try:
        f = open(AUTH_LOG, "r")
        f.seek(0, 2)  # seek to end
        log.info(f"Tailing {AUTH_LOG} from current end")
    except FileNotFoundError:
        log.error(f"{AUTH_LOG} not found — is sshd running?")
        return

    inode = os.fstat(f.fileno()).st_ino

    while True:
        line = f.readline()

        if not line:
            # Check for log rotation
            try:
                current_inode = os.stat(AUTH_LOG).st_ino
                if current_inode != inode:
                    log.info("Log rotated — reopening")
                    f.close()
                    f = open(AUTH_LOG, "r")
                    inode = os.fstat(f.fileno()).st_ino
            except FileNotFoundError:
                pass
            time.sleep(0.2)
            continue

        line = line.strip()
        for pattern in PATTERNS:
            m = pattern.search(line)
            if m:
                username, src_ip, src_port = m.group(1), m.group(2), m.group(3)
                event = make_event(username, src_ip, src_port)
                log.info(f"auth_failure: user={username} src={src_ip}:{src_port}")

                if not send_event(sock, event):
                    sock = connect_pipeline()
                    send_event(sock, event)
                break

if __name__ == "__main__":
    log.info("Ghost IT Auth Log Tailer starting")
    while True:
        try:
            tail_auth_log()
        except Exception as e:
            log.error(f"Tailer crashed: {e} — restarting in 5s")
            time.sleep(5)
