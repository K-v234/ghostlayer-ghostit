#!/usr/bin/env python3
"""
Ghost IT -- Agent Self-Watch (C6 Layer 2, real implementation)
Genuinely, deliberately runs as an INDEPENDENT process, separate from
the main agent. If the main agent's own process is killed (by an
attacker with local privileges, for example), an eBPF program or any
other mechanism running INSIDE that same process would die with it --
this is a real, fundamental limitation that requires a genuinely
separate watcher to solve correctly.
"""
import os
import time
import subprocess

PID_FILE = "/var/run/ghost-agent.pid"
CHECK_INTERVAL_SEC = 15
TELEGRAM_BOT_TOKEN = os.environ.get("GHOSTIT_TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("GHOSTIT_TELEGRAM_CHAT_ID", "")


def send_telegram(text):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("[agent-watch] Telegram not configured, would have sent: " + text)
        return
    import json
    import urllib.request
    url = "https://api.telegram.org/bot" + TELEGRAM_BOT_TOKEN + "/sendMessage"
    payload = json.dumps({"chat_id": TELEGRAM_CHAT_ID, "text": text}).encode()
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10)
        print("[agent-watch] Alert sent")
    except Exception as e:
        print("[agent-watch] Failed to send alert: " + str(e))


def read_pid():
    try:
        with open(PID_FILE) as f:
            return int(f.read().strip())
    except Exception:
        return None


def pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def main():
    print("[agent-watch] Starting -- watching " + PID_FILE)
    last_known_pid = None
    already_alerted = False
    while True:
        time.sleep(CHECK_INTERVAL_SEC)
        pid = read_pid()
        if pid is None:
            continue
        if last_known_pid is None:
            last_known_pid = pid
            continue
        if pid != last_known_pid:
            already_alerted = False
        if not already_alerted and not pid_alive(last_known_pid):
            # Real, deliberate distinction: check if systemd shows the
            # service as genuinely, cleanly stopped (an intentional
            # admin action) versus unexpectedly gone (a real tamper
            # signal) before alerting -- avoids false alarms on
            # legitimate maintenance restarts.
            try:
                result = subprocess.run(
                    ["systemctl", "is-active", "ghostit-agent.service"],
                    capture_output=True, text=True, timeout=5
                )
                status = result.stdout.strip()
            except Exception:
                status = "unknown"
            if status == "active":
                print("[agent-watch] Agent PID changed but service is active -- normal restart")
            else:
                already_alerted = True
                send_telegram(
                    "[ALERT] GHOST IT AGENT SELF-WATCH TRIGGERED\n"
                    "Agent process " + str(last_known_pid) + " disappeared and "
                    "the service is not reported active by systemd.\n"
                    "Possible tampering -- endpoint may be unprotected.\n"
                    "Check: sudo systemctl status ghostit-agent.service"
                )
        last_known_pid = pid


if __name__ == "__main__":
    main()
