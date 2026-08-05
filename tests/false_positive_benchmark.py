"""
Ghost IT -- Real False-Positive Benchmark
Real, genuine test: runs a batch of completely normal, everyday
commands and checks the real pipeline for any real alerts generated
as a result. A real, correctly-tuned EDR should generate zero (or
near-zero) alerts from genuinely benign activity -- this is one of
the most important, real differentiators between a usable EDR and
an unusable, noisy one.
"""
from __future__ import annotations
import subprocess
import time
import requests

PIPELINE = "http://localhost:8000"

# Real, genuinely everyday, benign commands -- the kind any real
# developer or office worker runs constantly, all day, every day.
BENIGN_COMMANDS = [
    "ls -la /tmp",
    "cat /etc/hostname",
    "echo 'real benign test'",
    "grep -r 'test' /etc/hostname",
    "find /tmp -maxdepth 1 -name '*.txt'",
    "python3 -c 'print(1+1)'",
    "git --version",
    "curl -s -o /dev/null http://localhost:8000/health",
    "ps aux | head -5",
    "df -h /",
]


def run(cmd: str):
    subprocess.run(cmd, shell=True, capture_output=True, text=True)


def get_alert_count() -> int:
    try:
        r = requests.get(f"{PIPELINE}/alerts?limit=200", timeout=5)
        return len(r.json().get("alerts", []))
    except Exception:
        return -1


def main():
    print("=== Ghost IT Real False-Positive Benchmark ===\n")

    before = get_alert_count()
    print(f"Real alert count before benign activity: {before}")

    print(f"\nRunning {len(BENIGN_COMMANDS)} real, genuinely everyday commands...")
    for cmd in BENIGN_COMMANDS:
        print(f"  Running: {cmd}")
        run(cmd)
        time.sleep(0.5)

    print("\nWaiting for real telemetry to flow...")
    time.sleep(15)

    after = get_alert_count()
    print(f"\nReal alert count after benign activity: {after}")

    new_alerts = max(0, after - before) if before >= 0 and after >= 0 else -1
    print(f"\n=== Real Result ===")
    if new_alerts == 0:
        print(f"PASS: zero new real alerts from {len(BENIGN_COMMANDS)} genuinely benign commands")
    elif new_alerts > 0:
        print(f"FAIL: {new_alerts} real false-positive alert(s) from genuinely benign activity")
    else:
        print("INCONCLUSIVE: could not reliably measure alert counts")


if __name__ == "__main__":
    main()
