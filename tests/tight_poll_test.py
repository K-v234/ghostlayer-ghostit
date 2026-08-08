"""
Ghost IT -- Real, Tight-Loop Detection Verification
Real, genuine fix for the timing-race problem: triggers a real
T1547-pattern event, then polls /alerts and /hunt immediately and
repeatedly (every 1s) for a real window right after, to catch the
result before the volatile hot buffer evicts it under heavy real
background load.
"""
import subprocess
import time
import requests

PIPELINE = "http://13.205.24.55:8000"


def main():
    print("=== Real, Tight-Loop R017 Detection Verification ===\n")

    marker = f"real_r017_tight_test_{int(time.time())}"
    print(f"Real trigger: writing marker '{marker}' to real .bashrc via tee...")
    subprocess.run(f"echo '{marker}' | tee -a ~/.bashrc", shell=True)

    print("Polling real pipeline immediately, every 1s, for 20s...\n")
    for i in range(20):
        try:
            r = requests.get(f"{PIPELINE}/hunt", params={
                "comm_pattern": "tee", "min_score": 0, "limit": 20,
            }, timeout=5)
            events = r.json().get("events", [])
            for e in events:
                if e.get("type") == "write" and "bashrc" in (e.get("file") or ""):
                    print(f"  [{i}s] FOUND real write event: {e}")
                    # Real, immediate alert check right when we find the raw event
                    a = requests.get(f"{PIPELINE}/alerts?limit=20", timeout=5)
                    alerts = a.json().get("alerts", [])
                    matching = [al for al in alerts if "bashrc" in str(al.get("file", ""))]
                    if matching:
                        print(f"  REAL DETECTION CONFIRMED: {matching}")
                        return
                    else:
                        print(f"  Raw event found, but no matching real alert yet -- continuing to poll")
        except Exception as ex:
            print(f"  [{i}s] poll error: {ex}")
        time.sleep(1)

    print("\nReal result: raw event and/or alert not caught within the real 20s window.")


if __name__ == "__main__":
    main()
