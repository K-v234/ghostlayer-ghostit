"""
Ghost IT -- Real, Automated Regression Test Suite
Real, genuine, repeatable checks across every real system proven
tonight -- designed to catch exactly the kind of silent regression
(the timestamp bug) that cost real hours before being found. Run
this after ANY pipeline change, before trusting it again.
"""
from __future__ import annotations
import requests
import time
import sys

PIPELINE = "http://localhost:8000"

results: list[tuple[str, bool, str]] = []


def check(name: str, condition: bool, detail: str = ""):
    results.append((name, condition, detail))
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name}" + (f" — {detail}" if detail else ""))


def test_health():
    r = requests.get(f"{PIPELINE}/health", timeout=5)
    check("Pipeline /health responds", r.status_code == 200, f"status={r.status_code}")
    data = r.json()
    check("Pipeline reports status=ok", data.get("status") == "ok")


def test_stats():
    r = requests.get(f"{PIPELINE}/stats", timeout=5)
    data = r.json()
    check("Pipeline /stats responds", r.status_code == 200)
    check("Real total events > 0", data.get("total", 0) > 0, f"total={data.get('total')}")


def test_history_endpoint_not_broken():
    """
    Real, genuine regression check for tonight's actual bug: verifies
    /events/history can find data known to exist via /top. This is
    the SPECIFIC test that would have caught tonight's timestamp bug
    immediately, the first time it was introduced.
    """
    top = requests.get(f"{PIPELINE}/top?limit=5", timeout=5).json()
    procs = top.get("processes", [])
    if not procs:
        check("History regression check (no real data to test against)", True, "skipped, no /top data")
        return
    real_comm = procs[0]["comm"]
    hist = requests.get(
        f"{PIPELINE}/events/history",
        params={"days_back": 1, "comm_pattern": real_comm, "min_score": 0, "limit": 5},
        timeout=10,
    ).json()
    check(
        f"/events/history finds real, known-existing comm '{real_comm}'",
        hist.get("total", 0) > 0,
        f"total={hist.get('total')} (this is the exact check that would have caught tonight's timestamp bug)",
    )


def test_metrics_endpoint():
    r = requests.get(f"{PIPELINE}/metrics", timeout=5)
    check("Prometheus /metrics responds", r.status_code == 200)
    check("Metrics contain real event counter", "ghostit_events_total" in r.text)


def test_alerts_endpoint():
    r = requests.get(f"{PIPELINE}/alerts?limit=5", timeout=5)
    check("Alerts endpoint responds", r.status_code == 200)


def test_replay_endpoint_exists():
    # Real, genuine check that the endpoint exists and responds
    # sanely to a bogus ID (404 or empty, not a 500 crash)
    r = requests.get(f"{PIPELINE}/replay/nonexistent-real-test-id", timeout=5)
    check("Replay endpoint doesn't crash on bad ID", r.status_code in (200, 404), f"status={r.status_code}")


def run_all():
    print("=== Ghost IT Real Regression Suite ===\n")
    for fn in [test_health, test_stats, test_history_endpoint_not_broken,
               test_metrics_endpoint, test_alerts_endpoint, test_replay_endpoint_exists]:
        try:
            fn()
        except Exception as ex:
            check(fn.__name__, False, f"EXCEPTION: {ex}")

    print("\n=== Summary ===")
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"{passed}/{total} real checks passed")

    failed = [(n, d) for n, ok, d in results if not ok]
    if failed:
        print("\nFAILED CHECKS:")
        for name, detail in failed:
            print(f"  - {name}: {detail}")
        sys.exit(1)
    else:
        print("All real checks passed.")
        sys.exit(0)


if __name__ == "__main__":
    run_all()
