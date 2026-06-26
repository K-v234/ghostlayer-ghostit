#!/usr/bin/env python3
"""
Ghost IT — FP Rate Report
Run anytime to see current status. At day 60 this is your V1 acceptance report.
"""
import json, os, datetime

LOG_FILE = os.path.expanduser("~/ghostlayer/fp_tracker/fp_log.json")

def main():
    if not os.path.exists(LOG_FILE):
        print("No data yet. Run daily_log.py first.")
        return

    log = json.load(open(LOG_FILE))
    days = log["days"]
    fps  = log["false_positives"]

    if not days:
        print("No days logged yet.")
        return

    total_alerts = sum(d["total_alerts"] for d in days)
    total_fps    = sum(d["false_positives_today"] for d in days)
    fp_rate      = (total_fps / total_alerts * 100) if total_alerts > 0 else 0

    start = datetime.date.fromisoformat(log["start_date"])
    elapsed = (datetime.date.today() - start).days + 1
    remaining = max(0, 60 - elapsed)

    print("=" * 50)
    print("Ghost IT — 60-Day FP Measurement Report")
    print("=" * 50)
    print(f"Start date   : {log['start_date']}")
    print(f"Day          : {elapsed} / 60")
    print(f"Remaining    : {remaining} days")
    print(f"Total alerts : {total_alerts}")
    print(f"False positives: {total_fps}")
    print(f"FP rate      : {fp_rate:.2f}%")
    print(f"Target       : < 2.00%")
    print(f"Status       : {'✅ PASSING' if fp_rate < 2.0 else '❌ FAILING'}")
    print("-" * 50)
    print("By alert type (last 7 days):")
    recent = days[-7:]
    agg = {}
    for d in recent:
        for t, c in d["by_type"].items():
            agg[t] = agg.get(t, 0) + c
    for t, c in sorted(agg.items(), key=lambda x: -x[1]):
        print(f"  {t}: {c}")
    if fps:
        print("-" * 50)
        print("False positives logged:")
        for fp in fps:
            print(f"  [{fp['date']}] {fp['reason']}")
    print("=" * 50)

if __name__ == "__main__":
    main()
