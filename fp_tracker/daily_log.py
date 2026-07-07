#!/usr/bin/env python3
"""
Ghost IT — 60-Day False Positive Tracker
Runs daily via cron. Logs alert counts and types.
Start date: 2026-06-26
Target: < 2% FP rate across 60 days
"""
import json, os, time, urllib.request, datetime

LOG_FILE = os.path.expanduser("~/ghostlayer/fp_tracker/fp_log.json")
API = "http://127.0.0.1:8001/api"
CREDS = {"username": "admin", "password": "ghostit-admin-2026"}
START_DATE = "2026-06-26"

def get_token():
    r = urllib.request.urlopen(
        urllib.request.Request(f"{API}/auth/login",
        data=json.dumps(CREDS).encode(),
        headers={"Content-Type": "application/json"},
        method="POST"), timeout=5)
    return json.loads(r.read())["token"]

def get_alerts(token):
    r = urllib.request.urlopen(
        urllib.request.Request(f"{API}/alerts?limit=500",
        headers={"Authorization": f"Bearer {token}"}), timeout=5)
    return json.loads(r.read())

def load_log():
    if os.path.exists(LOG_FILE):
        return json.load(open(LOG_FILE))
    return {"start_date": START_DATE, "days": [], "false_positives": []}

def save_log(log):
    json.dump(log, open(LOG_FILE, "w"), indent=2)

def main():
    today = datetime.date.today().isoformat()
    log = load_log()

    # Check if already logged today
    if any(d["date"] == today for d in log["days"]):
        print(f"Already logged for {today}")
        return

    try:
        token = get_token()
        data = get_alerts(token)
        alerts = data.get("alerts", [])

        # Count by type
        by_type = {}
        for a in alerts:
            t = a.get("type", "unknown")
            by_type[t] = by_type.get(t, 0) + 1

        # Day number
        start = datetime.date.fromisoformat(START_DATE)
        day_num = (datetime.date.today() - start).days + 1

        entry = {
            "date": today,
            "day": day_num,
            "total_alerts": len(alerts),
            "by_type": by_type,
            "false_positives_today": 0,  # Updated manually via mark_fp.py
        }
        log["days"].append(entry)
        save_log(log)

        print(f"Day {day_num} logged — {len(alerts)} alerts: {by_type}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
