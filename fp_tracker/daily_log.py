
#!/usr/bin/env python3

"""

Ghost IT -- False Positive Tracker (rebuilt)



The original version queried the lab VM's own local dashboard API

(127.0.0.1:8001), which itself queried a local pipeline

(127.0.0.1:8000) that no longer exists -- the real architecture has

since moved to agent-on-lab-VM forwarding to pipeline-on-Lightsail.

That original chain was silently returning "0 alerts" for the past

~50 days, not because there genuinely were none, but because it was

querying a disconnected, nonexistent local service that itself

silently swallowed its own connection failures.



Rebuilt to run directly on Lightsail (where the real pipeline and

the real internal-auth secret both actually live), querying the

real pipeline's /alerts endpoint directly -- no intermediate

dashboard-api hop needed for this specific purpose.



Groups by `comm` now, not `type` -- every real alert currently shares

type=="detection"; the actual rule identifier lives in comm as

"detection:{rule_id}" (confirmed via real /alerts output).

"""

import json, os, subprocess, urllib.request, datetime



LOG_FILE = os.path.expanduser("~/ghostlayer/fp_tracker/fp_log.json")

PIPELINE_URL = "http://localhost:8000/alerts?limit=500"

START_DATE = "2026-08-15"  # real restart date -- see docs/TECHNICAL_DEBT.md for why





def _get_internal_secret() -> str:

    try:

        return subprocess.check_output(

            ["sudo", "cat", "/etc/ghostit/.internal_secret"], text=True

        ).strip()

    except Exception:

        return ""





def get_alerts():

    req = urllib.request.Request(

        PIPELINE_URL, headers={"X-Internal-Auth": _get_internal_secret()}

    )

    with urllib.request.urlopen(req, timeout=10) as r:

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

    if any(d["date"] == today for d in log["days"]):

        print(f"Already logged for {today}")

        return

    try:

        data = get_alerts()

        alerts = data.get("alerts", [])

        by_type = {}

        for a in alerts:

            t = a.get("comm", "unknown")

            by_type[t] = by_type.get(t, 0) + 1

        start = datetime.date.fromisoformat(log["start_date"])

        day_num = (datetime.date.today() - start).days + 1

        entry = {

            "date": today,

            "day": day_num,

            "total_alerts": len(alerts),

            "by_type": by_type,

            "false_positives_today": 0,  # updated manually via mark_fp.py

        }

        log["days"].append(entry)

        save_log(log)

        print(f"Day {day_num} logged -- {len(alerts)} real alerts: {by_type}")

    except Exception as e:

        print(f"Error: {e}")





if __name__ == "__main__":

    main()

