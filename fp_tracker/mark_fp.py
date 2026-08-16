
#!/usr/bin/env python3

"""

Ghost IT -- Manual False Positive Marker



Run this whenever a real alert turns out to be a false positive.

Increments today's false_positives_today count (if today's entry

already exists) and appends a real, reasoned record to

log["false_positives"] -- report.py reads both.



Usage: python3 mark_fp.py "reason for why this was a false positive"

"""

import json, os, sys, datetime



LOG_FILE = os.path.expanduser("~/ghostlayer/fp_tracker/fp_log.json")





def main():

    if len(sys.argv) < 2:

        print('Usage: python3 mark_fp.py "reason"')

        return

    reason = " ".join(sys.argv[1:])

    if not os.path.exists(LOG_FILE):

        print("No fp_log.json yet -- run daily_log.py first.")

        return

    log = json.load(open(LOG_FILE))

    today = datetime.date.today().isoformat()

    found = False

    for d in log["days"]:

        if d["date"] == today:

            d["false_positives_today"] += 1

            found = True

            break

    if not found:

        print(f"Warning: no log entry for {today} yet -- run daily_log.py first, "

              f"recording the FP anyway but it won't count toward today's total until then.")

    log["false_positives"].append({"date": today, "reason": reason})

    json.dump(log, open(LOG_FILE, "w"), indent=2)

    print(f"Marked FP: {reason}")





if __name__ == "__main__":

    main()

