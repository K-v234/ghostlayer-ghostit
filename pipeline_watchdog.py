
#!/usr/bin/env python3

"""

Ghost IT -- Pipeline Health Watchdog

Runs OUTSIDE the pipeline's own Docker container, as an independent

systemd service on the host. If the pipeline dies, this process

survives to detect and alert on exactly that.

"""

import json

import time

import urllib.request

import urllib.error

import os



HEALTH_URL = os.environ.get("GHOST_HEALTH_URL", "http://localhost:8000/health")

CHECK_INTERVAL_SEC = int(os.environ.get("GHOST_WATCHDOG_INTERVAL", "60"))

FAILURE_THRESHOLD = int(os.environ.get("GHOST_WATCHDOG_FAILURES", "3"))



TELEGRAM_BOT_TOKEN = os.environ.get("GHOSTIT_TELEGRAM_BOT_TOKEN", "")

TELEGRAM_CHAT_ID = os.environ.get("GHOSTIT_TELEGRAM_CHAT_ID", "")





def send_telegram(text):

    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:

        print("[watchdog] Telegram not configured, would have sent: " + text)

        return

    url = "https://api.telegram.org/bot" + TELEGRAM_BOT_TOKEN + "/sendMessage"

    payload = json.dumps({"chat_id": TELEGRAM_CHAT_ID, "text": text}).encode()

    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})

    try:

        urllib.request.urlopen(req, timeout=10)

        print("[watchdog] Alert sent: " + text)

    except Exception as e:

        print("[watchdog] Failed to send Telegram alert: " + str(e))





def check_health():

    try:

        req = urllib.request.Request(HEALTH_URL)

        with urllib.request.urlopen(req, timeout=10) as resp:

            data = json.loads(resp.read())

            return data.get("status") == "ok"

    except Exception as e:

        print("[watchdog] Health check failed: " + str(e))

        return False





def main():

    print("[watchdog] Starting -- checking " + HEALTH_URL + " every " + str(CHECK_INTERVAL_SEC) + "s")

    consecutive_failures = 0

    was_down = False



    while True:

        healthy = check_health()



        if healthy:

            if was_down:

                send_telegram(

                    "[OK] GHOST IT PIPELINE RECOVERED\n"

                    "The pipeline is responding normally again after " + str(consecutive_failures) + " failed checks."

                )

                was_down = False

            consecutive_failures = 0

        else:

            consecutive_failures += 1

            print("[watchdog] Failure " + str(consecutive_failures) + "/" + str(FAILURE_THRESHOLD))

            if consecutive_failures == FAILURE_THRESHOLD and not was_down:

                send_telegram(

                    "[ALERT] GHOST IT PIPELINE DOWN\n"

                    "Health check has failed " + str(FAILURE_THRESHOLD) + " times in a row.\n"

                    "Every connected customer endpoint is currently blind.\n"

                    "Check: sudo docker compose logs pipeline"

                )

                was_down = True



        time.sleep(CHECK_INTERVAL_SEC)





if __name__ == "__main__":

    main()

