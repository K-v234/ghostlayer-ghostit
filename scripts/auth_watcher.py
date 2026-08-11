
#!/usr/bin/env python3

"""

Ghost IT -- Auth Failure Watcher (T1110 Brute Force data source)



Tails /var/log/auth.log for real "Failed password" lines and forwards

a genuine auth_failure event to the pipeline over the same TCP +

API-key protocol used everywhere else (matches send_to_pipeline's

protocol exactly, confirmed working end-to-end this session). This

is the real data source T1110's check_t1110_brute_force() needs --

it was never wireable before because no auth-failure event type

existed anywhere in the system.



Deliberately a standalone watcher, not a change to the Rust/eBPF

agent -- avoids a recompile+redeploy cycle for what's fundamentally

simple userspace log-tailing, not kernel-level capture.

"""

import os

import re

import socket

import json

import time

import logging



logging.basicConfig(level=logging.INFO, format="%(asctime)s [auth-watcher] %(levelname)s %(message)s")

log = logging.getLogger(__name__)



AUTH_LOG_PATH = os.environ.get("GHOST_AUTH_LOG", "/var/log/auth.log")

PIPELINE_HOST = os.environ.get("GHOST_PIPELINE_HOST", "13.205.24.55")

PIPELINE_PORT = int(os.environ.get("GHOST_PIPELINE_PORT", "9000"))

API_KEY = os.environ.get("GHOST_API_KEY", "e5fc9ef08eb9a71509e7420ea42cf8577f10da26b43d8a71")



FAILED_PW_RE = re.compile(

    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>[\d.]+) port (?P<port>\d+)"

)





def send_event(user: str, src_ip: str):

    event = [{

        "type": "auth_failure",

        "comm": "sshd",

        "pid": 0,

        "uid": 0,

        "gid": 0,

        "ts": int(time.time_ns()),

        "received_at": int(time.time()),

        "score": 0,

        "daddr": src_ip,

        "args": user,

    }]

    try:

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.settimeout(3)

        s.connect((PIPELINE_HOST, PIPELINE_PORT))

        s.sendall((API_KEY + "\n").encode())

        s.sendall((json.dumps(event) + "\n").encode())

        s.close()

        log.info(f"Forwarded auth_failure: user={user} src_ip={src_ip}")

    except OSError as ex:

        log.error(f"Pipeline unavailable, dropping auth_failure event: {ex}")





def tail_auth_log():

    log.info(f"Watching {AUTH_LOG_PATH} for real failed-password events")

    with open(AUTH_LOG_PATH, "r") as f:

        f.seek(0, os.SEEK_END)

        while True:

            line = f.readline()

            if not line:

                time.sleep(0.5)

                continue

            m = FAILED_PW_RE.search(line)

            if m:

                send_event(m.group("user"), m.group("src_ip"))





if __name__ == "__main__":

    while True:

        try:

            tail_auth_log()

        except FileNotFoundError:

            log.error(f"{AUTH_LOG_PATH} not found, retrying in 10s")

            time.sleep(10)

        except Exception as ex:

            log.error(f"Watcher crashed, restarting in 5s: {ex}")

            time.sleep(5)

