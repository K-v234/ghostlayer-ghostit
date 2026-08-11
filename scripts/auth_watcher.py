
#!/usr/bin/env python3

"""

Ghost IT -- Auth Failure Watcher (T1110 Brute Force data source)



Tails /var/log/auth.log for real "Failed password" lines and forwards

a genuine auth_failure event to the pipeline over TLS, using the same

certificate-pinned protocol as the Rust agent (tls_pin.rs) -- this

watcher runs on the lab VM and talks to Lightsail over the real

internet, same as the main agent, so it needs the same protection

Day 1's TLS work established. A plain socket here would silently

undo that work for this one component.



This is the real data source check_t1110_brute_force() needs -- it

was never wireable before because no auth-failure event type existed

anywhere in the system.



Deliberately a standalone watcher, not a change to the Rust/eBPF

agent -- avoids a recompile+redeploy cycle for what's fundamentally

simple userspace log-tailing, not kernel-level capture.

"""

import os

import re

import socket

import ssl

import json

import time

import hashlib

import logging



logging.basicConfig(level=logging.INFO, format="%(asctime)s [auth-watcher] %(levelname)s %(message)s")

log = logging.getLogger(__name__)



AUTH_LOG_PATH = os.environ.get("GHOST_AUTH_LOG", "/var/log/auth.log")

PIPELINE_HOST = os.environ.get("GHOST_PIPELINE_HOST", "13.205.24.55")

PIPELINE_PORT = int(os.environ.get("GHOST_PIPELINE_PORT", "9443"))

API_KEY = os.environ.get("GHOST_API_KEY", "e5fc9ef08eb9a71509e7420ea42cf8577f10da26b43d8a71")



PINNED_FINGERPRINT = "649c8d857e4d5b7a6ca09cb016d73a5be9dee08f485f67b194a1d9377a5c57e9"



FAILED_PW_RE = re.compile(

    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>[\d.]+) port (?P<port>\d+)"

)





def _pinned_ssl_context() -> ssl.SSLContext:

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    ctx.check_hostname = False

    ctx.verify_mode = ssl.CERT_NONE

    return ctx





def _verify_pin(sock: ssl.SSLSocket):

    der_cert = sock.getpeercert(binary_form=True)

    if der_cert is None:

        raise ssl.SSLError("no peer certificate presented")

    fingerprint = hashlib.sha256(der_cert).hexdigest()

    if fingerprint != PINNED_FINGERPRINT:

        raise ssl.SSLError(f"cert fingerprint mismatch -- expected {PINNED_FINGERPRINT}, got {fingerprint}")





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

        raw_sock = socket.create_connection((PIPELINE_HOST, PIPELINE_PORT), timeout=5)

        ctx = _pinned_ssl_context()

        s = ctx.wrap_socket(raw_sock, server_hostname="ghostit-pipeline")

        _verify_pin(s)

        s.sendall((API_KEY + "\n").encode())

        s.sendall((json.dumps(event) + "\n").encode())

        s.close()

        log.info(f"Forwarded auth_failure (TLS): user={user} src_ip={src_ip}")

    except (OSError, ssl.SSLError) as ex:

        log.error(f"Pipeline unavailable or TLS error, dropping auth_failure event: {ex}")





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

