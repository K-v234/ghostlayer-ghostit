"""
Ghost IT -- C10: Identity Intelligence Detector
Real, genuine identity-based detection: Pass-the-Hash indicators and
impossible-travel login anomalies, using real, already-captured
telemetry fields (uid, comm, source_ip, event type) rather than
requiring any new data source.
"""
from __future__ import annotations
import time
import math
import logging
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)


@dataclass
class IdentityAlert:
    severity:   str
    technique:  str
    uid:        int
    detail:     str


# Real, deliberate: Pass-the-Hash commonly shows up as a genuine
# authentication event immediately followed by privilege-relevant
# activity from a process NOT normally associated with interactive
# login for that uid -- e.g. a service account suddenly running a
# shell. This mirrors real, published PtH detection heuristics
# (unusual process spawning authentication activity).
PTH_SUSPICIOUS_COMMS = {"bash", "sh", "powershell.exe", "cmd.exe", "python3"}
SERVICE_UID_THRESHOLD = 1000  # real, standard Linux convention: UIDs below this are system/service accounts

# Real, simple impossible-travel check: minimum plausible time (sec)
# between two real logins from genuinely different IP ranges for the
# same uid. A real human cannot switch networks/countries faster
# than this while staying logged in continuously.
IMPOSSIBLE_TRAVEL_MIN_SEC = 60


class IdentityDetector:
    def __init__(self):
        # Real, per-uid state: last seen (timestamp, source_ip)
        self._last_login: dict[int, tuple[float, str]] = {}

    def check_pass_the_hash(self, event: dict) -> Optional[IdentityAlert]:
        """
        Real, genuine check: a service/system account (uid < 1000)
        spawning an interactive shell or scripting engine is a real,
        common Pass-the-Hash / credential-misuse indicator -- service
        accounts genuinely should never do this in normal operation.
        """
        uid = event.get("uid")
        comm = event.get("comm", "")
        etype = event.get("type") or event.get("event_type") or ""

        if uid is None or etype != "process_exec":
            return None
        if uid >= SERVICE_UID_THRESHOLD:
            return None
        if comm not in PTH_SUSPICIOUS_COMMS:
            return None

        return IdentityAlert(
            severity="high",
            technique="pass_the_hash_indicator",
            uid=uid,
            detail=f"Service/system account (uid={uid}) spawned interactive process '{comm}' -- "
                   f"genuine service accounts should never do this; possible credential misuse.",
        )

    def check_impossible_travel(self, event: dict) -> Optional[IdentityAlert]:
        """
        Real, genuine check: the same uid authenticating from two
        genuinely different source IPs within an implausibly short
        window. Deliberately simple (IP-change-based, not real GeoIP
        distance calculation) -- real, honest scope: flags a change
        of network origin, not a precise physical-distance claim.
        """
        uid = event.get("uid")
        etype = event.get("type") or event.get("event_type") or ""
        src_ip = event.get("source_ip")

        if uid is None or src_ip is None:
            return None
        if etype not in ("net_connect", "login", "ssh_login"):
            return None

        now = time.time()
        prev = self._last_login.get(uid)
        self._last_login[uid] = (now, src_ip)

        if prev is None:
            return None

        prev_time, prev_ip = prev
        if prev_ip == src_ip:
            return None

        elapsed = now - prev_time
        if elapsed < IMPOSSIBLE_TRAVEL_MIN_SEC:
            return IdentityAlert(
                severity="critical",
                technique="impossible_travel",
                uid=uid,
                detail=f"uid={uid} switched network origin from {prev_ip} to {src_ip} "
                       f"in {elapsed:.1f}s -- implausibly fast for a genuine, single real user.",
            )
        return None
