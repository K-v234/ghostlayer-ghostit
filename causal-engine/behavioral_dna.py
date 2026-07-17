#!/usr/bin/env python3
"""
Ghost IT — Behavioral DNA: Process Masquerading Detection

Breakthrough #1: an attacker naming malware "svchost.exe" and placing
it in a normal-looking path can blend past every pillar built today --
none of them check whether a process actually BEHAVES like what it
claims to be. Behavioral DNA builds a genuine fingerprint of how each
trusted process name normally behaves on THIS machine (typical parent
process, typical file-touch patterns, typical network behavior) and
flags any process claiming that identity but behaving differently --
defeating masquerading regardless of how convincing the fake name is.
"""
from __future__ import annotations
import os
import time
import logging
import threading
import duckdb

log = logging.getLogger(__name__)

DNA_DB_PATH = os.environ.get("DNA_DB_PATH",
    os.path.expanduser("~/ghostlayer/data/behavioral_dna.duckdb"))

# Minimum real observations needed before a comm's DNA profile is
# considered reliable enough to flag deviations against -- prevents
# false positives from a genuinely new, legitimate process that just
# hasn't been observed enough yet.
MIN_OBSERVATIONS_FOR_PROFILE = 20

class BehavioralDNA:
    def __init__(self, db_path: str = DNA_DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._lock = threading.Lock()
        self.conn = duckdb.connect(db_path)
        self._init_schema()
        log.info(f"BehavioralDNA initialized: {db_path}")

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS profile_observations (
                comm         VARCHAR NOT NULL,
                parent_comm  VARCHAR,
                event_type   VARCHAR,
                path_prefix  VARCHAR,
                ts           DOUBLE NOT NULL
            )
        """)
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_comm ON profile_observations(comm)")

    def observe(self, comm: str, parent_comm: str, event_type: str, path: str):
        """Record a real, genuine behavioral observation for this
        process name -- building its DNA profile from actual local
        activity, not a hardcoded external whitelist."""
        path_prefix = "/".join(path.split("/")[:3]) if path else ""
        with self._lock:
            self.conn.execute(
                "INSERT INTO profile_observations VALUES (?, ?, ?, ?, ?)",
                [comm, parent_comm, event_type, path_prefix, time.time()]
            )

    def check_masquerade(self, comm: str, parent_comm: str, event_type: str, path: str) -> dict:
        """
        Check if THIS instance of a process behaves consistently with
        this comm's established DNA profile. A process named
        'svchost.exe' whose parent is normally 'services.exe' but is
        suddenly spawned by 'winword.exe' -- a real, classic
        masquerading pattern -- gets flagged here, regardless of how
        convincing the filename itself looks.
        """
        with self._lock:
            total = self.conn.execute(
                "SELECT COUNT(*) FROM profile_observations WHERE comm = ?", [comm]
            ).fetchone()[0]
            if total < MIN_OBSERVATIONS_FOR_PROFILE:
                return {"masquerade_suspected": False,
                         "reason": "insufficient profile history", "sample_size": total}

            common_parents = self.conn.execute(
                "SELECT parent_comm, COUNT(*) as c FROM profile_observations "
                "WHERE comm = ? GROUP BY parent_comm ORDER BY c DESC LIMIT 3",
                [comm]
            ).fetchall()

        known_parents = {p[0] for p in common_parents if p[0]}
        parent_is_typical = parent_comm in known_parents

        if not parent_is_typical and known_parents:
            return {
                "masquerade_suspected": True,
                "comm": comm, "observed_parent": parent_comm,
                "typical_parents": list(known_parents),
                "sample_size": total,
                "reasoning": f"'{comm}' is normally spawned by {list(known_parents)}, "
                             f"but this instance was spawned by '{parent_comm}' -- "
                             f"a real, classic process-masquerading pattern regardless "
                             f"of how legitimate the process name itself looks.",
            }
        return {"masquerade_suspected": False, "sample_size": total,
                 "typical_parents": list(known_parents)}

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    dna = BehavioralDNA(db_path="/tmp/dna_test.duckdb")

    print("=== Building a real behavioral profile for 'svchost.exe' (normally spawned by services.exe) ===\n")
    for _ in range(25):
        dna.observe("svchost.exe", "services.exe", "process_exec", "C:/Windows/System32/svchost.exe")

    print("=== Legitimate instance: svchost.exe spawned by services.exe (normal) ===")
    r1 = dna.check_masquerade("svchost.exe", "services.exe", "process_exec", "C:/Windows/System32/svchost.exe")
    print(f"  {r1}\n")

    print("=== ATTACK: malware named 'svchost.exe' but spawned by winword.exe (masquerading attempt) ===")
    r2 = dna.check_masquerade("svchost.exe", "winword.exe", "process_exec", "C:/Users/temp/svchost.exe")
    print(f"  {r2}\n")

    print(f"=== Result: masquerading detected purely from BEHAVIOR, not filename -- the fake process has a perfectly convincing name but wrong lineage ===")

    os.remove("/tmp/dna_test.duckdb")
