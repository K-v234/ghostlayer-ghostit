"""
Ghost IT — C2: 17-Feature Behavioral Vector Extractor

Extracts the locked 17-feature vector from a 15-second event window.
Feature set is LOCKED — do not change after first model training.

Ghost Layer Technologies — CONFIDENTIAL
"""
from __future__ import annotations
import time
import logging
from dataclasses import dataclass, field
from typing import Optional
from collections import defaultdict

log = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
# Locked 17-feature vector — per PRD v5.0 C2 spec                   #
# ------------------------------------------------------------------ #
BEHAVIORAL_FEATURES = [
    "proc_spawn_rate",          # processes spawned / minute
    "proc_spawn_diversity",     # unique parent-child pairs / hour
    "network_conn_rate",        # new TCP connections / minute
    "network_dst_diversity",    # unique destination IPs / hour
    "network_bytes_out",        # bytes transmitted / minute (estimated)
    "file_write_rate",          # file writes / minute
    "file_entropy_delta",       # average entropy change of written files
    "auth_failure_rate",        # auth failures / hour
    "privilege_escalation_ct",  # setuid/setgid/capset calls / hour
    "lolbin_access_ct",         # accesses to known LOLBin paths
    "mmap_exec_rate",           # mmap(PROT_EXEC) calls / hour
    "mprotect_exec_rate",       # mprotect to exec / hour
    "active_hours_deviation",   # sigma from role archetype active hours
    "session_duration_z",       # z-score vs entity baseline
    "entropy_read_rate",        # /dev/urandom reads / hour
    "unique_file_ext_writes",   # unique extensions written / hour
    "shadow_delete_ct",         # shadow copy deletion attempts
]

assert len(BEHAVIORAL_FEATURES) == 17, "Feature vector must be exactly 17"

# Known LOLBin paths
LOLBIN_PATHS = {
    "/usr/bin/curl", "/usr/bin/wget", "/usr/bin/nc",
    "/usr/bin/netcat", "/usr/bin/socat", "/usr/bin/ncat",
    "/usr/bin/python3", "/usr/bin/python", "/usr/bin/perl",
    "/usr/bin/ruby", "/usr/bin/php", "/usr/bin/lua",
    "/usr/bin/tclsh", "/usr/bin/awk", "/usr/bin/gawk",
    "/bin/bash", "/bin/sh", "/bin/dash", "/bin/zsh",
    # Windows LOLBins (for future C9 integration)
    "certutil.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "wmic.exe", "powershell.exe",
    "cmd.exe", "cscript.exe", "wscript.exe",
}

SENSITIVE_EXTENSIONS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".jpg", ".jpeg", ".png", ".mp4",
    ".sql", ".db", ".sqlite", ".mdb",
    ".py", ".js", ".ts", ".java", ".cpp", ".rs",
    ".key", ".pem", ".p12", ".pfx", ".env",
}


@dataclass
class FeatureWindow:
    """
    Accumulates events over a time window and computes
    the 17-feature behavioral vector on demand.
    """
    entity_id:   str
    window_start: float = field(default_factory=time.time)
    window_sec:  float  = 15.0  # 15-second windows per spec

    # Raw counters
    _exec_events:        list[dict] = field(default_factory=list)
    _open_events:        list[dict] = field(default_factory=list)
    _connect_events:     list[dict] = field(default_factory=list)
    _privilege_events:   list[dict] = field(default_factory=list)
    _mmap_exec_ct:       int = 0
    _mprotect_exec_ct:   int = 0
    _shadow_delete_ct:   int = 0
    _unique_dst_ips:     set = field(default_factory=set)
    _unique_ext_writes:  set = field(default_factory=set)
    _parent_child_pairs: set = field(default_factory=set)

    def add_event(self, event: dict):
        """Add a single event to the window."""
        t = event.get("type", "")
        path = event.get("path") or event.get("file") or ""
        comm = event.get("comm", "")

        if t == "exec":
            self._exec_events.append(event)
            pid  = event.get("pid", 0)
            ppid = event.get("ppid", event.get("parent_pid", 0))
            if pid and ppid:
                self._parent_child_pairs.add((ppid, pid))
            if path in LOLBIN_PATHS:
                self._open_events.append({**event, "_lolbin": True})

        elif t == "open":
            flags = event.get("flags", 0)
            if flags and (flags & 0x1 or flags & 0x2):
                self._open_events.append(event)
                ext = self._ext(path)
                if ext in SENSITIVE_EXTENSIONS:
                    self._unique_ext_writes.add(ext)
            # Entropy read detection
            if path in ("/dev/urandom", "/dev/random"):
                self._open_events.append({**event, "_entropy_read": True})

        elif t == "connect":
            self._connect_events.append(event)
            daddr = event.get("daddr") or event.get("path", "")
            if daddr:
                self._unique_dst_ips.add(daddr)

        elif t in ("setuid", "setgid", "capset", "ptrace"):
            self._privilege_events.append(event)

        elif t == "mmap_exec":
            self._mmap_exec_ct += 1

        elif t == "mprotect":
            self._mprotect_exec_ct += 1

        # Shadow copy deletion
        if comm in ("vssadmin", "wmic", "bcdedit"):
            self._shadow_delete_ct += 1

    def compute(self) -> dict[str, float]:
        """
        Compute the 17-feature vector for this window.
        Returns dict mapping feature name → float value.
        """
        elapsed_min = max(self.window_sec / 60.0, 1e-6)
        elapsed_hr  = max(self.window_sec / 3600.0, 1e-6)

        lolbin_ct = sum(
            1 for e in self._exec_events
            if (e.get("path") or "") in LOLBIN_PATHS
        )

        entropy_reads = sum(
            1 for e in self._open_events
            if e.get("_entropy_read")
        )

        return {
            "proc_spawn_rate":         len(self._exec_events) / elapsed_min,
            "proc_spawn_diversity":    len(self._parent_child_pairs) / elapsed_hr,
            "network_conn_rate":       len(self._connect_events) / elapsed_min,
            "network_dst_diversity":   len(self._unique_dst_ips) / elapsed_hr,
            "network_bytes_out":       len(self._connect_events) * 1500 / elapsed_min,
            "file_write_rate":         len(self._open_events) / elapsed_min,
            "file_entropy_delta":      float(len(self._unique_ext_writes)) / max(len(self._open_events), 1),
            "auth_failure_rate":       0.0,  # Requires auth log integration
            "privilege_escalation_ct": len(self._privilege_events) / elapsed_hr,
            "lolbin_access_ct":        lolbin_ct / elapsed_hr,
            "mmap_exec_rate":          self._mmap_exec_ct / elapsed_hr,
            "mprotect_exec_rate":      self._mprotect_exec_ct / elapsed_hr,
            "active_hours_deviation":  0.0,  # Requires session history
            "session_duration_z":      0.0,  # Requires session history
            "entropy_read_rate":       entropy_reads / elapsed_hr,
            "unique_file_ext_writes":  len(self._unique_ext_writes) / elapsed_hr,
            "shadow_delete_ct":        float(self._shadow_delete_ct),
        }

    @property
    def is_expired(self) -> bool:
        return time.time() - self.window_start > self.window_sec

    @staticmethod
    def _ext(path: str) -> str:
        import os
        return os.path.splitext(path)[1].lower() if path else ""

    def to_vector(self) -> list[float]:
        """Return features as ordered list (matches BEHAVIORAL_FEATURES order)."""
        computed = self.compute()
        return [computed[f] for f in BEHAVIORAL_FEATURES]
