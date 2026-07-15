"""
Ghost IT — C15 File Entropy Monitor
Watches directories via inotify for file writes.
Computes Shannon entropy on written content.
Feeds file_entropy_delta to RansomwareEMADetector.
"""
from __future__ import annotations
import os
import math
import time
import socket
import json
import logging
import threading
import struct
import fcntl
from collections import Counter
from typing import Optional

log = logging.getLogger(__name__)

def _get_file_accessor(filepath: str) -> tuple[int, str]:
    """
    Find PID and comm of process currently holding the given file
    open. Ported from deception/canary/watcher.py's _get_accessor(),
    the same proven pattern used for canary file hit attribution.
    Scans /proc/*/fd, matching by resolved symlink target. May not
    find the process if it already closed the file before this scan
    runs -- returns (0, "unknown") in that case, same as before this
    fix, so this is a pure improvement with no new failure mode.
    """
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                fd_dir = f"/proc/{pid}/fd"
                for fd in os.listdir(fd_dir):
                    try:
                        link = os.readlink(f"{fd_dir}/{fd}")
                        if link == filepath:
                            comm = open(f"/proc/{pid}/comm").read().strip()
                            return int(pid), comm
                    except (OSError, PermissionError):
                        continue
            except (OSError, PermissionError):
                continue
    except Exception:
        pass
    return 0, "unknown"

# inotify flags
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM  = 0x00000040
IN_MOVED_TO    = 0x00000080
IN_CREATE      = 0x00000100
WATCH_FLAGS    = IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE

EVENT_STRUCT = "iIII"
EVENT_SIZE   = struct.calcsize(EVENT_STRUCT)

WATCH_DIRS = [
    os.path.expanduser("~"),
    "/tmp",
    "/var/tmp",
    "/home",
]

def get_watch_dirs() -> list[str]:
    """Get all dirs to watch including existing /tmp subdirs."""
    dirs = list(WATCH_DIRS)
    for base in ["/tmp", "/var/tmp"]:
        try:
            for sub in os.listdir(base):
                subpath = os.path.join(base, sub)
                if os.path.isdir(subpath):
                    dirs.append(subpath)
        except PermissionError:
            pass
    return dirs

# Extension changes typical of ransomware
RANSOM_EXTENSIONS = {
    ".locked", ".encrypted", ".enc", ".crypt", ".crypto",
    ".ghost", ".ghostlocked", ".aes", ".rsa", ".vault",
    ".wcry", ".wncry", ".cerber", ".locky", ".zepto",
}

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy  # max 8.0 for random bytes

def compute_file_entropy(filepath: str) -> Optional[float]:
    try:
        with open(filepath, "rb") as f:
            data = f.read(65536)  # Read first 64KB
        return shannon_entropy(data)
    except OSError:
        return None

class FileEntropyMonitor:
    """
    Monitors directories for high-entropy file writes — ransomware indicator.
    Sends events to pipeline TCP socket.
    """
    def __init__(self, pipeline_host: str = "127.0.0.1", pipeline_port: int = 9000):
        self.pipeline_host = pipeline_host
        self.pipeline_port = pipeline_port
        self._fd = None
        self._watches: dict[int, str] = {}  # wd → dirpath
        self._running = False
        self._thread = None
        self._write_count = 0
        self._ext_changes: set[str] = set()
        self._window_start = time.time()
        self._libc = None
        self._baseline_entropy = 4.5  # typical text file entropy

    def _get_libc(self):
        if self._libc is None:
            import ctypes
            self._libc = ctypes.CDLL("libc.so.6", use_errno=True)
        return self._libc

    def _init(self):
        libc = self._get_libc()
        fd = libc.inotify_init()
        if fd < 0:
            raise OSError("inotify_init failed")
        fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK)
        return fd

    def _add_watch(self, dirpath: str):
        if not os.path.isdir(dirpath):
            return
        libc = self._get_libc()
        wd = libc.inotify_add_watch(self._fd, dirpath.encode(), WATCH_FLAGS)
        if wd >= 0:
            self._watches[wd] = dirpath
            log.info(f"C15 watching: {dirpath}")

    def start(self, watch_dirs: list[str] = None):
        self._fd = self._init()
        for d in (watch_dirs or get_watch_dirs()):
            self._add_watch(d)
            # Also watch immediate subdirectories
            try:
                for sub in os.listdir(d):
                    subpath = os.path.join(d, sub)
                    if os.path.isdir(subpath):
                        self._add_watch(subpath)
            except PermissionError:
                pass
        self._running = True
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="C15-EntropyMonitor"
        )
        self._thread.start()
        log.info(f"C15 FileEntropyMonitor started — watching {len(self._watches)} dirs")

    def stop(self):
        self._running = False
        if self._fd:
            os.close(self._fd)
            self._fd = None

    def _loop(self):
        while self._running:
            try:
                self._read_events()
            except BlockingIOError:
                pass
            except Exception as ex:
                log.error(f"C15 monitor error: {ex}")
            time.sleep(0.1)

    def _read_events(self):
        try:
            buf = os.read(self._fd, 4096)
        except BlockingIOError:
            return
        offset = 0
        while offset + EVENT_SIZE <= len(buf):
            wd, mask, cookie, name_len = struct.unpack_from(EVENT_STRUCT, buf, offset)
            offset += EVENT_SIZE
            name = ""
            if name_len > 0 and offset + name_len <= len(buf):
                name = buf[offset:offset+name_len].rstrip(b'\x00').decode(errors='replace')
                offset += name_len

            dirpath = self._watches.get(wd, "")
            if not dirpath or not name:
                continue

            filepath = os.path.join(dirpath, name)
            ext = os.path.splitext(name)[1].lower()

            if mask & IN_CLOSE_WRITE:
                self._on_file_written(filepath, ext)
            if mask & (IN_MOVED_TO | IN_MOVED_FROM):
                if ext in RANSOM_EXTENSIONS:
                    self._on_ransom_ext(filepath, ext)
            if mask & IN_CREATE:
                # Watch newly created subdirectories
                if os.path.isdir(filepath):
                    self._add_watch(filepath)
                    # Also watch its children immediately
                    try:
                        for sub in os.listdir(filepath):
                            self._add_watch(os.path.join(filepath, sub))
                    except (PermissionError, OSError):
                        pass

    def _on_file_written(self, filepath: str, ext: str):
        entropy = compute_file_entropy(filepath)
        if entropy is None:
            return

        self._write_count += 1
        now = time.time()
        window_elapsed = now - self._window_start

        # Reset window every 60 seconds
        if window_elapsed > 60:
            self._write_count = 1
            self._ext_changes = set()
            self._window_start = now

        # Track unique extensions
        if ext:
            self._ext_changes.add(ext)

        # High entropy write — possible ransomware
        entropy_delta = entropy - self._baseline_entropy
        if entropy_delta > 2.0:  # > 6.5 entropy = likely encrypted
            log.warning(
                f"C15 HIGH ENTROPY WRITE: {filepath} "
                f"entropy={entropy:.2f} delta={entropy_delta:.2f} "
                f"writes_in_window={self._write_count}"
            )
            self._send_event(filepath, entropy, entropy_delta)

    def _on_ransom_ext(self, filepath: str, ext: str):
        log.warning(f"C15 RANSOMWARE EXTENSION: {filepath} → {ext}")
        self._send_event(filepath, 8.0, 8.0, is_ransom_ext=True)

    def _send_event(self, filepath: str, entropy: float,
                    entropy_delta: float, is_ransom_ext: bool = False):
        # Deduplication: same alert type within 30s = skip
        import time as _time
        if not hasattr(self, '_c15_dedup'):
            self._c15_dedup = {}
        now_ts = _time.time()
        dedup_key = "ransom_ext" if is_ransom_ext else "high_entropy"
        last_sent = self._c15_dedup.get(dedup_key, 0)
        if now_ts - last_sent < 30:
            return  # suppress duplicate
        self._c15_dedup[dedup_key] = now_ts

        # Proven PID-capture pattern reused from
        # deception/canary/watcher.py's _get_accessor() -- scans
        # /proc/*/fd for a file descriptor pointing at the touched
        # file. Real PID/comm here (instead of hardcoded 0) is what
        # lets C4's causal engine build a subgraph and add the process
        # to its watchlist -- closing C4-WATCHLIST-E2E-UNVERIFIED-01,
        # since inotify alone never carries the accessing process's PID.
        real_pid, real_comm = _get_file_accessor(filepath)
        event = [{
            "ts":           int(time.time_ns()),
            "pid":          real_pid, "ppid": 0, "uid": 0, "gid": 0,
            "event_type":   "file_write",
            "comm":         real_comm if real_comm != "unknown" else "c15_monitor",
            "type":         "file_write",
            "score":        min(100, int(entropy_delta * 12)),
            "alert":        entropy_delta > 2.5 or is_ransom_ext,
            "reasons":      [
                f"file_entropy_delta:{entropy_delta:.2f}",
                f"entropy:{entropy:.2f}",
                f"writes_per_min:{self._write_count}",
                f"unique_ext:{len(self._ext_changes)}",
                "ransomware_extension" if is_ransom_ext else "high_entropy_write",
            ],
            "file":         filepath,
            "daddr":        None,
            "dport":        None,
            "dpdp_pii_flag": False,
        }]
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((self.pipeline_host, self.pipeline_port))
            s.sendall((json.dumps(event) + "\n").encode())
            s.close()
        except OSError as ex:
            log.error(f"C15 pipeline send failed: {ex}")
