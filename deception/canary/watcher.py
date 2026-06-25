"""
Ghost IT — File Canary Watcher
Monitors canary files via Linux inotify.
Triggers instantly when a canary file is opened or read.
"""
from __future__ import annotations
import os
import fcntl
import struct
import logging
import threading
from typing import Callable

log = logging.getLogger(__name__)

# inotify event flags
IN_ACCESS      = 0x00000001   # File read
IN_MODIFY      = 0x00000002   # File modified
IN_OPEN        = 0x00000020   # File opened
IN_CLOSE_READ  = 0x00000008   # File closed after read
IN_CLOSE_WRITE = 0x00000010   # File closed after write
IN_DELETE_SELF = 0x00000400   # Canary file deleted

WATCH_FLAGS = IN_ACCESS | IN_OPEN | IN_MODIFY | IN_CLOSE_READ | IN_CLOSE_WRITE

EVENT_STRUCT = "iIII"
EVENT_SIZE   = struct.calcsize(EVENT_STRUCT)


class FileCanaryWatcher:
    """
    Watches canary files using Linux inotify.
    Calls alert_callback(filepath, event_type) on any access.
    Runs in a background daemon thread.
    """

    def __init__(self, alert_callback: Callable[[str, str], None]):
        self.callback = alert_callback
        self.watches: dict[int, str] = {}  # wd → filepath
        self._fd  = None
        self._running = False
        self._thread = None

    def _inotify_init(self) -> int:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        fd   = libc.inotify_init()
        if fd < 0:
            raise OSError("inotify_init failed")
        # Set non-blocking so os.read() doesn't block forever
        fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK)
        return fd

    def _inotify_add_watch(self, fd: int, path: str, mask: int) -> int:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        wd   = libc.inotify_add_watch(fd, path.encode(), mask)
        if wd < 0:
            raise OSError(f"inotify_add_watch failed for {path}")
        return wd

    def add_file(self, filepath: str):
        """Add a file to the watch list."""
        if not os.path.exists(filepath):
            log.warning(f"Canary file not found: {filepath}")
            return
        if self._fd is None:
            self._fd = self._inotify_init()
        wd = self._inotify_add_watch(self._fd, filepath, WATCH_FLAGS)
        self.watches[wd] = filepath
        log.info(f"Watching canary file: {filepath}")

    def _get_accessor(self, filepath: str) -> tuple[int, str]:
        """Find PID and comm of process currently accessing the file via /proc."""
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

    def _read_events(self):
        try:
            buf = os.read(self._fd, 4096)
        except BlockingIOError:
            # No events right now — non-blocking fd returns this
            return
        offset = 0
        while offset + EVENT_SIZE <= len(buf):
            wd, mask, cookie, name_len = struct.unpack_from(EVENT_STRUCT, buf, offset)
            offset += EVENT_SIZE + name_len
            filepath = self.watches.get(wd, "unknown")
            pid, comm = self._get_accessor(filepath)

            if mask & IN_OPEN:
                self.callback(filepath, "file_open", pid, comm)
            if mask & IN_ACCESS:
                self.callback(filepath, "file_read", pid, comm)
            if mask & IN_MODIFY:
                self.callback(filepath, "file_modify", pid, comm)
            if mask & IN_CLOSE_WRITE:
                self.callback(filepath, "file_close_write", pid, comm)
            if mask & IN_CLOSE_READ:
                self.callback(filepath, "file_close_read", pid, comm)
            if mask & IN_DELETE_SELF:
                self.callback(filepath, "file_deleted", pid, comm)
                log.warning(f"Canary file DELETED: {filepath}")

    def start(self):
        """Start the watcher thread. Files should already be added via add_file()."""
        if not self.watches:
            log.warning("No canary files registered — watcher idle")
            return

        # Only start if not already running
        if self._thread is not None and self._thread.is_alive():
            return

        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="CanaryWatcher")
        self._thread.start()
        log.info(f"File watcher started — watching {len(self.watches)} canaries")

    def _loop(self):
        import time
        while self._running:
            try:
                self._read_events()
            except Exception as ex:
                log.error(f"Watcher error: {ex}")
            time.sleep(0.05)  # 50ms poll — low CPU, fast response

    def stop(self):
        self._running = False
        if self._fd:
            os.close(self._fd)
            self._fd = None
