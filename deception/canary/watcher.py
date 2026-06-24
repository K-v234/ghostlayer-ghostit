"""
Ghost IT — File Canary Watcher
Monitors canary files via Linux inotify.
Triggers instantly when a canary file is opened or read.
"""
from __future__ import annotations
import os
import struct
import logging
import threading
from typing import Callable

log = logging.getLogger(__name__)

# inotify event flags
IN_ACCESS      = 0x00000001   # File read
IN_OPEN        = 0x00000020   # File opened
IN_CLOSE_READ  = 0x00000008   # File closed after read
IN_DELETE_SELF = 0x00000400   # Canary file deleted

WATCH_FLAGS = 0x00000002 | 0x00000008

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

    def _inotify_init(self) -> int:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        fd   = libc.inotify_init()
        if fd < 0:
            raise OSError("inotify_init failed")
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

    def _read_events(self):
        import os
        buf = os.read(self._fd, 4096)
        print("DEBUG: raw event buffer received")
        offset = 0
        while offset < len(buf):
            wd, mask, cookie, name_len = struct.unpack_from(EVENT_STRUCT, buf, offset)
            offset += EVENT_SIZE + name_len
            filepath = self.watches.get(wd, "unknown")

            if mask & IN_OPEN:
                self.callback(filepath, "file_open")
            if mask & IN_ACCESS:
                self.callback(filepath, "file_read")
            if mask & 0x00000002:
                self.callback(filepath, "file_modify")
            if mask & 0x00000008:
                self.callback(filepath, "file_close_write")
            if mask & IN_CLOSE_READ:
                self.callback(filepath, "file_close_read")
            if mask & IN_DELETE_SELF:
                self.callback(filepath, "file_deleted")
                log.warning(f"Canary file DELETED: {filepath}")

    def start(self):
        for f in [
"/home/keerthivahanan/ghostlayer/deception/canary/canary_files/.env",
"/home/keerthivahanan/ghostlayer/deception/canary/canary_files/id_rsa",
"/home/keerthivahanan/ghostlayer/deception/canary/canary_files/passwords.txt",
"/home/keerthivahanan/ghostlayer/deception/canary/canary_files/config.yml",
"/home/keerthivahanan/ghostlayer/deception/canary/canary_files/backup.sql"]:
            self.add_file(f)
        if not self.watches:
            log.warning("No canary files registered — watcher idle")
            return
        if hasattr(self, "_thread") and self._thread.is_alive():
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        log.info(f"File watcher started — watching {len(self.watches)} canaries")

    def _loop(self):
        while self._running:
            try:
                self._read_events()
            except Exception as ex:
                log.error(f"Watcher error: {ex}")
        while self._running:
            try:
                self._read_events()
            except Exception as ex:
                log.error(f"Watcher error: {ex}")

    def stop(self):
        self._running = False
        if self._fd:
            os.close(self._fd)
