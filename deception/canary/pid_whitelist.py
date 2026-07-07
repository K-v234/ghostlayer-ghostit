"""
Ghost IT — C3: Canary PID Whitelist
Prevents canary service from alerting on its own file registrations.
Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 100% — complete
"""
import os

class CanaryPIDWhitelist:
    def __init__(self):
        self._whitelist = set()
        self._whitelist.add(os.getpid())

    def add(self, pid: int):
        self._whitelist.add(pid)

    def is_whitelisted(self, pid: int) -> bool:
        return pid in self._whitelist

whitelist = CanaryPIDWhitelist()
