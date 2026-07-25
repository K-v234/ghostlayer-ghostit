"""
Ghost IT — C14: LOLBin Detector
Detects Living-off-the-Land Binary abuse.
Matches suspicious command patterns and process chains.

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 100% — complete
"""
from __future__ import annotations
import re
import logging
from dataclasses import dataclass
from typing import Optional, List

log = logging.getLogger(__name__)

@dataclass
class LOLBinAlert:
    severity:   str
    technique:  str
    pattern:    str
    comm:       str
    args:       str
    mitre:      str

# LOLBin command patterns — MITRE T1218
LOLBIN_PATTERNS = [
    (r"certutil.*-urlcache.*-f",        "Certutil download",           "T1105", "HIGH"),
    (r"certutil.*-decode",              "Certutil base64 decode",       "T1140", "HIGH"),
    (r"wmic.*process.*call.*create",    "WMIC remote execution",        "T1047", "CRITICAL"),
    (r"regsvr32.*/s.*/n.*/u.*/i:http",  "Regsvr32 download+exec",      "T1218.010", "CRITICAL"),
    (r"mshta.*http",                    "MSHTA remote script",          "T1218.005", "CRITICAL"),
    (r"rundll32.*javascript:",          "Rundll32 JS execution",        "T1218.011", "CRITICAL"),
    (r"powershell.*-enc",               "PowerShell encoded command",   "T1059.001", "HIGH"),
    (r"powershell.*-w.*hidden",         "PowerShell hidden window",     "T1059.001", "HIGH"),
    (r"powershell.*downloadstring",     "PowerShell download cradle",   "T1059.001", "CRITICAL"),
    (r"powershell.*iex\(",              "PowerShell IEX execution",     "T1059.001", "CRITICAL"),
    (r"bitsadmin.*/transfer",           "BITSAdmin download",           "T1197", "HIGH"),
    (r"wscript.*\.js",                  "WScript JS execution",         "T1059.007", "HIGH"),
    (r"cscript.*\.vbs",                 "CScript VBS execution",        "T1059.005", "HIGH"),
    (r"msiexec.*/q.*/i.*http",          "MSIExec remote install",       "T1218.007", "CRITICAL"),
    (r"odbcconf.*\/a.*\{regsvr",        "ODBCConf DLL load",            "T1218.008", "HIGH"),
]

# Suspicious process parent→child chains
SUSPICIOUS_CHAINS = [
    ("wmic.exe",    "powershell.exe",  "WMIC spawning PowerShell",     "T1047",     "CRITICAL"),
    ("word.exe",    "powershell.exe",  "Word spawning PowerShell",     "T1566.001", "CRITICAL"),
    ("excel.exe",   "powershell.exe",  "Excel spawning PowerShell",    "T1566.001", "CRITICAL"),
    ("excel.exe",   "wscript.exe",     "Excel spawning WScript",       "T1566.001", "CRITICAL"),
    ("winword.exe", "cmd.exe",         "Word spawning CMD",            "T1566.001", "HIGH"),
    ("outlook.exe", "powershell.exe",  "Outlook spawning PowerShell",  "T1566.001", "CRITICAL"),
    ("explorer.exe","powershell.exe",  "Explorer spawning PowerShell", "T1059.001", "HIGH"),
    ("svchost.exe", "powershell.exe",  "Svchost spawning PowerShell",  "T1055",     "CRITICAL"),
    ("lsass.exe",   "cmd.exe",         "LSASS spawning CMD",           "T1003.001", "CRITICAL"),
    ("apache2",     "bash",           "Apache spawning shell (webshell)",      "T1505.003", "CRITICAL"),
    ("apache2",     "sh",             "Apache spawning shell (webshell)",      "T1505.003", "CRITICAL"),
    ("nginx",       "bash",           "Nginx spawning shell (webshell)",       "T1505.003", "CRITICAL"),
    ("nginx",       "sh",             "Nginx spawning shell (webshell)",       "T1505.003", "CRITICAL"),
    ("httpd",       "bash",           "Apache (httpd) spawning shell",         "T1505.003", "CRITICAL"),
    ("php-fpm",     "bash",           "PHP-FPM spawning shell (webshell)",     "T1505.003", "CRITICAL"),
    ("mysqld",      "bash",           "MySQL spawning shell (SQLi->RCE)",      "T1505.003", "CRITICAL"),
    ("cron",        "wget",           "Cron spawning wget (persistence/C2)",   "T1053.003", "HIGH"),
    ("cron",        "curl",           "Cron spawning curl (persistence/C2)",   "T1053.003", "HIGH"),
    ("vim",         "bash",           "Vim spawning shell (editor breakout)",  "T1548",     "MEDIUM"),
    ("nano",        "bash",           "Nano spawning shell (editor breakout)", "T1548",     "MEDIUM"),
]

class LOLBinDetector:
    """
    Detects LOLBin abuse via:
    1. Command-line pattern matching
    2. Suspicious parent→child process chains
    """

    def check_cmdline(self, comm: str, args: str) -> Optional[LOLBinAlert]:
        """Check command line for LOLBin patterns."""
        if not args:
            return None

        cmdline = f"{comm} {args}".lower()

        for pattern, technique, mitre, severity in LOLBIN_PATTERNS:
            if re.search(pattern, cmdline, re.IGNORECASE):
                log.warning(f"LOLBin detected: {technique} — {comm}")
                return LOLBinAlert(
                    severity=severity,
                    technique=technique,
                    pattern=pattern,
                    comm=comm,
                    args=args,
                    mitre=mitre
                )
        return None

    def check_process_chain(self, parent: str, child: str) -> Optional[LOLBinAlert]:
        """Check for suspicious parent→child process chain."""
        parent_lower = parent.lower()
        child_lower  = child.lower()

        for p, c, desc, mitre, severity in SUSPICIOUS_CHAINS:
            if p.lower() in parent_lower and c.lower() in child_lower:
                log.warning(f"Suspicious chain: {parent} → {child} ({desc})")
                return LOLBinAlert(
                    severity=severity,
                    technique=desc,
                    pattern=f"{p}→{c}",
                    comm=child,
                    args="",
                    mitre=mitre
                )
        return None

    def check_event(self, event: dict) -> Optional[LOLBinAlert]:
        """Check a single eBPF event for LOLBin activity."""
        comm = event.get("comm", "")
        args = event.get("args", "") or ""

        # Command line check
        alert = self.check_cmdline(comm, args)
        if alert:
            return alert

        return None

# Singleton
lolbin_detector = LOLBinDetector()
