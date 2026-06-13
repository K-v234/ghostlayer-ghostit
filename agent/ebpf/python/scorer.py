"""
Ghost IT — Suspicion Scorer v2
Scores each event 0-100. Fixed false positives from v1.
"""
from __future__ import annotations
from events import GhostEvent

THRESHOLD_LOG   = 10
THRESHOLD_ALERT = 40

# Exact sensitive file paths (not directories)
SENSITIVE_FILES = {
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/etc/crontab", "/etc/hosts",
}

# Sensitive directory prefixes — only flag writes, not reads
SENSITIVE_DIRS_WRITE_ONLY = {
    "/root/.ssh", "/etc/ssh", "/var/log",
}

# Always suspicious regardless of read/write
ALWAYS_SENSITIVE = {
    "/tmp", "/dev/shm", "/proc/self/mem",
}

SUSPICIOUS_PORTS = {
    4444, 1337, 31337, 8888,
    6666, 6667, 6668, 6669,
    9001, 9030,
}

NO_NET_PROCS = {"bash", "sh", "python3", "python", "perl", "ruby"}
NO_FORK_PROCS = {"nginx", "apache2", "sshd"}

# Exact binary names — not substrings
ATTACKER_TOOLS = {
    "nmap", "nc", "netcat", "curl", "wget",
    "socat", "ncat", "tcpdump", "wireshark",
    "msfconsole", "msfvenom", "sqlmap",
}

# Exact shell names
SHELLS = {"bash", "sh", "dash", "zsh", "fish", "ksh"}

# Interpreters that exec things
INTERPRETERS = {"python3", "python", "python2", "perl", "ruby", "php"}


def _basename(path: str) -> str:
    return path.rstrip("/").rsplit("/", 1)[-1] if path else ""


def score(event: GhostEvent) -> tuple[int, list[str]]:
    s = 0
    reasons = []

    if event.type == "exec":
        s += 5
        fname = _basename(event.file or "")

        if fname in SHELLS:
            s += 20
            reasons.append("shell_spawned")

        if fname in INTERPRETERS:
            s += 15
            reasons.append("interpreter_exec")

        # Exact match only — no substring
        if fname in ATTACKER_TOOLS:
            s += 40
            reasons.append(f"attacker_tool:{fname}")

    elif event.type == "open":
        path  = event.file or ""
        write = bool(event.flags and (event.flags & 0x1))

        if path in SENSITIVE_FILES:
            s += 25
            reasons.append(f"sensitive_file:{path}")
            if write:
                s += 20
                reasons.append("write_access")

        elif any(path.startswith(d) for d in SENSITIVE_DIRS_WRITE_ONLY):
            if write:
                s += 35
                reasons.append(f"sensitive_dir_write:{path}")

        elif any(path.startswith(d) for d in ALWAYS_SENSITIVE):
            s += 20
            reasons.append(f"always_sensitive:{path}")

    elif event.type == "connect":
        s += 5
        if event.dport in SUSPICIOUS_PORTS:
            s += 60
            reasons.append(f"suspicious_port:{event.dport}")
        if event.comm in NO_NET_PROCS:
            s += 35
            reasons.append(f"unexpected_network:{event.comm}")
        if event.daddr and event.daddr.startswith("127."):
            s -= 10

    elif event.type == "clone":
        if event.comm in NO_FORK_PROCS:
            s += 25
            reasons.append(f"unexpected_fork:{event.comm}")

    elif event.type == "unlink":
        s += 5
        path = event.file or ""
        if any(path.startswith(d) for d in ("/var/log", "/tmp")):
            s += 20
            reasons.append("suspicious_deletion")

    return min(max(s, 0), 100), reasons
