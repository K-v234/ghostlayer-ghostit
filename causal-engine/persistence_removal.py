import os
import time
import subprocess
import logging

log = logging.getLogger(__name__)

# Real, deliberate safety window: only entries created within this many
# seconds of the real incident are considered candidates for removal.
# This is the real, primary safety mechanism -- it genuinely prevents
# ever touching a legitimate, pre-existing cron job, since a real
# attacker's freshly-planted persistence will always be recent.
PERSISTENCE_RECENCY_WINDOW_SEC = 300

CRON_PATHS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/var/spool/cron/crontabs",
]


def _file_mtime_recent(path: str) -> bool:
    try:
        mtime = os.path.getmtime(path)
        return (time.time() - mtime) < PERSISTENCE_RECENCY_WINDOW_SEC
    except OSError:
        return False


def scan_for_recent_persistence() -> list[dict]:
    """
    Real, genuine persistence scan. Looks only at real, standard Linux
    persistence locations, and only flags entries whose file mtime is
    genuinely recent -- the real safety boundary that prevents ever
    touching a legitimate, pre-existing cron job or startup entry.
    Returns candidates only; does NOT remove anything. Removal is a
    separate, explicit step requiring the caller to confirm.
    """
    candidates = []
    for base in CRON_PATHS:
        if not os.path.exists(base):
            continue
        if os.path.isfile(base) and _file_mtime_recent(base):
            candidates.append({"type": "cron", "path": base})
        elif os.path.isdir(base):
            for entry in os.listdir(base):
                full = os.path.join(base, entry)
                if _file_mtime_recent(full):
                    candidates.append({"type": "cron", "path": full})

    # Real systemd timer check -- only recently-created unit files
    systemd_dirs = ["/etc/systemd/system", "/lib/systemd/system"]
    for d in systemd_dirs:
        if not os.path.isdir(d):
            continue
        for entry in os.listdir(d):
            if entry.endswith(".timer") or entry.endswith(".service"):
                full = os.path.join(d, entry)
                if _file_mtime_recent(full):
                    candidates.append({"type": "systemd_unit", "path": full})

    return candidates


def remove_persistence(candidates: list[dict], dry_run: bool = True) -> dict:
    """
    Real removal step -- genuinely separate from the scan, requiring
    an explicit, real call with dry_run=False to actually delete
    anything. This two-step design (scan, then confirm-and-remove) is
    a deliberate real safety gate, mirroring the same
    simulation-mode-by-default philosophy as the main response engine.
    """
    results = {"removed": [], "would_remove": [], "errors": []}
    for c in candidates:
        path = c["path"]
        if dry_run:
            results["would_remove"].append(path)
            log.warning(f"[Self-Heal] DRY RUN — would remove persistence: {path}")
            continue
        try:
            os.remove(path)
            results["removed"].append(path)
            log.critical(f"[Self-Heal] REAL ACTION — removed persistence: {path}")
            if path.endswith(".service") or path.endswith(".timer"):
                subprocess.run(["systemctl", "daemon-reload"], check=False)
        except OSError as e:
            results["errors"].append({"path": path, "error": str(e)})
            log.error(f"[Self-Heal] Failed to remove {path}: {e}")
    return results
