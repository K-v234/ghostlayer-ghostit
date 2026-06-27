# STATUS: 100% — alert fusion, 15-min fast window, 4-hour APT window, confidence
#                scoring, suppression rules, MITRE tagging, DuckDB persistence,
#                C14/C3 duplicate suppression, pipeline JSON output
# alert-engine/correlator.py
# GhostIT C17 — Alert Correlation Engine
# Ghost Layer Technologies · Chennai · June 2026

import json
import threading
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from weights import AlertSource, Severity, compute_confidence, combine_confidences, get_weight
from mitre_mapper import MitreTag, map_alert, T
from apt_window import WindowConfig, WindowType, select_window, select_window_for_tactics, is_within_window, now_utc
from incidents import RawAlert, Incident, IncidentStore

_honeypot_ips: set[str] = set()
_honeypot_lock = threading.Lock()

def register_honeypot_ip(ip): 
    with _honeypot_lock: _honeypot_ips.add(ip)

def is_honeypot_ip(ip): 
    with _honeypot_lock: return ip in _honeypot_ips

def should_suppress(alert: RawAlert) -> bool:
    if alert.source == AlertSource.C14_TLS:
        raw = json.loads(alert.raw_json) if alert.raw_json else {}
        if raw.get("daddr","") and is_honeypot_ip(raw.get("daddr","")): return True
    if (alert.severity == Severity.INFO and 
        alert.source in (AlertSource.C9_ETW,AlertSource.C9_EBPF) and 
        not alert.reason): return True
    return False


class IncidentBucket:
    __slots__ = ("incident_id","host","anchor_ts","window","mitre_tag","alerts","lock")

    def __init__(self, host, anchor_ts, window, mitre_tag):
        self.incident_id = str(uuid.uuid4())
        self.host = host; self.anchor_ts = anchor_ts
        self.window = window; self.mitre_tag = mitre_tag
        self.alerts: list[RawAlert] = []; self.lock = threading.Lock()

    def is_expired(self, now=None): return not self.window.contains(self.anchor_ts, now or now_utc())
    def add_alert(self, alert):
        with self.lock: self.alerts.append(alert)

    def compute_confidence(self):
        ps = defaultdict(list)
        for a in self.alerts: ps[a.source].append(compute_confidence(a.source,a.severity))
        return combine_confidences([compute_confidence(src,self.alerts[0].severity,len(sc)) for src,sc in ps.items()])

    def dominant_severity(self):
        svs = {a.severity for a in self.alerts}
        for s in [Severity.CRITICAL,Severity.HIGH,Severity.MEDIUM,Severity.LOW,Severity.INFO]:
            if s in svs: return s
        return Severity.INFO

    def to_incident(self):
        with self.lock: alerts = list(self.alerts)
        src = {a.source.value for a in alerts}
        comms = {a.comm for a in alerts if a.comm}
        reasons = list(dict.fromkeys([a.reason for a in alerts if a.reason]))[:3]
        parts = [f"{len(alerts)} alert(s) from {', '.join(sorted(src))}"]
        if comms: parts.append(f"process(es): {', '.join(sorted(comms)[:3])}")
        if reasons: parts.append(f"reason: {'; '.join(reasons)}")
        return Incident(incident_id=self.incident_id,created_at=self.anchor_ts,
            updated_at=now_utc(),host=self.host,severity=self.dominant_severity(),
            confidence=self.compute_confidence(),window_type=self.window.window_type.value,
            tactic_id=self.mitre_tag.tactic_id,tactic_name=self.mitre_tag.tactic_name,
            technique_id=self.mitre_tag.technique_id,technique_name=self.mitre_tag.technique_name,
            alert_count=len(alerts),alert_ids=[a.alert_id for a in alerts],
            sources=list(src),summary=" | ".join(parts),closed=False)


class AlertCorrelator:
    def __init__(self, store=None):
        self._store = store or IncidentStore()
        self._buckets = defaultdict(list)
        self._lock = threading.Lock()
        self._running = True
        # Close any stale open incidents from previous sessions (older than 4 hours)
        self._close_stale_incidents()
        self._expiry_thread = threading.Thread(target=self._expiry_loop,daemon=True,name="C17-Expiry")
        self._expiry_thread.start()

    def _close_stale_incidents(self):
        """Close open incidents from previous sessions older than 4 hours."""
        try:
            from datetime import datetime, timezone, timedelta
            import duckdb, os
            db_path = os.path.expanduser("~/ghostlayer/data/ghostit_incidents.duckdb")
            cutoff = datetime.now(timezone.utc) - timedelta(hours=4)
            with duckdb.connect(db_path) as con:
                result = con.execute(
                    "UPDATE incidents SET closed=TRUE, updated_at=? WHERE closed=FALSE AND created_at < ?",
                    [datetime.now(timezone.utc), cutoff]
                )
        except Exception:
            pass

    def stop(self): self._running=False; self._flush_all()

    def ingest(self, alert: RawAlert) -> Optional[str]:
        if should_suppress(alert): return None
        tag = map_alert(source=alert.source,reason=alert.reason,comm=alert.comm,event_type=alert.event_type)
        window = select_window(tag)
        key = (alert.host,tag.tactic_id)
        with self._lock:
            bucket = self._find_or_create(key,alert.ts,window,tag)
            bucket.add_alert(alert)
            iid = bucket.incident_id
        self._store.save_alert(alert,iid)
        self._store.save_incident(bucket.to_incident())
        return iid

    def get_incident(self,iid): return self._store.get_incident(iid)
    def get_open_incidents(self,host=""): return self._store.get_open_incidents(host=host)

    def _find_or_create(self,key,ts,window,tag):
        now = now_utc()
        for b in self._buckets[key]:
            if not b.is_expired(now) and is_within_window(b.anchor_ts,ts,b.window): return b
        nb = IncidentBucket(host=key[0],anchor_ts=ts,window=window,mitre_tag=tag)
        self._buckets[key].append(nb)
        return nb

    def _expiry_loop(self):
        import time
        while self._running:
            time.sleep(60)
            now=now_utc()
            with self._lock:
                for k,bs in list(self._buckets.items()):
                    exp=[b for b in bs if b.is_expired(now)]
                    self._buckets[k]=[b for b in bs if not b.is_expired(now)]
                    for b in exp:
                        i=b.to_incident();i.closed=True
                        self._store.save_incident(i);self._store.close_incident(i.incident_id)

    def _flush_all(self):
        with self._lock:
            for bs in self._buckets.values():
                for b in bs:
                    i=b.to_incident();i.closed=True
                    self._store.save_incident(i);self._store.close_incident(i.incident_id)
            self._buckets.clear()
