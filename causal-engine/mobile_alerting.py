#!/usr/bin/env python3
"""
Ghost IT — Mobile/SMS Critical Alerting
Real gap: a critical alert nobody sees in the dashboard has zero value.
Sends critical alerts (score >= 90) via webhook (Twilio/MSG91/Slack/
Teams-compatible) with a safe logging fallback if unconfigured.
"""
from __future__ import annotations
import os, time, logging, urllib.request, json

log = logging.getLogger(__name__)
WEBHOOK_URL = os.environ.get("GHOSTIT_ALERT_WEBHOOK_URL", "")
SMS_TRIGGER_SCORE = 90

def should_alert(score: float) -> bool:
    return score >= SMS_TRIGGER_SCORE

def send_critical_alert(message: str, entity_id: str, score: float) -> dict:
    payload = {"text": f"GHOST IT CRITICAL ALERT: {message} (entity={entity_id}, score={score})",
               "entity_id": entity_id, "score": score, "ts": time.time()}
    if not WEBHOOK_URL:
        log.critical(f"[MobileAlert] NO WEBHOOK CONFIGURED -- {payload['text']}")
        return {"sent": False, "reason": "no webhook configured", "payload": payload}
    try:
        req = urllib.request.Request(WEBHOOK_URL, data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        urllib.request.urlopen(req, timeout=5)
        log.warning(f"[MobileAlert] Sent: {payload['text']}")
        return {"sent": True, "payload": payload}
    except Exception as ex:
        log.error(f"[MobileAlert] Send failed: {ex}")
        return {"sent": False, "reason": str(ex), "payload": payload}

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    r = send_critical_alert("Ransomware confirmed on pid:9999", "pid:9999", 96)
    print(f"  {r}")
