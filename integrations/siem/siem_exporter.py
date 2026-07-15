#!/usr/bin/env python3
"""
Ghost IT — V2: SIEM Export Daemon
Polls the Ghost IT pipeline for new alerts and forwards them to a
configured SIEM endpoint via syslog (UDP/TCP), formatted as CEF.
This is the real, running bridge between Ghost IT's own detection
pipeline and a customer's existing SIEM infrastructure -- the actual
feature customers ask for when evaluating a new EDR product.
"""
import sys
import os
import time
import socket
import logging
import argparse
import urllib.request
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cef_formatter import to_cef
from leef_formatter import to_leef
from splunk_cim_formatter import to_splunk_cim
import urllib.request as _urlreq

log = logging.getLogger("siem_exporter")
logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [siem_export] %(levelname)s %(message)s")

class SIEMExporter:
    def __init__(self, pipeline_api: str, siem_host: str, siem_port: int,
                 protocol: str = "udp", poll_interval: int = 15,
                 format: str = "cef", splunk_hec_url: str = "",
                 splunk_hec_token: str = ""):
        self.pipeline_api = pipeline_api
        self.siem_host = siem_host
        self.siem_port = siem_port
        self.protocol = protocol
        self.poll_interval = poll_interval
        self.format = format
        self.splunk_hec_url = splunk_hec_url
        self.splunk_hec_token = splunk_hec_token
        self._max_seen_id = 0

    def _fetch_new_alerts(self) -> list[dict]:
        try:
            url = f"{self.pipeline_api}/alerts?limit=100"
            with urllib.request.urlopen(url, timeout=10) as r:
                data = json.loads(r.read())
            alerts = data.get("alerts", [])
            new = [a for a in alerts if a.get("id", 0) > self._max_seen_id]
            if new:
                self._max_seen_id = max(a.get("id", 0) for a in new)
            return new
        except Exception as e:
            log.error(f"Pipeline fetch error: {e}")
            return []

    def _send_to_siem(self, line: str):
        try:
            if self.protocol == "udp":
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(line.encode(), (self.siem_host, self.siem_port))
                s.close()
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((self.siem_host, self.siem_port))
                s.sendall((line + "\n").encode())
                s.close()
        except Exception as e:
            log.error(f"SIEM send error: {e}")

    def _send_to_splunk_hec(self, alert: dict):
        # Splunk uses HTTP Event Collector (HEC), not raw syslog like
        # CEF/LEEF -- a JSON POST to a Splunk-provided HEC token URL,
        # not a socket send.
        try:
            payload = json.dumps(to_splunk_cim(alert)).encode()
            req = _urlreq.Request(
                self.splunk_hec_url,
                data=payload,
                headers={
                    "Authorization": f"Splunk {self.splunk_hec_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with _urlreq.urlopen(req, timeout=5) as r:
                r.read()
        except Exception as e:
            log.error(f"Splunk HEC send error: {e}")

    def run(self):
        log.info(f"SIEM exporter running -- forwarding to {self.siem_host}:{self.siem_port} "
                  f"({self.protocol.upper()}), poll={self.poll_interval}s")
        while True:
            alerts = self._fetch_new_alerts()
            for alert in alerts:
                if self.format == "splunk":
                    self._send_to_splunk_hec(alert)
                    log.info(f"Exported (splunk): alert id={alert.get('id')}")
                else:
                    line = to_leef(alert) if self.format == "leef" else to_cef(alert)
                    self._send_to_siem(line)
                    log.info(f"Exported ({self.format}): {line[:100]}...")
            time.sleep(self.poll_interval)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pipeline-api", default="http://127.0.0.1:8000")
    ap.add_argument("--siem-host", required=True)
    ap.add_argument("--siem-port", type=int, default=514)
    ap.add_argument("--protocol", choices=["udp", "tcp"], default="udp")
    ap.add_argument("--poll-interval", type=int, default=15)
    ap.add_argument("--format", choices=["cef", "leef", "splunk"], default="cef")
    ap.add_argument("--splunk-hec-url", default="")
    ap.add_argument("--splunk-hec-token", default="")
    args = ap.parse_args()

    exporter = SIEMExporter(
        pipeline_api=args.pipeline_api,
        siem_host=args.siem_host,
        siem_port=args.siem_port,
        protocol=args.protocol,
        poll_interval=args.poll_interval,
        format=args.format,
        splunk_hec_url=args.splunk_hec_url,
        splunk_hec_token=args.splunk_hec_token,
    )
    exporter.run()

if __name__ == "__main__":
    main()
