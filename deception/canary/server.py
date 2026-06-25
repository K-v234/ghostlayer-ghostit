#!/usr/bin/env python3
"""
Ghost IT — Canary Server

Deploys and monitors three types of canary traps:
  1. File canaries  — fake credentials in canary_files/
  2. HTTP canaries  — fake API endpoints on port 8080
  3. Token registry — tracks all deployed tokens

Any hit = score 100 alert forwarded to pipeline immediately.

Usage:
    python3 deception/canary/server.py
    python3 deception/canary/server.py --http-port 8080 --pipeline-port 9000
"""
import os
import sys
import logging
import argparse
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from tokens  import (TokenRegistry, generate_fake_aws_key,
                     generate_fake_aws_secret, generate_fake_db_password,
                     generate_fake_api_key, generate_fake_ssh_key)
from alerts  import AlertForwarder, CanaryAlert
from pid_whitelist import whitelist as _pid_whitelist
import time as _time
from watcher import FileCanaryWatcher

from http.server import HTTPServer, BaseHTTPRequestHandler
import json

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [canary] %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

CANARY_DIR = "/var/lib/ghostit/canary"


class CanaryServer:
    def __init__(self, http_port: int, pipeline_host: str, pipeline_port: int):
        self.http_port     = http_port
        self.registry      = TokenRegistry()
        self.forwarder     = AlertForwarder(pipeline_host, pipeline_port)
        self.watcher       = FileCanaryWatcher(self._on_file_hit)
        self._startup_time = _time.time()  # Suppress alerts for 10s after startup

    def _on_file_hit(self, filepath: str, event_type: str, pid: int = 0, comm: str = 'unknown'):
        """Called by inotify watcher when a canary file is accessed."""
        # Suppress self-trigger: ignore hits within 30s of startup
        if _time.time() - self._startup_time < 30.0:
            return
        # Suppress known OS telemetry processes
        WHITELISTED_PROCS = {"ubuntu-insights", "ubuntu-insigh", "updatedb", "locate", "mlocate"}
        import subprocess as _sp
        try:
            # Check recent processes for known scanners
            pass  # Process name not available via inotify — handled by startup window
        except Exception:
            pass
        # Whitelist known safe processes
        WHITELISTED_PROCS = {"ubuntu-insights", "ubuntu-insigh", "updatedb",
                              "locate", "mlocate", "systemd", "snapd", "aide"}
        if comm in WHITELISTED_PROCS:
            return

        token = self.registry.lookup_value(filepath)
        if not token:
            return
        self.registry.record_hit(token.token_id)
        hit_by = f"{comm}(PID={pid})" if pid and comm != "unknown" else "local_process"
        log.warning(f"CANARY HIT [file] {token.description} | trigger={event_type} | by={hit_by}")
        self.forwarder.send(CanaryAlert(
            token_id    = token.token_id,
            token_type  = "file",
            description = token.description,
            hit_by      = hit_by,
            hit_method  = event_type,
            extra       = {"filepath": filepath, "pid": pid, "comm": comm},
        ))

    def _on_http_hit(self, path: str, client_ip: str, headers: dict):
        """Called when a canary HTTP endpoint is requested."""
        token = self.registry.lookup_value(f"http:{path}")
        if not token:
            return
        self.registry.record_hit(token.token_id)
        self.forwarder.send(CanaryAlert(
            token_id    = token.token_id,
            token_type  = "http",
            description = token.description,
            hit_by      = client_ip,
            hit_method  = "http_request",
            extra       = {"path": path, "headers": dict(headers)},
        ))

    def _deploy_file_canaries(self):
        """Write fake credential files into canary_files/."""
        os.makedirs(CANARY_DIR, exist_ok=True)

        files = [
            (".env",          f"AWS_ACCESS_KEY_ID={generate_fake_aws_key()}\n"
                              f"AWS_SECRET_ACCESS_KEY={generate_fake_aws_secret()}\n"
                              f"DB_PASSWORD={generate_fake_db_password()}\n"
                              f"API_KEY={generate_fake_api_key()}\n",
                              "fake .env file with credentials"),

            ("id_rsa",        generate_fake_ssh_key(),
                              "fake SSH private key"),

            ("passwords.txt", "admin:admin123\nroot:toor\nubuntu:ubuntu\n"
                              f"api_key:{generate_fake_api_key()}\n",
                              "fake passwords list"),

            ("config.yml",    f"database:\n  host: db.internal\n"
                              f"  password: {generate_fake_db_password()}\n"
                              f"api:\n  secret: {generate_fake_api_key()}\n",
                              "fake service config"),

            ("backup.sql",    "-- Ghost IT Canary DB Dump\n"
                              "-- Production backup 2024-01-01\n"
                              "CREATE TABLE users (id INT, email VARCHAR, password VARCHAR);\n",
                              "fake SQL backup"),
        ]

        for filename, content, description in files:
            filepath = os.path.join(CANARY_DIR, filename)
            with open(filepath, "w") as f:
                f.write(content)
            os.chmod(filepath, 0o644)
            self.registry.register("file", filepath, description)
            self.watcher.add_file(filepath)
            log.info(f"Deployed file canary: {filepath}")

    def _deploy_http_canaries(self):
        """Register fake HTTP endpoints."""
        endpoints = [
            ("/api/v1/admin",      "fake admin API endpoint"),
            ("/api/v1/keys",       "fake API key listing endpoint"),
            ("/internal/config",   "fake internal config endpoint"),
            ("/backup/dump",       "fake backup endpoint"),
            ("/.env",              "fake .env via HTTP"),
            ("/admin/credentials", "fake credential endpoint"),
        ]
        for path, description in endpoints:
            self.registry.register("http", f"http:{path}", description)
            log.info(f"Deployed HTTP canary: {path}")

    def _make_http_handler(self):
        """Create HTTP handler with access to this server instance."""
        server_ref = self

        class CanaryHTTPHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                client_ip = self.client_address[0]
                server_ref._on_http_hit(self.path, client_ip, self.headers)

                # Return plausible-looking fake response
                if self.path.endswith(".env"):
                    body = b"DB_PASSWORD=supersecret\nAPI_KEY=fake123\n"
                    ctype = "text/plain"
                elif self.path.endswith("keys"):
                    body = json.dumps({"keys": ["key1", "key2"]}).encode()
                    ctype = "application/json"
                else:
                    body = json.dumps({"status": "ok"}).encode()
                    ctype = "application/json"

                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", len(body))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass  # Suppress default HTTP logs — we handle logging

        return CanaryHTTPHandler

    def start(self):
        self._deploy_file_canaries()
        self._deploy_http_canaries()
        self.watcher.start()

        # HTTP canary server in background thread
        handler  = self._make_http_handler()
        http_srv = HTTPServer(("0.0.0.0", self.http_port), handler)
        t = threading.Thread(target=http_srv.serve_forever, daemon=True)
        t.start()
        log.info(f"HTTP canary server on port {self.http_port}")

        tokens = self.registry.all_tokens()
        log.info(f"Canary server ready — {len(tokens)} traps deployed")

        # Summary
        for tok in tokens:
            log.info(f"  [{tok.token_type}] {tok.description}")

        # Keep alive
        try:
            threading.Event().wait()
        except KeyboardInterrupt:
            log.info("Canary server stopped")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--http-port",      default=8080, type=int)
    ap.add_argument("--pipeline-host",  default="127.0.0.1")
    ap.add_argument("--pipeline-port",  default=9000, type=int)
    args = ap.parse_args()

    server = CanaryServer(args.http_port, args.pipeline_host, args.pipeline_port)
    server.start()


if __name__ == "__main__":
    main()
