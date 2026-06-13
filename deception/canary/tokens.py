"""
Ghost IT — Canary Token Registry
Generates and tracks all canary tokens.
A token hit = guaranteed malicious activity. Zero false positives.
"""
from __future__ import annotations
import os
import json
import hashlib
import secrets
import logging
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional

log = logging.getLogger(__name__)

REGISTRY_PATH = os.path.expanduser("~/ghostlayer/data/canary_registry.json")


@dataclass
class CanaryToken:
    token_id:    str
    token_type:  str        # file | http | aws | db | ssh
    value:       str        # the actual fake credential/path
    description: str
    created_at:  str
    hit_count:   int = 0
    last_hit:    Optional[str] = None


class TokenRegistry:
    """
    Persistent canary token store.
    Survives restarts — tokens stay deployed.
    """

    def __init__(self, path: str = REGISTRY_PATH):
        self.path   = path
        self.tokens: dict[str, CanaryToken] = {}
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path) as f:
                    data = json.load(f)
                for k, v in data.items():
                    self.tokens[k] = CanaryToken(**v)
                log.info(f"Loaded {len(self.tokens)} canary tokens")
            except Exception as ex:
                log.error(f"Registry load error: {ex}")

    def _save(self):
        with open(self.path, "w") as f:
            json.dump({k: asdict(v) for k, v in self.tokens.items()}, f, indent=2)

    def _make_id(self, token_type: str, value: str) -> str:
        return hashlib.sha256(f"{token_type}:{value}".encode()).hexdigest()[:16]

    def register(self, token_type: str, value: str, description: str) -> CanaryToken:
        tid = self._make_id(token_type, value)
        token = CanaryToken(
            token_id    = tid,
            token_type  = token_type,
            value       = value,
            description = description,
            created_at  = datetime.now(timezone.utc).isoformat(),
        )
        self.tokens[tid] = token
        self._save()
        log.info(f"Registered canary [{token_type}] {description}")
        return token

    def record_hit(self, token_id: str) -> Optional[CanaryToken]:
        token = self.tokens.get(token_id)
        if token:
            token.hit_count += 1
            token.last_hit   = datetime.now(timezone.utc).isoformat()
            self._save()
        return token

    def lookup_value(self, value: str) -> Optional[CanaryToken]:
        """Find token by its value (e.g. fake API key string)."""
        for token in self.tokens.values():
            if token.value == value:
                return token
        return None

    def all_tokens(self) -> list[CanaryToken]:
        return list(self.tokens.values())


def generate_fake_aws_key() -> str:
    """Realistic-looking fake AWS access key."""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "AKIA" + "".join(secrets.choice(chars) for _ in range(16))


def generate_fake_aws_secret() -> str:
    return secrets.token_urlsafe(40)


def generate_fake_db_password() -> str:
    return "Gh0stDB_" + secrets.token_hex(8) + "!prod"


def generate_fake_api_key() -> str:
    return "ghst_" + secrets.token_hex(24)


def generate_fake_ssh_key() -> str:
    """Fake RSA private key header — triggers on read."""
    fake_b64 = secrets.token_hex(200)
    lines = [fake_b64[i:i+64] for i in range(0, len(fake_b64), 64)]
    body  = "\n".join(lines)
    return f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n"
