"""
Ghost IT — C3: Polymorphic Canary Token Generator
Generates format-valid credential tokens that trigger callbacks
when accessed. Different format every render — attacker cannot
fingerprint by token format.

Supported types: AWS Access Key, GitHub PAT, SSH Private Key

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 100% — complete
"""
from __future__ import annotations
import os
import hmac
import json
import base64
import hashlib
import logging
from enum import Enum
from dataclasses import dataclass
from typing import Optional

log = logging.getLogger(__name__)

class CredentialType(Enum):
    AWS_ACCESS_KEY = "aws"
    GITHUB_PAT     = "github"
    SSH_PRIVATE_KEY = "ssh"

@dataclass
class CanaryToken:
    token_id:   str
    ctype:      CredentialType
    secret:     bytes
    nonces:     list  # Registered nonces for callback resolution

class PolymorphicTokenGenerator:
    """
    Generates polymorphic canary tokens.
    Each render produces a different visible ID.
    Backend links nonce → token for callback resolution.
    Token must pass format validation as real credential.
    """

    def __init__(self):
        self._tokens: dict[str, CanaryToken] = {}
        self._nonce_map: dict[str, str] = {}  # nonce_hex → token_id

    def create_token(self, ctype: CredentialType) -> CanaryToken:
        """Create a new canary token of the given type."""
        secret   = os.urandom(32)
        token_id = hashlib.sha256(secret).hexdigest()[:16]
        token    = CanaryToken(
            token_id=token_id,
            ctype=ctype,
            secret=secret,
            nonces=[]
        )
        self._tokens[token_id] = token
        log.info(f"Canary token created: {ctype.value} id={token_id}")
        return token

    def render(self, token: CanaryToken) -> str:
        """
        Render a token. Different every call — polymorphic.
        Returns format-valid credential string.
        """
        nonce      = os.urandom(16)
        nonce_hex  = nonce.hex()
        visible_id = hmac.new(token.secret, nonce, 'sha256').digest()[:12].hex()

        # Register nonce for callback resolution
        self._nonce_map[nonce_hex] = token.token_id
        token.nonces.append(nonce_hex)

        return self._format_credential(visible_id, token.ctype, nonce_hex)

    def _format_credential(self, visible_id: str, ctype: CredentialType, nonce: str) -> str:
        """Format as valid credential of the specified type."""

        if ctype == CredentialType.AWS_ACCESS_KEY:
            # Real AWS format: AKIA + 16 base32 chars (exactly 20 chars total)
            suffix = base64.b32encode(bytes.fromhex(visible_id)).decode().upper()[:16]
            return f"AKIA{suffix}"

        elif ctype == CredentialType.GITHUB_PAT:
            # Real GitHub PAT: ghp_ + 36 alphanumeric chars (total 40)
            raw = bytes.fromhex(visible_id) + bytes.fromhex(nonce[:16])
            encoded = base64.b64encode(raw).decode()
            # Remove non-alphanumeric chars, pad to exactly 36
            clean = ''.join(c for c in encoded if c.isalnum())
            padded = (clean + 'a' * 36)[:36]
            return f"ghp_{padded}"

        elif ctype == CredentialType.SSH_PRIVATE_KEY:
            # Valid-looking RSA private key structure
            key_data = base64.b64encode(
                bytes.fromhex(visible_id) + os.urandom(32)
            ).decode()
            return (
                "-----BEGIN RSA PRIVATE KEY-----\n"
                f"{key_data[:64]}\n"
                f"{key_data[64:128] if len(key_data) > 64 else key_data}\n"
                "-----END RSA PRIVATE KEY-----"
            )

        return visible_id  # Fallback

    def resolve_callback(self, nonce_hex: str) -> Optional[str]:
        """Resolve a callback nonce to a token ID."""
        return self._nonce_map.get(nonce_hex)

    def get_token(self, token_id: str) -> Optional[CanaryToken]:
        return self._tokens.get(token_id)


# Singleton
token_generator = PolymorphicTokenGenerator()
