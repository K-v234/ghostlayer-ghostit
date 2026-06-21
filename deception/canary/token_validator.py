"""
Ghost IT — C3: Canary Token Validator
Validates that generated canary tokens pass format checks
for their respective credential types.
A detectable format = useless canary.

Ghost Layer Technologies — CONFIDENTIAL
# STATUS: 100% — complete
"""
from __future__ import annotations
import re
import base64
import logging

log = logging.getLogger(__name__)

class TokenValidator:
    """
    Validates canary tokens pass format checks for their type.
    Real security tools and attackers validate credentials before use.
    If our token fails format validation — it's useless as a canary.
    """

    def validate_aws(self, token: str) -> bool:
        """
        AWS Access Key format: AKIA + 16 base32 uppercase chars
        Total: exactly 20 chars
        """
        if not token.startswith("AKIA"):
            return False
        if len(token) != 20:
            return False
        suffix = token[4:]
        # Must be valid base32 chars: A-Z and 2-7
        if not re.match(r'^[A-Z2-7]{16}$', suffix):
            return False
        log.debug(f"AWS token valid: {token[:8]}...")
        return True

    def validate_github_pat(self, token: str) -> bool:
        """
        GitHub PAT format: ghp_ + 36 base64 chars
        Total: exactly 40 chars
        """
        if not token.startswith("ghp_"):
            return False
        if len(token) != 40:
            return False
        suffix = token[4:]
        # Must be valid base64 chars
        if not re.match(r'^[A-Za-z0-9+/=]{36}$', suffix):
            return False
        log.debug(f"GitHub PAT valid: {token[:8]}...")
        return True

    def validate_ssh_key(self, token: str) -> bool:
        """
        SSH private key format:
        Must have BEGIN/END markers and base64 body
        """
        if "-----BEGIN RSA PRIVATE KEY-----" not in token:
            return False
        if "-----END RSA PRIVATE KEY-----" not in token:
            return False
        # Extract body between markers
        lines = token.strip().split("\n")
        body_lines = [l for l in lines
                     if not l.startswith("-----")]
        if not body_lines:
            return False
        log.debug("SSH key valid: markers + body present")
        return True

    def validate(self, token: str, ctype: str) -> bool:
        """Validate a token of the given type."""
        validators = {
            "aws":    self.validate_aws,
            "github": self.validate_github_pat,
            "ssh":    self.validate_ssh_key,
        }
        validator = validators.get(ctype)
        if not validator:
            log.warning(f"No validator for type: {ctype}")
            return False
        result = validator(token)
        if not result:
            log.error(f"Token FAILED format validation: type={ctype}")
        return result

    def validate_all(self, tokens: dict) -> dict:
        """
        Validate multiple tokens. Returns dict of type → pass/fail.
        Used in V1 acceptance test.
        """
        results = {}
        for ctype, token in tokens.items():
            results[ctype] = self.validate(token, ctype)
        all_pass = all(results.values())
        if all_pass:
            log.info("All canary tokens passed format validation ✅")
        else:
            failed = [k for k, v in results.items() if not v]
            log.error(f"Token format validation FAILED: {failed}")
        return results


# Singleton
token_validator = TokenValidator()
