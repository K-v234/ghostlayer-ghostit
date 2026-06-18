"""
Ghost IT — C8/C16: Hybrid Signature Scheme
Ed25519 || ML-DSA-65 (Dilithium3)

Both signatures must verify for acceptance.
Either alone is insufficient — quantum AND classical security.

Ghost Layer Technologies — CONFIDENTIAL
"""
from __future__ import annotations
import os
import json
import logging
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from dilithium_py.dilithium import Dilithium3

log = logging.getLogger(__name__)

KEYS_DIR         = os.path.expanduser("~/ghostlayer/data/model_keys")
ED25519_PRIV     = os.path.join(KEYS_DIR, "model_signing.key")
ED25519_PUB      = os.path.join(KEYS_DIR, "model_signing.pub")
MLDSA_PRIV       = os.path.join(KEYS_DIR, "mldsa65.priv")
MLDSA_PUB        = os.path.join(KEYS_DIR, "mldsa65.pub")

# ------------------------------------------------------------------ #
# Key generation                                                      #
# ------------------------------------------------------------------ #

def generate_hybrid_keypair():
    """Generate Ed25519 + ML-DSA-65 keypair. Run once."""
    os.makedirs(KEYS_DIR, exist_ok=True)

    # Ed25519
    ed_priv = Ed25519PrivateKey.generate()
    ed_pub  = ed_priv.public_key()
    with open(ED25519_PRIV, "wb") as f:
        f.write(ed_priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.chmod(ED25519_PRIV, 0o600)
    with open(ED25519_PUB, "wb") as f:
        f.write(ed_pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    # ML-DSA-65 (Dilithium3)
    pk, sk = Dilithium3.keygen()
    with open(MLDSA_PUB, "wb") as f:
        f.write(pk)
    with open(MLDSA_PRIV, "wb") as f:
        f.write(sk)
    os.chmod(MLDSA_PRIV, 0o600)

    log.info(f"Hybrid keypair generated: Ed25519 + ML-DSA-65 in {KEYS_DIR}")
    return ed_priv, ed_pub, sk, pk

# ------------------------------------------------------------------ #
# Signing                                                             #
# ------------------------------------------------------------------ #

def hybrid_sign(data: bytes) -> dict:
    """
    Sign data with both Ed25519 and ML-DSA-65.
    Returns dict with both signatures + sha256 digest.
    """
    digest = hashlib.sha256(data).digest()

    # Ed25519 sign
    with open(ED25519_PRIV, "rb") as f:
        ed_priv = serialization.load_pem_private_key(f.read(), password=None)
    ed_sig = ed_priv.sign(digest)

    # ML-DSA-65 sign
    with open(MLDSA_PRIV, "rb") as f:
        sk = f.read()
    mldsa_sig = Dilithium3.sign(sk, digest)

    return {
        "alg":      "Ed25519+ML-DSA-65",
        "sha256":   digest.hex(),
        "ed25519":  ed_sig.hex(),
        "mldsa65":  mldsa_sig.hex(),
    }

def sign_file(path: str) -> dict:
    """Sign a file with hybrid scheme. Returns signature dict."""
    with open(path, "rb") as f:
        data = f.read()
    sig = hybrid_sign(data)
    sig_path = path + ".hybrid.sig"
    with open(sig_path, "w") as f:
        json.dump(sig, f, indent=2)
    log.info(f"Hybrid signed: {path} -> {sig_path}")
    return sig

# ------------------------------------------------------------------ #
# Verification                                                        #
# ------------------------------------------------------------------ #

def hybrid_verify(data: bytes, sig: dict) -> bool:
    """
    Verify both Ed25519 AND ML-DSA-65 signatures.
    Both must pass — failure of either = rejection.
    """
    digest = hashlib.sha256(data).digest()

    # Check digest matches
    if digest.hex() != sig.get("sha256", ""):
        log.error("Hybrid verify FAILED: SHA-256 mismatch")
        return False

    # Verify Ed25519
    try:
        with open(ED25519_PUB, "rb") as f:
            ed_pub = serialization.load_pem_public_key(f.read())
        ed_pub.verify(bytes.fromhex(sig["ed25519"]), digest)
    except (InvalidSignature, Exception) as e:
        log.error(f"Hybrid verify FAILED: Ed25519 invalid — {e}")
        return False

    # Verify ML-DSA-65
    try:
        with open(MLDSA_PUB, "rb") as f:
            pk = f.read()
        ok = Dilithium3.verify(pk, digest, bytes.fromhex(sig["mldsa65"]))
        if not ok:
            log.error("Hybrid verify FAILED: ML-DSA-65 invalid")
            return False
    except Exception as e:
        log.error(f"Hybrid verify FAILED: ML-DSA-65 error — {e}")
        return False

    log.info("Hybrid verify OK: Ed25519 + ML-DSA-65 both valid")
    return True

def verify_file(path: str) -> bool:
    """Verify a file against its .hybrid.sig sidecar."""
    sig_path = path + ".hybrid.sig"
    if not os.path.exists(sig_path):
        log.error(f"No hybrid sig found: {sig_path}")
        return False
    with open(path, "rb") as f:
        data = f.read()
    with open(sig_path, "r") as f:
        sig = json.load(f)
    return hybrid_verify(data, sig)
