"""
Ghost IT — C8: Model Signing + Verification

All ONNX models signed with Ed25519 before deployment.
Verification happens at load time — tampered model = refused.

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

log = logging.getLogger(__name__)

# Hybrid signing (Ed25519 + ML-DSA-65)
try:
    from inference.hybrid_signing import sign_file as hybrid_sign_file, verify_file as hybrid_verify_file
    HYBRID_AVAILABLE = True
except ImportError:
    HYBRID_AVAILABLE = False
    log.warning("Hybrid signing not available — Ed25519 only")

KEYS_DIR    = os.path.expanduser("~/ghostlayer/data/model_keys")
SIGNING_KEY = os.path.join(KEYS_DIR, "model_signing.key")
VERIFY_KEY  = os.path.join(KEYS_DIR, "model_signing.pub")


def generate_signing_keypair():
    """Generate Ed25519 keypair for model signing. Run once."""
    os.makedirs(KEYS_DIR, exist_ok=True)

    private_key = Ed25519PrivateKey.generate()
    public_key  = private_key.public_key()

    # Save private key
    with open(SIGNING_KEY, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.chmod(SIGNING_KEY, 0o600)

    # Save public key
    with open(VERIFY_KEY, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    log.info(f"Ed25519 keypair generated: {KEYS_DIR}")
    return private_key, public_key


def load_private_key() -> Ed25519PrivateKey:
    with open(SIGNING_KEY, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key() -> Ed25519PublicKey:
    with open(VERIFY_KEY, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def sign_model(model_path: str) -> str:
    """
    Sign an ONNX model file with Ed25519.
    Returns path to signature file (.sig).
    Creates a manifest with model hash + metadata.
    """
    private_key = load_private_key()

    # Hash the model file
    with open(model_path, "rb") as f:
        model_bytes = f.read()
    model_hash = hashlib.sha256(model_bytes).hexdigest()

    # Create manifest
    manifest = {
        "model_path": os.path.basename(model_path),
        "sha256":     model_hash,
        "size_bytes": len(model_bytes),
        "version":    "0.1.0",
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()

    # Sign manifest
    signature = private_key.sign(manifest_bytes)

    # Write signature bundle
    sig_path = model_path + ".sig"
    bundle = {
        "manifest":  manifest,
        "signature": signature.hex(),
    }
    with open(sig_path, "w") as f:
        json.dump(bundle, f, indent=2)

    log.info(f"Model signed: {model_path} → {sig_path}")
    # Hybrid: also sign with ML-DSA-65
    if HYBRID_AVAILABLE:
        try:
            hybrid_sign_file(model_path)
            log.info(f"Hybrid signed (Ed25519+ML-DSA-65): {model_path}")
        except Exception as e:
            log.warning(f"Hybrid signing failed: {e}")
    return sig_path


def verify_model(model_path: str) -> bool:
    """
    Verify ONNX model signature before loading.
    Returns True if valid, raises SecurityError if tampered.
    """
    sig_path = model_path + ".sig"

    if not os.path.exists(sig_path):
        raise SecurityError(f"No signature file for {model_path}")

    public_key = load_public_key()

    with open(sig_path) as f:
        bundle = json.load(f)

    manifest   = bundle["manifest"]
    signature  = bytes.fromhex(bundle["signature"])
    manifest_bytes = json.dumps(manifest, sort_keys=True).encode()

    # Verify signature
    try:
        public_key.verify(signature, manifest_bytes)
    except InvalidSignature:
        raise SecurityError(f"INVALID SIGNATURE for {model_path} — possible tampering")

    # Verify file hash
    with open(model_path, "rb") as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()

    if actual_hash != manifest["sha256"]:
        raise SecurityError(
            f"HASH MISMATCH for {model_path} — "
            f"expected {manifest['sha256']}, got {actual_hash}"
        )

    log.info(f"Model verified OK: {model_path}")
    return True


class SecurityError(Exception):
    pass
