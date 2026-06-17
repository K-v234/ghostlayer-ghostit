"""
Ghost IT — C16: Model Registry

Tracks all model versions with metadata.
Supports rollback to previous verified version.

Ghost Layer Technologies — CONFIDENTIAL
"""
from __future__ import annotations
import os
import json
import shutil
import logging
import hashlib
import time
from typing import Optional

log = logging.getLogger(__name__)

MODELS_DIR   = os.path.expanduser("~/ghostlayer/data/models")
REGISTRY_PATH = os.path.join(MODELS_DIR, "registry.json")


class ModelRegistry:
    """
    Tracks model versions and manages rollback.
    Each registered model has: version, hash, timestamp, verified status.
    """

    def __init__(self):
        self.models: dict = {}
        self._load()

    def register(self, model_name: str, model_path: str,
                 metadata: Optional[dict] = None) -> str:
        """Register a new model version."""
        with open(model_path, "rb") as f:
            model_hash = hashlib.sha256(f.read()).hexdigest()

        version = f"v{int(time.time())}"
        entry   = {
            "version":    version,
            "path":       model_path,
            "sha256":     model_hash,
            "registered": time.time(),
            "verified":   False,
            "metadata":   metadata or {},
        }

        if model_name not in self.models:
            self.models[model_name] = []
        self.models[model_name].append(entry)
        self._save()

        log.info(f"Registered model {model_name} {version}")
        return version

    def mark_verified(self, model_name: str, version: str):
        """Mark a model version as signature-verified."""
        for entry in self.models.get(model_name, []):
            if entry["version"] == version:
                entry["verified"] = True
                self._save()
                log.info(f"Model {model_name} {version} marked verified")
                return
        raise ValueError(f"Model {model_name} {version} not found")

    def get_current(self, model_name: str) -> Optional[dict]:
        """Get the latest verified model version."""
        versions = [
            e for e in self.models.get(model_name, [])
            if e["verified"]
        ]
        if not versions:
            return None
        return max(versions, key=lambda e: e["registered"])

    def rollback(self, model_name: str) -> Optional[dict]:
        """Roll back to previous verified version."""
        versions = sorted(
            [e for e in self.models.get(model_name, []) if e["verified"]],
            key=lambda e: e["registered"],
        )
        if len(versions) < 2:
            log.warning(f"No previous version for {model_name}")
            return None
        prev = versions[-2]
        log.warning(f"Rolling back {model_name} to {prev['version']}")
        return prev

    def list_versions(self, model_name: str) -> list[dict]:
        return self.models.get(model_name, [])

    def _save(self):
        os.makedirs(MODELS_DIR, exist_ok=True)
        with open(REGISTRY_PATH, "w") as f:
            json.dump(self.models, f, indent=2)

    def _load(self):
        if os.path.exists(REGISTRY_PATH):
            with open(REGISTRY_PATH) as f:
                self.models = json.load(f)
