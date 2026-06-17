"""
Ghost IT — C16: Model Updater

Watches for new signed models and hot-reloads them.
Runs as background thread inside pipeline server.

Ghost Layer Technologies — CONFIDENTIAL
"""
from __future__ import annotations
import os
import time
import logging
import threading
from .registry import ModelRegistry

log = logging.getLogger(__name__)

MODELS_DIR    = os.path.expanduser("~/ghostlayer/data/models")
CHECK_INTERVAL = 300  # Check every 5 minutes


class ModelUpdater:
    """
    Background model updater.
    Checks for new signed model versions periodically.
    Hot-reloads without restarting the pipeline.
    """

    def __init__(self):
        self.registry  = ModelRegistry()
        self._runtimes = {}
        self._running  = False

    def register_runtime(self, model_name: str, runtime):
        """Register a runtime to be notified on model updates."""
        self._runtimes[model_name] = runtime

    def start(self):
        """Start background update checker."""
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        log.info("Model updater started")

    def _loop(self):
        while self._running:
            try:
                self._check_updates()
            except Exception as ex:
                log.error(f"Model updater error: {ex}")
            time.sleep(CHECK_INTERVAL)

    def _check_updates(self):
        """Check for new model files and reload if found."""
        for model_name, runtime in self._runtimes.items():
            model_path = os.path.join(MODELS_DIR, f"{model_name}.onnx")
            sig_path   = model_path + ".sig"

            if not os.path.exists(model_path):
                continue
            if not os.path.exists(sig_path):
                continue

            # Check if newer than current
            current = self.registry.get_current(model_name)
            mtime   = os.path.getmtime(model_path)

            if current and current["registered"] >= mtime:
                continue  # No update

            # New model found — verify and reload
            try:
                from inference.signing import verify_model
                verify_model(model_path)

                version = self.registry.register(model_name, model_path)
                self.registry.mark_verified(model_name, version)

                runtime.reload()
                log.info(f"Model {model_name} hot-reloaded: {version}")

            except Exception as ex:
                log.critical(f"Model update FAILED for {model_name}: {ex}")
                # Trigger rollback
                prev = self.registry.rollback(model_name)
                if prev:
                    log.warning(f"Rolled back to {prev['version']}")

    def stop(self):
        self._running = False
