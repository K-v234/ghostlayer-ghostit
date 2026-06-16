"""
Ghost IT — C8/C16: Model Exporter

Exports trained sklearn models to ONNX format,
then signs them with Ed25519.

Ghost Layer Technologies — CONFIDENTIAL
"""
from __future__ import annotations
import os
import logging
import numpy as np
from sklearn.ensemble import IsolationForest
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from .signing import sign_model, generate_signing_keypair, verify_model

log = logging.getLogger(__name__)

MODELS_DIR = os.path.expanduser("~/ghostlayer/data/models")


def export_isolation_forest(
    model: IsolationForest,
    model_name: str = "isolation_forest",
    n_features: int = 17,
) -> str:
    """
    Export trained IsolationForest to ONNX and sign it.
    Returns path to signed ONNX file.
    """
    os.makedirs(MODELS_DIR, exist_ok=True)

    # Convert to ONNX
    initial_type = [("X", FloatTensorType([None, n_features]))]
    onnx_model   = convert_sklearn(
        model,
        initial_types=initial_type,
        target_opset={
            "": 17,
            "ai.onnx.ml": 3
        },
    )

    # Save ONNX
    model_path = os.path.join(MODELS_DIR, f"{model_name}.onnx")
    with open(model_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    log.info(f"ONNX model exported: {model_path}")

    # Sign it
    sig_path = sign_model(model_path)
    log.info(f"Model signed: {sig_path}")

    return model_path


def create_and_export_initial_model() -> str:
    """
    Create initial Isolation Forest model on synthetic data.
    Used to bootstrap the system before real data accumulates.
    """
    from detection.behavioral.features import BEHAVIORAL_FEATURES

    log.info("Creating initial Isolation Forest model...")

    # Synthetic normal behavioral data (17 features)
    np.random.seed(42)
    n_samples = 500
    X = np.random.exponential(scale=0.5, size=(n_samples, 17)).astype(np.float32)

    # Train
    model = IsolationForest(
        n_estimators  = 100,
        contamination = 0.05,
        random_state  = 42,
    )
    model.fit(X)
    log.info(f"Initial model trained on {n_samples} synthetic samples")

    # Export + sign
    model_path = export_isolation_forest(model)
    return model_path
