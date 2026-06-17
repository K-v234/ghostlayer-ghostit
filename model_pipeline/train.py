"""
Ghost IT — C16: Model Training Script

Trains Isolation Forest on accumulated behavioral data.
Falls back to synthetic data if insufficient real data.
Exports to ONNX and signs with Ed25519.

Run: python3 model_pipeline/train.py
CI:  triggered by GitHub Actions on release tag

Ghost Layer Technologies — CONFIDENTIAL
"""
from __future__ import annotations
import os
import sys
import json
import logging
import argparse
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [model-pipeline] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

MIN_REAL_SAMPLES = 100  # Use real data only if >= this many samples
MODELS_DIR       = os.path.expanduser("~/ghostlayer/data/models")
DATA_DIR         = os.path.expanduser("~/ghostlayer/data/training")


def load_training_data() -> np.ndarray:
    """
    Load real behavioral feature vectors from DuckDB.
    Falls back to synthetic if insufficient data.
    """
    from detection.behavioral.features import BEHAVIORAL_FEATURES

    real_samples = []

    # Try loading from saved feature vectors
    data_path = os.path.join(DATA_DIR, "feature_vectors.jsonl")
    if os.path.exists(data_path):
        with open(data_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    vec = json.loads(line)
                    real_samples.append(
                        [vec.get(f, 0.0) for f in BEHAVIORAL_FEATURES]
                    )
                except Exception:
                    pass

    if len(real_samples) >= MIN_REAL_SAMPLES:
        log.info(f"Using {len(real_samples)} real behavioral samples")
        return np.array(real_samples, dtype=np.float32)

    # Fall back to synthetic data
    log.warning(
        f"Insufficient real data ({len(real_samples)} < {MIN_REAL_SAMPLES})"
        f" — using synthetic bootstrap data"
    )
    return _generate_synthetic_data()


def _generate_synthetic_data(n_samples: int = 1000) -> np.ndarray:
    """
    Generate synthetic normal behavioral data for bootstrap training.
    Based on Developer archetype population baseline.
    """
    np.random.seed(42)

    # Simulate realistic behavioral distributions
    data = np.column_stack([
        np.random.exponential(0.5,  n_samples),  # proc_spawn_rate
        np.random.exponential(2.0,  n_samples),  # proc_spawn_diversity
        np.random.exponential(0.3,  n_samples),  # network_conn_rate
        np.random.exponential(1.0,  n_samples),  # network_dst_diversity
        np.random.exponential(500,  n_samples),  # network_bytes_out
        np.random.exponential(1.0,  n_samples),  # file_write_rate
        np.random.beta(1, 10,       n_samples),  # file_entropy_delta
        np.zeros(n_samples),                     # auth_failure_rate
        np.random.poisson(0.1,      n_samples).astype(float), # privilege_escalation_ct
        np.random.poisson(0.5,      n_samples).astype(float), # lolbin_access_ct
        np.random.exponential(0.2,  n_samples),  # mmap_exec_rate
        np.random.exponential(1.0,  n_samples),  # mprotect_exec_rate
        np.zeros(n_samples),                     # active_hours_deviation
        np.zeros(n_samples),                     # session_duration_z
        np.random.exponential(0.1,  n_samples),  # entropy_read_rate
        np.random.exponential(0.5,  n_samples),  # unique_file_ext_writes
        np.zeros(n_samples),                     # shadow_delete_ct
    ]).astype(np.float32)

    log.info(f"Generated {n_samples} synthetic training samples")
    return data


def train_isolation_forest(X: np.ndarray):
    """Train Isolation Forest on feature matrix."""
    from sklearn.ensemble import IsolationForest

    model = IsolationForest(
        n_estimators  = 100,
        contamination = 0.05,
        random_state  = 42,
        n_jobs        = -1,
    )
    model.fit(X)
    log.info(f"Isolation Forest trained: {X.shape[0]} samples, {X.shape[1]} features")
    return model


def save_training_metadata(X: np.ndarray, output_dir: str):
    """Save training metadata for audit trail."""
    import hashlib, time
    meta = {
        "timestamp":     time.time(),
        "n_samples":     int(X.shape[0]),
        "n_features":    int(X.shape[1]),
        "data_sha256":   hashlib.sha256(X.tobytes()).hexdigest(),
        "version":       "0.1.0",
    }
    path = os.path.join(output_dir, "training_metadata.json")
    with open(path, "w") as f:
        json.dump(meta, f, indent=2)
    log.info(f"Training metadata saved: {path}")
    return meta


def main():
    ap = argparse.ArgumentParser(description="Ghost IT Model Training Pipeline")
    ap.add_argument("--output-dir", default=MODELS_DIR)
    ap.add_argument("--model-name", default="isolation_forest")
    ap.add_argument("--verify",     action="store_true",
                    help="Verify signature after signing")
    args = ap.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

    # Step 1: Load data
    log.info("=== Ghost IT Model Training Pipeline ===")
    X = load_training_data()

    # Step 2: Train
    model = train_isolation_forest(X)

    # Step 3: Export to ONNX + sign
    from inference.exporter import export_isolation_forest
    model_path = export_isolation_forest(
        model,
        model_name = args.model_name,
        n_features = X.shape[1],
    )

    # Step 4: Save metadata
    save_training_metadata(X, args.output_dir)

    # Step 5: Verify (optional but recommended)
    if args.verify:
        from inference.signing import verify_model
        verify_model(model_path)
        log.info("✅ Signature verification passed")

    # Step 6: Test inference
    from inference.runtime import GhostONNXRuntime
    runtime = GhostONNXRuntime(args.model_name)
    test_vec = [0.1] * X.shape[1]
    result   = runtime.infer(test_vec)
    log.info(
        f"✅ Inference test: score={result['score']:.3f} "
        f"latency={result['latency_ms']:.2f}ms"
    )

    if result["latency_ms"] > 5.0:
        log.warning(f"⚠️  Latency {result['latency_ms']:.2f}ms exceeds 5ms target")
    else:
        log.info("✅ Latency within 5ms target")

    log.info(f"=== Pipeline complete: {model_path} ===")
    return model_path


if __name__ == "__main__":
    main()
