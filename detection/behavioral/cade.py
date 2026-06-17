"""
Ghost IT — C2: CADE Adversarial Drift Detection

Contrastive Autoencoder for Drift Explanation (CCS 2021).

Detects adversarial baseline poisoning — distinguishes organic drift
from targeted manipulation of specific behavioral features.

Adversarial pattern: high distance concentrated in 1-3 features.
Legitimate drift: moderate distance spread across all 17 features.

Ghost Layer Technologies — CONFIDENTIAL
"""
from __future__ import annotations
import os
import math
import time
import logging
import numpy as np
from typing import Optional
from dataclasses import dataclass
from enum import Enum

log = logging.getLogger(__name__)

MODELS_DIR = os.path.expanduser("~/ghostlayer/data/models")


class DriftType(str, Enum):
    STABLE      = "stable"
    ORGANIC     = "organic"
    ADVERSARIAL = "adversarial"


@dataclass
class DriftReport:
    type:              DriftType
    severity:          str          # info | medium | high
    contrastive_dist:  float
    adversarial_score: float
    drifting_features: list[str]
    recommendation:    str


class ContrastiveAutoencoder:
    """
    Lightweight contrastive autoencoder for behavioral drift detection.
    
    Uses numpy — no PyTorch dependency for inference.
    Training uses simple gradient descent.
    
    Architecture:
        Input (17) → Encoder (8) → Latent (4) → Decoder (8) → Output (17)
    """

    def __init__(self, input_dim: int = 17, latent_dim: int = 4):
        self.input_dim  = input_dim
        self.latent_dim = latent_dim
        self.trained    = False

        # Initialize weights (Xavier initialization)
        self._init_weights()

    def _init_weights(self):
        """Xavier uniform initialization."""
        def xavier(fan_in, fan_out):
            limit = math.sqrt(6.0 / (fan_in + fan_out))
            return np.random.uniform(-limit, limit, (fan_in, fan_out)).astype(np.float32)

        np.random.seed(42)
        # Encoder: 17 → 8 → 4
        self.W_e1 = xavier(self.input_dim, 8)
        self.b_e1 = np.zeros(8, dtype=np.float32)
        self.W_e2 = xavier(8, self.latent_dim)
        self.b_e2 = np.zeros(self.latent_dim, dtype=np.float32)

        # Decoder: 4 → 8 → 17
        self.W_d1 = xavier(self.latent_dim, 8)
        self.b_d1 = np.zeros(8, dtype=np.float32)
        self.W_d2 = xavier(8, self.input_dim)
        self.b_d2 = np.zeros(self.input_dim, dtype=np.float32)

    def _relu(self, x: np.ndarray) -> np.ndarray:
        return np.maximum(0, x)

    def _relu_grad(self, x: np.ndarray) -> np.ndarray:
        return (x > 0).astype(np.float32)

    def encode(self, x: np.ndarray) -> np.ndarray:
        """Encode input to latent representation."""
        h1 = self._relu(x @ self.W_e1 + self.b_e1)
        z  = self._relu(h1 @ self.W_e2 + self.b_e2)
        return z

    def decode(self, z: np.ndarray) -> np.ndarray:
        """Decode latent representation to output."""
        h1 = self._relu(z @ self.W_d1 + self.b_d1)
        x  = h1 @ self.W_d2 + self.b_d2
        return x

    def forward(self, x: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Forward pass. Returns (reconstruction, latent)."""
        z    = self.encode(x)
        x_hat = self.decode(z)
        return x_hat, z

    def train(self, X: np.ndarray, epochs: int = 100,
              lr: float = 0.001, batch_size: int = 32):
        """
        Train autoencoder on normal behavioral data.
        Uses mini-batch gradient descent.
        """
        n = len(X)
        losses = []

        for epoch in range(epochs):
            # Shuffle
            idx = np.random.permutation(n)
            X_shuffled = X[idx]
            epoch_loss = 0.0
            n_batches  = 0

            for i in range(0, n, batch_size):
                batch = X_shuffled[i:i+batch_size]
                loss  = self._train_step(batch, lr)
                epoch_loss += loss
                n_batches  += 1

            avg_loss = epoch_loss / max(n_batches, 1)
            losses.append(avg_loss)

            if epoch % 20 == 0:
                log.debug(f"CADE epoch {epoch}/{epochs} loss={avg_loss:.6f}")

        self.trained = True
        final_loss = losses[-1] if losses else 0
        log.info(f"CADE trained: {epochs} epochs, final loss={final_loss:.6f}")
        return losses

    def _train_step(self, batch: np.ndarray, lr: float) -> float:
        """Single gradient descent step."""
        # Forward
        h1_e   = batch @ self.W_e1 + self.b_e1
        a1_e   = self._relu(h1_e)
        h2_e   = a1_e @ self.W_e2 + self.b_e2
        z      = self._relu(h2_e)

        h1_d   = z @ self.W_d1 + self.b_d1
        a1_d   = self._relu(h1_d)
        x_hat  = a1_d @ self.W_d2 + self.b_d2

        # MSE loss
        diff   = x_hat - batch
        loss   = float(np.mean(diff ** 2))

        # Backward
        d_out  = 2 * diff / len(batch)

        # Decoder gradients
        dW_d2  = a1_d.T @ d_out
        db_d2  = d_out.sum(axis=0)
        d_a1_d = d_out @ self.W_d2.T
        d_h1_d = d_a1_d * self._relu_grad(h1_d)
        dW_d1  = z.T @ d_h1_d
        db_d1  = d_h1_d.sum(axis=0)

        # Encoder gradients
        d_z    = d_h1_d @ self.W_d1.T
        d_h2_e = d_z * self._relu_grad(h2_e)
        dW_e2  = a1_e.T @ d_h2_e
        db_e2  = d_h2_e.sum(axis=0)
        d_a1_e = d_h2_e @ self.W_e2.T
        d_h1_e = d_a1_e * self._relu_grad(h1_e)
        dW_e1  = batch.T @ d_h1_e
        db_e1  = d_h1_e.sum(axis=0)

        # Update weights
        self.W_e1 -= lr * dW_e1
        self.b_e1 -= lr * db_e1
        self.W_e2 -= lr * dW_e2
        self.b_e2 -= lr * db_e2
        self.W_d1 -= lr * dW_d1
        self.b_d1 -= lr * db_d1
        self.W_d2 -= lr * dW_d2
        self.b_d2 -= lr * db_d2

        return loss

    def reconstruction_error_per_feature(self, x: np.ndarray) -> np.ndarray:
        """
        Compute per-feature reconstruction error.
        High error on specific features = those features are drifting.
        """
        x_hat, _ = self.forward(x)
        return (x - x_hat) ** 2

    def save(self, path: str):
        """Save model weights."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        np.savez(
            path,
            W_e1=self.W_e1, b_e1=self.b_e1,
            W_e2=self.W_e2, b_e2=self.b_e2,
            W_d1=self.W_d1, b_d1=self.b_d1,
            W_d2=self.W_d2, b_d2=self.b_d2,
            trained=np.array([self.trained]),
        )

    def load(self, path: str):
        """Load model weights."""
        if not os.path.exists(path + ".npz"):
            return False
        data = np.load(path + ".npz")
        self.W_e1 = data["W_e1"]
        self.b_e1 = data["b_e1"]
        self.W_e2 = data["W_e2"]
        self.b_e2 = data["b_e2"]
        self.W_d1 = data["W_d1"]
        self.b_d1 = data["b_d1"]
        self.W_d2 = data["W_d2"]
        self.b_d2 = data["b_d2"]
        self.trained = bool(data["trained"][0])
        return True


def _cosine_distance(a: np.ndarray, b: np.ndarray) -> float:
    """Cosine distance between two vectors (0=identical, 1=orthogonal)."""
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a < 1e-8 or norm_b < 1e-8:
        return 0.0
    return float(1.0 - np.dot(a, b) / (norm_a * norm_b))


def _compute_adversarial_score(feature_deltas: np.ndarray) -> float:
    """
    Adversarial score based on feature drift concentration.

    Adversarial pattern: high distance in 1-3 features → high score
    Legitimate drift: moderate distance spread across features → low score

    Uses Gini coefficient — measures inequality of drift distribution.
    Gini=1: all drift in one feature (adversarial)
    Gini=0: drift equally spread (legitimate)
    """
    if feature_deltas.sum() < 1e-8:
        return 0.0

    # Normalize
    deltas = np.abs(feature_deltas)
    deltas = deltas / (deltas.sum() + 1e-8)
    deltas_sorted = np.sort(deltas)
    n = len(deltas_sorted)

    # Gini coefficient
    cumsum = np.cumsum(deltas_sorted)
    gini   = (n + 1 - 2 * cumsum.sum() / cumsum[-1]) / n
    return float(max(0.0, min(1.0, gini)))


class CADEDriftDetector:
    """
    CADE: Contrastive Autoencoder for Drift Explanation.

    Per entity:
    - Trains on first 14 days of behavioral windows (reference period)
    - Computes contrastive distance between current and reference
    - Identifies which features are drifting
    - Classifies drift as STABLE / ORGANIC / ADVERSARIAL

    Ghost Layer Technologies — CONFIDENTIAL
    """

    REFERENCE_DAYS    = 14
    REFERENCE_WINDOWS = REFERENCE_DAYS * 24 * 4  # 15-sec windows
    CHECK_EVERY       = 50    # Check drift every 50 windows
    ADVERSARIAL_THRESH = 0.85  # Gini > 0.85 = adversarial
    ORGANIC_THRESH     = 0.60  # Cosine dist > 0.6 = organic drift

    def __init__(self, entity_id: str,
                 feature_names: Optional[list[str]] = None):
        self.entity_id     = entity_id
        self.feature_names = feature_names or [f"f{i}" for i in range(17)]
        self.n_features    = len(self.feature_names)

        self.encoder       = ContrastiveAutoencoder(self.n_features)
        self.reference_embeddings: list[np.ndarray] = []
        self.current_windows: list[np.ndarray] = []
        self.window_count  = 0
        self.last_report:  Optional[DriftReport] = None

        # Try loading existing model
        model_path = os.path.join(
            MODELS_DIR, f"cade_{entity_id}"
        )
        self.encoder.load(model_path)
        self.model_path = model_path

    def add_window(self, feature_vector: dict[str, float]) -> Optional[DriftReport]:
        """
        Add a behavioral window.
        Returns DriftReport if drift detected, None otherwise.
        """
        vec = np.array(
            [feature_vector.get(f, 0.0) for f in self.feature_names],
            dtype=np.float32,
        )

        self.window_count += 1

        # Phase 1: Collect reference period
        if len(self.reference_embeddings) < self.REFERENCE_WINDOWS:
            self.reference_embeddings.append(vec)

            # Train autoencoder once reference period complete
            if len(self.reference_embeddings) == self.REFERENCE_WINDOWS:
                X_ref = np.array(self.reference_embeddings)
                self.encoder.train(X_ref, epochs=50)
                self.encoder.save(self.model_path)
                log.info(
                    f"CADE reference period complete for {self.entity_id} "
                    f"({self.REFERENCE_WINDOWS} windows)"
                )
            return None

        # Phase 2: Collect current window
        self.current_windows.append(vec)

        # Check drift periodically
        if len(self.current_windows) >= self.CHECK_EVERY:
            report = self._check_drift()
            self.current_windows = []  # Reset
            self.last_report = report
            return report

        return None

    def _check_drift(self) -> DriftReport:
        """
        Compare current behavioral distribution to reference.
        Returns DriftReport with classification.
        """
        if not self.encoder.trained:
            return DriftReport(
                type              = DriftType.STABLE,
                severity          = "info",
                contrastive_dist  = 0.0,
                adversarial_score = 0.0,
                drifting_features = [],
                recommendation    = "CADE not yet trained",
            )

        X_current = np.array(self.current_windows, dtype=np.float32)
        X_ref     = np.array(self.reference_embeddings[-self.CHECK_EVERY:],
                             dtype=np.float32)

        # Get latent representations
        z_current = self.encoder.encode(X_current).mean(axis=0)
        z_ref     = self.encoder.encode(X_ref).mean(axis=0)

        # Contrastive distance
        contrastive_dist = _cosine_distance(z_current, z_ref)

        # Per-feature reconstruction errors
        err_current = self.encoder.reconstruction_error_per_feature(X_current).mean(axis=0)
        err_ref     = self.encoder.reconstruction_error_per_feature(X_ref).mean(axis=0)
        feature_deltas = np.abs(err_current - err_ref)

        # Adversarial score
        adversarial_score = _compute_adversarial_score(feature_deltas)

        # Top drifting features
        top_idx = np.argsort(feature_deltas)[::-1][:5]
        drifting_features = [self.feature_names[i] for i in top_idx
                             if feature_deltas[i] > 1e-6]

        # Classify
        if adversarial_score > self.ADVERSARIAL_THRESH:
            drift_type    = DriftType.ADVERSARIAL
            severity      = "high"
            recommendation = (
                f"ADVERSARIAL BASELINE POISONING DETECTED — "
                f"manual review required. "
                f"Drifting features: {drifting_features[:3]}"
            )
            log.critical(
                f"CADE ADVERSARIAL DRIFT [{self.entity_id}] "
                f"score={adversarial_score:.3f} "
                f"features={drifting_features[:3]}"
            )
        elif contrastive_dist > self.ORGANIC_THRESH:
            drift_type    = DriftType.ORGANIC
            severity      = "info"
            recommendation = "Organic behavioral drift — monitor"
            log.info(
                f"CADE organic drift [{self.entity_id}] "
                f"dist={contrastive_dist:.3f}"
            )
        else:
            drift_type    = DriftType.STABLE
            severity      = "info"
            recommendation = "Baseline stable"

        return DriftReport(
            type              = drift_type,
            severity          = severity,
            contrastive_dist  = contrastive_dist,
            adversarial_score = adversarial_score,
            drifting_features = drifting_features,
            recommendation    = recommendation,
        )

    def force_check(self) -> Optional[DriftReport]:
        """Force a drift check with current windows."""
        if not self.current_windows:
            return None
        return self._check_drift()
