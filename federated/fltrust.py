#!/usr/bin/env python3
"""
Ghost IT — V2: C10 Federated Collective Intelligence (FLTrust)
Byzantine-robust gradient aggregation for federated learning across
Ghost IT deployments. No raw customer data ever leaves customer
premises -- only model gradients are shared, and those are
differentially private.

Architecture note: this is genuine, correct scaffolding for the
FLTrust mechanism, buildable and testable in isolation now. Full
end-to-end validation requires real gradient diversity from multiple
independent, genuinely different customer deployments -- which
doesn't exist yet (zero pilot customers as of this writing). Building
this now means it's ready to activate the moment real deployments
exist, rather than starting from scratch then.
"""
from __future__ import annotations
import numpy as np
import logging

log = logging.getLogger(__name__)

def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Standard cosine similarity between two gradient vectors."""
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))

def clip_by_norm(gradient: np.ndarray, max_norm: float = 1.0) -> np.ndarray:
    """Clip a gradient's L2 norm -- required before adding DP noise,
    since unbounded gradients could leak more information than the
    noise budget accounts for."""
    norm = np.linalg.norm(gradient)
    if norm > max_norm:
        return gradient * (max_norm / norm)
    return gradient

def apply_differential_privacy(gradient: np.ndarray, sensitivity: float = 1.0,
                                epsilon: float = 0.1, delta: float = 1e-5) -> np.ndarray:
    """
    Per Tech Spec section on C10: each client adds Gaussian noise
    before uploading its gradient, so individual client behavior
    cannot be reconstructed from the aggregated update. epsilon=0.1
    (tight privacy budget, per Tech Spec's documented choice).
    """
    clipped = clip_by_norm(gradient, sensitivity)
    sigma = sensitivity * np.sqrt(2 * np.log(1.25 / delta)) / epsilon
    noise = np.random.normal(0, sigma, size=clipped.shape)
    return clipped + noise

def fltrust_aggregate(client_gradients: list[np.ndarray],
                       reference_gradient: np.ndarray) -> np.ndarray:
    """
    FLTrust Byzantine-robust aggregation (Cao et al., NDSS 2021).

    Each client's gradient is scored by cosine similarity to a trusted
    reference gradient (trained on a known-good dataset the server
    controls). A malicious/poisoned gradient pointing in a very
    different direction gets a low or negative score, clipped to 0 --
    it contributes nothing to the final aggregate. This is what
    protects the federated model from any single compromised or
    malicious customer deployment poisoning the shared model.

    Raises SecurityError if ALL clients score 0 (indicates either a
    coordinated attack, or the reference gradient itself is stale/wrong
    and needs review).
    """
    scores = [max(0.0, cosine_similarity(g, reference_gradient)) for g in client_gradients]
    total = sum(scores)
    if total == 0:
        raise SecurityError(
            "All client gradients scored 0 against reference -- "
            "refusing to aggregate. Either a coordinated poisoning "
            "attempt, or the reference gradient needs review."
        )
    weights = [s / total for s in scores]
    aggregated = sum(w * g for w, g in zip(weights, client_gradients))
    log.info(f"FLTrust aggregated {len(client_gradients)} client gradients, "
              f"weights: {[round(w, 3) for w in weights]}")
    return aggregated

class SecurityError(Exception):
    pass

if __name__ == "__main__":
    # Self-test with synthetic gradients: 3 "good" clients pointing
    # roughly the same direction as reference, 1 "malicious" client
    # pointing in a very different direction.
    logging.basicConfig(level=logging.INFO)
    np.random.seed(42)

    reference = np.array([1.0, 0.5, 0.2, 0.0])
    good_clients = [
        reference + np.random.normal(0, 0.05, size=4) for _ in range(3)
    ]
    malicious_client = -reference + np.random.normal(0, 0.1, size=4)  # opposite direction

    all_clients = good_clients + [malicious_client]
    print("Testing FLTrust aggregation with 3 good clients + 1 malicious...")
    result = fltrust_aggregate(all_clients, reference)
    print(f"Aggregated result: {result}")
    print(f"Reference:         {reference}")
    print(f"Cosine sim to reference: {cosine_similarity(result, reference):.3f} "
          f"(should be high -- malicious client's influence was down-weighted)")

    print("\\nTesting differential privacy noise addition...")
    noisy = apply_differential_privacy(good_clients[0])
    print(f"Original: {good_clients[0]}")
    print(f"Noisy:    {noisy}")
