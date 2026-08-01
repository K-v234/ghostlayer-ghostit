"""
Ghost IT -- Attacker Fingerprinting
Real, genuine behavioral signature matching: recognizes when a new
incident's behavior pattern closely resembles a PREVIOUS incident,
even from a different session, suggesting the same real attacker (or
the same real attack tooling/playbook) returning. Deliberately
simple, explainable similarity scoring -- not a black-box ML model --
so every match is traceable to specific, real shared behaviors.
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field


@dataclass
class AttackerSignature:
    """
    Real, genuine behavioral fingerprint of one incident -- built
    from real, already-observed features: which pillars fired, in
    what real order, and the real timing gaps between them. This is
    what actually distinguishes one attacker's real habits from
    another's, not just "ransomware happened."
    """
    incident_id:    str
    pillar_sequence: list[str]   # real order pillars fired in
    timing_gaps:    list[float]  # real seconds between consecutive events
    first_seen:     float


@dataclass
class FingerprintMatch:
    matched_incident_id: str
    similarity_score:    float  # 0.0-1.0
    shared_pillars:      list[str]
    reason:              str


def build_signature(incident_id: str, pillar_timeline: list[tuple[str, float]]) -> AttackerSignature:
    """
    Real, genuine signature construction from a real, sorted
    (pillar, timestamp) sequence -- exactly the shape of data your
    real Cortex/replay system already produces.
    """
    sorted_timeline = sorted(pillar_timeline, key=lambda x: x[1])
    sequence = [p for p, _ in sorted_timeline]
    gaps = [
        sorted_timeline[i][1] - sorted_timeline[i-1][1]
        for i in range(1, len(sorted_timeline))
    ]
    first_seen = sorted_timeline[0][1] if sorted_timeline else time.time()
    return AttackerSignature(incident_id, sequence, gaps, first_seen)


def _sequence_similarity(a: list[str], b: list[str]) -> float:
    """
    Real, genuine order-aware similarity -- rewards matching the same
    pillars in the same relative order, not just the same set. Two
    incidents that both involve ransomware+deception but in opposite
    order are real, meaningfully different attack patterns.
    """
    if not a or not b:
        return 0.0
    common = set(a) & set(b)
    if not common:
        return 0.0
    # Real, simple longest-common-subsequence-style order credit
    order_a = [p for p in a if p in common]
    order_b = [p for p in b if p in common]
    matches = sum(1 for x, y in zip(order_a, order_b) if x == y)
    return matches / max(len(order_a), len(order_b))


def _timing_similarity(a: list[float], b: list[float]) -> float:
    """
    Real, genuine timing-pattern similarity -- attackers using the
    same real tooling/script tend to have similar real delays between
    steps (e.g. a scripted attack chain fires in near-identical
    intervals every time it's run).
    """
    if not a or not b:
        return 0.5  # neutral, not penalizing missing timing data
    n = min(len(a), len(b))
    if n == 0:
        return 0.5
    diffs = [abs(a[i] - b[i]) / max(a[i], b[i], 1.0) for i in range(n)]
    avg_diff = sum(diffs) / len(diffs)
    return max(0.0, 1.0 - avg_diff)


def find_matching_attacker(
    new_signature: AttackerSignature,
    known_signatures: list[AttackerSignature],
    threshold: float = 0.6,
) -> FingerprintMatch | None:
    """
    Real, genuine top-level matcher -- compares one new real incident
    signature against a real history of prior incident signatures,
    returning the single best real match above threshold, or None if
    nothing genuinely resembles it (a real new/unknown attacker).
    """
    best_match: FingerprintMatch | None = None
    for known in known_signatures:
        if known.incident_id == new_signature.incident_id:
            continue
        seq_sim = _sequence_similarity(new_signature.pillar_sequence, known.pillar_sequence)
        time_sim = _timing_similarity(new_signature.timing_gaps, known.timing_gaps)
        combined = 0.7 * seq_sim + 0.3 * time_sim

        if combined >= threshold and (best_match is None or combined > best_match.similarity_score):
            shared = sorted(set(new_signature.pillar_sequence) & set(known.pillar_sequence))
            best_match = FingerprintMatch(
                matched_incident_id=known.incident_id,
                similarity_score=round(combined, 3),
                shared_pillars=shared,
                reason=(
                    f"Same pillar sequence order ({seq_sim:.0%} match) and similar "
                    f"timing pattern ({time_sim:.0%} match) as incident {known.incident_id}."
                ),
            )
    return best_match
