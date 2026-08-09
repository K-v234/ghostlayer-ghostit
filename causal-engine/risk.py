
"""

Ghost IT -- Risk scoring (Week 2 Cortex split, part 1 of 3)



Wraps Cortex.contribute(): takes one piece of evidence about an

entity and returns the fused risk score for that entity across all

evidence contributed so far. Deliberately just a thin wrapper around

the existing, proven Cortex fusion logic -- this split separates

*what the score is* from *what we do about it* (decision.py) and

*how signals connect across entities* (correlation.py), without

changing any scoring behavior.

"""

from __future__ import annotations





def compute_risk(pid: int, pillar: str, reason: str) -> dict:

    """Returns the same dict shape Cortex.contribute() already

    returns: entity_id, score, distinct_pillars, pillars,

    contributions."""

    from cortex import Cortex, CortexContribution

    cortex = Cortex()

    return cortex.contribute(CortexContribution(f"pid:{pid}", pillar, reason))

