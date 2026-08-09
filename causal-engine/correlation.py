
"""

Ghost IT -- Cross-entity correlation (Week 2 Cortex split, part 2 of 3)



Wraps the Curiosity Engine (checks whether an entity has entered the

genuine ambiguous middle worth investigating further) and World-Model

observation (records that this entity exists and is active, feeding

the graph other subsystems use for blast-radius/criticality checks).

Both are about *connecting this evidence to the wider picture*, not

about scoring or deciding -- kept together here for that reason.

"""

from __future__ import annotations

import logging



log = logging.getLogger(__name__)





def check_curiosity(pid: int, pillar: str, score: float, distinct_pillars: int) -> None:

    from curiosity_engine import should_investigate, build_investigation_plan

    try:

        if should_investigate(score, distinct_pillars):

            plan = build_investigation_plan(f"pid:{pid}", pillar, score)

            log.info(f"[Curiosity] Investigation triggered for pid:{pid}: {plan['reasoning']}")

    except Exception as ex:

        log.debug(f"Curiosity engine error: {ex}")





def observe_world_model(pid: int, pillar: str) -> None:

    from world_model import WorldModel

    try:

        WorldModel().observe(f"pid:{pid}", "unknown", pillar, event_type="cortex_contribution")

    except Exception as ex:

        log.debug(f"World-model observe error: {ex}")

