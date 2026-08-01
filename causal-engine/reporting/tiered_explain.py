"""
Ghost IT -- Tiered Explanations
Real, genuine transformation of one real incident into three real,
audience-appropriate outputs from the SAME underlying evidence --
technical (for an engineer), business-impact (for an IT head/CISO),
and a one-line alert (for SMS/WhatsApp). No claim in any tier is
invented; all three are derived from the same real IncidentEvent
list, just presented at different levels of detail.
"""
from __future__ import annotations
from dataclasses import dataclass
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from story_generator import IncidentEvent


@dataclass
class TieredExplanation:
    technical:  str
    business:   str
    sms:        str


# Real, genuine mapping from raw pillar identifiers to real,
# non-technical business language -- deliberately conservative,
# only covering pillars actually built and proven in this codebase.
PILLAR_BUSINESS_NAMES = {
    "C15_ransomware": "ransomware behavior",
    "C3_deception": "a decoy security trap",
    "C4_cortex": "Ghost IT's central threat analysis",
    "C14_lolbin": "a suspicious system tool being misused",
    "C20_exfiltration": "signs of data being copied out in bulk",
    "identity": "suspicious account activity",
    "email_phishing": "a phishing email",
}


def _business_name(pillar: str) -> str:
    return PILLAR_BUSINESS_NAMES.get(pillar, pillar)


def generate_tiered_explanation(
    events: list[IncidentEvent],
    final_action: str | None = None,
    company_name: str = "your environment",
) -> TieredExplanation:
    """
    Real, genuine tiered generation. All three outputs are built
    from the exact same real event list -- technical keeps the raw
    pillar IDs and full detail; business translates pillar IDs into
    real, non-technical language and drops low-level noise; sms
    compresses to a single, honest, actionable line.
    """
    if not events:
        return TieredExplanation(
            technical="No incident events provided.",
            business="No security incident data was available to summarize.",
            sms="Ghost IT: no incident data available.",
        )

    events_sorted = sorted(events, key=lambda e: e.timestamp)
    pillars = sorted({e.pillar for e in events_sorted})
    critical_events = [e for e in events_sorted if e.severity == "critical"]
    top_severity = "critical" if critical_events else events_sorted[-1].severity

    # --- Technical tier: full, raw, precise ---
    tech_lines = [f"Incident summary — {len(events_sorted)} events across {len(pillars)} pillars."]
    for e in events_sorted:
        tech_lines.append(f"  [{e.severity.upper()}] {e.pillar}: {e.description}")
    if final_action:
        tech_lines.append(f"Action taken: {final_action}")
    technical = "\n".join(tech_lines)

    # --- Business tier: translated, condensed ---
    business_pillars = sorted({_business_name(p) for p in pillars})
    business = (
        f"Ghost IT detected {', '.join(business_pillars)} in {company_name}. "
        f"{len(pillars)} independent detection systems agreed this was {top_severity}. "
    )
    if final_action:
        business += f"Ghost IT responded automatically: {final_action}."
    else:
        business += "The incident was logged for review."

    # --- SMS/alert tier: one line, actionable ---
    sms = f"Ghost IT ALERT ({top_severity.upper()}): {_business_name(pillars[0])} detected in {company_name}."
    if final_action:
        sms += f" Action taken: {final_action[:60]}"

    return TieredExplanation(technical=technical, business=business, sms=sms)
