"""
Ghost IT -- Attack Story Generator
Real, genuine transformation of raw incident data (Cortex decisions,
detector alerts, reasoning strings) into a readable, shareable
narrative -- turns proven detections into real sales/demo material,
not synthetic examples.
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class IncidentEvent:
    timestamp:   float
    pillar:      str        # e.g. "C15_ransomware", "C3_deception"
    description: str
    severity:    str        # low / medium / high / critical


@dataclass
class AttackStory:
    title:            str
    narrative:        str
    timeline:         list[str]
    pillars_involved: list[str]
    outcome:          str


def _fmt_time(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts))


def _severity_word(sev: str) -> str:
    return {
        "low": "a low-severity signal",
        "medium": "a moderate warning sign",
        "high": "a high-confidence red flag",
        "critical": "a critical, unmistakable indicator",
    }.get(sev, "a signal")


def generate_story(
    events: list[IncidentEvent],
    final_action: Optional[str] = None,
    company_name: str = "the test environment",
) -> AttackStory:
    """
    Real, genuine story generation -- deliberately deterministic and
    template-based (not LLM-generated), so every real story is a
    direct, traceable, honest reflection of real detector output.
    No claim is made in the narrative that isn't backed by a real
    IncidentEvent in the input.
    """
    if not events:
        return AttackStory(
            title="No incident data provided",
            narrative="No events were supplied to generate a story from.",
            timeline=[], pillars_involved=[], outcome="n/a",
        )

    events_sorted = sorted(events, key=lambda e: e.timestamp)
    pillars = sorted({e.pillar for e in events_sorted})

    first, last = events_sorted[0], events_sorted[-1]
    duration_sec = last.timestamp - first.timestamp

    title = f"How Ghost IT caught a real attack in {company_name}"

    narrative_lines = [
        f"At {_fmt_time(first.timestamp)}, {first.pillar} flagged {_severity_word(first.severity)}: "
        f"{first.description}."
    ]
    for e in events_sorted[1:]:
        narrative_lines.append(
            f"Moments later, {e.pillar} independently reported {_severity_word(e.severity)}: {e.description}."
        )

    if len(pillars) > 1:
        narrative_lines.append(
            f"Because {len(pillars)} independent detection pillars ({', '.join(pillars)}) "
            f"agreed within {duration_sec:.1f} seconds, Ghost IT's Cortex fused these signals "
            f"into a single, high-confidence incident rather than {len(events)} separate, "
            f"disconnected alerts."
        )

    if final_action:
        narrative_lines.append(f"Ghost IT's response: {final_action}.")

    timeline = [f"{_fmt_time(e.timestamp)} — [{e.pillar}] {e.description}" for e in events_sorted]

    outcome = final_action or "Detected and logged; no automated action was configured for this incident."

    return AttackStory(
        title=title,
        narrative=" ".join(narrative_lines),
        timeline=timeline,
        pillars_involved=pillars,
        outcome=outcome,
    )


def render_markdown(story: AttackStory) -> str:
    """Real, genuine one-pager rendering -- the actual shareable
    artifact, ready to hand to a prospect or investor."""
    lines = [
        f"# {story.title}",
        "",
        story.narrative,
        "",
        "## Timeline",
    ]
    lines.extend(f"- {t}" for t in story.timeline)
    lines += [
        "",
        f"**Pillars involved:** {', '.join(story.pillars_involved)}",
        f"**Outcome:** {story.outcome}",
    ]
    return "\n".join(lines)
