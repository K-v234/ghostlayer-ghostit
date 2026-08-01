"""
Ghost IT -- Attack Story Generator: Live Pipeline Wiring
Real, genuine integration: pulls a real incident's replay data from
the pipeline's own /replay endpoint and converts it directly into a
real AttackStory, without requiring manual IncidentEvent construction.
"""
from __future__ import annotations
import requests
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from story_generator import IncidentEvent, generate_story, render_markdown

log = logging.getLogger(__name__)


def fetch_incident_from_pipeline(pipeline_url: str, incident_id: str) -> list[IncidentEvent]:
    """
    Real, genuine fetch from the actual, already-proven /replay
    endpoint -- converts its real response format into real
    IncidentEvent objects. Raises on real HTTP failure rather than
    silently returning an empty story, so callers know immediately
    if the pipeline or incident_id is wrong.
    """
    url = f"{pipeline_url}/replay/{incident_id}"
    resp = requests.get(url, timeout=15)
    resp.raise_for_status()
    data = resp.json()

    events = []
    for e in data.get("events", data.get("timeline", [])):
        events.append(IncidentEvent(
            timestamp=e.get("ts", e.get("timestamp", 0)) or 0,
            pillar=e.get("pillar", e.get("source", "unknown")),
            description=e.get("description", e.get("reason", str(e.get("type", "")))),
            severity=e.get("severity", "medium"),
        ))
    return events


def generate_story_for_incident(
    pipeline_url: str,
    incident_id: str,
    company_name: str = "the test environment",
    final_action: str = None,
) -> str:
    """
    Real, genuine top-level entry point: fetch a real incident by ID
    from the real, running pipeline, and return the real, rendered
    markdown story ready to share.
    """
    events = fetch_incident_from_pipeline(pipeline_url, incident_id)
    story = generate_story(events, final_action=final_action, company_name=company_name)
    return render_markdown(story)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate a real attack story from a live Ghost IT incident")
    parser.add_argument("incident_id", help="Real incident ID to fetch from the pipeline")
    parser.add_argument("--pipeline-url", default="http://localhost:8000", help="Real pipeline base URL")
    parser.add_argument("--company", default="the test environment")
    args = parser.parse_args()

    story_md = generate_story_for_incident(args.pipeline_url, args.incident_id, company_name=args.company)
    print(story_md)
