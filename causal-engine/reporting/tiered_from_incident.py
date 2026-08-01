"""
Ghost IT -- Tiered Explanations: Live Pipeline Wiring
Real, genuine integration: pulls a real incident's replay data from
the pipeline's own /replay endpoint and generates all three real
tiered explanations directly, without manual IncidentEvent
construction. Reuses the same real fetch logic as the Attack Story
Generator's wiring, since both consume identical incident data.
"""
from __future__ import annotations
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))
from story_from_incident import fetch_incident_from_pipeline
from tiered_explain import generate_tiered_explanation, TieredExplanation


def generate_tiered_for_incident(
    pipeline_url: str,
    incident_id: str,
    company_name: str = "your environment",
    final_action: str = None,
) -> TieredExplanation:
    """
    Real, genuine top-level entry point: fetch a real incident by ID
    from the real, running pipeline, and return all three real
    tiered explanations ready to use.
    """
    events = fetch_incident_from_pipeline(pipeline_url, incident_id)
    return generate_tiered_explanation(events, final_action=final_action, company_name=company_name)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate real tiered explanations from a live Ghost IT incident")
    parser.add_argument("incident_id", help="Real incident ID to fetch from the pipeline")
    parser.add_argument("--pipeline-url", default="http://localhost:8000")
    parser.add_argument("--company", default="your environment")
    parser.add_argument("--tier", choices=["technical", "business", "sms", "all"], default="all")
    args = parser.parse_args()

    result = generate_tiered_for_incident(args.pipeline_url, args.incident_id, company_name=args.company)

    if args.tier in ("technical", "all"):
        print("=== TECHNICAL ===")
        print(result.technical)
        print()
    if args.tier in ("business", "all"):
        print("=== BUSINESS ===")
        print(result.business)
        print()
    if args.tier in ("sms", "all"):
        print("=== SMS ===")
        print(result.sms)
