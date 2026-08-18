"""
pipeline.py
End-to-end pipeline: parsed logs -> embeddings -> per-user anomaly detection
-> incident grouping -> MITRE-mapped LLM narrative.

Orchestration only -- no detection or mapping logic lives here.

Usage:
    python src/pipeline.py --input data/processed/parsed.csv --no-llm
    python src/pipeline.py --input data/processed/parsed.csv --output data/processed/incidents.json
"""

import argparse
import json
import pandas as pd

from embedding import add_embeddings_to_df
from anomaly_detection import run_anomaly_detection, highest_severity
from sequence_grouping import group_anomalies, describe_incident
from mitre_mapping import map_incident_to_mitre
from llm_narrative import generate_narrative
from config import NARRATE_SEVERITIES, NARRATE_MIN_EVENTS


def should_narrate(severity: str, event_count: int) -> bool:
    """Narrative budget policy -- see NARRATE_* in config.py for the rationale."""
    return severity in NARRATE_SEVERITIES or event_count >= NARRATE_MIN_EVENTS


def build_incident_entry(incident_id: int, incident: pd.DataFrame) -> dict:
    """Everything about an incident that doesn't need the LLM."""
    techniques = map_incident_to_mitre(incident)
    return {
        "incident_id": incident_id,
        "summary": describe_incident(incident),
        "users": sorted({str(u) for u in incident["user"].dropna()}),
        "source_ips": sorted({str(p) for p in incident["source_ip"].dropna()}),
        "start": str(incident["timestamp"].min()),
        "end": str(incident["timestamp"].max()),
        "event_count": len(incident),
        "severity": highest_severity(incident["severity"]),
        "mitre_techniques": [
            {"technique_id": t["technique_id"], "technique_name": t["technique_name"],
             "tactic": t["tactic"]}
            for t in techniques
        ],
        # fillna before astype(str), or missing cells serialise as the string "nan"
        "events": incident[["timestamp", "user", "source_ip", "message"]]
                  .astype(object).where(incident[["timestamp", "user", "source_ip", "message"]].notna(), "")
                  .astype(str).to_dict(orient="records"),
    }


def run_pipeline(input_csv: str, output_json: str, use_llm: bool = True,
                 narrate_all: bool = False):
    df = pd.read_csv(input_csv, parse_dates=["timestamp"])
    print(f"Loaded {len(df)} parsed log rows")

    df = add_embeddings_to_df(df, template_col="template")
    print("Embeddings generated")

    scored = run_anomaly_detection(df)
    print(f"Flagged {scored['is_anomaly'].sum()} anomalous rows out of {len(scored)} "
          f"({scored['impossible_travel'].sum()} via impossible-travel)")

    incidents = group_anomalies(scored)
    print(f"Grouped into {len(incidents)} incidents "
          f"({sum(1 for i in incidents if len(i) > 1)} multi-event)")

    results = [build_incident_entry(i, inc) for i, inc in enumerate(incidents)]

    if use_llm:
        targets = [e for e in results
                   if narrate_all or should_narrate(e["severity"], e["event_count"])]
        print(f"Narrating {len(targets)} of {len(results)} incidents "
              f"({'all' if narrate_all else 'severity in ' + str(sorted(NARRATE_SEVERITIES)) + f' or >={NARRATE_MIN_EVENTS} events'})")

        for n, entry in enumerate(targets, start=1):
            print(f"  [{n}/{len(targets)}] incident {entry['incident_id']} "
                  f"({entry['severity']}, {entry['event_count']} events)...", flush=True)
            try:
                entry["narrative"] = generate_narrative(incidents[entry["incident_id"]])
            except Exception as e:
                entry["narrative"] = f"[LLM narrative generation failed: {e}]"

        for entry in results:
            entry.setdefault("narrative", None)

    with open(output_json, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Wrote {len(results)} incidents -> {output_json}")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the full log anomaly detection pipeline.")
    parser.add_argument("--input", required=True, help="Parsed log CSV (from preprocessing.py)")
    parser.add_argument("--output", default="data/processed/incidents.json")
    parser.add_argument("--no-llm", action="store_true", help="Skip LLM narrative generation")
    parser.add_argument("--narrate-all", action="store_true",
                        help="Narrate every incident, ignoring the NARRATE_* budget policy (slow)")
    args = parser.parse_args()

    run_pipeline(args.input, args.output, use_llm=not args.no_llm,
                 narrate_all=args.narrate_all)
