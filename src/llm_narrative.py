"""
llm_narrative.py
Feeds a grouped anomaly incident (+ its retrieved MITRE technique matches)
to a local LLM (via Ollama) and asks it to produce a plain-English attack
narrative. The prompt is retrieval-grounded: the LLM is given the actual
MITRE matches found via mitre_mapping.py, not asked to invent technique IDs
from scratch -- this reduces hallucination and should be called out
explicitly in your report as a design decision.

Requires Ollama running locally: https://ollama.com
    ollama serve
    ollama pull phi3
"""

import pandas as pd
import requests

from mitre_mapping import map_incident_to_mitre
from config import (OLLAMA_URL, LLM_MODEL, LLM_TIMEOUT_SECONDS, LLM_NUM_PREDICT,
                    LLM_TEMPERATURE, NARRATIVE_SENTENCE_RANGE, NARRATIVE_MAX_EVENTS)

PROMPT_TEMPLATE = """You are a SOC analyst assistant. Below is a sequence of anomalous log events
from a single incident, along with MITRE ATT&CK techniques that were matched
by a grounded lookup table.

Incident summary:
{summary}

Incident events (chronological):
{events}

Matched MITRE ATT&CK techniques (grounded lookup, do not invent new ones):
{mitre_matches}

Write a concise ({sentences} sentence) narrative explaining:
1. What likely happened, in plain English, in chronological order
2. Which MITRE ATT&CK stage(s) this incident progresses through
3. A confidence level (Low/Medium/High) and brief justification
4. One recommended next action for the analyst

Only reference technique IDs listed above. Do not invent new ones.
"""


def _field(value) -> str | None:
    """Readable field value, or None when the parser found nothing.

    Missing cells must never reach the prompt as the literal string "nan":
    phi3 treats it as a real value and invents detail around it (an early run
    produced "escalated to root using 'nan'").
    """
    if value is None or pd.isna(value):
        return None
    text = str(value).strip()
    return None if text.lower() in {"", "nan", "none", "unknown"} else text


def summarise_incident(incident_df: pd.DataFrame) -> str:
    """Compact factual header: who, where, when, how many events.

    Enumeration incidents hit a different username on every line, so the
    per-line events alone read as noise -- the LLM needs the aggregate view to
    tell "one attacker probing many accounts" from "many unrelated failures".
    """
    users = sorted({u for u in map(_field, incident_df.get("user", [])) if u})
    ips = sorted({p for p in map(_field, incident_df.get("source_ip", [])) if p})
    times = pd.to_datetime(incident_df["timestamp"])

    lines = [
        f"- {len(incident_df)} anomalous events from {times.min()} to {times.max()}",
        f"- Distinct usernames involved ({len(users)}): {', '.join(users) or 'n/a'}",
        f"- Distinct source IPs ({len(ips)}): {', '.join(ips) or 'n/a'}",
    ]
    if "impossible_travel" in incident_df.columns and incident_df["impossible_travel"].any():
        lines.append("- Flagged by the impossible-travel physics check")
    return "\n".join(lines)


def format_incident_for_prompt(incident_df: pd.DataFrame) -> tuple[str, str]:
    """Return (events_block, mitre_block) for the prompt."""
    shown = incident_df.head(NARRATIVE_MAX_EVENTS)
    event_lines = []
    for _, row in shown.iterrows():
        # omit fields entirely when absent rather than showing a placeholder
        parts = [f"- [{row['timestamp']}]"]
        user, src = _field(row.get("user")), _field(row.get("source_ip"))
        if user:
            parts.append(f"user={user}")
        if src:
            parts.append(f"src={src}")
        parts.append(f": {row['message']}")
        event_lines.append(" ".join(parts))
    events_str = "\n".join(event_lines)
    if len(incident_df) > len(shown):
        events_str += f"\n- ... and {len(incident_df) - len(shown)} further similar events"

    matches = map_incident_to_mitre(incident_df)
    mitre_str = "\n".join(
        f"- {m['technique_id']} ({m['technique_name']}) - {m['tactic']}"
        + (f" [{m['evidence']}]" if "evidence" in m else "")
        for m in matches
    ) or "- No known technique matched; treat as a novel/unclassified anomaly."

    return events_str, mitre_str


def generate_narrative(incident_df: pd.DataFrame, model: str = LLM_MODEL) -> str:
    events_str, mitre_str = format_incident_for_prompt(incident_df)
    prompt = PROMPT_TEMPLATE.format(
        summary=summarise_incident(incident_df),
        events=events_str,
        mitre_matches=mitre_str,
        sentences=NARRATIVE_SENTENCE_RANGE,
    )

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": LLM_NUM_PREDICT,
                "temperature": LLM_TEMPERATURE,
            },
        },
        timeout=LLM_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json().get("response", "").strip()


if __name__ == "__main__":
    # smoke test (requires Ollama running locally)
    sample = pd.DataFrame({
        "timestamp": pd.to_datetime(["2026-07-18 10:00:00", "2026-07-18 10:02:00",
                                     "2026-07-18 10:10:00", "2026-07-18 10:12:00"]),
        "user": ["alice", "alice", "alice", "alice"],
        "source_ip": ["203.0.113.5"] * 4,
        "impossible_travel": [False] * 4,
        "message": [
            "Failed password for alice from 203.0.113.5 port 51422 ssh2",
            "Failed password for alice from 203.0.113.5 port 51423 ssh2",
            "Accepted password for alice from 203.0.113.5 port 51430 ssh2",
            "sudo: alice : COMMAND=/bin/su root",
        ],
    })
    events, mitre = format_incident_for_prompt(sample)
    print("Grounded techniques passed to the LLM:")
    print(mitre, "\n")
    try:
        print(generate_narrative(sample))
    except requests.exceptions.ConnectionError:
        print("Ollama not running locally -- start it with `ollama serve` and `ollama pull phi3`.")
