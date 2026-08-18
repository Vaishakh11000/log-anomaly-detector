"""
dashboard.py
Streamlit dashboard: triage view over detected incidents, with the
LLM-generated attacker narrative and mapped MITRE ATT&CK techniques.

Design note -- this is a *triage* view, not an alert list. The detector runs at
CONTAMINATION=0.20, which deliberately favours recall: on the synthetic corpus
that means ~94 incidents of which 9 are real attacks. Showing all 94 in
timestamp order (the original behaviour) put a singleton false positive at the
top of the screen and buried every real attack. So the default view is ranked
and filtered to the notable set, with an explicit escape hatch to see
everything -- the false positives are not hidden, they are ordered last.

Run with:
    streamlit run src/dashboard.py
"""

import json

import pandas as pd
import streamlit as st

from config import NARRATE_MIN_EVENTS, NARRATE_SEVERITIES

st.set_page_config(page_title="LLM Log Anomaly Detector", layout="wide")

SEVERITY_ICON = {"high": "🔴", "medium": "🟠", "low": "🟡"}
SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "none": 0}


def is_notable(incident: dict) -> bool:
    """Same policy the pipeline uses to decide what gets a narrative
    (pipeline.should_narrate) -- kept in sync via the NARRATE_* config values
    so the dashboard's default view matches what was actually narrated."""
    return (incident.get("severity") in NARRATE_SEVERITIES
            or incident.get("event_count", 0) >= NARRATE_MIN_EVENTS)


def triage_key(incident: dict):
    """Rank corroborated incidents above loud single lines.

    Event count leads: a multi-event incident is several independent signals
    about the same actor, which is stronger evidence than one line with an
    extreme anomaly score. Severity breaks ties.
    """
    return (incident.get("event_count", 0),
            SEVERITY_RANK.get(incident.get("severity"), 0))


st.title("🛡️ LLM-Powered Log Anomaly Detector")
st.caption("Embedding-based anomaly detection with attacker narrative reconstruction "
           "(grounded in MITRE ATT&CK)")

incidents_path = st.sidebar.text_input("Incidents JSON path", "data/processed/incidents.json")

try:
    with open(incidents_path) as f:
        incidents = json.load(f)
except FileNotFoundError:
    st.warning(f"No incidents file found at `{incidents_path}`. Run `src/pipeline.py` first.")
    st.stop()
except json.JSONDecodeError as e:
    st.error(f"`{incidents_path}` is not valid JSON: {e}")
    st.stop()

notable = [i for i in incidents if is_notable(i)]
narrated = [i for i in incidents if i.get("narrative")]

# --- Headline counts -------------------------------------------------------
c1, c2, c3, c4 = st.columns(4)
c1.metric("Incidents", len(incidents))
c2.metric("High severity", sum(1 for i in incidents if i.get("severity") == "high"))
c3.metric("Notable", len(notable), help="High severity, or more than one correlated event")
c4.metric("Narrated", len(narrated), help="Incidents with an LLM-generated narrative")

# --- Filters ---------------------------------------------------------------
st.sidebar.markdown("### View")
show_all = st.sidebar.checkbox(
    f"Show all {len(incidents)} incidents", value=False,
    help="Off by default: the detector favours recall, so most single-event "
         "incidents are false positives. They are ranked last, not hidden.")

severities = st.sidebar.multiselect(
    "Severity", ["high", "medium", "low"], default=["high", "medium", "low"])

users = sorted({u for i in incidents for u in i.get("users", [])})
selected_user = st.sidebar.selectbox("Filter by user", ["All"] + users)

only_mitre = st.sidebar.checkbox("Only incidents with MITRE techniques", value=False)

pool = incidents if show_all else notable
filtered = [
    i for i in pool
    if i.get("severity") in severities
    and (selected_user == "All" or selected_user in i.get("users", []))
    and (not only_mitre or i.get("mitre_techniques"))
]
filtered.sort(key=triage_key, reverse=True)

st.markdown(f"**Showing {len(filtered)} of {len(incidents)} incidents**, "
            "highest-corroboration first.")
if not show_all and len(notable) < len(incidents):
    st.caption(f"{len(incidents) - len(notable)} single-event, non-high incidents hidden. "
               "Tick *Show all* in the sidebar to include them.")

if not filtered:
    st.info("No incidents match the current filters.")

# --- Incident list ---------------------------------------------------------
for incident in filtered:
    severity = incident.get("severity", "low")
    who = ", ".join(incident.get("users", [])) or "n/a"
    techniques = incident.get("mitre_techniques", [])
    badge = " ".join(f"`{t['technique_id']}`" for t in techniques)

    with st.expander(
        f"{SEVERITY_ICON.get(severity, '⚪')} #{incident['incident_id']} — {who} · "
        f"{incident['event_count']} event(s) · {incident['start']} → {incident['end']}"
        + (f" · {badge}" if badge else "")
    ):
        st.caption(incident.get("summary", ""))

        if incident.get("source_ips"):
            st.markdown("**Source IPs:** " + ", ".join(f"`{ip}`" for ip in incident["source_ips"]))

        if techniques:
            st.markdown("**MITRE ATT&CK:** " + " · ".join(
                f"`{t['technique_id']}` {t['technique_name']} ({t['tactic']})"
                for t in techniques
            ))
        else:
            st.caption("No MITRE technique matched — the lookup table is deliberately "
                       "small and keyword-grounded, so unmatched is common and honest.")

        col1, col2 = st.columns([1, 1])

        with col1:
            st.subheader("Raw events")
            st.dataframe(pd.DataFrame(incident["events"]), width="stretch")

        with col2:
            st.subheader("LLM narrative")
            narrative = incident.get("narrative")
            if narrative:
                st.write(narrative)
            else:
                st.info("Not narrated — below the narrative budget threshold "
                        "(see `NARRATE_*` in `config.py`). Re-run the pipeline "
                        "with `--narrate-all` to narrate every incident.")

st.sidebar.markdown("---")
st.sidebar.caption(
    "Detection: per-user Isolation Forest over sentence-embedding vectors, plus an "
    "impossible-travel physics rule. Narrative: local LLM (phi3 via Ollama) grounded "
    "in a MITRE ATT&CK keyword lookup table."
)
