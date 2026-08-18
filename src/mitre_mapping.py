"""
mitre_mapping.py
Small reference lookup table mapping anomaly *keywords/patterns* to MITRE
ATT&CK technique IDs. This is intentionally simple and retrieval-based (not
left to LLM free-association) -- the LLM narrative step is grounded in this
table, so it cannot hallucinate technique IDs.

Two levels of mapping:
  * map_to_mitre(message)          -- per-line keyword lookup
  * map_incident_to_mitre(df)      -- the above, plus techniques that are only
                                      visible at incident level (impossible
                                      travel, account enumeration), which no
                                      single log line reveals on its own

Keep this table small and deliberate -- building a full ATT&CK ontology is an
explicit anti-goal. Reference: https://attack.mitre.org/techniques/enterprise/
"""

import pandas as pd

from config import ENUMERATION_MIN_DISTINCT_USERS

MITRE_LOOKUP = [
    {
        "keywords": ["failed password", "authentication failure", "invalid user",
                     "login attempt rejected", "invalid credentials"],
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
    },
    {
        "keywords": ["accepted password", "session opened", "authentication succeeded",
                     "successful auth"],
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
    },
    {
        "keywords": ["usermod", "added to group", "gpasswd", "adduser"],
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "tactic": "Persistence",
    },
    {
        "keywords": ["useradd", "new user", "creating user"],
        "technique_id": "T1136",
        "technique_name": "Create Account",
        "tactic": "Persistence",
    },
    {
        "keywords": ["sudo", "command=", "su root", "privilege"],
        "technique_id": "T1548",
        "technique_name": "Abuse Elevation Control Mechanism",
        "tactic": "Privilege Escalation",
    },
    {
        # Deliberately NOT the bare word "cron": routine CRON job lines are the
        # single most common benign message in these logs, and matching them
        # tagged half the dataset as Persistence.
        "keywords": ["crontab", "new cron job", "at job", "systemd-run"],
        "technique_id": "T1053",
        "technique_name": "Scheduled Task/Job",
        "tactic": "Persistence / Execution",
    },
    {
        "keywords": ["scp", "wget", "curl", "outbound connection"],
        "technique_id": "T1041",
        "technique_name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
    },
    {
        "keywords": ["port scan", "nmap", "connection refused"],
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "tactic": "Discovery",
    },
    {
        "keywords": ["log cleared", "truncated", "history -c", "unset histfile",
                     "shred", "rm /var/log"],
        "technique_id": "T1070",
        "technique_name": "Indicator Removal",
        "tactic": "Defense Evasion",
    },
]

# Techniques attached from structural signals rather than message text. These
# are patterns no single log line can show -- they only exist across an incident.
SIGNAL_LOOKUP = {
    "impossible_travel": {
        "technique_id": "T1021.004",
        "technique_name": "Remote Services: SSH",
        "tactic": "Lateral Movement",
        "evidence": "Successful authentications from geographically implausible "
                    "source IPs within a short window",
    },
    "account_enumeration": {
        "technique_id": "T1087",
        "technique_name": "Account Discovery",
        "tactic": "Discovery",
        "evidence": f"{ENUMERATION_MIN_DISTINCT_USERS}+ distinct usernames probed "
                    "from a single source IP",
    },
}


def map_to_mitre(message: str) -> list[dict]:
    """Return matching MITRE technique dicts for a single log message."""
    message_lower = str(message).lower()
    return [entry for entry in MITRE_LOOKUP
            if any(kw in message_lower for kw in entry["keywords"])]


def detect_incident_signals(incident_df: pd.DataFrame) -> list[str]:
    """Return the names of structural signals present in this incident."""
    signals = []

    if "impossible_travel" in incident_df.columns and incident_df["impossible_travel"].any():
        signals.append("impossible_travel")

    # Account enumeration: many distinct usernames, one source IP.
    if {"user", "source_ip"}.issubset(incident_df.columns):
        for _, rows in incident_df.groupby("source_ip"):
            distinct_users = rows["user"].dropna().nunique()
            if distinct_users >= ENUMERATION_MIN_DISTINCT_USERS:
                signals.append("account_enumeration")
                break

    return signals


def map_incident_to_mitre(incident_df: pd.DataFrame) -> list[dict]:
    """Full grounded technique set for one incident: per-line keyword matches
    plus incident-level structural signals, de-duplicated by technique ID."""
    matched: dict[str, dict] = {}

    for message in incident_df.get("message", []):
        for entry in map_to_mitre(message):
            matched[entry["technique_id"]] = entry

    for signal in detect_incident_signals(incident_df):
        entry = SIGNAL_LOOKUP[signal]
        matched[entry["technique_id"]] = entry

    return list(matched.values())


if __name__ == "__main__":
    print("--- per-line keyword lookup ---")
    for m in [
        "Failed password for admin from 10.0.0.5 port 51422 ssh2",
        "sudo: alice : COMMAND=/bin/su root",
        "nmap scan detected from 10.0.0.9",
        "CRON[8124]: (root) CMD (run-parts /etc/cron.hourly)",   # benign: expect no match
    ]:
        hits = [f"{e['technique_id']} {e['technique_name']}" for e in map_to_mitre(m)]
        print(f"  {m}\n    -> {hits or 'no match (correct for benign routine lines)'}")

    print("\n--- incident-level signals ---")
    enumeration = pd.DataFrame({
        "user": ["root", "test", "guest", "oracle"],
        "source_ip": ["203.0.113.7"] * 4,
        "impossible_travel": [False] * 4,
        "message": [f"Failed password for {u} from 203.0.113.7 port 5000 ssh2"
                    for u in ["root", "test", "guest", "oracle"]],
    })
    for e in map_incident_to_mitre(enumeration):
        print(f"  {e['technique_id']} ({e['technique_name']}) - {e['tactic']}")
    print("  Expected: T1110 Brute Force + T1087 Account Discovery (signal-derived)")
