"""
sequence_grouping.py
Groups flagged anomalies into time-windowed clusters so related events
(e.g. recon -> brute force -> lateral movement) can be narrated together as a
single incident, instead of being reported as disconnected single-line alerts.

Grouping runs on two axes -- same user OR same source IP -- because attacks
don't all hold one of those constant. A brute-force burst keeps the user fixed
and varies nothing; account enumeration deliberately varies the *username* on
every line while holding the source IP fixed. Grouping on user alone (the
Phase 3 behaviour) scattered enumeration into N singleton alerts.
"""

import pandas as pd

from config import INCIDENT_WINDOW_MINUTES, GROUP_BY_SOURCE_IP, NON_IDENTITY_VALUES


def _identity(value) -> str | None:
    """Normalise a user/IP cell to a joinable identity, or None if it isn't one.

    Placeholders like "unknown" are not identities -- they're the parser saying
    it found no user. Joining on them would merge unrelated systemd noise into
    one fake incident.
    """
    if pd.isna(value):
        return None
    text = str(value).strip()
    if not text or text.lower() in NON_IDENTITY_VALUES:
        return None
    return text


def _linked(row_a: pd.Series, row_b: pd.Series, group_by_source_ip: bool) -> bool:
    """True if two anomalies share an identity (same user, or same source IP)."""
    user_a, user_b = _identity(row_a.get("user")), _identity(row_b.get("user"))
    if user_a is not None and user_a == user_b:
        return True

    if group_by_source_ip:
        ip_a, ip_b = _identity(row_a.get("source_ip")), _identity(row_b.get("source_ip"))
        if ip_a is not None and ip_a == ip_b:
            return True

    return False


class _UnionFind:
    """Minimal union-find so incident membership is transitive: if A links to B
    and B links to C, all three land in one incident even if A and C share nothing."""

    def __init__(self, size: int):
        self.parent = list(range(size))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]   # path compression
            x = self.parent[x]
        return x

    def union(self, x: int, y: int) -> None:
        root_x, root_y = self.find(x), self.find(y)
        if root_x != root_y:
            # keep the lower index as root so incidents stay in chronological order
            self.parent[max(root_x, root_y)] = min(root_x, root_y)


def group_anomalies(df: pd.DataFrame,
                    window_minutes: int = INCIDENT_WINDOW_MINUTES,
                    group_by_source_ip: bool = GROUP_BY_SOURCE_IP,
                    time_col: str = "timestamp") -> list[pd.DataFrame]:
    """
    Given a dataframe of scored log rows, return one dataframe per "incident".

    Two anomalies join the same incident when they fall within `window_minutes`
    of each other AND share a user or a source IP. Linking is transitive, so a
    chain of events spanning more than one window still reads as one story.
    """
    anomalies = df[df["is_anomaly"] == True].copy()
    anomalies = anomalies.dropna(subset=[time_col]).sort_values(time_col).reset_index(drop=True)

    if anomalies.empty:
        return []

    window = pd.Timedelta(minutes=window_minutes)
    groups = _UnionFind(len(anomalies))

    for i in range(len(anomalies)):
        row_i = anomalies.iloc[i]
        # walk backwards only while the previous rows are still inside the window
        for j in range(i - 1, -1, -1):
            row_j = anomalies.iloc[j]
            if row_i[time_col] - row_j[time_col] > window:
                break
            if _linked(row_i, row_j, group_by_source_ip):
                groups.union(i, j)

    incidents: dict[int, list[int]] = {}
    for i in range(len(anomalies)):
        incidents.setdefault(groups.find(i), []).append(i)

    return [anomalies.iloc[idx].reset_index(drop=True) for idx in incidents.values()]


def describe_incident(incident: pd.DataFrame) -> str:
    """One-line human summary -- used in logs and the incident JSON."""
    users = sorted({u for u in map(_identity, incident.get("user", [])) if u})
    ips = sorted({p for p in map(_identity, incident.get("source_ip", [])) if p})
    user_part = ", ".join(users[:3]) + ("..." if len(users) > 3 else "") or "n/a"
    ip_part = ", ".join(ips[:3]) + ("..." if len(ips) > 3 else "") or "n/a"
    return f"{len(incident)} events | users: {user_part} | source IPs: {ip_part}"


if __name__ == "__main__":
    data = {
        "user": ["alice", "alice", "alice", "bob",
                 # enumeration: one IP, a different username every line
                 "root", "test", "guest"],
        "source_ip": ["10.0.0.5", "10.0.0.5", "10.0.0.5", "10.0.0.9",
                      "203.0.113.7", "203.0.113.7", "203.0.113.7"],
        "timestamp": pd.to_datetime([
            "2026-07-18 10:00:00", "2026-07-18 10:05:00",
            "2026-07-18 11:30:00", "2026-07-18 10:00:00",
            "2026-07-18 14:00:00", "2026-07-18 14:01:00", "2026-07-18 14:02:00",
        ]),
        "is_anomaly": [True] * 7,
        "message": ["failed login", "failed login", "priv escalation", "failed login",
                    "failed password for root", "failed password for test",
                    "failed password for guest"],
    }
    incidents = group_anomalies(pd.DataFrame(data))
    print(f"Found {len(incidents)} incidents")
    for i, inc in enumerate(incidents):
        print(f"  Incident {i}: {describe_incident(inc)}")
    print("\nExpected: alice x2 together, alice priv-esc separate (>30min), bob alone,")
    print("and the 3 enumeration lines as ONE incident despite 3 different usernames.")
