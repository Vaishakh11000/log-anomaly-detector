"""
baseline_rules.py
Rule-based detection baseline -- the conventional SIEM this project is
measured *against*, not part of the shipping pipeline.

Evaluation target #1 needs an honest comparison, so these rules are written
the way a competent analyst would write them: thresholds on failure counts,
distinct-username fan-out, and keyword alerts on privileged commands. Each
rule was checked against the synthetic corpus to confirm it fires on the
attack it targets and not on benign traffic -- a strawman baseline would
make the embedding detector look good for the wrong reason.

IMPORTANT: nothing here may be imported by pipeline.py. Adding hand-written
detection rules to the production path is an explicit non-goal (see docs/DESIGN.md
section 11); the one rule that *is* in the pipeline (impossible travel) lives
in anomaly_detection.py and is admitted only because it is a physics check.
"""

import pandas as pd

from config import (
    BASELINE_BRUTE_FORCE_WINDOW_MINUTES,
    BASELINE_BRUTE_FORCE_MIN_FAILURES,
    BASELINE_ENUMERATION_WINDOW_MINUTES,
    BASELINE_ENUMERATION_MIN_USERS,
    BASELINE_PRIVILEGE_KEYWORDS,
)

FAILED_LOGIN = "failed password"
ACCEPTED_LOGIN = "accepted password"


def _matching(df: pd.DataFrame, phrase: str, message_col: str = "message") -> pd.DataFrame:
    return df[df[message_col].str.contains(phrase, case=False, na=False)]


def _windows(times: list[pd.Timestamp], window: pd.Timedelta):
    """Yield (start_i, end_i) index spans of every maximal forward window.

    Plain two-pointer sweep rather than a rolling join -- this gets read out
    loud in a viva, so it stays obvious.
    """
    for i in range(len(times)):
        j = i
        while j + 1 < len(times) and times[j + 1] - times[i] <= window:
            j += 1
        yield i, j


def rule_brute_force(
    df: pd.DataFrame,
    window_minutes: int = BASELINE_BRUTE_FORCE_WINDOW_MINUTES,
    min_failures: int = BASELINE_BRUTE_FORCE_MIN_FAILURES,
) -> set:
    """N failed passwords for one user in a short window, plus any success
    that follows the burst (the classic "brute force succeeded" alert)."""
    window = pd.Timedelta(minutes=window_minutes)
    failed = _matching(df, FAILED_LOGIN)
    accepted = _matching(df, ACCEPTED_LOGIN)
    hits: set = set()

    for user, group in failed.groupby("user"):
        group = group.sort_values("timestamp")
        times = group["timestamp"].tolist()
        idxs = group.index.tolist()
        for i, j in _windows(times, window):
            if j - i + 1 < min_failures:
                continue
            hits.update(idxs[i:j + 1])
            follow_up = accepted[
                (accepted["user"] == user)
                & (accepted["timestamp"] >= times[j])
                & (accepted["timestamp"] <= times[j] + window)
            ]
            hits.update(follow_up.index)
    return hits


def rule_enumeration(
    df: pd.DataFrame,
    window_minutes: int = BASELINE_ENUMERATION_WINDOW_MINUTES,
    min_users: int = BASELINE_ENUMERATION_MIN_USERS,
) -> set:
    """One source IP failing against K or more distinct usernames in a window."""
    window = pd.Timedelta(minutes=window_minutes)
    failed = _matching(df, FAILED_LOGIN)
    failed = failed[failed["source_ip"].notna()]
    hits: set = set()

    for _, group in failed.groupby("source_ip"):
        group = group.sort_values("timestamp")
        times = group["timestamp"].tolist()
        idxs = group.index.tolist()
        users = group["user"].tolist()
        for i, j in _windows(times, window):
            if len(set(users[i:j + 1])) >= min_users:
                hits.update(idxs[i:j + 1])
    return hits


def rule_privileged_command(
    df: pd.DataFrame,
    keywords: tuple = BASELINE_PRIVILEGE_KEYWORDS,
) -> set:
    """Keyword alert on privilege escalation and account creation."""
    lowered = df["message"].fillna("").str.lower()
    mask = pd.Series(False, index=df.index)
    for keyword in keywords:
        mask |= lowered.str.contains(keyword, regex=False, na=False)
    return set(df.index[mask])


RULES = {
    "brute_force": rule_brute_force,
    "enumeration": rule_enumeration,
    "privileged_command": rule_privileged_command,
}


def detect(df: pd.DataFrame) -> pd.DataFrame:
    """Run every baseline rule. Adds 'is_anomaly' (bool) and 'rules_fired' (str).

    Deliberately excludes impossible travel: that rule is shared with the
    production detector, so leaving it out of the baseline keeps the
    comparison about rules-vs-embeddings rather than double-counting it.
    Its contribution is reported separately as an ablation in evaluate.py.
    """
    df = df.copy()
    fired: dict = {idx: [] for idx in df.index}
    for name, rule in RULES.items():
        for idx in rule(df):
            fired[idx].append(name)

    df["rules_fired"] = [",".join(fired[idx]) for idx in df.index]
    df["is_anomaly"] = df["rules_fired"] != ""
    return df


def per_rule_counts(df: pd.DataFrame) -> dict:
    """How many lines each rule claimed, for the report's breakdown table."""
    return {
        name: int(df["rules_fired"].str.contains(name, regex=False).sum())
        for name in RULES
    }


if __name__ == "__main__":
    # smoke test: one brute-force burst, one enumeration sweep, one sudo line,
    # and benign traffic that must stay unflagged
    base = pd.Timestamp("2026-07-18 02:00:00")
    rows = []
    for i in range(4):
        rows.append({"timestamp": base + pd.Timedelta(seconds=i * 3), "user": "alice",
                     "source_ip": "203.0.113.9",
                     "message": "Failed password for alice from 203.0.113.9 port 5100 ssh2"})
    rows.append({"timestamp": base + pd.Timedelta(seconds=20), "user": "alice",
                 "source_ip": "203.0.113.9",
                 "message": "Accepted password for alice from 203.0.113.9 port 5100 ssh2"})
    rows.append({"timestamp": base + pd.Timedelta(seconds=50), "user": "alice", "source_ip": None,
                 "message": "user=alice : COMMAND=/bin/su root"})
    for n, probe in enumerate(["ftpuser", "postgres", "test", "guest"]):
        rows.append({"timestamp": base + pd.Timedelta(minutes=30, seconds=n * 4), "user": probe,
                     "source_ip": "198.51.100.7",
                     "message": f"Failed password for {probe} from 198.51.100.7 port 6100 ssh2"})
    rows.append({"timestamp": base + pd.Timedelta(hours=8), "user": "bob", "source_ip": "10.0.1.4",
                 "message": "Accepted password for bob from 10.0.1.4 port 5200 ssh2"})
    rows.append({"timestamp": base + pd.Timedelta(hours=8, seconds=1), "user": "bob",
                 "source_ip": None,
                 "message": "pam_unix(sshd:session): session opened for user bob by (uid=0)"})
    rows.append({"timestamp": base + pd.Timedelta(hours=9), "user": "carol", "source_ip": "10.0.2.8",
                 "message": "Failed password for carol from 10.0.2.8 port 5300 ssh2"})

    result = detect(pd.DataFrame(rows))
    print(result[["timestamp", "user", "rules_fired"]].to_string(index=False))
    print("\nper-rule counts:", per_rule_counts(result))
    print(f"flagged {result['is_anomaly'].sum()} of {len(result)} lines")
    assert result["is_anomaly"].sum() == 10, "expected the 3 attack groups, nothing else"
    assert not result.loc[result["user"] == "bob", "is_anomaly"].any(), "benign login flagged"
    assert not result.loc[result["user"] == "carol", "is_anomaly"].any(), "isolated typo flagged"
    print("OK")
