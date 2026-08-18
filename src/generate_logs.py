"""
generate_logs.py
Generates a synthetic auth/syslog-style log with mostly benign traffic
plus three labeled attack scenarios, for Phase 2. Pure data generation --
no detection logic belongs here.

Attack scenarios (see docs/DESIGN.md for the spec this implements):
    A - rapid failed passwords -> success -> sudo su root -> new user added to sudo group
    B - normal login from usual IP, then ~15 min later a success from a
        completely different IP range (impossible travel)
    C - failed logins across many different usernames from one IP (enumeration)

Output:
    data/raw/synthetic.log       - syslog-style lines, sorted by time
    data/raw/ground_truth.csv    - line_number -> scenario label for attack lines only

Note on message formats: sudo/usermod lines use `user=<name>` (rather than
the multi-field real-world sudo TTY/PWD/USER= format) so the acting user is
attributable via the existing extract_user() regex in preprocessing.py --
the real format's "USER=root" target-user field would otherwise be
misparsed as the actor, splitting Scenario A across two "users" during
incident grouping.

Usage:
    python src/generate_logs.py --output-log data/raw/synthetic.log --output-gt data/raw/ground_truth.csv
"""

import argparse
import csv
import random
from datetime import datetime, timedelta

from config import (
    SYNTHETIC_HOST,
    SYNTHETIC_USERS,
    SYNTHETIC_DAYS,
    SYNTHETIC_TOTAL_LINES,
    SYNTHETIC_INSTANCES_PER_SCENARIO,
    SYNTHETIC_SEED,
    SYNTHETIC_YEAR,
)

# Per-user "home" subnet for benign traffic and Scenario B's baseline leg.
USER_HOME_SUBNET = {
    "alice": "10.0.0.",
    "bob": "10.0.1.",
    "carol": "10.0.2.",
    "dave": "10.0.3.",
    "admin": "10.0.10.",
}

# Foreign ranges used for attacks. RFC 5737 documentation ranges -- never
# routable, safe to embed in synthetic text.
FOREIGN_SUBNETS = ["203.0.113.", "198.51.100.", "192.0.2."]
INSIDER_SUBNET = "172.16.5."  # compromised-workstation flavor for Scenario A

# Common account names probed during enumeration (Scenario C) -- deliberately
# distinct from SYNTHETIC_USERS so a probe doesn't pollute a real user's
# per-user baseline with attack embeddings.
PROBE_USERNAMES = [
    "root", "test", "guest", "oracle", "postgres",
    "www-data", "ftpuser", "backup", "deploy", "support",
]

CRON_COMMANDS = [
    "(root) CMD (run-parts /etc/cron.hourly)",
    "(root) CMD (/usr/lib/php/sessionclean)",
    "(root) CMD (/usr/local/bin/backup-nightly.sh)",
]
SYSTEMD_MESSAGES = [
    "Starting Daily apt upgrade and clean activities...",
    "Started Session {n} of user {user}.",
    "Reloading system manager configuration.",
    "Starting Cleanup of Temporary Directories...",
]

_pid_counter = 1000


def next_pid() -> int:
    global _pid_counter
    _pid_counter += random.randint(1, 9)
    return _pid_counter


def rand_ip(subnet: str) -> str:
    return f"{subnet}{random.randint(2, 250)}"


def rand_port() -> int:
    return random.randint(50000, 65000)


def make_event(ts: datetime, process: str, message: str, pid: int = None,
               scenario: str = None, instance: int = None,
               user: str = None, description: str = None) -> dict:
    return {
        "ts": ts, "process": process, "pid": pid, "message": message,
        "scenario": scenario, "instance": instance,
        "user": user, "description": description,
    }


# --- Benign event generators ---

def gen_login_session(user: str, day_start: datetime) -> list[dict]:
    hour = random.randint(7, 20)
    login_ts = day_start + timedelta(hours=hour, minutes=random.randint(0, 59),
                                      seconds=random.randint(0, 59))
    ip = rand_ip(USER_HOME_SUBNET[user])
    port = rand_port()
    pid = next_pid()
    events = [
        make_event(login_ts, "sshd", f"Accepted password for {user} from {ip} port {port} ssh2", pid),
        make_event(login_ts + timedelta(seconds=1), "sshd",
                   f"pam_unix(sshd:session): session opened for user {user} by (uid=0)", pid),
    ]
    if random.random() < 0.7:
        logout_ts = login_ts + timedelta(hours=random.randint(1, 6), minutes=random.randint(0, 59))
        events.append(make_event(logout_ts, "sshd",
                                  f"pam_unix(sshd:session): session closed for user {user}", pid))
    return events


def gen_isolated_failed_password(user: str, day_start: datetime) -> list[dict]:
    ts = day_start + timedelta(hours=random.randint(7, 20), minutes=random.randint(0, 59))
    ip = rand_ip(USER_HOME_SUBNET[user])
    return [make_event(ts, "sshd", f"Failed password for {user} from {ip} port {rand_port()} ssh2", next_pid())]


def gen_cron(day_start: datetime) -> list[dict]:
    ts = day_start + timedelta(hours=random.randint(0, 23), minutes=random.randint(0, 59))
    return [make_event(ts, "CRON", random.choice(CRON_COMMANDS), next_pid())]


def gen_systemd_noise(day_start: datetime) -> list[dict]:
    ts = day_start + timedelta(hours=random.randint(0, 23), minutes=random.randint(0, 59))
    msg = random.choice(SYSTEMD_MESSAGES)
    if "{user}" in msg:
        user = random.choice(SYNTHETIC_USERS)
        msg = msg.format(n=random.randint(1, 99), user=user)
    return [make_event(ts, "systemd", msg, 1)]


BENIGN_GENERATORS = [
    ("login_session", 3),
    ("cron", 3),
    ("systemd", 2),
    ("isolated_failed", 1),
]


def gen_benign_unit(day_start: datetime) -> list[dict]:
    kind = random.choices(
        [k for k, _ in BENIGN_GENERATORS],
        weights=[w for _, w in BENIGN_GENERATORS],
    )[0]
    user = random.choice(SYNTHETIC_USERS)
    if kind == "login_session":
        return gen_login_session(user, day_start)
    if kind == "isolated_failed":
        return gen_isolated_failed_password(user, day_start)
    if kind == "cron":
        return gen_cron(day_start)
    return gen_systemd_noise(day_start)


# --- Attack scenario generators ---

def gen_scenario_a(user: str, day_start: datetime, instance: int) -> list[dict]:
    """Rapid failed passwords -> success -> sudo su root -> new user added to sudo group."""
    ip = rand_ip(INSIDER_SUBNET)
    port = rand_port()
    start = day_start + timedelta(hours=random.randint(1, 5), minutes=random.randint(0, 59))
    events = []
    t = start
    for _ in range(random.randint(3, 5)):
        events.append(make_event(t, "sshd", f"Failed password for {user} from {ip} port {port} ssh2",
                                  next_pid(), "A", instance, user,
                                  "Rapid failed password attempts preceding compromise"))
        t += timedelta(seconds=random.randint(1, 4))

    events.append(make_event(t, "sshd", f"Accepted password for {user} from {ip} port {port} ssh2",
                              next_pid(), "A", instance, user,
                              "Brute-force succeeds"))
    t += timedelta(seconds=random.randint(15, 45))

    new_user = f"backdoor{instance:02d}"
    events.append(make_event(t, "sudo", f"user={user} : COMMAND=/bin/su root",
                              next_pid(), "A", instance, user,
                              "Privilege escalation via sudo su"))
    t += timedelta(seconds=random.randint(20, 60))

    events.append(make_event(t, "usermod", f"user={user} added new user '{new_user}' to group sudo",
                              next_pid(), "A", instance, user,
                              "Persistence: backdoor account added to sudo group"))
    return events


def gen_scenario_b(user: str, day_start: datetime, instance: int) -> list[dict]:
    """Normal login from usual IP, then ~15 min later a success from a different IP range."""
    start = day_start + timedelta(hours=random.randint(7, 20), minutes=random.randint(0, 40))
    home_ip = rand_ip(USER_HOME_SUBNET[user])
    foreign_ip = rand_ip(random.choice(FOREIGN_SUBNETS))
    port = rand_port()

    events = [
        make_event(start, "sshd", f"Accepted password for {user} from {home_ip} port {port} ssh2",
                   next_pid(), "B", instance, user, "Baseline login from usual location"),
    ]
    travel_ts = start + timedelta(minutes=15)
    events.append(make_event(travel_ts, "sshd",
                              f"Accepted password for {user} from {foreign_ip} port {rand_port()} ssh2",
                              next_pid(), "B", instance, user,
                              "Impossible travel: success from a different IP range 15 min later"))
    return events


def gen_scenario_c(day_start: datetime, instance: int) -> list[dict]:
    """Failed logins across many different usernames from one IP (enumeration/recon)."""
    ip = rand_ip(random.choice(FOREIGN_SUBNETS))
    start = day_start + timedelta(hours=random.randint(0, 23), minutes=random.randint(0, 59))
    targets = random.sample(PROBE_USERNAMES, k=random.randint(6, 8))
    events = []
    t = start
    for target in targets:
        events.append(make_event(t, "sshd", f"Failed password for {target} from {ip} port {rand_port()} ssh2",
                                  next_pid(), "C", instance, target,
                                  "Account enumeration: many usernames probed from one source IP"))
        t += timedelta(seconds=random.randint(2, 6))
    return events


def build_dataset(total_lines: int = SYNTHETIC_TOTAL_LINES,
                   days: int = SYNTHETIC_DAYS,
                   instances_per_scenario: int = SYNTHETIC_INSTANCES_PER_SCENARIO,
                   year: int = SYNTHETIC_YEAR,
                   seed: int = SYNTHETIC_SEED) -> list[dict]:
    random.seed(seed)
    base_date = datetime(year, 7, 14)
    day_starts = [base_date + timedelta(days=d) for d in range(days)]

    events: list[dict] = []
    for instance in range(1, instances_per_scenario + 1):
        events += gen_scenario_a(random.choice(SYNTHETIC_USERS), random.choice(day_starts), instance)
        events += gen_scenario_b(random.choice(SYNTHETIC_USERS), random.choice(day_starts), instance)
        events += gen_scenario_c(random.choice(day_starts), instance)

    benign_target = max(0, total_lines - len(events))
    benign_events: list[dict] = []
    while len(benign_events) < benign_target:
        benign_events += gen_benign_unit(random.choice(day_starts))
    events += benign_events

    events.sort(key=lambda e: e["ts"])
    return events


def format_line(event: dict, host: str = SYNTHETIC_HOST) -> str:
    ts_str = event["ts"].strftime("%b %d %H:%M:%S")
    pid_part = f"[{event['pid']}]" if event.get("pid") else ""
    return f"{ts_str} {host} {event['process']}{pid_part}: {event['message']}"


def write_outputs(events: list[dict], log_path: str, gt_path: str, host: str = SYNTHETIC_HOST):
    with open(log_path, "w") as f:
        f.write("\n".join(format_line(e, host) for e in events) + "\n")

    with open(gt_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["line_number", "timestamp", "user", "scenario", "instance", "description"])
        for i, e in enumerate(events, start=1):
            if e.get("scenario"):
                writer.writerow([i, e["ts"].isoformat(), e["user"], e["scenario"], e["instance"], e["description"]])

    n_attack = sum(1 for e in events if e.get("scenario"))
    print(f"Wrote {len(events)} log lines -> {log_path}")
    print(f"Wrote {n_attack} labeled attack lines -> {gt_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate synthetic auth log + ground truth.")
    parser.add_argument("--output-log", default="data/raw/synthetic.log")
    parser.add_argument("--output-gt", default="data/raw/ground_truth.csv")
    parser.add_argument("--total-lines", type=int, default=SYNTHETIC_TOTAL_LINES)
    parser.add_argument("--days", type=int, default=SYNTHETIC_DAYS)
    parser.add_argument("--instances-per-scenario", type=int, default=SYNTHETIC_INSTANCES_PER_SCENARIO)
    parser.add_argument("--seed", type=int, default=SYNTHETIC_SEED)
    args = parser.parse_args()

    events = build_dataset(
        total_lines=args.total_lines,
        days=args.days,
        instances_per_scenario=args.instances_per_scenario,
        seed=args.seed,
    )
    write_outputs(events, args.output_log, args.output_gt)
