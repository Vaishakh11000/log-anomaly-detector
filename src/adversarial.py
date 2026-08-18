"""
adversarial.py
Phase 5 -- the robustness evaluation. Generates "camouflaged" variants of the
synthetic attack scenarios and measures how far detection degrades, per
scenario and per camouflage strategy.

This is an evaluation track, not production pipeline code: it *calls* the real
detection stack rather than reimplementing any of it, so the numbers describe
the system that actually ships.

Camouflage strategies:
  temporal  - spread events 8-20 min apart (still inside the 30-min grouping window)
  slow      - spread events 35-90 min apart (past the grouping window)
  rephrase  - swap in novel but semantically-equivalent wording
  mimicry   - rewrite attack lines to match the *dominant benign* templates
  noise     - interleave benign log lines to dilute the attack pattern
  volume    - drop half the repeated mid-sequence lines ("low and slow")
  ip_rotate - give every attack line a different source IP

`rephrase` and `mimicry` are deliberately both present and are opposites.
Novel wording makes an attack *more* anomalous, because rare templates are
exactly what an outlier detector looks for; real evasion means adopting the
phrasing that already dominates benign traffic. Reporting only one of the two
would misrepresent how the detector behaves.

Method: camouflage is applied to the *event list* produced by generate_logs,
not to the finished log file, so each attack line keeps its scenario/instance
label through timestamp shuffling and noise injection. Both the original and
the camouflaged corpus then go through the identical preprocess -> embed ->
detect chain, and detection is measured only over ground-truth attack lines.

Usage:
    python src/adversarial.py
    python src/adversarial.py --output-dir results
"""

import argparse
import copy
import json
import random
import re
from pathlib import Path

import pandas as pd

from config import (
    CONTAMINATION,
    CAMOUFLAGE_MIN_GAP_MINUTES,
    CAMOUFLAGE_MAX_GAP_MINUTES,
    CAMOUFLAGE_SLOW_MIN_GAP_MINUTES,
    CAMOUFLAGE_SLOW_MAX_GAP_MINUTES,
    CAMOUFLAGE_NOISE_RATIO,
    CAMOUFLAGE_VOLUME_KEEP,
    INCIDENT_WINDOW_MINUTES,
    SYNTHETIC_SEED,
    SYNTHETIC_YEAR,
    SYNTHETIC_USERS,
    PROCESSED_DATA_DIR,
)
from generate_logs import build_dataset, write_outputs, next_pid
from preprocessing import preprocess_file
from embedding import add_embeddings_to_df
from anomaly_detection import run_anomaly_detection
from sequence_grouping import group_anomalies

from datetime import timedelta

# Alternate phrasings for the messages the scenarios actually emit. Kept
# semantically equivalent on purpose: the question is whether the detector
# generalises across wording, which a keyword rule cannot.
REPHRASE_MAP = {
    "Failed password for": ["Authentication failure for", "Invalid credentials for",
                            "Login attempt rejected for"],
    "Accepted password for": ["Authentication succeeded for", "Login accepted for",
                              "Session established for"],
    "COMMAND=/bin/su root": ["COMMAND=/bin/bash -l", "COMMAND=/usr/bin/sudo -i"],
    "added new user": ["registered account", "provisioned account"],
}

# Benign-looking filler, as (process, message) so it formats like a real line.
NOISE_TEMPLATES = [
    ("CRON", "(root) CMD (run-parts /etc/cron.hourly)"),
    ("CRON", "(root) CMD (/usr/lib/php/sessionclean)"),
    ("systemd", "Started Session {n} of user {user}."),
    ("systemd", "Reloading system manager configuration."),
    ("systemd", "Starting Cleanup of Temporary Directories..."),
]

# Mimicry: rewrite the *distinctive* attack lines into the shape of the single
# most common benign template in this corpus -- "pam_unix(sshd:session): session
# opened for user <u> by (uid=<n>)". The brute-force and enumeration lines are
# left alone because they are already textually identical to benign isolated
# failed passwords; their only tell is structural (volume, one source IP), which
# is what `volume` and `ip_rotate` attack instead.
MIMICRY_MAP = {
    "COMMAND=/bin/su root": "pam_unix(sudo:session): session opened for user root by (uid=0)",
    "added new user": "pam_unix(sudo:session): session opened for user",
}

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Subnets an attacker could plausibly rotate through (RFC 5737 documentation
# ranges, same convention as generate_logs.py -- never routable).
ROTATION_SUBNETS = ["203.0.113.", "198.51.100.", "192.0.2."]

STRATEGIES = ["temporal", "slow", "rephrase", "mimicry", "noise", "volume", "ip_rotate"]

# The strongest *realistic* attacker: everything that does not require inventing
# novel log wording (which we show backfires).
REALISTIC_COMBO = ["slow", "mimicry", "noise", "volume", "ip_rotate"]


# --- Camouflage strategies -------------------------------------------------

def rephrase_message(message: str, rng: random.Random) -> str:
    """Swap one known phrasing for an equivalent alternative.

    Deliberately preserves the "for <user> from <ip>" shape so preprocessing
    still extracts user and IP -- otherwise we would be measuring broken
    parsing rather than evaded detection.
    """
    for original, alternatives in REPHRASE_MAP.items():
        if original.lower() in message.lower():
            return message.replace(original, rng.choice(alternatives))
    return message


def mimic_message(message: str, actor: str) -> str:
    """Rewrite a distinctive attack line as the dominant benign template.

    This is the textbook mimicry attack: rather than inventing new wording
    (which makes a line rarer, and so easier to spot), adopt the wording the
    detector has already learned to consider normal.
    """
    if "COMMAND=/bin/su root" in message:
        return MIMICRY_MAP["COMMAND=/bin/su root"]
    if "added new user" in message:
        # keep the created account name, drop everything that reads as escalation
        created = message.split("'")[1] if "'" in message else actor
        return f"pam_unix(sudo:session): session opened for user {created} by (uid=0)"
    return message


def rotate_ip(message: str, rng: random.Random) -> str:
    """Give this line its own source IP, breaking the source-IP grouping axis."""
    subnet = rng.choice(ROTATION_SUBNETS)
    return IP_RE.sub(f"{subnet}{rng.randint(2, 250)}", message, count=1)


def reduce_volume(events: list[dict], rng: random.Random,
                  keep: float = CAMOUFLAGE_VOLUME_KEEP) -> list[dict]:
    """Drop a share of the repeated middle events, keeping first and last.

    The pivotal lines (first probe, final escalation) are what make the sequence
    an attack, so an evader thins the repetition rather than the payload.
    """
    events = sorted(events, key=lambda e: e["ts"])
    if len(events) <= 2:
        return events
    middle = [e for e in events[1:-1] if rng.random() < keep]
    return [events[0]] + middle + [events[-1]]


def spread_timestamps(events: list[dict], rng: random.Random,
                      min_gap: int = CAMOUFLAGE_MIN_GAP_MINUTES,
                      max_gap: int = CAMOUFLAGE_MAX_GAP_MINUTES) -> list[dict]:
    """Re-space one attack instance so its events no longer burst together."""
    events = sorted(events, key=lambda e: e["ts"])
    current = events[0]["ts"]
    for event in events[1:]:
        current = current + timedelta(minutes=rng.randint(min_gap, max_gap))
        event["ts"] = current
    return events


def make_noise_events(attack_events: list[dict], rng: random.Random,
                      ratio: float = CAMOUFLAGE_NOISE_RATIO) -> list[dict]:
    """Benign filler spread across the attack's (post-spreading) time range."""
    start = min(e["ts"] for e in attack_events)
    end = max(e["ts"] for e in attack_events)
    span_seconds = max(int((end - start).total_seconds()), 60)

    noise = []
    for _ in range(int(len(attack_events) * ratio)):
        process, template = rng.choice(NOISE_TEMPLATES)
        message = template.format(n=rng.randint(1, 254), user=rng.choice(SYNTHETIC_USERS))
        noise.append({
            "ts": start + timedelta(seconds=rng.randint(0, span_seconds)),
            "process": process,
            "pid": next_pid() if process != "systemd" else 1,
            "message": message,
            "scenario": None, "instance": None, "user": None, "description": None,
        })
    return noise


def camouflage_events(events: list[dict], strategies: list[str], seed: int) -> list[dict]:
    """Apply the chosen strategies to every attack instance in an event list.

    Benign events are left untouched -- an attacker controls their own traffic,
    not the rest of the host's logs.
    """
    rng = random.Random(seed)
    events = copy.deepcopy(events)

    attacks: dict[tuple, list[dict]] = {}
    benign = []
    for event in events:
        if event.get("scenario"):
            attacks.setdefault((event["scenario"], event["instance"]), []).append(event)
        else:
            benign.append(event)

    result = list(benign)
    for instance_events in attacks.values():
        if "volume" in strategies:
            instance_events = reduce_volume(instance_events, rng)
        for event in instance_events:
            if "rephrase" in strategies:
                event["message"] = rephrase_message(event["message"], rng)
            if "mimicry" in strategies:
                event["message"] = mimic_message(event["message"], event.get("user") or "root")
            if "ip_rotate" in strategies:
                event["message"] = rotate_ip(event["message"], rng)
        if "slow" in strategies:
            instance_events = spread_timestamps(
                instance_events, rng,
                CAMOUFLAGE_SLOW_MIN_GAP_MINUTES, CAMOUFLAGE_SLOW_MAX_GAP_MINUTES)
        elif "temporal" in strategies:
            instance_events = spread_timestamps(instance_events, rng)
        if "noise" in strategies:
            result += make_noise_events(instance_events, rng)
        result += instance_events

    result.sort(key=lambda e: e["ts"])
    return result


# --- Evaluation ------------------------------------------------------------

def detect_on_log(log_path: str, parsed_csv: str, year: int = SYNTHETIC_YEAR,
                  contamination: float = CONTAMINATION) -> pd.DataFrame:
    """Run the real detection chain over a log file.

    `contamination` is exposed so Phase 7's proposed retune can be tested under
    camouflage before it is adopted -- a setting that looks good on clean data
    has to survive here first."""
    df = preprocess_file(log_path, parsed_csv, year=year)
    df = add_embeddings_to_df(df, template_col="template")
    return run_anomaly_detection(df, contamination=contamination)


def measure(scored: pd.DataFrame, ground_truth: pd.DataFrame, log_path: str) -> dict:
    """Detection rates over ground-truth attack lines only.

    Reports line-level and instance-level separately on purpose: an analyst
    cares whether the attack was caught *at all* (instance level), while the
    line-level rate shows how much of the evidence survived.
    """
    n_lines = sum(1 for _ in open(log_path))
    if len(scored) != n_lines:
        raise AssertionError(
            f"{len(scored)} parsed rows vs {n_lines} log lines -- ground-truth "
            "line numbers would be misaligned")

    # ground truth line_number is 1-based into the log file
    scored = scored.reset_index(drop=True)
    gt = ground_truth.copy()
    gt["is_anomaly"] = gt["line_number"].map(lambda n: bool(scored.loc[n - 1, "is_anomaly"]))
    gt["impossible_travel"] = gt["line_number"].map(
        lambda n: bool(scored.loc[n - 1, "impossible_travel"]))

    per_scenario = {}
    for scenario, rows in gt.groupby("scenario"):
        instances = rows.groupby("instance")["is_anomaly"].any()
        per_scenario[scenario] = {
            "attack_lines": int(len(rows)),
            "lines_detected": int(rows["is_anomaly"].sum()),
            "line_detection_rate": round(float(rows["is_anomaly"].mean()), 3),
            "instances": int(len(instances)),
            "instances_detected": int(instances.sum()),
            "instance_detection_rate": round(float(instances.mean()), 3),
            "impossible_travel_hits": int(rows["impossible_travel"].sum()),
        }

    all_instances = gt.groupby(["scenario", "instance"])["is_anomaly"].any()
    return {
        "overall": {
            "attack_lines": int(len(gt)),
            "line_detection_rate": round(float(gt["is_anomaly"].mean()), 3),
            "instance_detection_rate": round(float(all_instances.mean()), 3),
            "total_flagged_lines": int(scored["is_anomaly"].sum()),
            "incidents": len(group_anomalies(scored)),
        },
        "per_scenario": per_scenario,
    }


def run_condition(name: str, strategies: list[str], base_events: list[dict],
                  work_dir: Path, seed: int,
                  contamination: float = CONTAMINATION) -> dict:
    """Build one camouflaged corpus, detect on it, and measure."""
    events = base_events if not strategies else camouflage_events(base_events, strategies, seed)

    log_path = work_dir / f"{name}.log"
    gt_path = work_dir / f"{name}_ground_truth.csv"
    write_outputs(events, str(log_path), str(gt_path))

    scored = detect_on_log(str(log_path), str(work_dir / f"{name}_parsed.csv"),
                           contamination=contamination)
    result = measure(scored, pd.read_csv(gt_path), str(log_path))
    result["condition"] = name
    result["strategies"] = strategies
    return result


_POOLED_COUNTS = ["attack_lines", "lines_detected", "instances", "instances_detected",
                  "impossible_travel_hits"]


def pool(runs: list[dict]) -> dict:
    """Pool per-seed runs of one condition into a single result.

    Rates are recomputed from summed counts rather than averaged, so a seed
    that happens to produce fewer attack lines doesn't get equal weight.
    """
    scenarios = sorted({s for r in runs for s in r["per_scenario"]})
    per_scenario = {}
    for scenario in scenarios:
        rows = [r["per_scenario"][scenario] for r in runs if scenario in r["per_scenario"]]
        totals = {k: sum(row[k] for row in rows) for k in _POOLED_COUNTS}
        per_scenario[scenario] = {
            **totals,
            "line_detection_rate": round(totals["lines_detected"] / max(totals["attack_lines"], 1), 3),
            "instance_detection_rate": round(
                totals["instances_detected"] / max(totals["instances"], 1), 3),
        }

    attack_lines = sum(r["overall"]["attack_lines"] for r in runs)
    lines_detected = sum(s["lines_detected"] for s in per_scenario.values())
    instances = sum(s["instances"] for s in per_scenario.values())
    instances_detected = sum(s["instances_detected"] for s in per_scenario.values())

    return {
        "condition": runs[0]["condition"],
        "strategies": runs[0]["strategies"],
        "seeds": len(runs),
        "overall": {
            "attack_lines": attack_lines,
            "line_detection_rate": round(lines_detected / max(attack_lines, 1), 3),
            "instance_detection_rate": round(instances_detected / max(instances, 1), 3),
            "instances": instances,
            "instances_detected": instances_detected,
            "total_flagged_lines": sum(r["overall"]["total_flagged_lines"] for r in runs),
            "incidents": sum(r["overall"]["incidents"] for r in runs),
        },
        "per_scenario": per_scenario,
        "per_seed_instance_rate": [r["overall"]["instance_detection_rate"] for r in runs],
    }


MECHANISM_NOTES = {
    "temporal": "Gaps of 8-20 min stay inside the 30-min grouping window, and timestamps "
                "are never embedded, so this changes nothing. It is the control condition.",
    "slow": "Gaps of 35-90 min exceed both the 30-min grouping window and the 60-min "
            "impossible-travel window. Scenario B is detectable *only* by the physics "
            "rule (its two legs are textually identical once IPs are masked), so pushing "
            "the legs outside that window makes B effectively invisible.",
    "rephrase": "Novel wording backfires: rare templates are precisely what an outlier "
                "detector flags, so detection goes *up*. It does defeat the keyword-based "
                "impossible-travel rule, but the embedding layer then catches what the "
                "rule lost -- defence in depth, by accident rather than design.",
    "mimicry": "The most effective *line-level* attack (biggest drop in evidence retained), "
               "because rewriting escalation lines as the dominant benign template moves "
               "them toward the centre of the learned distribution instead of away from it. "
               "It never hides a whole instance, though: enough sibling lines still fire.",
    "noise": "Ineffective by construction: `contamination` fixes the *proportion* of lines "
             "flagged, so padding the corpus raises the absolute number of alerts rather "
             "than hiding the attack among them.",
    "volume": "Fewer repeated lines means less evidence, but the pivotal first and last "
              "events remain and are the ones that carry the anomaly.",
    "ip_rotate": "Also lands on Scenario B, and for a specific reason: rotating *both* legs "
                 "into the documentation ranges frequently puts them in the same /16, and "
                 "the impossible-travel check compares only the first two octets -- so it "
                 "sees no change and stays silent. A probabilistic defeat of the rule, not "
                 "an attack on the embeddings.",
}


def render_report(results: list[dict], n_seeds: int = 1) -> str:
    baseline = results[0]["overall"]

    ranked = sorted(
        (r for r in results if r["strategies"]),
        key=lambda r: (r["overall"]["instance_detection_rate"] - baseline["instance_detection_rate"],
                       r["overall"]["line_detection_rate"] - baseline["line_detection_rate"]),
    )

    lines = [
        "# Adversarial Robustness Evaluation",
        "",
        "Generated by `src/adversarial.py`. Each condition rebuilds the synthetic",
        "corpus with camouflage applied to the attack lines only, then runs the",
        "identical preprocess -> embed -> detect chain. Detection is measured over",
        "ground-truth attack lines.",
        "",
        f"Pooled over **{n_seeds} seed(s)**; each seed varies both the corpus and the",
        "camouflage draw. Rates are computed from summed counts, not averaged rates.",
        "",
        "**Line detection rate** = share of attack lines flagged. ",
        "**Instance detection rate** = share of attack instances where at least",
        "one line was flagged -- i.e. would an analyst see the attack at all.",
        "",
        "## Which camouflage worked best",
        "",
        "Ranked by drop in instance detection (most effective evasion first). The line",
        "column is shown alongside because the two rank differently -- `mimicry` destroys",
        "the most evidence without ever hiding a whole attack.",
        "",
        "| Rank | Strategy | Instance detection (Δ) | Line detection (Δ) | Why |",
        "|---|---|---|---|---|",
    ]
    for i, r in enumerate(ranked, start=1):
        o = r["overall"]
        gap = o["instance_detection_rate"] - baseline["instance_detection_rate"]
        line_gap = o["line_detection_rate"] - baseline["line_detection_rate"]
        note = MECHANISM_NOTES.get(r["condition"], "Combination of the strategies above.")
        lines.append(f"| {i} | {r['condition']} | {o['instance_detection_rate']:.0%} ({gap:+.0%}) "
                     f"| {o['line_detection_rate']:.0%} ({line_gap:+.0%}) | {note} |")

    # The headline finding, derived rather than asserted: check whether every
    # instance-level loss is confined to one scenario, and whether that
    # scenario's detection tracks the impossible-travel rule one-for-one.
    lossy = {}
    for r in results:
        for scenario, v in r["per_scenario"].items():
            base_v = results[0]["per_scenario"][scenario]
            if v["instance_detection_rate"] < base_v["instance_detection_rate"]:
                lossy.setdefault(scenario, []).append(r["condition"])

    lines += ["", "## Headline finding", ""]
    if len(lossy) == 1:
        scenario = next(iter(lossy))
        # Where does detection of this scenario exceed what the rule alone explains?
        # Those are the conditions in which the embedding layer is compensating.
        compensating = [r["condition"] for r in results
                        if r["per_scenario"][scenario]["instances_detected"]
                        > r["per_scenario"][scenario]["impossible_travel_hits"]]
        rule_bound = len(compensating) < len(results)
        lines += [
            f"Every instance-level detection loss is confined to **scenario {scenario}** "
            f"(via {', '.join(sorted(lossy[scenario]))}). Scenarios "
            f"{', '.join(s for s in sorted(results[0]['per_scenario']) if s != scenario)} "
            "are never fully hidden by any camouflage tested -- their instance detection "
            "stays at 100%.",
            "",
        ]
        if rule_bound:
            lines += [
                f"In most conditions, scenario {scenario} detection does not exceed the "
                "number of impossible-travel rule hits -- it is carried by **the rule, not "
                "the embeddings**. That follows from the design: the two legs of the login "
                "are textually identical once IPs are masked, so they embed to the same "
                "vector and the outlier detector cannot separate them. Every effective "
                "evasion found here works by stepping outside that rule's 60-minute window "
                "(`slow`) or fooling its two-octet subnet comparison (`ip_rotate`).",
                "",
                "That is the honest weak point of this system: the embedding layer is "
                "robust to every camouflage tested at instance level, and the single "
                "hand-written rule is where the fragility lives.",
                "",
            ]
            if compensating:
                lines += [
                    f"The exception is **{', '.join(sorted(compensating))}**, where detection "
                    "exceeds the rule's hits -- the rule is defeated outright (novel wording "
                    "no longer matches its \"accepted password\" keyword) yet the attack is "
                    "still caught, because unusual phrasing is exactly what an outlier "
                    "detector responds to. The two layers fail on opposite inputs, which is "
                    "the one genuinely reassuring result here.",
                    "",
                ]
    else:
        lines += ["Instance-level losses are spread across scenarios "
                  f"{', '.join(sorted(lossy))}.", ""]

    lines += [
        "## Overall",
        "",
        "| Condition | Line detection | Δ vs baseline | Instance detection | Δ vs baseline |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        o = r["overall"]
        line_gap = o["line_detection_rate"] - baseline["line_detection_rate"]
        inst_gap = o["instance_detection_rate"] - baseline["instance_detection_rate"]
        lines.append(
            f"| {r['condition']} | {o['line_detection_rate']:.0%} | {line_gap:+.0%} "
            f"| {o['instance_detection_rate']:.0%} | {inst_gap:+.0%} |")

    for label, key in (("line detection rate", "line_detection_rate"),
                       ("instance detection rate", "instance_detection_rate")):
        lines += ["", f"## Per scenario ({label})", "",
                  "| Condition | A: brute force | B: impossible travel | C: enumeration |",
                  "|---|---|---|---|"]
        for r in results:
            cells = []
            for s in ("A", "B", "C"):
                v = r["per_scenario"].get(s)
                cells.append(f"{v[key]:.0%}" if v else "n/a")
            lines.append(f"| {r['condition']} | " + " | ".join(cells) + " |")

    lines += ["", "## Impossible-travel rule hits (scenario B)", "",
              "The physics check keys off the literal phrase \"accepted password\",",
              "so it is a rule, not a semantic signal -- this row shows how it holds up.",
              "",
              "| Condition | B lines flagged by the rule |", "|---|---|"]
    for r in results:
        b = r["per_scenario"].get("B")
        lines.append(f"| {r['condition']} | {b['impossible_travel_hits'] if b else 'n/a'} |")

    lines += ["", "## Noise", "",
              "| Condition | Total lines flagged | Incidents formed |", "|---|---|---|"]
    for r in results:
        o = r["overall"]
        lines.append(f"| {r['condition']} | {o['total_flagged_lines']} | {o['incidents']} |")

    lines.append("")
    return "\n".join(lines)


def main(output_dir: str, seed: int, n_seeds: int,
         contamination: float = CONTAMINATION) -> list[dict]:
    work_dir = Path(PROCESSED_DATA_DIR) / "adversarial"
    work_dir.mkdir(parents=True, exist_ok=True)

    conditions = ([("baseline", [])]
                  + [(s, [s]) for s in STRATEGIES]
                  + [("realistic-combo", REALISTIC_COMBO)])

    # Each seed varies both the corpus and the camouflage draw. With only 3
    # instances per scenario a single seed moves in 33% steps, which is far too
    # coarse to call a detection gap -- so pool over several.
    runs: dict[str, list[dict]] = {name: [] for name, _ in conditions}
    for s in range(seed, seed + n_seeds):
        print(f"\n########## seed {s} ##########")
        base_events = build_dataset(seed=s)
        for name, strategies in conditions:
            result = run_condition(name, strategies, base_events, work_dir, s,
                                   contamination=contamination)
            runs[name].append(result)
            o = result["overall"]
            print(f"  {name:<16} line {o['line_detection_rate']:.0%} | "
                  f"instance {o['instance_detection_rate']:.0%}")

    results = [pool(runs[name]) for name, _ in conditions]

    print(f"\n=== pooled over {n_seeds} seeds ===")
    for r in results:
        o = r["overall"]
        print(f"  {r['condition']:<16} line {o['line_detection_rate']:.0%} | "
              f"instance {o['instance_detection_rate']:.0%} "
              f"({o['instances_detected']}/{o['instances']} instances)")

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "adversarial_results.json").write_text(json.dumps(results, indent=2))
    (out / "adversarial_results.md").write_text(render_report(results, n_seeds))
    print(f"\nWrote {out}/adversarial_results.md and .json")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run the adversarial robustness evaluation.")
    parser.add_argument("--output-dir", default="results")
    parser.add_argument("--seed", type=int, default=SYNTHETIC_SEED)
    parser.add_argument("--seeds", type=int, default=5,
                        help="How many consecutive seeds to pool over")
    parser.add_argument("--contamination", type=float, default=CONTAMINATION,
                        help="Override the detector's contamination (Phase 7 retune check)")
    args = parser.parse_args()

    main(args.output_dir, args.seed, args.seeds, contamination=args.contamination)
