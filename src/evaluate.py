"""
evaluate.py
Phase 7 evaluation: the numbers the report needs.

Produces three things, all written to results/evaluation.md:

  1. Rule-based baseline vs. embedding detector -- precision/recall/F1 at line
     level plus instance detection (evaluation target #1)
  2. An ablation separating the embedding layer from the impossible-travel
     rule, because the shipping system is both and the report must not credit
     one for the other's work (Phase 5 found scenario B is carried by the rule)
  3. A generalisation test: the same two detectors run over camouflaged
     corpora from Phase 5, which is where a keyword rule and a learned
     baseline are supposed to diverge

Plus a contamination sweep, so CONTAMINATION=0.20 stops being an informal call.

Everything is pooled over several seeds with rates recomputed from summed
counts, following the Phase 5 methodology -- 9 attack instances move a rate in
coarse steps, and a single seed misreports.

Usage:
    python src/evaluate.py                 # full run, EVAL_SEEDS seeds
    python src/evaluate.py --seeds 1       # quick pass while iterating
"""

import argparse
import json
import tempfile
from pathlib import Path

import pandas as pd

from adversarial import camouflage_events
from anomaly_detection import PerUserAnomalyDetector, detect_impossible_travel, run_anomaly_detection
from baseline_rules import detect as rule_detect, per_rule_counts
from config import EVAL_CONTAMINATION_SWEEP, EVAL_SEEDS, SYNTHETIC_SEED, SYNTHETIC_YEAR
from embedding import add_embeddings_to_df
from generate_logs import build_dataset, write_outputs
from preprocessing import preprocess_file
from sequence_grouping import group_anomalies

# Camouflage conditions for the generalisation test. Chosen because they attack
# *wording*, which is exactly the axis a keyword rule cannot survive and an
# embedding model can.
CAMOUFLAGE_CONDITIONS = {
    "clean": [],
    "mimicry": ["mimicry"],
    "rephrase": ["rephrase"],
    "realistic-combo": ["slow", "mimicry", "noise", "volume", "ip_rotate"],
}

DETECTOR_LABELS = {
    "rules": "Rule baseline (thresholds + keywords)",
    "rules_travel": "Rule baseline + impossible travel",
    "embeddings": "Embeddings only",
    "travel_rule": "Impossible-travel rule only",
    "full": "Full system (embeddings + rule)",
}

# The baseline the comparison is actually against. `rules` alone can never see
# scenario B, so comparing against it would hand this system a free win on
# instance detection -- any real SIEM has a geo/subnet velocity rule.
FAIR_BASELINE = "rules_travel"


# --- Corpus + detectors ----------------------------------------------------

def build_corpus(seed: int, work_dir: Path, name: str,
                 strategies: list[str] | None = None) -> tuple[str, str]:
    """Generate one synthetic corpus (optionally camouflaged) and write it out."""
    events = build_dataset(seed=seed)
    if strategies:
        events = camouflage_events(events, strategies, seed)
    log_path = work_dir / f"{name}.log"
    gt_path = work_dir / f"{name}_ground_truth.csv"
    write_outputs(events, str(log_path), str(gt_path))
    return str(log_path), str(gt_path)


def prepare(log_path: str, parsed_csv: str) -> pd.DataFrame:
    """Parse + embed once; every detector then scores the same frame."""
    df = preprocess_file(log_path, parsed_csv, year=SYNTHETIC_YEAR)
    return add_embeddings_to_df(df, template_col="template")


def predictions(df: pd.DataFrame, contamination: float | None = None) -> dict:
    """Boolean prediction Series per detector, all on the same parsed frame."""
    scored = (run_anomaly_detection(df) if contamination is None
              else run_anomaly_detection(df, contamination=contamination))
    rules = rule_detect(df)
    return {
        "rules": rules["is_anomaly"],
        "rules_travel": rules["is_anomaly"] | scored["impossible_travel"],
        "embeddings": scored["ml_anomaly"],
        "travel_rule": scored["impossible_travel"],
        "full": scored["is_anomaly"],
    }, scored, rules


# --- Metrics ---------------------------------------------------------------

def count(pred: pd.Series, gt: pd.DataFrame, n_lines: int) -> dict:
    """Raw confusion counts against ground-truth attack line numbers.

    Counts, not rates: pooling across seeds sums these and recomputes the
    rates, so a seed with fewer attack lines doesn't get equal weight.
    """
    if len(pred) != n_lines:
        raise AssertionError(
            f"{len(pred)} parsed rows vs {n_lines} log lines -- ground-truth "
            "line numbers would be misaligned")

    pred = pred.reset_index(drop=True)
    attack_rows = gt.assign(hit=gt["line_number"].map(lambda n: bool(pred.iloc[n - 1])))
    instances = attack_rows.groupby(["scenario", "instance"])["hit"].any()

    tp = int(attack_rows["hit"].sum())
    flagged = int(pred.sum())
    return {
        "tp": tp,
        "fp": flagged - tp,
        "fn": int(len(attack_rows) - tp),
        "flagged": flagged,
        "attack_lines": int(len(attack_rows)),
        "instances": int(len(instances)),
        "instances_detected": int(instances.sum()),
        "per_scenario": {
            scenario: {
                "tp": int(rows["hit"].sum()),
                "attack_lines": int(len(rows)),
                "instances": int(rows.groupby("instance")["hit"].any().shape[0]),
                "instances_detected": int(rows.groupby("instance")["hit"].any().sum()),
            }
            for scenario, rows in attack_rows.groupby("scenario")
        },
    }


def rates(counts: dict) -> dict:
    """precision / recall / F1 from summed counts."""
    tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    instances = counts["instances"]
    return {
        **counts,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "instance_detection_rate": round(counts["instances_detected"] / instances, 3) if instances else 0.0,
    }


_SUMMED = ["tp", "fp", "fn", "flagged", "attack_lines", "instances", "instances_detected"]


def pool(runs: list[dict]) -> dict:
    """Sum counts across seeds, then recompute rates once."""
    totals = {k: sum(r[k] for r in runs) for k in _SUMMED}
    scenarios = sorted({s for r in runs for s in r["per_scenario"]})
    totals["per_scenario"] = {}
    for scenario in scenarios:
        rows = [r["per_scenario"][scenario] for r in runs if scenario in r["per_scenario"]]
        summed = {k: sum(row[k] for row in rows)
                  for k in ["tp", "attack_lines", "instances", "instances_detected"]}
        totals["per_scenario"][scenario] = {
            **summed,
            "line_detection_rate": round(summed["tp"] / summed["attack_lines"], 3) if summed["attack_lines"] else 0.0,
            "instance_detection_rate": round(summed["instances_detected"] / summed["instances"], 3) if summed["instances"] else 0.0,
        }
    per_scenario = totals.pop("per_scenario")
    pooled = rates(totals)
    pooled["per_scenario"] = per_scenario
    return pooled


# --- Experiments -----------------------------------------------------------

def run_seed(seed: int, work_dir: Path) -> dict:
    """One seed: clean corpus through every detector, plus camouflaged corpora."""
    out = {"detectors": {}, "camouflage": {}, "sweep": {}, "rule_counts": {}, "volume": {}}

    for condition, strategies in CAMOUFLAGE_CONDITIONS.items():
        name = f"s{seed}_{condition}"
        log_path, gt_path = build_corpus(seed, work_dir, name, strategies)
        df = prepare(log_path, str(work_dir / f"{name}_parsed.csv"))
        gt = pd.read_csv(gt_path)
        n_lines = sum(1 for _ in open(log_path))

        preds, scored, rules = predictions(df)
        scores = {d: count(p, gt, n_lines) for d, p in preds.items()}

        if condition == "clean":
            out["detectors"] = scores
            out["rule_counts"] = per_rule_counts(rules)
            out["volume"] = {
                "log_lines": n_lines,
                "rule_incidents": len(group_anomalies(scored[preds[FAIR_BASELINE]])),
                "full_incidents": len(group_anomalies(scored[scored["is_anomaly"]])),
            }
            # contamination sweep reuses the embeddings already computed
            for c in EVAL_CONTAMINATION_SWEEP:
                swept, _, _ = predictions(df, contamination=c)
                out["sweep"][str(c)] = count(swept["full"], gt, n_lines)
        else:
            out["camouflage"][condition] = {
                d: scores[d] for d in ("rules", "rules_travel", "embeddings", "full")}

    return out


def aggregate(seed_results: list[dict]) -> dict:
    detectors = {d: pool([r["detectors"][d] for r in seed_results])
                 for d in DETECTOR_LABELS}
    camouflage = {
        condition: {
            d: pool([r["camouflage"][condition][d] for r in seed_results])
            for d in seed_results[0]["camouflage"][condition]
        }
        for condition in seed_results[0]["camouflage"]
    }
    sweep = {c: pool([r["sweep"][c] for r in seed_results])
             for c in seed_results[0]["sweep"]}
    rule_counts = {name: sum(r["rule_counts"][name] for r in seed_results)
                   for name in seed_results[0]["rule_counts"]}
    volume = {k: sum(r["volume"][k] for r in seed_results) // len(seed_results)
              for k in seed_results[0]["volume"]}
    return {"detectors": detectors, "camouflage": camouflage, "sweep": sweep,
            "rule_counts": rule_counts, "volume": volume, "n_seeds": len(seed_results)}


# --- Report ----------------------------------------------------------------

def _pct(x: float) -> str:
    return f"{x * 100:.0f}%"

def render_report(agg: dict) -> str:
    d = agg["detectors"]
    n = agg["n_seeds"]
    base = d[FAIR_BASELINE]
    full, embeddings, travel = d["full"], d["embeddings"], d["travel_rule"]

    lines = [
        "# Evaluation",
        "",
        "Generated by `src/evaluate.py`. Every detector scores the **same** parsed",
        "and embedded corpus, so any difference is the detector, not the data.",
        "",
        f"Pooled over **{n} seed(s)**. Precision/recall/F1 are recomputed from summed",
        "confusion counts rather than averaged across seeds -- with 9 attack instances",
        "per corpus, per-seed rates move in coarse steps and averaging them misreports.",
        "",
        "Line level: every ground-truth attack line is a positive.  ",
        "Instance level: an attack instance counts as detected if *any* of its lines",
        "was flagged -- i.e. would an analyst see the attack at all.",
        "",
        "## 1. Rule-based baseline vs. embedding detector",
        "",
        "| Detector | Precision | Recall | F1 | Instance detection | Lines flagged |",
        "|---|---|---|---|---|---|",
    ]
    for key in ["rules", "rules_travel", "embeddings", "travel_rule", "full"]:
        m = d[key]
        lines.append(
            f"| {DETECTOR_LABELS[key]} | {m['precision']:.2f} | {m['recall']:.2f} | "
            f"{m['f1']:.2f} | {_pct(m['instance_detection_rate'])} | {m['flagged']} |")

    lines += [
        "",
        "The comparison that counts is **rule baseline + impossible travel** vs. the",
        "**full system**. Giving the baseline the same physics rule the pipeline has is",
        "the fair matchup: every real SIEM has a subnet-velocity rule, and withholding",
        "it would hand this system a free win on scenario B.",
        "",
        "### Read this result honestly",
        "",
        f"On this corpus the rule baseline **beats** the embedding system on every",
        f"headline metric: precision {base['precision']:.2f} vs {full['precision']:.2f}, recall",
        f"{base['recall']:.2f} vs {full['recall']:.2f}, F1 {base['f1']:.2f} vs {full['f1']:.2f}. Instance",
        f"detection ties at {_pct(base['instance_detection_rate'])} / {_pct(full['instance_detection_rate'])}.",
        "",
        "That is not a flattering number and it should not be buried. It also should",
        "not be over-read, because the baseline is close to an *oracle* here:",
        "",
        "- The synthetic corpus is built from exactly three attack templates.",
        "- The baseline's thresholds and keywords were written knowing those templates.",
        "",
        "A rule that encodes the attack it is scored on will approach perfect precision",
        "by construction. The number to take from this section is therefore not \"rules",
        "win\" but \"**rules win when you already know the attack**\" -- which is precisely",
        "the assumption section 3 removes.",
        "",
        "### What each baseline rule contributed",
        "",
        "| Rule | Lines claimed (all seeds) |",
        "|---|---|",
    ]
    for name, c in agg["rule_counts"].items():
        lines.append(f"| {name} | {c} |")

    lines += [
        "",
        "### Per scenario",
        "",
        "| Scenario | Baseline line recall | Full-system line recall | Baseline instances | Full-system instances |",
        "|---|---|---|---|---|",
    ]
    for scenario in sorted(base["per_scenario"]):
        b, f = base["per_scenario"][scenario], full["per_scenario"][scenario]
        lines.append(
            f"| {scenario} | {_pct(b['line_detection_rate'])} | {_pct(f['line_detection_rate'])} | "
            f"{_pct(b['instance_detection_rate'])} | {_pct(f['instance_detection_rate'])} |")

    lines += [
        "",
        "## 2. Ablation: what the embeddings actually contribute",
        "",
        "The shipping system is an embedding model OR-ed with one hand-written physics",
        "rule. Reported as a single number, each layer takes credit for the other's",
        "work, so they are separated here.",
        "",
        "| Layer | Precision | Recall | F1 | Instance detection |",
        "|---|---|---|---|---|",
    ]
    for key in ["embeddings", "travel_rule", "full"]:
        m = d[key]
        lines.append(f"| {DETECTOR_LABELS[key]} | {m['precision']:.2f} | {m['recall']:.2f} | "
                     f"{m['f1']:.2f} | {_pct(m['instance_detection_rate'])} |")

    b_embed = embeddings["per_scenario"].get("B", {})
    b_full = full["per_scenario"].get("B", {})
    lines += [
        "",
        "Scenario B is the row to read carefully. The embedding layer alone detects",
        f"**{_pct(b_embed.get('instance_detection_rate', 0))}** of impossible-travel instances; with the rule the full",
        f"system reaches **{_pct(b_full.get('instance_detection_rate', 0))}**. The embeddings contribute nothing there.",
        "",
        "That gap is by design, not a defect: `template_message()` masks IPs before",
        "embedding, so the two legs of an impossible-travel login are textually",
        "identical and embed to the same vector. No semantic model can separate them.",
        "It does mean **the report must not claim embedding-based detection catches",
        "impossible travel** -- the rule catches it, and Phase 5 showed the rule is also",
        "where the adversarial fragility lives.",
        "",
        "Conversely, the rule alone is nearly useless on its own",
        f"(F1 {travel['f1']:.2f}, {_pct(travel['instance_detection_rate'])} of instances): it sees one scenario and is blind",
        "to the other two. Neither layer is sufficient.",
        "",
        "## 3. Generalisation: the same detectors under camouflage",
        "",
        "Section 1 scores both detectors on attacks phrased the way they were written.",
        "This section re-runs them on the Phase 5 camouflaged corpora, where the attack",
        "*behaviour* is unchanged but its surface form is not. This is the comparison",
        "the project exists to make.",
        "",
        "| Condition | Baseline recall | Baseline F1 | Full-system recall | Full-system F1 |",
        "|---|---|---|---|---|",
        f"| _clean (section 1)_ | {base['recall']:.2f} | {base['f1']:.2f} | "
        f"{full['recall']:.2f} | {full['f1']:.2f} |",
    ]
    for condition, per_detector in agg["camouflage"].items():
        b, f = per_detector[FAIR_BASELINE], per_detector["full"]
        lines.append(f"| {condition} | {b['recall']:.2f} | {b['f1']:.2f} | "
                     f"{f['recall']:.2f} | {f['f1']:.2f} |")

    mimicry = agg["camouflage"]["mimicry"]
    rephrase = agg["camouflage"]["rephrase"]
    combo = agg["camouflage"]["realistic-combo"]
    lines += [
        "",
        f"**rephrase** (novel wording, identical behaviour): baseline recall",
        f"{base['recall']:.2f} -> {rephrase[FAIR_BASELINE]['recall']:.2f}, full system {full['recall']:.2f} -> {rephrase['full']['recall']:.2f}.",
        "Rewording defeats a keyword rule by construction. It makes an outlier detector",
        "*more* confident, because unusual phrasing is exactly what it responds to.",
        "",
        f"**realistic-combo** (slow timing + mimicry + noise + volume + IP rotation):",
        f"baseline recall collapses to {combo[FAIR_BASELINE]['recall']:.2f} while the full system holds at",
        f"{combo['full']['recall']:.2f}. The mechanism is not subtle -- the 35-90 min gaps exceed both the",
        "5-min brute-force window and the 10-min enumeration window, and mimicry rewrites",
        "the one line the keyword rule was watching. Every threshold the baseline depends",
        "on is a number an attacker can simply stay under.",
        "",
        f"**mimicry** (attack lines rewritten as the dominant benign template) is the",
        "only condition where the two degrade comparably: baseline recall falls by",
        f"{base['recall'] - mimicry[FAIR_BASELINE]['recall']:.2f} to {mimicry[FAIR_BASELINE]['recall']:.2f}, the full system by "
        f"{full['recall'] - mimicry['full']['recall']:.2f} to {mimicry['full']['recall']:.2f}. Moving lines toward the",
        "centre of the learned distribution is the correct attack on an outlier",
        "detector and it lands -- this is the one strategy that does not simply exploit",
        "a threshold. Note it is not a *bigger* drop than the baseline's; it is just the",
        "only drop the baseline survives too.",
        "",
        "So the two approaches fail on opposite inputs. That is the defensible claim",
        "this evaluation supports -- not that embeddings are better, but that they",
        "degrade gracefully where rules fall off a cliff, and that the pairing covers",
        "more than either alone.",
        "",
        "## 4. Contamination sweep",
        "",
        "`CONTAMINATION` was set to 0.20 in Phase 3 from an informal sweep on a single",
        "corpus. Repeated properly here, pooled across seeds:",
        "",
        "| contamination | Precision | Recall | F1 | Instance detection | Lines flagged |",
        "|---|---|---|---|---|---|",
    ]
    for c in EVAL_CONTAMINATION_SWEEP:
        m = agg["sweep"][str(c)]
        marker = " **(current)**" if abs(c - 0.20) < 1e-9 else ""
        lines.append(f"| {c}{marker} | {m['precision']:.2f} | {m['recall']:.2f} | {m['f1']:.2f} | "
                     f"{_pct(m['instance_detection_rate'])} | {m['flagged']} |")

    best_f1 = max(EVAL_CONTAMINATION_SWEEP, key=lambda c: agg["sweep"][str(c)]["f1"])
    full_inst = [c for c in EVAL_CONTAMINATION_SWEEP
                 if agg["sweep"][str(c)]["instance_detection_rate"] >= 1.0]
    lines += [
        "",
        f"Best F1 in the sweep is at contamination={best_f1}. "
        + (f"The lowest setting that still detects every attack instance is {min(full_inst)}."
           if full_inst else "No setting in the sweep detects every attack instance."),
        "",
        "F1 is the wrong thing to optimise here, and the table shows why: it weights a",
        "false positive and a missed attack equally. This is an analyst-triage tool --",
        "severity tiers and the LLM narrative exist to make false positives cheap to",
        "dismiss, while a missed attack is unrecoverable. Instance detection is the",
        "metric that matches how the tool is used, and it is what 0.20 was chosen for.",
        "",
        "### The sweep does not vindicate 0.20",
    ]
    if full_inst:
        cheapest = min(full_inst)
        cheap, current = agg["sweep"][str(cheapest)], agg["sweep"]["0.2"]
        if cheapest < 0.20:
            lines += [
                "",
                f"contamination={cheapest} reaches the same {_pct(cheap['instance_detection_rate'])} instance detection as",
                f"0.20 while flagging {cheap['flagged']} lines instead of {current['flagged']} -- "
                f"**{current['flagged'] / max(cheap['flagged'], 1):.1f}x less noise for the same",
                "attacks caught**, on clean data.",
                "",
                "It is deliberately *not* adopted here, for one reason: line-level recall",
                f"falls {current['recall']:.2f} -> {cheap['recall']:.2f}, meaning far fewer lines survive per attack.",
                "Instance detection at 100% with thin evidence is fragile in exactly the way",
                "Phase 5 measured -- camouflage removes lines, and an instance detected by a",
                "single line becomes an instance missed. The clean-data margin is real but",
                "it is the margin that adversarial conditions consume first.",
                "",
                f"Adopting {cheapest} would therefore require re-running the Phase 5 robustness",
                "evaluation at that setting before the number could be trusted. That is the",
                "correct next experiment, not a change to make on this table alone.",
            ]
        else:
            lines += ["", f"contamination={cheapest} is the lowest setting reaching full instance "
                          "detection, which is at or above the current setting."]
    lines += [
        "",
        "## 5. Alert volume",
        "",
        "Precision understates the practical cost, so here it is directly",
        f"(per corpus of ~{agg['volume']['log_lines']} lines, averaged over seeds):",
        "",
        "| Detector | Lines flagged | Incidents after grouping |",
        "|---|---|---|",
        f"| {DETECTOR_LABELS[FAIR_BASELINE]} | {base['flagged'] // n} | {agg['volume']['rule_incidents']} |",
        f"| {DETECTOR_LABELS['full']} | {full['flagged'] // n} | {agg['volume']['full_incidents']} |",
        "",
        f"The full system produces about {full['flagged'] / max(base['flagged'], 1):.1f}x the flagged lines and",
        f"{agg['volume']['full_incidents'] / max(agg['volume']['rule_incidents'], 1):.0f}x the incidents. This is the real cost of the recall-favouring",
        "contamination setting, and the strongest argument for the narrative layer:",
        "grouping and severity tiers are what make that volume triageable instead of",
        "useless. It is also this system's weakest number and should be stated as such.",
        "",
        "## Threats to validity",
        "",
        "- **The corpus is synthetic and self-authored.** Both the attacks and the",
        "  baseline rules come from the same three templates, which inflates baseline",
        "  precision in section 1 and would not transfer to real logs.",
        "- **The camouflage is self-authored too.** No independent red team wrote these",
        "  evasions, so section 3 measures robustness to attacks this project thought of.",
        f"- **The eval set is small**: {base['instances'] // n} attack instances and ~{base['attack_lines'] // n} attack lines per corpus,",
        f"  pooled over {n} seeds. Rates are coarse; small differences are not meaningful.",
        "- **Precision is measured against attack lines only.** A flagged benign line is",
        "  a false positive even if it was genuinely unusual, so precision here is a",
        "  lower bound on analyst-perceived usefulness.",
        "",
    ]
    return "\n".join(lines)
def main(output_dir: str = "results", seeds: int = EVAL_SEEDS,
         start_seed: int = SYNTHETIC_SEED, render_only: bool = False) -> dict:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    if render_only:
        # re-render prose from the last run's counts; no detection re-run
        agg = json.loads((out_dir / "evaluation.json").read_text())
    else:
        seed_results = []
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp)
            for i in range(seeds):
                seed = start_seed + i
                print(f"\n=== seed {seed} ({i + 1}/{seeds}) ===", flush=True)
                seed_results.append(run_seed(seed, work_dir))
        agg = aggregate(seed_results)
    (out_dir / "evaluation.json").write_text(json.dumps(agg, indent=2, default=str))
    (out_dir / "evaluation.md").write_text(render_report(agg))
    print(f"\nWrote {out_dir / 'evaluation.md'} and {out_dir / 'evaluation.json'}")

    d = agg["detectors"]
    print("\n--- headline ---")
    for key in DETECTOR_LABELS:
        m = d[key]
        print(f"{DETECTOR_LABELS[key]:38s} P={m['precision']:.2f} R={m['recall']:.2f} "
              f"F1={m['f1']:.2f} instances={_pct(m['instance_detection_rate'])}")
    return agg


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 7 evaluation: baseline vs embeddings.")
    parser.add_argument("--output-dir", default="results")
    parser.add_argument("--seeds", type=int, default=EVAL_SEEDS,
                        help="number of seeds to pool over")
    parser.add_argument("--seed", type=int, default=SYNTHETIC_SEED, help="first seed")
    parser.add_argument("--render-only", action="store_true",
                        help="re-render the report from the last evaluation.json without re-running detection")
    args = parser.parse_args()

    main(args.output_dir, seeds=args.seeds, start_seed=args.seed,
         render_only=args.render_only)
