# Log Anomaly Detector

Finds attacks in system/auth logs **without being told what an attack looks like**,
explains what it found as a chronological story mapped to MITRE ATT&CK techniques,
then measures how much worse it gets when the attacker actively tries to hide.

Runs entirely on your own machine. CPU-only, no GPU, no cloud API, no internet
required after setup.

---

## What it actually does

A conventional SIEM catches attacks by matching rules someone wrote in advance —
"5 failed logins in 60 seconds is a brute force". That works right up until the
attack doesn't match the rule.

This takes a different route:

1. **Parse** raw syslog/auth lines into structured events, masking IPs, ports and PIDs
   so the *shape* of a message matters more than its specific values.
2. **Embed** each templated line into a 384-dim vector with a sentence-transformer,
   so semantically similar log lines land near each other.
3. **Score** each line with a per-user Isolation Forest. Every user gets their own
   baseline of "normal", so a foreign IP isn't automatically suspicious — it's
   suspicious relative to *that user's* habits.
4. **Group** related anomalies into incidents — same user *or* same source IP,
   within a 30-minute window, linked transitively.
5. **Map** each incident to MITRE ATT&CK technique IDs via a fixed lookup table.
6. **Narrate** the incident with a local LLM (phi3 via Ollama), which writes prose
   *only* about techniques the lookup handed it.
7. **Evaluate** everything against a rule-based baseline, and against seven
   camouflage strategies that try to hide the same attacks.

One extra piece that embeddings can't do: an **impossible-travel** check. Because
IPs are masked before embedding, two logins from opposite sides of the world are
literally identical vectors. That one needs a physics check on the raw timestamps
and IPs, running outside the embedding path entirely.

### The LLM never picks the techniques

This matters. The LLM is given a list of ATT&CK matches from the lookup table and
asked to write a narrative about *those*. It never chooses technique IDs itself.
That's deliberate: an LLM asked to name techniques will confidently invent
plausible-sounding IDs that don't apply.

---

## Try it in two minutes

```bash
# 1. install uv (once, globally) if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh
# Windows PowerShell: powershell -c "irm https://astral.sh/uv/install.ps1 | iex"

# 2. clone and enter
git clone <repo-url> && cd log-anomaly-detector

# 3. install dependencies (creates .venv automatically, ~1.5GB, CPU-only torch)
uv sync

# 4. open the dashboard
uv run streamlit run src/dashboard.py
```

**That's it.** Pre-computed results ship with the repo (`data/processed/incidents.json`),
so the dashboard works immediately — no Ollama, no GPU, no waiting.

The dashboard opens **ranked by triage priority**, not chronologically. The first
six rows are the real attacks:

| Row | What it is |
|---|---|
| 🔴 #2 — alice, 10 events, `T1110` `T1548` `T1136` | brute force → privilege escalation → backdoor account |
| 🟠 #91 / #1 / #27 — 6-8 events, `T1110` `T1087` | account enumeration from one IP across many usernames |
| 🔴 #26 — admin, 2 events, `T1021.004` | impossible travel |

Open **#2** and read the narrative — that's the headline feature.

> Run all commands from the repo root. Paths are relative, so running from
> elsewhere gives "No incidents file found".

---

## Running it yourself, end to end

Regenerating from scratch needs [Ollama](https://ollama.com) for the narrative step:

```bash
ollama serve          # separate terminal
ollama pull phi3
```

Then:

```bash
# parse raw logs → structured CSV
uv run python src/preprocessing.py --input data/raw/synthetic.log \
    --output data/processed/parsed.csv --year 2026

# full pipeline: embed → detect → group → map → narrate
uv run python src/pipeline.py --input data/processed/parsed.csv \
    --output data/processed/incidents.json

# faster options:
#   --no-llm        skip narratives entirely (seconds, good for iterating)
#   --narrate-all   narrate every incident (very slow, ~1.5h)
```

**Expect 13-15 minutes** for a full run. phi3 costs roughly a minute per incident
on CPU, so by default only high-severity or multi-event incidents get narrated —
19 of 94, which still covers all 9 real attacks. Tune with `NARRATE_*` in
[`src/config.py`](src/config.py).

### The evaluation tracks

```bash
uv run python src/evaluate.py       # rule baseline vs this system  (~5 min)
uv run python src/adversarial.py    # robustness under camouflage   (~8 min)
uv run python src/export_samples.py # one sample narrative per scenario
```

Both write markdown reports into [`results/`](results/), which already contains
their committed output if you'd rather just read it.

---

## The dataset

`data/raw/synthetic.log` — 751 lines, 5 users, 5 simulated days. Mostly ordinary
noise: routine logins, cron jobs, systemd messages, people mistyping passwords.
Hidden inside are **9 attack instances** across three scenarios:

- **A** — rapid failed passwords → success → `sudo su root` → new user added to sudo
- **B** — normal login, then 15 minutes later a success from a completely different
  IP range (impossible travel)
- **C** — failed logins across many *different* usernames from one IP (enumeration)

Ground truth is in `data/raw/ground_truth.csv`, mapping line numbers to scenario
labels. Attack IPs use RFC 5737 documentation ranges (`203.0.113.0/24` etc.) so
nothing in here can point at a real host.

Synthetic data was a deliberate choice — it guarantees exact ground truth, which
precision/recall depends on. It's also the main limitation; see
[`docs/DESIGN.md`](docs/DESIGN.md).

---

## Results, including the unflattering ones

Measured on the synthetic corpus, pooled over 5 seeds.

**Detection quality — the rule baseline wins on clean data:**

| | Precision | Recall | F1 |
|---|---|---|---|
| Rule-based baseline | 0.99 | 0.94 | **0.96** |
| This system | 0.29 | 0.86 | 0.43 |

Both find **100% of attack instances (9/9)**. The baseline just does it far more
cleanly — 8 incidents versus 94.

That result is real and it's reported as-is. It's also explainable: the corpus is
built from three attack templates, and the baseline's rules were written knowing
all three. The baseline is close to an oracle by construction.

**Under camouflage, it inverts:**

| | Recall, clean | Recall, realistic camouflage |
|---|---|---|
| Rule-based baseline | 0.94 | **0.07** |
| This system | 0.86 | **0.78** |

That's the actual argument. Rules win when you already know the attack. Take that
assumption away and they collapse; the embedding approach degrades gracefully.

**Worst-case robustness:** instance detection falls from 100% to **80%** under the
strongest evasion (spreading attack events over 35-90 minutes, beating the 30-minute
grouping window). All of that loss is in scenario B — which is caught by the
impossible-travel *rule*, not the embeddings. So the measured weakness is the one
hand-written rule in the system, not the model.

Full details in [`results/`](results/):
[`evaluation.md`](results/evaluation.md) ·
[`adversarial_results.md`](results/adversarial_results.md) ·
[`sample_narratives.md`](results/sample_narratives.md)

---

## FAQ

**Why is precision so low?**
Deliberate. `CONTAMINATION=0.20` favours recall because a missed attack is
unrecoverable while a false positive costs an analyst thirty seconds. The severity
ranking and the narratives exist specifically to make false positives cheap to
dismiss. A sweep showed `0.10` would cut alert volume 2.4× at the same instance
detection — it was tested and **rejected**, because it also halves line-level recall,
and camouflage works by removing evidence. See
[`results/contamination_retune.md`](results/contamination_retune.md).

**Isn't this just anomaly detection with extra steps?**
The detection itself is standard Isolation Forest. What isn't standard is grouping
anomalies into incidents, mapping them to ATT&CK, narrating them, and then measuring
how all of that degrades under evasion. Detection is the input, not the contribution.

**Can the LLM hallucinate technique IDs?**
It could, which is why it never picks them — they come from a lookup table and the
LLM only writes prose about matches it's handed.

**Incident #26 only shows one login. Where's the travel?**
Only the *arriving* login gets flagged; the earlier login from the user's usual IP
is ordinary traffic the detector correctly ignores. So the incident shows the
conclusion without the line that produced it. A known display-layer gap — detection
is unaffected.

**Can I run it on my own logs?**
Yes, if they're syslog/auth format. Point `preprocessing.py` at your file. The parser
expects standard `sshd`/`sudo`/`systemd` message shapes; anything else falls through
to a generic template.

---

## Requirements

- Python 3.11+
- [uv](https://docs.astral.sh/uv/) for dependency management
- ~2GB disk (mostly CPU-only PyTorch)
- [Ollama](https://ollama.com) with `phi3` — **only** for regenerating narratives
- No GPU. No internet after `uv sync`.

## Layout

```
data/raw/          synthetic logs + ground truth
data/processed/    parsed CSV + pre-computed incidents (ships with the repo)
results/           evaluation reports
docs/DESIGN.md     why it's built this way
src/
  preprocessing.py     parsing, templating, field extraction
  embedding.py         sentence-transformer vectors
  anomaly_detection.py Isolation Forest, severity tiers, impossible travel
  sequence_grouping.py anomalies → incidents
  mitre_mapping.py     ATT&CK lookup
  llm_narrative.py     Ollama prompts
  pipeline.py          orchestration
  dashboard.py         Streamlit UI
  generate_logs.py     synthetic log + attack generator
  baseline_rules.py    rule-based SIEM  (evaluation only, never imported by pipeline)
  adversarial.py       camouflage generators + robustness metrics
  evaluate.py          precision/recall/F1, ablation, sweeps
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `uv: command not found` | `export PATH="$HOME/.local/bin:$PATH"` |
| "No incidents file found" | Run from the repo root |
| Narratives say `[LLM narrative generation failed]` | `ollama serve` isn't running |
| Streamlit port in use | add `--server.port 8502` |
| `warning: VIRTUAL_ENV ... does not match` | Harmless — another venv is active; uv uses the right one |

## License

MIT — see [LICENSE](LICENSE).
