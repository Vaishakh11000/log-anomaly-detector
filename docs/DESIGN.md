# Design Notes

Why the system is built the way it is. Most of these were decisions with real
alternatives, and several were forced by measurements that contradicted the
original plan.

---

## Detection

### Per-user baselines, not a global model

A global model learns "logins from unusual IPs are suspicious", which is wrong —
it flags every travelling user and every new office. Per-user Isolation Forests
learn what's normal *for that account*, so the question becomes "unusual for
alice", not "unusual in general".

### Impossible travel is a rule, not a feature

`template_message()` masks IPs before embedding. That means the two legs of an
impossible-travel login are **literally identical vectors** — semantically
indistinguishable by design.

So the check can't live in the embedding path. It runs on the raw, pre-mask
`source_ip` and `timestamp` columns, and ORs its verdict into the ML score
(`is_anomaly |= impossible_travel`, severity forced to high).

This is an honest limitation, stated plainly: **the embeddings contribute nothing
to detecting impossible travel.** Scenario B's robustness is the rule's robustness.

### Contamination is set to 0.20, favouring recall

A line-level sweep:

| contamination | precision | recall | F1 |
|---|---|---|---|
| 0.05 | 0.62 | 0.36 | 0.45 |
| 0.10 | 0.31 | 0.42 | 0.36 |
| 0.15 | 0.33 | 0.67 | 0.44 |
| **0.20** | **0.30** | **0.87** | **0.45** |

This is an analyst-triage tool, not an auto-blocker. A missed attack is
unrecoverable; a false positive costs someone thirty seconds. 0.20 is where
scenario A's brute-force burst actually started getting caught (6/18 → 15/18 lines)
without further F1 gain past it.

### The 0.10 retune was tested and rejected — this is the most important finding here

A later sweep showed `CONTAMINATION=0.10` reaching the same 100% instance detection
with **2.4× fewer flagged lines** (297 vs 699). On clean data it looked strictly
better.

It was re-run under camouflage before adopting. Results:

- identical to 0.20 on 7 of 9 camouflage conditions
- **`mimicry`: 100% → 93%**
- **`realistic-combo`: 91% → 87%**

Mimicry is the only strategy that attacks the *model* rather than a threshold, and
at 0.20 it had never hidden a whole instance. At 0.10 it hides 3 of 45.

The mechanism: 0.10 halves line-level recall (0.86 → 0.40). Camouflage works by
*subtracting evidence*, so thin evidence is what it eats first. The 2.4× alert-volume
saving was real — but it was the safety margin.

> **General lesson: any tuning validated only on clean data must be re-validated
> under camouflage. Clean instance detection saturates at 100% and hides exactly
> this.**

Details in [`../results/contamination_retune.md`](../results/contamination_retune.md).

---

## Grouping

### Two axes — user OR source IP, linked transitively

Grouping strictly by user scattered enumeration attacks into singletons, because
enumeration deliberately varies the username on every line. Incidents now join if
they're within the 30-minute window and share **either** the same user **or** the
same source IP, linked via union-find.

Measured effect: 111 → 94 incidents, and all 9 ground-truth attack instances land
in exactly one incident each.

Note the precise claim: **9 instances across 8 distinct incidents.** Scenario A
instances 1 and 3 both target `alice` 27 minutes apart and correctly merge into one
incident. It is not "9 instances → 9 incidents".

### Parser placeholders are never joinable identities

22 of 130 anomalies are user-less systemd noise where the parser writes `unknown`.
Joining on `user == "unknown"` merged unrelated lines into a fabricated "incident" —
`unknown` is the parser reporting *absence*, not an identity. Hence `NON_IDENTITY_VALUES`.

---

## MITRE mapping

### A fixed lookup table, not LLM free-association

An LLM asked to name ATT&CK techniques will confidently produce plausible IDs that
don't apply. The table is retrieval, not generation — it can be wrong, but it can't
hallucinate.

### `"ssh"` had to be removed from the T1021 keyword list

`"ssh"` substring-matched the `ssh2` suffix on *every* sshd line, so every ordinary
failed password was tagged Lateral Movement. The grounding table was feeding the LLM
a false premise, and the narratives duly described lateral movement that never
happened. Same problem with `"cron"` matching every benign hourly CRON line as
Persistence.

Grounded generation only helps if the grounding is correct.

### Some techniques are invisible per-line

No single "Failed password for guest" line is enumeration — it's enumeration only in
aggregate. So mapping has an incident-level layer driven by structural signals:
impossible-travel flag → T1021.004; ≥3 distinct usernames from one source IP → T1087.
Still retrieval-based, just over patterns keywords can't express.

---

## LLM narrative

### Missing fields are omitted, never serialised as `"nan"`

`sudo`/`usermod` lines legitimately have no `source_ip`, and `astype(str)` on `NaN`
yields the literal string `"nan"`. phi3 treated it as a real value and fabricated
detail around it — a saved narrative once read *"elevating privileges … by switching
to root user with 'nan'"*.

A formatting slip became a hallucinated fact in a report artifact, which is precisely
the failure mode the grounded-lookup design exists to prevent. Missing fields are now
dropped from the prompt entirely.

### `num_predict=400`, `temperature=0.2`

Two of 19 incidents hit the 180s timeout on the first full run — and both were
*single-event* incidents, the sparsest prompts, while a 10-event one finished fine.
Given little to anchor on, phi3 keeps generating until something kills it. Capping
output tokens fixed both. Raising the timeout would have hidden an unbounded
generation instead of bounding it.

### Only some incidents get narrated

~60s/incident on CPU means narrating all 94 takes ~1.5 hours. The policy (high
severity **or** ≥2 events) narrates 19, takes 13-15 minutes, and still covers all 9
real attack instances. The 75 skipped are singleton false positives.

---

## Evaluation

### The baseline is given the impossible-travel rule too

The pipeline's travel rule is the only thing that detects scenario B. Comparing
against a baseline *without* it would have handed this system a free 100%-vs-67%
win on instance detection derived from a rule both systems have. Every real SIEM has
a subnet-velocity rule; withholding it would be a strawman.

### The baseline wins on clean data, and that's reported as the headline

F1 0.96 vs 0.43. Burying it would be dishonest. It's also explainable rather than
damning: the corpus is built from three attack templates and the baseline's rules
were written knowing them, so the baseline is near-oracle by construction.

The defensible claim isn't "embeddings win" — it's **"rules win when you already know
the attack"**, which the camouflage evaluation then removes.

### Camouflage is applied to events, not to the finished log file

Camouflage shifts timestamps and injects lines, so ground-truth *line numbers* stop
being stable. Transforming the event list instead keeps each attack line bound to its
scenario/instance label through the transformation. Both corpora then run the
identical preprocess → embed → detect chain, so the numbers describe the system that
actually ships.

### Results are pooled over 5 seeds, recomputed from summed counts

With 3 instances per scenario, a single seed moves instance detection in 33% steps.
Observed directly: `ip_rotate` reads 100% at seed 42 alone but 84% pooled over 5. A
single-seed number would have reported no effect where a real 16% drop exists.

### Both `rephrase` and `mimicry` are kept, and rephrasing *helps* detection

The first implementation only had `rephrase` (novel wording), which made every
condition look *more* detectable — a nonsense result that came from the camouflage,
not the detector: rare templates are exactly what an outlier detector flags.

`mimicry` (benign wording) was added as its opposite. Reporting only the strategy that
flatters the system would be dishonest; reporting only the one that beats it would be
too. The pair is the actual finding — wording attacks help or hurt depending on which
direction they move a line relative to the learned distribution.

### Two temporal spreads, one of which is a control

The original 8-20 minute spread produced 0% change and looked like "robust to timing
attacks". It wasn't robust — the gaps simply never left the 30-minute grouping window.
A second spread (35-90 min) straddles it. The narrow one is retained explicitly as the
control that proves the *window*, not the timing, is what matters.

---

## Non-goals

Deliberately out of scope, not oversights:

- **Auto-response / blocking (SOAR).** This is decision support for an analyst. It
  may recommend; it must never act.
- **Many hand-written detection rules.** That recreates the SIEM this project is
  measured against. Rules are limited to physics-based impossibility checks.
- **A full ATT&CK ontology.** The small lookup table is intentional.
- **Multi-source correlation, real-time streaming, fine-tuning.** Scope boundaries
  for a CPU-only, single-log-source system.
- **`baseline_rules.py` is never imported by the pipeline.** Measuring yourself with
  code you also depend on is how benchmarks lie.

---

## Known limitations

- **Precision is 0.29** and the system produces ~13× the incidents of the rule
  baseline. This is the weakest number. Contamination is *not* the lever (see above).
  Untried candidates: suppressing singleton incidents with no MITRE match,
  recalibrating severity thresholds.
- **The baseline's near-perfect clean precision is partly an artifact** of the corpus
  being built from the same three attack templates the rules encode. The honest fix is
  a public dataset where the rules have no oracle advantage.
- **Severity tiers don't cleanly separate precision by tier** at contamination 0.20 —
  medium is actually noisier than low. Informal calls against a 45-line ground truth,
  not calibrated numbers.
- **Impossible-travel incidents show the conclusion without the evidence.** Only the
  arriving login is flagged and grouped; the earlier login it was compared against is
  benign, so it's never flagged and never carried in. Display-layer gap; detection is
  unaffected.
- **Synthetic data.** Guarantees ground truth and reliable reproduction, but the
  attacks and the baseline rules share an author, which inflates the baseline.

---

## Dataset spec

- ~750 lines, 5 users, 5 simulated days
- Majority benign: routine logins at plausible hours, cron, systemd, occasional
  isolated failed password (typos are normal — the baseline needs to learn this)
- 3 instances each of scenarios A/B/C → 9 attack instances, 45 labelled lines
- Attack source IPs use RFC 5737 documentation ranges (`203.0.113.0/24`,
  `198.51.100.0/24`, `192.0.2.0/24`) — never routable, so the log can't reference a
  real host while still reading as plausible attacker infrastructure

`sudo`/`usermod` lines use a simplified `user=<name>` field rather than real sudo's
`TTY=...; USER=root; COMMAND=...` format, because the real format's `USER=root`
(the *target* user) gets misparsed as the *actor*, attributing privilege escalation
to "root" and splitting scenario A across two users during grouping.
