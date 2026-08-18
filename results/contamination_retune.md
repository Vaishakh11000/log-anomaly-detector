# Contamination Retune: 0.20 vs 0.10 Under Camouflage

**Verdict: keep `CONTAMINATION=0.20`.** The retune is rejected on evidence.

## Why this was tested

The Phase 7 sweep (`evaluation.md` §4) found that `CONTAMINATION=0.10` reaches
the same **100% instance detection** as 0.20 on clean data while flagging 297
lines instead of 699 — **2.4x less noise for the same attacks caught**. Alert
volume is this system's weakest number, so that looked like a free win.

It was not accepted on that basis, because clean-data instance detection says
nothing about how much *evidence* survives per attack. At 0.10, line-level
recall falls 0.86 → 0.40: instances are still detected, but on far fewer lines
each. Phase 5 showed camouflage works by removing or relocating lines. An
instance carried by one surviving line is an instance about to be missed.

So the question was empirical: **does 0.10 still hold up under camouflage?**

## Method

`src/adversarial.py --contamination 0.10 --seeds 5`, identical to the Phase 5
run in every other respect — same strategies, same 5 seeds, same pooling from
summed counts. Only the detector's contamination differs.

## Result

| Condition | Instance detection @0.20 | @0.10 | Δ | Line @0.20 | @0.10 |
|---|---|---|---|---|---|
| baseline | 100% | 100% | +0% | 86% | 40% |
| temporal | 100% | 100% | +0% | 86% | 46% |
| slow | 80% | 80% | +0% | 82% | 35% |
| rephrase | 100% | 100% | +0% | 100% | 84% |
| **mimicry** | **100%** | **93%** | **−7%** | 76% | 34% |
| noise | 100% | 100% | +0% | 82% | 46% |
| volume | 100% | 100% | +0% | 85% | 53% |
| ip_rotate | 84% | 84% | +0% | 84% | 37% |
| **realistic-combo** | **91%** | **87%** | **−4%** | 78% | 49% |

Instance detection is **identical on 7 of 9 conditions**. It degrades on
exactly two — and they are the two that matter most:

- **mimicry** is the only strategy that attacks the *model* rather than a
  threshold or a time window. At 0.20 it never hid a single attack instance,
  only evidence. At 0.10 it hides 3 of 45.
- **realistic-combo** is the closest thing here to a real adversary: slow
  timing, benign-looking wording, padding, and IP rotation together.

Line detection drops sharply everywhere, which is the mechanism: fewer lines
flagged per attack means less redundancy, and camouflage only has to remove
what little is left.

## Conclusion

The clean-data margin was real but illusory as a safety margin — it is exactly
what adversarial conditions consume. Trading 7% of instance detection under the
only model-directed evasion for a quieter alert list is the wrong trade for a
tool whose stated priority is that a missed attack is unrecoverable while a
false positive costs an analyst thirty seconds.

The alert-volume problem stands and is reported honestly in `evaluation.md` §5
(~3.2x the flagged lines and ~13x the incidents of the rule baseline). The fix
is not a lower contamination. Better candidates, none of them attempted:
suppressing singleton incidents that carry no MITRE match, or calibrating the
severity thresholds — both reduce what an analyst *sees* without reducing what
the detector *catches*.

This also generalises past the specific number: **any tuning validated only on
clean data should be re-validated under camouflage before adoption.** Clean-data
instance detection saturates at 100% and hides differences that only appear
once an adversary is subtracting evidence.
