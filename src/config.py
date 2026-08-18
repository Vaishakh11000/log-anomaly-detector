"""
config.py
Central configuration. All tunable values live here so they aren't
scattered as magic numbers across modules -- makes tuning sessions fast
and keeps values from drifting apart across modules.
"""

# --- Embedding ---
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
EMBEDDING_BATCH_SIZE = 64

# --- Anomaly detection ---
CONTAMINATION = 0.20          # tuned in Phase 3 against synthetic ground truth --
                               # see Decision Log: 0.05 gave P=0.62/R=0.36, 0.20 gave
                               # P=0.30/R=0.87. Favors recall: this is an analyst-triage
                               # tool (severity tiers + narrative manage the FP volume),
                               # and a missed attack is worse than an extra alert.
MIN_SAMPLES_PER_USER = 5      # below this, fall back to the global baseline
RANDOM_STATE = 42

# Severity thresholds applied to the (negated) anomaly score.
# Higher value = more anomalous. Tune these in Phase 3 against your ground truth.
SEVERITY_THRESHOLDS = {
    "high": 0.15,
    "medium": 0.05,
    "low": 0.0,
}

# --- Impossible travel check (Phase 3) ---
IMPOSSIBLE_TRAVEL_WINDOW_MINUTES = 60   # different subnet within this window = suspicious
TRAVEL_SUBNET_PREFIX_LENGTH = 2         # compare first N octets of IPv4 to judge "different region"

# --- Incident grouping ---
INCIDENT_WINDOW_MINUTES = 30
GROUP_BY_SOURCE_IP = True     # Phase 4: also join anomalies sharing a source IP, not just a
                              # user. Account enumeration varies the username on every line by
                              # design, so a user-only grouping split it into N singleton alerts.
# Parser placeholders that are NOT real identities -- never join two anomalies on these.
NON_IDENTITY_VALUES = {"unknown", "none", "n/a", "-", "?"}

# --- MITRE mapping ---
ENUMERATION_MIN_DISTINCT_USERS = 3   # distinct usernames from one source IP before an
                                     # incident counts as account enumeration (T1087)

# --- LLM ---
OLLAMA_URL = "http://localhost:11434/api/generate"
LLM_MODEL = "phi3"            # switch to "llama3" for final demo if speed allows
LLM_TIMEOUT_SECONDS = 180
LLM_NUM_PREDICT = 400         # hard cap on generated tokens. Without it, phi3 rambles past the
                              # timeout on *sparse* prompts (single-event incidents give it little
                              # to anchor on) -- 2/19 incidents failed that way before this cap.
                              # 4-6 sentences fits comfortably in 400 tokens.
LLM_TEMPERATURE = 0.2         # low: narratives should be reproducible for the demo and the report
NARRATIVE_SENTENCE_RANGE = "4-6"
NARRATIVE_MAX_EVENTS = 25     # cap events pasted into one prompt; the rest are summarised

# Which incidents get an LLM narrative. phi3 costs ~40-60s per incident on this
# CPU, so narrating all 94 would run about an hour -- unusable for a demo or an
# iteration loop. Narrating only high-severity or multi-event incidents covers
# every ground-truth attack instance in the synthetic set, and the measured full
# run is 13-15 min for 19 incidents (measured 13m24s and 15m20s).
NARRATE_SEVERITIES = {"high"}
NARRATE_MIN_EVENTS = 2

# --- Synthetic dataset generation (Phase 2) ---
SYNTHETIC_HOST = "server1"
SYNTHETIC_USERS = ["alice", "bob", "carol", "dave", "admin"]
SYNTHETIC_DAYS = 5                    # simulated days the log spans
SYNTHETIC_TOTAL_LINES = 750           # target total line count, incl. attack lines
SYNTHETIC_INSTANCES_PER_SCENARIO = 3  # how many times each of A/B/C occurs
SYNTHETIC_SEED = 42
SYNTHETIC_YEAR = 2026                 # must match --year passed to preprocessing.py

# --- Adversarial camouflage (Phase 5) ---
# Two temporal spreads on purpose, straddling INCIDENT_WINDOW_MINUTES (30): the
# narrow one stays inside the grouping window, the wide one steps past it. The
# pair is what shows the window is the thing doing the work.
CAMOUFLAGE_MIN_GAP_MINUTES = 8
CAMOUFLAGE_MAX_GAP_MINUTES = 20
CAMOUFLAGE_SLOW_MIN_GAP_MINUTES = 35
CAMOUFLAGE_SLOW_MAX_GAP_MINUTES = 90
CAMOUFLAGE_NOISE_RATIO = 1.5   # benign noise lines injected per attack line
CAMOUFLAGE_VOLUME_KEEP = 0.5   # share of repeated mid-sequence attack lines kept
                               # ("low and slow": make less noise, not different noise)

# --- Rule-based baseline (Phase 7 evaluation only) ---
# These drive src/baseline_rules.py, which exists ONLY as the comparison baseline
# for evaluation target #1. It is deliberately the SIEM this project differentiates
# from -- do not wire it into pipeline.py (see docs/DESIGN.md).
BASELINE_BRUTE_FORCE_WINDOW_MINUTES = 5
BASELINE_BRUTE_FORCE_MIN_FAILURES = 3    # N failed passwords for one user in the window
BASELINE_ENUMERATION_WINDOW_MINUTES = 10
BASELINE_ENUMERATION_MIN_USERS = 3       # distinct usernames failing from one source IP
# Substrings a conventional SIEM would alert on. Verified against the synthetic
# corpus: these match attack lines only -- the baseline is not a strawman.
BASELINE_PRIVILEGE_KEYWORDS = (
    "command=/bin/su", "su root", "to group sudo", "to group wheel",
    "useradd", "adduser",
)

# --- Evaluation (Phase 7) ---
EVAL_CONTAMINATION_SWEEP = [0.05, 0.10, 0.15, 0.20, 0.25]
EVAL_SEEDS = 5                # pooled like Phase 5: 9 attack instances move rates in coarse steps

# --- Paths ---
RAW_DATA_DIR = "data/raw"
PROCESSED_DATA_DIR = "data/processed"
DEFAULT_INCIDENTS_PATH = "data/processed/incidents.json"
