"""Hidden-variation test: inject randomised attacks into a cleaned copy of the evidence
and measure whether TrustLine still detects them, and how many false alarms it raises.

usage: python tools/run_variations.py <evidence_dir> <labels.csv> [seeds_per_scenario]
"""
import json
import os
import sys
import tempfile

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from trustline.cli import analyse, load_cfg            # noqa: E402
from trustline.simulate import SCENARIOS, make_variation  # noqa: E402

src, labels = sys.argv[1], sys.argv[2]
n = int(sys.argv[3]) if len(sys.argv) > 3 else 5
cfg = load_cfg(None)
rows = []
with tempfile.TemporaryDirectory() as tmp:
    for sc in SCENARIOS:
        for seed in range(n):
            d = os.path.join(tmp, f"{sc}_{seed}")
            desc = make_variation(src, labels, d, sc, seed)
            _, _, scored, inc, acts, _ = analyse(d, cfg, None, quiet=True)
            lab = pd.read_csv(os.path.join(d, "_labels.csv"))
            m = scored.merge(lab, on=["system", "eid"], how="left")
            truth = m.label.eq("malicious")
            alert = m.level.eq("alert") | m.incident.notna()
            review = m.level.eq("review")
            rows.append({
                "scenario": sc, "seed": seed, "variation": desc,
                "injected": int(truth.sum()),
                "detected_alert": int((alert & truth).sum()),
                "detected_review_only": int((review & ~alert & truth).sum()),
                "false_alarms": int((m.level.eq("alert") & ~truth).sum()),
                "caught": bool((alert & truth).any()),
                "payment_hold": any(s["do"] == "HOLD_PAYMENT" for a in acts for s in a["steps"]),
            })
            print(f"{sc:<22} seed={seed} caught={rows[-1]['caught']!s:<5} "
                  f"{rows[-1]['detected_alert']}/{rows[-1]['injected']} (+{rows[-1]['detected_review_only']} review) "
                  f"FP={rows[-1]['false_alarms']}  | {desc}")
df = pd.DataFrame(rows)
summ = df.groupby("scenario").agg(runs=("seed", "size"), caught=("caught", "sum"),
                                  event_recall=("detected_alert", "sum"), injected=("injected", "sum"),
                                  review_only=("detected_review_only", "sum"),
                                  false_alarms=("false_alarms", "sum"))
summ["event_recall"] = (summ.event_recall / summ.injected).round(3)
print("\n", summ.to_string())
os.makedirs("out", exist_ok=True)
df.to_csv("out/variation_results.csv", index=False)
summ.to_csv("out/variation_summary.csv")
