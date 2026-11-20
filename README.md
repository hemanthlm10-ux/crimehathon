# Crimehathon — TrustLine

**CRIMEATHON'26 · Case CR-26-047 · Team Wi-Fight Club.exe · Approach: DEFENSE**

TrustLine detects stolen or misused **integration identities** — API keys, service accounts and storage keys that software uses without a human signing in. It learns how each key normally behaves from its own logs, stitches any deviation across systems into a single incident, and produces the containment playbook: which keys to revoke, which vendor payment to hold before the next run, which export files may still exist, and what data left.

On the supplied case evidence it reconstructs the full TallyBridge campaign (9 Aug → 6 Sep, across 6 systems), including the unapproved bank-detail change on vendor **V-0412** ahead of the 8 Sep payment run — with **0 false alarms** and **241/241** labelled malicious events detected, using no IP blocklist and no hard-coded indicators.

## Repository layout
```
.
├── trustline/                              # the project (code, config, labels, docs)
│   ├── trustline/                          # Python package: loaders, engine, correlate, respond, gate, evaluate, simulate
│   ├── tools/                              # label builder, variation test harness, doc/slide builders
│   ├── config/default.json                 # detection configuration
│   ├── labels/cr26047_labels.csv           # analyst ground truth
│   ├── docs/                               # problem statement, technical report, proof pack, submission PDFs/slides
│   └── README.md                           # detailed technical README
└── drive-download-20261119T060920Z-1-001/  # case evidence files E01–E20 (synthetic)
```

## Quick start
Requires Python 3.10+.
```bash
cd trustline
pip install -r requirements.txt

# Investigate: incidents, playbook and HTML report -> out/
python -m trustline.cli analyse  --evidence "../drive-download-20261119T060920Z-1-001" --out out

# Accuracy vs ground truth and vs baseline approaches
python -m trustline.cli evaluate --evidence "../drive-download-20261119T060920Z-1-001" --labels labels/cr26047_labels.csv --out out

# Prevention replay: what enforcing the learned contracts would have blocked
python -m trustline.cli replay   --evidence "../drive-download-20261119T060920Z-1-001" --labels labels/cr26047_labels.csv
```
On Windows you can run everything at once with `trustline/run_demo.ps1`. Open `trustline/out/report.html` in a browser to view the results.

See [`trustline/README.md`](trustline/README.md) for how it works, configuration options and the unseen-variation tests.

## Safety
TrustLine reads only the supplied synthetic evidence, makes no network connections and never modifies the evidence files. No real credentials are included.
