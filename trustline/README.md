# TrustLine: behaviour contracts for integration identities

**CRIMEATHON'26 · Case CR-26-047 · Team Wi-Fight Club.exe · Approach: DEFENSE**

TrustLine finds stolen or misused integration keys. These are the API keys, service accounts and storage keys that software uses with nobody signing in. It learns how each key normally behaves, from its own logs. Then it joins any break from that behaviour across systems into one incident, and it outputs the containment steps: which keys to revoke, which vendor payment to hold before the next run, which export files may still exist, and what data left.

On the supplied evidence it reconstructs the whole TallyBridge campaign, 9 Aug → 6 Sep, across 6 systems. That includes the unapproved bank change on **V-0412** before the 8 Sep payment run. Results: 0 false alarms and 241/241 labelled malicious events found. It needs no IP blocklist and contains no hard-coded indicators.

## Why it is different
| The obvious approach | Result on this case | TrustLine |
|---|---|---|
| Block the vendor's indicator list (E17) | finds 28% of malicious events; misses the build host and the BlueVault addresses | learns each key's normal origins, so a new address is suspicious whoever reports it |
| Block the indicators' /24 | 291 false alarms (63 staff use that home-broadband range) | ignores how "bad" an IP looks; checks whether *this key* has ever used it |
| Volume-threshold SIEM rules | 4% recall, 144 false alarms | checks *what* a key does (new operation, new data area, export→erase), not how much |
| "Rotate the keys" (the vendor's answer) | key was still abused on 3 Sep | revokes, then re-issues with a least-privilege contract **generated from the logs** |

Core ideas:
1. **The contract is learned, not written.** For each non-human identity it learns origins, private-link host, client family and version, active hours, operations and data areas. Clean events extend the contract, so upgrades and schedule shifts are absorbed. Violating events are never learned, so an attacker cannot train the baseline.
2. **Cross-system stitching.** Violations are joined using the connected-software register (same vendor), API `request_id` ↔ vendor-change records, private-link host labels, shared public IPs, and *secret searched → secret used* (a ticket search for `bvk-` links to the later misuse of key `bvk-7f3a`).
3. **Money-aware.** Bank-detail changes made through an integration, without an approval ref, or with a recycled or out-of-sequence ref are scored against the next payment run (8th and 23rd), and a hold is generated.
4. **Same contract → prevention.** `replay` enforces the learned contracts as a gateway policy and reports exactly what would have been blocked, including the legitimate traffic it would cost.

## Setup
Requires Python 3.10+.
```bash
pip install -r requirements.txt
```

## Run
The evidence folder is the organisers' `drive-download-…` directory. Files are recognised by **column signature**, not file name, so renamed or new evidence works.
```bash
# 1. Investigate: incidents, playbook, HTML report -> out/
python -m trustline.cli analyse  --evidence "../drive-download-20261119T060920Z-1-001" --out out

# 2. Accuracy vs ground truth, and vs the obvious approaches
python -m trustline.cli evaluate --evidence "../drive-download-20261119T060920Z-1-001" --labels labels/cr26047_labels.csv --out out

# 3. Prevention replay: what enforcing the learned contracts would have blocked
python -m trustline.cli replay   --evidence "../drive-download-20261119T060920Z-1-001" --labels labels/cr26047_labels.csv

# 4. Unseen variations: inject randomised attacks into a cleaned copy and re-test
python tools/run_variations.py "../drive-download-20261119T060920Z-1-001" labels/cr26047_labels.csv 4
```
Windows one-shot: `run_demo.ps1`. Outputs go to `out/`: `report.html` (open in a browser), `incidents.json`, `playbook.json`, `alerts.csv`, `hygiene.csv`, `evaluation.json`, `false_alarms.csv`, `missed.csv`, `variation_summary.csv`.

## Configuration (`config/default.json`)
`warmup_days` (learning period), `helpdesk_tz_offset_minutes` (IST = 330), `storage_clock_skew_seconds`, `payment_run_days`, signal `weights`, `alert_threshold`, `secret_keywords`, and `approved_changes`. The last one is an operator list of announced capability changes. The vendor's 1 Sep contact sync is listed; remove it to see the change flagged.

## Layout
```
trustline/loaders.py    signature-based loading, UTC alignment, host enrichment
trustline/engine.py     learned behaviour contracts + signals + governance checks
trustline/correlate.py  cross-system incident stitching (union-find)
trustline/respond.py    playbook: revoke/re-issue spec, payment holds, orphan exports, exposure
trustline/gate.py       prevention replay
trustline/evaluate.py   scoring vs labels and vs baseline approaches
trustline/simulate.py   randomised attack-variation generator
tools/make_labels.py    analyst ground truth (explicit criteria, independent of the detector)
tools/run_variations.py hidden-variation test harness
docs/                   Tier 1 statement, technical report, proof pack, slides
```

## Safety and scope
TrustLine reads only the supplied synthetic files. It makes no network connections, and it never modifies the evidence: the simulator writes to a temporary copy. No real credentials are included. AI assistance (Claude) was used to help write the code and documents. Every finding was checked against the records, and the record IDs are cited in `docs/`.
