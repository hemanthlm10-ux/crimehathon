# CR-26-047 Proof Pack: TrustLine (Defense)

## 1. How to reproduce (about 3 minutes)
```bash
pip install -r requirements.txt
python -m trustline.cli analyse  --evidence <evidence_dir> --out out
python -m trustline.cli evaluate --evidence <evidence_dir> --labels labels/cr26047_labels.csv --out out
python -m trustline.cli replay   --evidence <evidence_dir> --labels labels/cr26047_labels.csv
python tools/run_variations.py <evidence_dir> labels/cr26047_labels.csv 4
python -I tools/make_labels.py <evidence_dir> labels/cr26047_labels.csv   # regenerate ground truth
```
Deterministic: the same input gives the same output. The variation seeds are fixed (0…n-1).

## 2. Input files and formats (recognised by columns, any file name)
| Role | Required columns | Time basis handled |
|---|---|---|
| API log (E01, E18) | ts_utc, request_id, api_key_id, caller_ip, user_agent, endpoint, method, records_returned, status | UTC |
| Helpdesk audit (E02) | ts_local, event_id, actor, actor_type, action, object_id, source_ip, result, details | IST → UTC (−330 min) |
| SSO (E03) | ts_utc, event_id, user, source_ip, auth_method, mfa_result, … | UTC |
| Storage (E05) | epoch_s, event_id, principal, source_ip, action, path, bytes, result | epoch; skew configurable |
| Private-link flows (E15) | ts_utc, flow_id, src_ip, src_label, dst_system, … | UTC; also used to label API callers |
| Vendor changes (E19) | ts_utc, change_id, vendor_id, field, changed_by, channel, approval_ref, request_id, … | UTC; joined to API by request_id |
| Register (E04, JSON) | integrations[ credential_id, vendor, scope, ip_restriction, token_lifetime_days, last_used, … ] | |
| Roster (E14), indicators (E17), chat (E13) | optional | |
Missing optional files only disable the checks that need them.

## 3. Results on the supplied data
Ground truth comes from `tools/make_labels.py`. These are explicit analyst criteria (specific keys, addresses and records found by manual cross-reading) that the detector never sees. There are 241 malicious rows: ledger 81, helpdesk 52, link 60, storage 44, SSO 3, vendor-master 1. Ten build-host→sandbox flows on 9 Jul and the V-0233 change are labelled *unknown* and left out of scoring.

| Approach | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|
| A. Vendor indicator list (E17) | 67 | 4 | 174 | 0.94 | 0.28 |
| B. Block the indicators' /24 | 112 | **291** | 129 | 0.28 | 0.47 |
| C. Volume > p99.5 | 10 | 144 | 231 | 0.07 | 0.04 |
| **TrustLine, event alert** | 237 | **0** | 4 | 1.00 | 0.98 |
| **TrustLine, incident** | **241** | **0** | **0** | 1.00 | 1.00 |

The 4 events that miss the alert level on their own (the 3 failed sign-ins on a.kapoor and 1 BlueVault read with no recorded IP) are pulled into the incident by correlation.

**Prevention replay.** Contracts were learned on 3–23 Jun and then frozen. Enforcing them blocks **177/177** malicious integration requests and **0** pre-existing legitimate ones. It *would* block the 70 legitimate `write.contact` calls from 1 Sep. That is a new capability the vendor added to an existing key without approval (E16-7). We count it as the cost of enforcement: it needs a change-approval step, which is what policy E10 §2.3 already requires.

## 4. Evidence IDs behind each conclusion
| Conclusion | Records |
|---|---|
| Reconnaissance 9 Aug (vendor says 11–12 Aug only) | E01 req-c28d87e49d, req-ac7784b06, req-237a2dbb88, req-b2408099c8, req-f7324b62a9, req-1c4bd03e6b, req-5a24b86fcc, req-b7f4b937ed |
| Retired client version used by the attacker | E01 user_agent 3.4.1 after 10 Jul; E20-C, E20-E (19–20 Aug posts) |
| Secret hunting, then 10 export→delete cycles | E02 11/08 23:12–00:33 IST, EXP-5410…EXP-5419 (5419 delete *error timeout*); E06 (14 jobs = 4 + 10); E13 12 Aug 09:15 |
| Vendor master and payments exfiltration | E01 req-c35c2ccaff, req-d877f18b6c, req-51b30fba51, req-507360d11e, req-2cb75d3eac; export 9932 never deleted |
| Pasted storage key harvested and used | E13 25 Jun 11:31; E02 TKT-48213, search "bvk-"; E05 bv-dccaa92256 … bv-bc555c47da; E04 bvk-7f3a read:all-folders, no IP limit |
| Build host on the private link | E15 flows src 10.20.4.77 "tb-build-02" 17–19 Aug; E20-B 16 Aug re-provisioning, E20-D build servers |
| Payment-data harvest 17–19 Aug | E01 req-eafb1d40b5 … req-d97c30be81; req-fe4bd4fe93 (4,210 rows), req-ab03db20b8 (delete) |
| **Unauthorised bank change V-0412** | E18 req-15a052a5e, req-93d66fcd5, req-33a3928eca, **req-5f61b0de8** = E19 **chg-8b9888c39b** (API, no approval_ref, 10.20.4.77) |
| Continued interest in the payment run | E18 req-bb819dfe0c (6 Sep) |
| Admin account targeted | E03 sso-74805f5dd1, sso-5e1305b0b4, sso-562f41d2b5 (198.18.7.77 = an E05 address) |
| Keys never rotated or restricted | E04 (2 Sep export), E10 §2, §7, E11 #4–#7, E09 R-031 |

## 5. Errors, false alarms and misses
* **False alarms on the supplied data: 0** at alert level.
* **Review queue: 3 items.** These are human bank changes with no approval ref (m.sundar 9 Jun, f.hegde 20 Jul, g.sethi 4 Aug). They are process lapses, not attacks, and we show them as review rather than alarm on purpose.
* **One alert we cannot classify:** V-0233 (f.dsouza, 20 Aug, APR-1182 about 60 numbers older than refs in use that week). Either a delayed legitimate change or an insider. We hold the payment pending verification and do not claim it is fraud.
* **Correctly left at review:** the 9 Jul build-host→sandbox flows. They fall inside an announced maintenance window, and we cannot tell maintenance from a first touch.

## 6. Hidden-variation testing (attacks we did not see)
`tools/run_variations.py` removes every malicious row, then injects a randomised attack in each file's native format: random key, address, time, version, keywords, folder and vendor. Four seeds per scenario:

| Scenario (what changes vs the reference) | Caught | Event recall | False alarms |
|---|---|---|---|
| Stolen key from a new public IP, **real client UA copied**, sometimes inside the normal window | 4/4 | 1.00 | 0 |
| Rogue host on the private link, **inside the sync window**, current UA, quiet bank change | 4/4 | 1.00 | 0 |
| Service account hunts tickets with **different keywords** + export→delete | 4/4 | 1.00 | 0 |
| Storage key reads a new folder **from its normal IP** | 4/4 | 1.00 | 0 |
| Dormant key wakes up (register says unused for over 180 days) | 4/4 | 1.00 | 0 |
| Staff bank change with a **recycled approval ref** | 4/4 | 1.00 | 0 |
| **Perfect mimic:** real sync host, real UA, in window, normal endpoints | **0/4** | 0.00 | 0 |

*Honesty note:* we wrote these variations ourselves, after building the detector, and we tuned three weights after the first variation round (dormant keys, repeated folder drift, recycled approval refs). The jury's variations will differ.

## 7. Known limitations
1. **Perfect mimicry is invisible.** If an attacker runs only normal reads from a real sync host, in the window, with the real UA, the contract holds. *Next step:* per-run call-count and sequence models, and request signing / mTLS on the private link.
2. **Warm-up assumption.** If the attacker is already active during the first 21 days, their behaviour is learned as normal. E01 keeps only 90 days.
3. **Human accounts are only lightly profiled:** sign-in bursts and bank changes. People roam, and the shared residential range makes IP-based rules unreliable.
4. **New legitimate capabilities raise alerts** unless an operator lists them in `approved_changes`. That is by design, but it costs analyst time.
5. **BlueVault times** carry the unsynced skew. The order of events holds; exact cross-system minute matching does not.
6. **Keyword list** for secret hunting is configurable but finite. Unusual words still trigger NEW_CAPABILITY and NEW_ORIGIN, just with less weight.
7. **Labels are ours.** The 100% figures measure agreement with our own investigation, not absolute truth.
