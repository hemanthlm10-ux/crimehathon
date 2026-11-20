"""Analyst ground truth for the supplied evidence (CR-26-047).

These labels come from the MANUAL investigation (see docs/technical_report.md),
written as explicit analyst criteria - specific credentials, addresses and records
established by cross-reading E01/E02/E05/E15/E18/E19/E03 against E04, E16, E20.
They deliberately use concrete indicators (which TrustLine never sees), so the
detector is scored against an independent definition of "malicious".

label = malicious | benign | unknown   (unknown rows are excluded from scoring)
"""
import sys
import pandas as pd
sys.path.insert(0, ".")
from trustline.loaders import load_dir

ATTACK_IPS = {"198.18.7.41", "198.18.7.58", "10.20.4.77"}            # E01/E02/E15/E17
BV_ATTACK_IPS = {"198.18.7.23", "198.18.7.24", "198.18.7.77"}        # E05, NOT in E17

ev = load_dir(sys.argv[1])
e = ev.events
lab = pd.Series("benign", index=e.index)
m = ((e.system == "ledger") & (e.actor == "key-tb-07") & e.ip.isin(ATTACK_IPS))
m |= ((e.system == "helpdesk") & (e.actor == "tb-sync-svc") & e.ip.isin(ATTACK_IPS))
m |= ((e.system == "link") & (e.actor == "tb-build-02") & (e.ts >= "2026-08-01"))
m |= ((e.system == "storage") & (e.actor == "key:bvk-7f3a") & ~e.target.astype(str).str.startswith("/customer-docs"))
m |= ((e.system == "vendormaster") & (e.eid == "chg-8b9888c39b"))
m |= ((e.system == "sso") & (e.actor == "a.kapoor") & e.ip.isin(BV_ATTACK_IPS))
lab[m] = "malicious"
# tb-build-02 -> sandbox on 9 Jul falls in a vendor-announced maintenance window (E20-B).
# It may be the attacker's first touch, or genuine maintenance: we cannot tell, so unscored.
lab[(e.system == "link") & (e.actor == "tb-build-02") & (e.ts < "2026-08-01")] = "unknown"
# V-0233 bank change used approval ref APR-1182, ~60 numbers older than refs in use that week.
# Could be a delayed legitimate change or an insider: the evidence cannot settle it, so unscored.
lab[(e.system == "vendormaster") & (e.eid == "chg-f57dc0fb09")] = "unknown"
out = e[["system", "eid", "ts", "actor"]].assign(label=lab)
out.to_csv(sys.argv[2], index=False)
print(out.groupby(["system", "label"]).size())
