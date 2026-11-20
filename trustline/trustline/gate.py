"""Prevention replay: what if the learned contract had been ENFORCED?

Contracts are learned from a training period only (default: the warm-up window),
frozen, and then every later integration request is replayed against them as an
API-gateway / key-restriction policy would apply them:
    allow  <=>  origin IP in contract  AND  operation in contract
(hours are reported but not enforced, because sync windows legitimately move).
Outputs blocked-malicious vs blocked-legitimate counts so the cost of enforcement
is visible, not hidden.
"""
from __future__ import annotations

from collections import defaultdict

import pandas as pd


def learn_contracts(events, until):
    tr = events[(events.ts < until) & (events.actor_kind == "integration") &
                events.system.isin(["ledger", "helpdesk", "storage"])]
    c = defaultdict(lambda: {"ips": set(), "ops": set(), "prefixes": set()})
    for r in tr.itertuples():
        k = (r.system, r.actor)
        if isinstance(r.ip, str):
            c[k]["ips"].add(r.ip)
        c[k]["ops"].add(r.op)
        if r.system == "storage" and isinstance(r.target, str):
            c[k]["prefixes"].add("/" + r.target.strip("/").split("/")[0])
    return c


def replay(scored, labels=None, train_days=21):
    start = scored.ts.min()
    until = start + pd.Timedelta(days=train_days)
    contracts = learn_contracts(scored, until)
    ev = scored[(scored.ts >= until) & (scored.actor_kind == "integration") &
                scored.system.isin(["ledger", "helpdesk", "storage"])].copy()

    def decide(r):
        c = contracts.get((r.system, r.actor))
        if c is None:
            return "deny:unknown-credential"
        if isinstance(r.ip, str) and r.ip not in c["ips"]:
            return "deny:origin"
        if r.system == "storage":
            p = "/" + str(r.target).strip("/").split("/")[0]
            if p not in c["prefixes"]:
                return "deny:path"
            return "allow"
        if r.op not in c["ops"]:
            return "deny:operation"
        return "allow"

    ev["decision"] = [decide(r) for r in ev.itertuples()]
    if labels is not None:
        ev = ev.merge(labels[["system", "eid", "label"]], on=["system", "eid"], how="left")
        ev["label"] = ev.label.fillna("benign")
    else:
        ev["label"] = "unlabelled"
    summary = ev.groupby(["label", "decision"]).size().unstack(fill_value=0)
    blocked_legit = ev[(ev.label == "benign") & ev.decision.str.startswith("deny")]
    return contracts, ev, summary, blocked_legit
