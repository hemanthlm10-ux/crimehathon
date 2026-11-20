"""Stitch scored events from different systems into incidents.

Links (union-find) between flagged events:
  * same integration credential (any time)            - one stolen key = one story
  * credentials registered to the same software vendor (connected software register)
  * same public IP within N days, across systems/identities
  * same private-link host label that is outside the learned sync pool
  * vendor-master change joined to the API request that made it (request_id)
Only components that contain at least one ALERT become incidents.
"""
from __future__ import annotations

from collections import defaultdict

import pandas as pd


class DSU:
    def __init__(self, n):
        self.p = list(range(n))

    def find(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        a, b = self.find(a), self.find(b)
        if a != b:
            self.p[b] = a


def build_incidents(scored: pd.DataFrame, register=None, cfg=None, ip_days=7):
    cfg = cfg or {}
    priv = tuple(cfg.get("private_ranges", ["10.", "172.16.", "192.168."]))
    f = scored[scored.level.isin(["alert", "review"])].reset_index()
    if f.empty:
        return [], f
    d = DSU(len(f))
    vendor_of = {}
    if register is not None:
        vendor_of = dict(zip(register.credential_id, register.vendor))

    def link_by(keyfun, max_gap=None):
        groups = defaultdict(list)
        for i, r in f.iterrows():
            k = keyfun(r)
            if k is not None:
                groups[k].append(i)
        for idx in groups.values():
            idx = sorted(idx, key=lambda i: f.at[i, "ts"])
            for a, b in zip(idx, idx[1:]):
                if max_gap is None or f.at[b, "ts"] - f.at[a, "ts"] <= max_gap:
                    d.union(a, b)

    def cred(r):
        a = str(r.actor)
        return a[4:] if a.startswith("key:") else a

    link_by(lambda r: ("cred", cred(r)) if r.actor_kind == "integration" and r.system != "link" else None)
    link_by(lambda r: ("human", r.actor), pd.Timedelta(days=1))
    link_by(lambda r: ("vendor", vendor_of[cred(r)]) if cred(r) in vendor_of
            and vendor_of[cred(r)] not in ("internal",) and r.level == "alert" else None)
    link_by(lambda r: ("ip", r.ip) if isinstance(r.ip, str) and not r.ip.startswith(priv) else None,
            pd.Timedelta(days=ip_days))
    link_by(lambda r: ("host", r.host) if isinstance(r.host, str) and r.level == "alert"
            and ("NEW_" in r.signals or r.system == "link") else None)
    # private-link flows from the same unknown host belong together
    link_by(lambda r: ("linkhost", r.actor) if r.system == "link" else None)
    # secret hunting -> later use of the secret it was looking for
    creds = {cred(r): i for i, r in f.iterrows() if r.actor_kind == "integration"}
    for i, r in f.iterrows():
        if "SECRET_HUNT" in r.signals and isinstance(r.detail, str):
            term = r.detail.strip().lower()
            for c, j in creds.items():
                if len(term) >= 3 and c.lower().startswith(term) and f.at[j, "ts"] >= r.ts:
                    d.union(i, j)
    # vendor-master change <-> API request
    req_idx = {r.req_id: i for i, r in f.iterrows() if r.system == "ledger" and isinstance(r.req_id, str)}
    for i, r in f.iterrows():
        if r.system == "vendormaster" and isinstance(r.req_id, str) and r.req_id in req_idx:
            d.union(i, req_idx[r.req_id])
    # private-link host <-> API calls made from that host's IP
    host_ip = {}
    for i, r in f.iterrows():
        if r.system == "link":
            if r.ip in host_ip:
                d.union(i, host_ip[r.ip])
            host_ip.setdefault(r.ip, i)
    for i, r in f.iterrows():
        if r.system != "link" and r.ip in host_ip:
            d.union(i, host_ip[r.ip])

    comps = defaultdict(list)
    for i in range(len(f)):
        comps[d.find(i)].append(i)
    incidents = []
    f["incident"] = None
    n = 0
    for idx in sorted(comps.values(), key=lambda ix: f.loc[ix, "ts"].min()):
        sub = f.loc[idx]
        if not (sub.level == "alert").any():
            continue
        n += 1
        iid = f"INC-{n:03d}"
        f.loc[idx, "incident"] = iid
        incidents.append(summarise(iid, sub))
    return incidents, f


def summarise(iid, sub):
    alerts = sub[sub.level == "alert"]
    sig = defaultdict(int)
    for s in sub.signals:
        for x in filter(None, s.split(";")):
            sig[x] += 1
    ops = sub.groupby(["system", "op"]).agg(n=("eid", "size"), volume=("volume", "sum")).reset_index()
    return {
        "id": iid,
        "first": alerts.ts.min(),
        "first_precursor": sub.ts.min(),
        "last": sub.ts.max(),
        "systems": sorted(sub.system.unique()),
        "identities": sorted(sub.actor.astype(str).unique()),
        "ips": sorted(x for x in sub.ip.dropna().unique()),
        "hosts": sorted(x for x in sub.host.dropna().unique() if isinstance(x, str)),
        "n_events": len(sub),
        "n_alerts": len(alerts),
        "max_score": int(sub.score.max()),
        "risk": int(sub.score.sum()),
        "signals": dict(sorted(sig.items(), key=lambda kv: -kv[1])),
        "ops": ops.to_dict("records"),
        "days": sorted({t.strftime("%Y-%m-%d") for t in sub.ts}),
        "eids": list(sub.eid),
    }
