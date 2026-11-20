"""Score TrustLine (and the obvious alternatives) against labelled evidence.

Detection unit = one evidence row. An event counts as detected when
  * strict:   its own score reaches the alert threshold, or
  * incident: it is part of an incident that contains an alert (what an analyst
              actually receives).
Compared approaches:
  A. Vendor indicator list (E17-style IOC matching on IP / user agent / credential)
  B. Blocking the indicators' whole /24 range (the "obvious" hardening step)
  C. Volume threshold: integration events above the 99.5th percentile of their system
  D. TrustLine
"""
from __future__ import annotations

import json
import os

import pandas as pd

from .cli import analyse


def _metrics(pred, truth):
    tp = int((pred & truth).sum())
    fp = int((pred & ~truth).sum())
    fn = int((~pred & truth).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {"TP": tp, "FP": fp, "FN": fn, "precision": round(prec, 3), "recall": round(rec, 3)}


def evaluate(evidence, labels_path, cfg, out="out", quiet=False):
    ev, eng, scored, incidents, acts, hyg = analyse(evidence, cfg, out, quiet=True)
    labels = pd.read_csv(labels_path)
    df = scored.merge(labels[["system", "eid", "label"]], on=["system", "eid"], how="left")
    df["label"] = df.label.fillna("benign")
    df = df[df.label != "unknown"].copy()
    truth = df.label.eq("malicious")

    res = {}
    # A/B: indicator matching
    if ev.indicators is not None:
        ind = ev.indicators
        ips = set(ind[ind.type == "ip"].indicator)
        uas = set(ind[ind.type == "user_agent"].indicator)
        creds = set(ind[ind.type == "credential"].indicator)
        a = df.ip.isin(ips) | df.ua.isin(uas) | df.actor.isin(creds)
        res["A_vendor_indicator_list"] = _metrics(a, truth)
        nets = {i.rsplit(".", 1)[0] + "." for i in ips}
        b = df.ip.fillna("").astype(str).apply(lambda x: any(x.startswith(n) for n in nets))
        res["B_block_indicator_/24"] = _metrics(b, truth)
    # C: volume threshold
    integ = df.actor_kind.eq("integration") & df.system.isin(["ledger", "helpdesk", "storage"])
    thr = df[integ].groupby("system").volume.quantile(0.995)
    c = integ & (df.volume > df.system.map(thr).fillna(float("inf")))
    res["C_volume_p99.5"] = _metrics(c, truth)
    # D: TrustLine
    res["D_TrustLine_strict_alert"] = _metrics(df.level.eq("alert"), truth)
    res["D_TrustLine_incident"] = _metrics(df.incident.notna(), truth)

    per_sys = {}
    for sysname, g in df.groupby("system"):
        t = g.label.eq("malicious")
        if t.any() or g.level.eq("alert").any():
            per_sys[sysname] = _metrics(g.incident.notna(), t)
    fps = df[(df.level == "alert") & ~truth][["ts", "system", "eid", "actor", "ip", "op", "signals"]]
    fns = df[truth & df.incident.isna()][["ts", "system", "eid", "actor", "ip", "op", "signals", "score"]]
    reviews = df[df.level.eq("review") & df.incident.isna()][["ts", "system", "eid", "actor", "op", "signals"]]
    report = {"approaches": res, "trustline_per_system": per_sys,
              "false_alarms": len(fps), "missed": len(fns),
              "unlinked_review_items": len(reviews), "incidents": len(incidents)}
    if out:
        os.makedirs(out, exist_ok=True)
        with open(os.path.join(out, "evaluation.json"), "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        fps.to_csv(os.path.join(out, "false_alarms.csv"), index=False)
        fns.to_csv(os.path.join(out, "missed.csv"), index=False)
        reviews.to_csv(os.path.join(out, "review_queue.csv"), index=False)
    if not quiet:
        print(f"{'approach':<28}{'TP':>6}{'FP':>7}{'FN':>6}{'precision':>11}{'recall':>8}")
        for k, v in res.items():
            print(f"{k:<28}{v['TP']:>6}{v['FP']:>7}{v['FN']:>6}{v['precision']:>11}{v['recall']:>8}")
        print("\nTrustLine (incident level) per system:")
        for k, v in per_sys.items():
            print(f"  {k:<14} {v}")
        print(f"\nFalse alarms: {len(fps)}   Missed: {len(fns)}   Review items outside incidents: {len(reviews)}")
        if len(fns):
            print(fns.head(10).to_string())
        if len(reviews):
            print(reviews.to_string())
    return report
