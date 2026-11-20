"""TrustLine command line.

    python -m trustline.cli analyse  --evidence DIR [--config FILE] [--out DIR]
    python -m trustline.cli evaluate --evidence DIR --labels FILE [--out DIR]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import pandas as pd

from .correlate import build_incidents
from .engine import Engine
from .loaders import load_dir
from .respond import playbook

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CFG = os.path.join(HERE, "..", "config", "default.json")


def load_cfg(path):
    with open(path or DEFAULT_CFG, encoding="utf-8") as fh:
        return json.load(fh)


def analyse(evidence, cfg, out=None, quiet=False):
    ev = load_dir(evidence, cfg)
    eng = Engine(cfg, register=ev.register, roster=ev.roster)
    scored = eng.run(ev.events)
    incidents, flagged = build_incidents(scored, ev.register, cfg)
    acts = playbook(incidents, scored, eng, cfg)
    hyg = eng.hygiene(ev.events)
    scored = scored.merge(flagged[["eid", "system", "incident"]], on=["eid", "system"], how="left") \
        if len(flagged) else scored.assign(incident=None)
    if out:
        os.makedirs(out, exist_ok=True)
        cols = ["ts", "system", "eid", "actor", "ip", "host", "ua", "op", "target", "volume",
                "result", "detail", "signals", "score", "level", "incident"]
        scored[scored.level != "none"][cols].to_csv(os.path.join(out, "alerts.csv"), index=False)
        with open(os.path.join(out, "incidents.json"), "w", encoding="utf-8") as fh:
            json.dump(incidents, fh, indent=2, default=str)
        with open(os.path.join(out, "playbook.json"), "w", encoding="utf-8") as fh:
            json.dump(acts, fh, indent=2, default=str)
        hyg.to_csv(os.path.join(out, "hygiene.csv"), index=False)
        from .report import write_html
        write_html(os.path.join(out, "report.html"), ev, scored, incidents, acts, hyg, cfg)
    if not quiet:
        print(f"Loaded {len(ev.events):,} events from {len(ev.files)} files: "
              + ", ".join(f"{k}={v}" for k, v in ev.files.items()))
        lv = scored.level.value_counts()
        print(f"Levels: alert={lv.get('alert', 0)}  review={lv.get('review', 0)}  none={lv.get('none', 0)}")
        for inc in incidents:
            print(f"\n{inc['id']}  {inc['first']:%Y-%m-%d %H:%M} -> {inc['last']:%Y-%m-%d %H:%M} UTC  "
                  f"events={inc['n_events']} alerts={inc['n_alerts']} risk={inc['risk']}")
            print(f"   systems:    {', '.join(inc['systems'])}")
            print(f"   identities: {', '.join(inc['identities'])}")
            print(f"   origins:    {', '.join(inc['ips'][:12])}{' ...' if len(inc['ips']) > 12 else ''}")
            print(f"   signals:    {inc['signals']}")
        for a in acts:
            print(f"\nPlaybook {a['incident']}:")
            for s in a["steps"]:
                print(f"   - {s['do']:<24} {s['target']}  ({s['why'][:110]})")
            print(f"   exposure: {json.dumps(a['exposure'], default=str)[:400]}")
        if len(hyg):
            print("\nGovernance / hygiene findings:")
            for r in hyg.itertuples():
                print(f"   - {r.finding:<28} {r.subject}: {r.detail[:120]}")
    return ev, eng, scored, incidents, acts, hyg


def main(argv=None):
    p = argparse.ArgumentParser(prog="trustline")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyse")
    a.add_argument("--evidence", required=True)
    a.add_argument("--config")
    a.add_argument("--out", default="out")
    e = sub.add_parser("evaluate")
    e.add_argument("--evidence", required=True)
    e.add_argument("--labels", required=True)
    e.add_argument("--config")
    e.add_argument("--out", default="out")
    g = sub.add_parser("replay", help="prevention replay: enforce learned contracts")
    g.add_argument("--evidence", required=True)
    g.add_argument("--labels")
    g.add_argument("--config")
    g.add_argument("--train-days", type=int, default=21)
    g.add_argument("--out", default="out")
    args = p.parse_args(argv)
    cfg = load_cfg(args.config)
    if args.cmd == "analyse":
        analyse(args.evidence, cfg, args.out)
    elif args.cmd == "evaluate":
        from .evaluate import evaluate
        evaluate(args.evidence, args.labels, cfg, args.out)
    else:
        from .gate import replay
        ev = load_dir(args.evidence, cfg)
        scored = Engine(cfg, ev.register, ev.roster).run(ev.events)
        labels = pd.read_csv(args.labels) if args.labels else None
        contracts, res, summary, blocked = replay(scored, labels, args.train_days)
        print("Contracts learned (first %d days):" % args.train_days)
        for (sy, ac), c in sorted(contracts.items()):
            print(f"  {sy}:{ac:<16} ips={len(c['ips'])} ops={sorted(c['ops'])[:8]}{' paths=' + str(sorted(c['prefixes'])) if c['prefixes'] else ''}")
        print("\nReplay of later integration traffic (rows=label, cols=decision):")
        print(summary.to_string())
        if len(blocked):
            print("\nLegitimate requests that enforcement would have blocked (the cost):")
            print(blocked.groupby(["system", "actor", "decision", "op"]).size().to_string())
        os.makedirs(args.out, exist_ok=True)
        res.to_csv(os.path.join(args.out, "replay_decisions.csv"), index=False)


if __name__ == "__main__":
    sys.exit(main())
