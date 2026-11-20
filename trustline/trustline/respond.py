"""Turn incidents into concrete containment and recovery actions.

The important output is not "an alert" but what a two-person IT team must do
before the next payment run, generated from the evidence itself:
  * which credentials to revoke, and the least-privilege contract to re-issue
    them with (IP allow-list, operations, hours) - learned, not guessed;
  * which vendor payments to hold, and until when;
  * which export files may still exist (created/downloaded but never deleted);
  * what data left, for Legal's notification clock.
"""
from __future__ import annotations

import re
from collections import defaultdict

import pandas as pd

from .engine import next_payment_run


def contract_for(profile):
    return {
        "allow_ips": sorted(profile.ips),
        "allow_hosts": sorted(profile.hosts),
        "allow_ops": sorted(profile.ops),
        "allow_hours_utc": sorted(h for h, c in profile.hours.items() if c >= 3),
        "allow_paths": sorted(profile.prefixes),
        "user_agents": {f: ".".join(map(str, v)) if v else None for f, v in profile.ua_max.items()},
    }


def playbook(incidents, scored, engine, cfg):
    actions = []
    for inc in incidents:
        sub = scored[scored.eid.isin(inc["eids"])]
        a = {"incident": inc["id"], "steps": []}
        # 1. credentials
        for (system, actor), g in sub[sub.actor_kind == "integration"].groupby(["system", "actor"]):
            if system == "vendormaster":
                continue                      # same credential is revoked via its own system
            if system == "link":
                a["steps"].append({"do": "ISOLATE_LINK_HOST", "target": actor,
                                   "why": f"host not in learned sync pool; {len(g)} flagged flows",
                                   "evidence": list(g.eid[:5])})
                continue
            prof = engine.profiles.get((system, actor))
            a["steps"].append({
                "do": "REVOKE_AND_REISSUE", "target": f"{system}:{actor}",
                "why": f"{len(g)} flagged events; signals {sorted(set(';'.join(g.signals).split(';')) - {''})}",
                "reissue_with": contract_for(prof) if prof else None,
                "evidence": list(g.eid[:5]),
            })
        # 2. money
        bank = sub[(sub.system == "vendormaster") & sub.op.str.contains("bank")]
        for r in bank.itertuples():
            run = next_payment_run(r.ts, cfg["payment_run_days"])
            a["steps"].append({
                "do": "HOLD_PAYMENT", "target": r.target,
                "why": f"bank account changed {r.detail} by {r.actor} via {r.channel}, approval_ref={r.approval_ref}",
                "until": f"out-of-band verification using contact details on file BEFORE {r.ts.date()}",
                "next_run": str(run.date()) if run is not None else None,
                "revert_to": str(r.detail).split("->")[0],
                "evidence": [r.eid, r.req_id] if isinstance(r.req_id, str) else [r.eid],
            })
        # 3. orphan exports
        for system in ("ledger", "helpdesk"):
            s = sub[sub.system == system]
            created = {}
            for r in s.itertuples():
                if r.op in ("export.create", "export.download"):
                    xid = _export_id(r)
                    if xid:
                        created.setdefault(xid, r)
                if r.op == "export.delete":
                    xid = _export_id(r)
                    if xid and str(r.result) in ("ok", "204", "200"):
                        created.pop(xid, None)
            for xid, r in created.items():
                a["steps"].append({"do": "LOCATE_AND_PURGE_EXPORT", "target": f"{system}:{xid}",
                                   "why": "export created/downloaded but no successful delete recorded",
                                   "evidence": [r.eid]})
        # 4. exposure for Legal
        # records packaged by export jobs + returned by searches/bank reads (downloads not re-counted)
        exp = sub[sub.op.isin(["export.create", "read.bank", "read", "probe"]) |
                  sub.op.str.contains("search|scheduled", regex=True)]
        files = sorted(set(sub[(sub.system == "storage") & (sub.op == "read")].target))
        a["exposure"] = {
            "first_malicious_utc": str(inc["first"]),
            "ledger_records_returned": int(exp[exp.system == "ledger"].volume.sum()),
            "helpdesk_exports": int((sub[(sub.system == "helpdesk")].op == "export.create").sum()),
            "storage_files_read": files,
            "storage_bytes_read": int(sub[(sub.system == "storage") & (sub.op == "read")].volume.sum()),
        }
        actions.append(a)
    return actions


def _export_id(r):
    if r.system == "helpdesk":
        return r.target if isinstance(r.target, str) and r.target.startswith("EXP") else None
    m = re.search(r"/exports/(\d+)", str(r.target))
    if m:
        return m.group(1)
    return None
