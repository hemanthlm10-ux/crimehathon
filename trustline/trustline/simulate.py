"""Generate UNSEEN attack variations for testing (never touches the originals).

1. Copy the evidence into a new directory with every known-malicious row removed
   (a clean reference period).
2. Inject one synthetic attack scenario, with randomised identities, addresses,
   times, versions, keywords and targets, written in each file's own native format
   (IST for the helpdesk log, epoch for storage, request_id joins for vendor
   changes, flows for the private link).
3. Write labels for the injected rows so detection can be scored.

Scenarios
  stolen_key_external   any integration key used from a new public address,
                        user agent COPIED from the real client, timing random
  rogue_link_host       new host on the private link, current UA, INSIDE the sync
                        window, quietly changes one vendor's bank account
  helpdesk_hunt         service account hunts tickets with different keywords and
                        runs export->delete cycles
  storage_drift         storage key reads a folder it never used, from its NORMAL IP
  dormant_key           a registered but long-unused key wakes up
  insider_bank_change   a staff member changes bank details with a recycled approval ref
  mimic_sync            attacker on a real sync host, real UA, in window, only reads
                        normal endpoints  (expected to be MISSED - documented limit)
"""
from __future__ import annotations

import glob
import os
import random
import shutil

import numpy as np
import pandas as pd

from .loaders import _classify

SCENARIOS = ["stolen_key_external", "rogue_link_host", "helpdesk_hunt", "storage_drift",
             "dormant_key", "insider_bank_change", "mimic_sync"]


def _hex(rng, n=10):
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


class Sim:
    def __init__(self, src, labels_path, dst, seed):
        self.rng = random.Random(seed)
        self.dst = dst
        os.makedirs(dst, exist_ok=True)
        lab = pd.read_csv(labels_path)
        drop = set(lab[lab.label != "benign"].eid)
        self.raw, self.kind, self.names = {}, {}, {}
        for f in sorted(glob.glob(os.path.join(src, "*"))):
            n = os.path.basename(f)
            if n.lower().endswith(".csv"):
                df = pd.read_csv(f, dtype=str, keep_default_na=False)
                k = _classify(set(df.columns))
                if k in ("api", "helpdesk", "sso", "storage", "flow", "vendorchg"):
                    idc = {"api": "request_id", "helpdesk": "event_id", "sso": "event_id", "storage": "event_id",
                           "flow": "flow_id", "vendorchg": "change_id"}[k]
                    df = df[~df[idc].isin(drop)]
                    self.raw[n] = df
                    self.kind[n] = k
                    self.names.setdefault(k, n)   # first file of each kind receives injections
                    continue
            if os.path.isfile(f) and n.lower().endswith((".csv", ".json")):
                shutil.copy(f, os.path.join(dst, n))
        self.labels = []
        api = pd.concat([d for n, d in self.raw.items() if self.kind[n] == "api"])
        self.api = api
        self.api_name = max((n for n in self.raw if self.kind[n] == "api"), key=lambda n: len(self.raw[n]))

    # ---------------------------------------------------------------- writers
    def add(self, kind, rows, name=None):
        name = name or (self.api_name if kind == "api" else self.names[kind])
        self.raw[name] = pd.concat([self.raw[name], pd.DataFrame(rows).astype(str)], ignore_index=True)
        idc = {"api": "request_id", "helpdesk": "event_id", "sso": "event_id", "storage": "event_id",
               "flow": "flow_id", "vendorchg": "change_id"}[kind]
        sysn = {"api": "ledger", "helpdesk": "helpdesk", "sso": "sso", "storage": "storage",
                "flow": "link", "vendorchg": "vendormaster"}[kind]
        for r in rows:
            self.labels.append({"system": sysn, "eid": r[idc], "label": "malicious"})

    def api_row(self, ts, key, ip, ua, ep, method="GET", rec=1, status=200):
        return {"ts_utc": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "request_id": "req-" + _hex(self.rng),
                "api_key_id": key, "caller_ip": ip, "user_agent": ua, "endpoint": ep, "method": method,
                "records_returned": rec, "status": status}

    def hd_row(self, ts, actor, action, obj, ip, details="", result="ok"):
        loc = ts + pd.Timedelta(minutes=330)
        return {"ts_local": loc.strftime("%d/%m/%Y %H:%M:%S"), "event_id": "evt-" + _hex(self.rng),
                "actor": actor, "actor_type": "integration", "action": action, "object_id": obj,
                "source_ip": ip, "result": result, "details": details}

    def flow_row(self, ts, ip, label, dst, bout, bin_):
        return {"ts_utc": ts.strftime("%Y-%m-%dT%H:%M:%SZ"), "flow_id": "flw-" + _hex(self.rng),
                "src_ip": ip, "src_label": label, "dst_system": dst, "dst_port": 443, "bytes_out": bout,
                "bytes_in": bin_, "tunnel_id": "tun-tb-01", "result": "allowed"}

    def write(self):
        for n, df in self.raw.items():
            df.to_csv(os.path.join(self.dst, n), index=False)
        pd.DataFrame(self.labels).to_csv(os.path.join(self.dst, "_labels.csv"), index=False)

    # ---------------------------------------------------------------- helpers
    def day(self, lo="2026-07-15", hi="2026-08-30"):
        d0, d1 = pd.Timestamp(lo, tz="UTC"), pd.Timestamp(hi, tz="UTC")
        return d0 + pd.Timedelta(days=self.rng.randint(0, (d1 - d0).days))

    def key_profile(self, key):
        k = self.api[self.api.api_key_id == key]
        ts = pd.to_datetime(k.ts_utc, utc=True)
        late = k[ts >= ts.max() - pd.Timedelta(days=14)]
        return {"ua": late.user_agent.mode().iat[0], "ips": sorted(set(late.caller_ip)),
                "hours": ts.dt.hour.value_counts().index[:2].tolist()}

    def public_ip(self):
        a = self.rng.choice(["198.18", "203.0.113", "192.0.2", "100.64"])
        return f"{a}.{self.rng.randint(1, 250)}.{self.rng.randint(2, 250)}" if a.count(".") == 1 \
            else f"{a}.{self.rng.randint(2, 250)}"

    # ---------------------------------------------------------------- scenarios
    def stolen_key_external(self):
        keys = [k for k in self.api.api_key_id.unique() if not k.startswith("user:")]
        key = self.rng.choice(keys)
        p = self.key_profile(key)
        ip = self.public_ip()
        hour = self.rng.choice([self.rng.randint(0, 23), p["hours"][0]])   # sometimes inside the window
        t = self.day() + pd.Timedelta(hours=hour, minutes=self.rng.randint(0, 50))
        rows = []
        for ep, m, rec in [("/v2/me", "GET", 1), ("/v2/vendors?limit=3", "GET", 3),
                           ("/v2/vendors/export", "POST", self.rng.randint(5000, 12000))]:
            rows.append(self.api_row(t, key, ip, p["ua"], ep, m, rec)); t += pd.Timedelta(minutes=self.rng.randint(1, 6))
        xid = self.rng.randint(10000, 99999)
        rows.append(self.api_row(t, key, ip, p["ua"], f"/v2/exports/{xid}/download", "GET", self.rng.randint(5000, 12000)))
        t += pd.Timedelta(minutes=3)
        rows.append(self.api_row(t, key, ip, p["ua"], f"/v2/exports/{xid}", "DELETE", 0, 204))
        self.add("api", rows)
        return f"key={key} ip={ip} ua={p['ua']} hour={hour}"

    def rogue_link_host(self):
        key = "key-tb-07" if "key-tb-07" in set(self.api.api_key_id) else \
            self.rng.choice([k for k in self.api.api_key_id.unique() if not k.startswith("user:")])
        p = self.key_profile(key)
        ip = f"10.20.4.{self.rng.randint(100, 250)}"
        label = self.rng.choice(["tb-ops-04", "tb-build-07", "tb-sync-09", "unlabelled"])
        hour = p["hours"][0]
        t = self.day("2026-08-01", "2026-08-30") + pd.Timedelta(hours=hour, minutes=self.rng.randint(0, 30))
        vc = self.raw[self.names["vendorchg"]]
        v = vc.sample(1, random_state=self.rng.randint(0, 9999)).iloc[0]
        rows, flows = [], []
        for ep, m in [(f"/v2/vendors/{v.vendor_id}", "GET"), (f"/v2/vendors/{v.vendor_id}/bank-details", "GET"),
                      (f"/v2/vendors/{v.vendor_id}/bank-details", "PATCH")]:
            rows.append(self.api_row(t, key, ip, p["ua"], ep, m, 1))
            flows.append(self.flow_row(t, ip, label, "LedgerOne", self.rng.randint(2000, 9000), self.rng.randint(2000, 9000)))
            t += pd.Timedelta(minutes=self.rng.randint(1, 3))
        self.add("api", rows)
        self.add("flow", flows)
        chg = {"ts_utc": rows[-1]["ts_utc"], "change_id": "chg-" + _hex(self.rng), "vendor_id": v.vendor_id,
               "vendor_name": v.vendor_name, "field": "bank_account", "old_value": "****" + str(self.rng.randint(1000, 9999)),
               "new_value": "****" + str(self.rng.randint(1000, 9999)), "changed_by": key, "channel": "API",
               "approval_ref": "", "source_ip": ip, "request_id": rows[-1]["request_id"]}
        self.add("vendorchg", [chg])
        return f"key={key} host={label}@{ip} in-window hour={hour} vendor={v.vendor_id}"

    def helpdesk_hunt(self):
        hd = self.raw[self.names["helpdesk"]]
        actor = hd[hd.actor_type == "integration"].actor.mode().iat[0]
        ip = self.public_ip()
        t = self.day() + pd.Timedelta(hours=self.rng.randint(0, 23))
        words = self.rng.sample(["pwd", "apikey", "connection string", "client_secret", "password", "login details",
                                 "otp", "keyfile", "creds", "authorization"], 5)
        rows = []
        for w in words:
            rows.append(self.hd_row(t, actor, "ticket.search", "-", ip, w)); t += pd.Timedelta(minutes=1)
        for i in range(self.rng.randint(2, 6)):
            x = f"EXP-{self.rng.randint(7000, 9999)}"
            for a in ("export.create", "export.download", "export.delete"):
                rows.append(self.hd_row(t, actor, a, x, ip)); t += pd.Timedelta(minutes=2)
        self.add("helpdesk", rows)
        return f"actor={actor} ip={ip} words={words}"

    def storage_drift(self):
        st = self.raw[self.names["storage"]]
        keys = st[st.principal.str.startswith("key:")]
        key = keys.principal.mode().iat[0]
        normal_ip = keys[keys.principal == key].source_ip.replace("", np.nan).dropna().mode().iat[0]
        folder = self.rng.choice(["/hr", "/legal", "/finance", "/ops"])
        t = self.day() + pd.Timedelta(hours=self.rng.randint(4, 10))
        rows = []
        for i in range(self.rng.randint(4, 12)):
            rows.append({"epoch_s": int(t.timestamp()), "event_id": "bv-" + _hex(self.rng), "principal": key,
                         "source_ip": normal_ip, "action": self.rng.choice(["list", "read", "read"]),
                         "path": f"{folder}/file-{self.rng.randint(1, 99)}.pdf",
                         "bytes": self.rng.randint(10_000, 4_000_000), "result": "ok"})
            t += pd.Timedelta(minutes=self.rng.randint(2, 20))
        self.add("storage", rows)
        return f"key={key} from NORMAL ip={normal_ip} folder={folder}"

    def dormant_key(self):
        key = self.rng.choice(["key-tb-03", "key-app-12", "key-legacy-01"])
        ip = self.rng.choice([self.public_ip(), f"172.16.{self.rng.randint(1, 20)}.{self.rng.randint(2, 250)}"])
        t = self.day() + pd.Timedelta(hours=self.rng.randint(0, 23))
        rows = [self.api_row(t + pd.Timedelta(minutes=i * 3), key, ip, "python-httpx/0.27",
                             self.rng.choice(["/v2/payments/search", "/v2/vendors", "/v2/payments/status"]), "GET",
                             self.rng.randint(50, 400)) for i in range(self.rng.randint(3, 10))]
        self.add("api", rows)
        return f"key={key} ip={ip}"

    def insider_bank_change(self):
        vc = self.raw[self.names["vendorchg"]]
        refs = vc[vc.approval_ref.str.startswith("APR-")]
        user = self.rng.choice(sorted(set(vc[vc.channel == "UI"].changed_by)))
        old_ref = refs.approval_ref.iloc[self.rng.randint(0, max(1, len(refs) // 3))]
        v = vc.sample(1, random_state=self.rng.randint(0, 9999)).iloc[0]
        t = self.day("2026-08-01", "2026-08-30")
        while t.day not in (1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22):
            t += pd.Timedelta(days=1)
        t += pd.Timedelta(hours=self.rng.randint(4, 11))
        ip = f"172.16.8.{self.rng.randint(20, 60)}"
        self.add("vendorchg", [{"ts_utc": t.strftime("%Y-%m-%dT%H:%M:%SZ"), "change_id": "chg-" + _hex(self.rng),
                                "vendor_id": v.vendor_id, "vendor_name": v.vendor_name, "field": "bank_account",
                                "old_value": "****1111", "new_value": "****2222", "changed_by": user, "channel": "UI",
                                "approval_ref": old_ref, "source_ip": ip, "request_id": ""}])
        return f"user={user} recycled {old_ref} vendor={v.vendor_id}"

    def mimic_sync(self):
        key = "key-tb-07" if "key-tb-07" in set(self.api.api_key_id) else self.api.api_key_id.iloc[0]
        p = self.key_profile(key)
        ip = self.rng.choice(p["ips"])
        t = self.day("2026-08-01", "2026-08-30") + pd.Timedelta(hours=p["hours"][0], minutes=self.rng.randint(0, 20))
        rows = [self.api_row(t + pd.Timedelta(seconds=40 * i), key, ip, p["ua"], "/v2/vendors", "GET",
                             self.rng.randint(100, 400)) for i in range(8)]
        self.add("api", rows)
        return f"key={key} REAL host ip={ip} REAL ua={p['ua']} normal endpoint"


def make_variation(src, labels, dst, scenario, seed):
    s = Sim(src, labels, dst, seed)
    desc = getattr(s, scenario)()
    s.write()
    return desc
