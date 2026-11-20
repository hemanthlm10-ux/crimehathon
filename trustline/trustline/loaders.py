"""Load heterogeneous evidence files into one normalised, UTC-aligned event stream.

Files are recognised by their COLUMN SIGNATURE, not their file name, so renamed
or re-ordered evidence (e.g. an unseen variation dataset) still loads.
Every original row keeps its own identifier (request_id / event_id / change_id /
flow_id) so each alert can be traced back to the exact evidence record.
"""
from __future__ import annotations

import glob
import json
import os
import re

import pandas as pd

EVENT_COLS = [
    "ts", "system", "src_file", "eid", "actor", "actor_kind", "ip", "host", "ua",
    "op", "target", "volume", "result", "detail", "req_id", "approval_ref", "channel",
]

SIGNATURES = {
    "api":     {"ts_utc", "request_id", "api_key_id", "caller_ip", "user_agent", "endpoint", "method"},
    "helpdesk": {"ts_local", "event_id", "actor", "actor_type", "action", "object_id", "source_ip"},
    "sso":     {"ts_utc", "event_id", "user", "source_ip", "auth_method", "mfa_result"},
    "storage": {"epoch_s", "event_id", "principal", "source_ip", "action", "path", "bytes"},
    "flow":    {"ts_utc", "flow_id", "src_ip", "src_label", "dst_system", "bytes_out"},
    "vendorchg": {"ts_utc", "change_id", "vendor_id", "field", "changed_by", "channel", "approval_ref"},
    "roster":  {"employee_id", "username", "status", "termination_date"},
    "indicators": {"indicator", "type", "first_seen", "confidence"},
}

ID_RE = re.compile(r"/(V-\d+|\d+)(?=/|$)")


def _classify(cols: set[str]) -> str | None:
    for kind, sig in SIGNATURES.items():
        if sig <= cols:
            return kind
    return None


def _api_op(endpoint: str, method: str, records: float) -> tuple[str, str]:
    """Return (normalised operation, endpoint template)."""
    path, _, query = endpoint.partition("?")
    tmpl = ID_RE.sub("/{id}", path)
    m = method.upper()
    if "bank-details" in path:
        return ("write.bank" if m in ("PATCH", "PUT", "POST") else "read.bank"), tmpl
    if path.endswith("/contact") and m in ("PATCH", "PUT", "POST"):
        return "write.contact", tmpl
    if path.endswith("/export") and m == "POST":
        return "export.create", tmpl
    if path.endswith("/download"):
        return "export.download", tmpl
    if path.startswith("/v2/exports") and m == "DELETE":
        return "export.delete", tmpl
    if path.rstrip("/") == "/v2/exports":
        return "export.list", tmpl
    lim = re.search(r"limit=(\d+)", query)
    if path in ("/v2/me", "/v2/schema") or (lim and int(lim.group(1)) <= 5):
        return "probe", tmpl
    return f"{m} {tmpl}", tmpl


def load_api(df, name):
    ts = pd.to_datetime(df.ts_utc, utc=True)
    ops = [_api_op(e, m, r) for e, m, r in zip(df.endpoint, df.method, df.records_returned)]
    human = df.api_key_id.str.startswith("user:")
    return pd.DataFrame({
        "ts": ts, "system": "ledger", "src_file": name, "eid": df.request_id,
        "actor": df.api_key_id, "actor_kind": human.map({True: "human", False: "integration"}),
        "ip": df.caller_ip, "host": None, "ua": df.user_agent,
        "op": [o for o, _ in ops], "target": df.endpoint, "volume": df.records_returned.fillna(0),
        "result": df.status.astype(str), "detail": None, "req_id": df.request_id,
        "approval_ref": None, "channel": "API",
    })


def load_helpdesk(df, name, tz_offset_minutes=330):
    ts = (pd.to_datetime(df.ts_local, dayfirst=True, format="mixed")
          - pd.Timedelta(minutes=tz_offset_minutes)).dt.tz_localize("UTC")
    kind = df.actor_type.map(lambda t: "integration" if str(t).lower() in ("integration", "service", "api") else "human")
    return pd.DataFrame({
        "ts": ts, "system": "helpdesk", "src_file": name, "eid": df.event_id,
        "actor": df.actor, "actor_kind": kind, "ip": df.source_ip, "host": None, "ua": None,
        "op": df.action, "target": df.object_id, "volume": 1, "result": df.result,
        "detail": df.details, "req_id": None, "approval_ref": None, "channel": None,
    })


def load_sso(df, name):
    return pd.DataFrame({
        "ts": pd.to_datetime(df.ts_utc, utc=True), "system": "sso", "src_file": name,
        "eid": df.event_id, "actor": df.user, "actor_kind": "human", "ip": df.source_ip,
        "host": df.get("device_id"), "ua": df.auth_method, "op": "signin." + df.result.astype(str),
        "target": df.get("city"), "volume": 1, "result": df.result,
        "detail": df.failure_reason.fillna("") + "|" + df.mfa_result.fillna(""),
        "req_id": None, "approval_ref": None, "channel": None,
    })


def load_storage(df, name, skew_seconds=0):
    ts = pd.to_datetime(df.epoch_s - skew_seconds, unit="s", utc=True)
    kind = df.principal.map(lambda p: "integration" if str(p).startswith("key:") else "human")
    return pd.DataFrame({
        "ts": ts, "system": "storage", "src_file": name, "eid": df.event_id,
        "actor": df.principal, "actor_kind": kind, "ip": df.source_ip, "host": None, "ua": None,
        "op": df.action, "target": df.path, "volume": df.bytes.fillna(0), "result": df.result,
        "detail": None, "req_id": None, "approval_ref": None, "channel": None,
    })


def load_vendorchg(df, name):
    is_api = df.channel.astype(str).str.upper().eq("API")
    return pd.DataFrame({
        "ts": pd.to_datetime(df.ts_utc, utc=True), "system": "vendormaster", "src_file": name,
        "eid": df.change_id, "actor": df.changed_by,
        "actor_kind": is_api.map({True: "integration", False: "human"}),
        "ip": df.source_ip, "host": None, "ua": None, "op": "change." + df.field.astype(str),
        "target": df.vendor_id + " " + df.vendor_name.astype(str), "volume": 1, "result": "ok",
        "detail": df.old_value.astype(str) + "->" + df.new_value.astype(str),
        "req_id": df.request_id, "approval_ref": df.approval_ref, "channel": df.channel,
    })


def load_flow(df, name):
    return pd.DataFrame({
        "ts": pd.to_datetime(df.ts_utc, utc=True), "system": "link", "src_file": name,
        "eid": df.flow_id, "actor": df.src_label, "actor_kind": "integration", "ip": df.src_ip,
        "host": df.src_label, "ua": None, "op": "flow->" + df.dst_system.astype(str),
        "target": df.dst_system, "volume": df.bytes_in.fillna(0) + df.bytes_out.fillna(0),
        "result": df.result, "detail": None, "req_id": None, "approval_ref": None, "channel": None,
    })


class Evidence:
    """All evidence for one case, keyed by role."""

    def __init__(self):
        self.events = pd.DataFrame(columns=EVENT_COLS)
        self.roster = None
        self.register = None
        self.indicators = None
        self.chat = None
        self.files = {}

    @property
    def flows(self):
        return self.events[self.events.system == "link"]


def load_dir(path: str, cfg: dict | None = None) -> Evidence:
    cfg = cfg or {}
    ev = Evidence()
    frames = []
    for f in sorted(glob.glob(os.path.join(path, "*"))):
        name = os.path.basename(f)
        low = name.lower()
        if low.endswith(".csv"):
            df = pd.read_csv(f)
            kind = _classify(set(df.columns))
            ev.files[name] = kind
            if kind == "api":
                frames.append(load_api(df, name))
            elif kind == "helpdesk":
                frames.append(load_helpdesk(df, name, cfg.get("helpdesk_tz_offset_minutes", 330)))
            elif kind == "sso":
                frames.append(load_sso(df, name))
            elif kind == "storage":
                frames.append(load_storage(df, name, cfg.get("storage_clock_skew_seconds", 0)))
            elif kind == "vendorchg":
                frames.append(load_vendorchg(df, name))
            elif kind == "flow":
                frames.append(load_flow(df, name))
            elif kind == "roster":
                ev.roster = df
            elif kind == "indicators":
                ev.indicators = df
        elif low.endswith(".json"):
            with open(f, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict) and "integrations" in data:
                ev.register = pd.DataFrame(data["integrations"])
                ev.files[name] = "register"
            elif isinstance(data, list) and data and "text" in data[0]:
                ev.chat = pd.DataFrame(data)
                ev.files[name] = "chat"
    ev.events = pd.concat([f for f in frames if len(f)], ignore_index=True)
    ev.events = ev.events.sort_values("ts", kind="stable").reset_index(drop=True)
    ev.events["volume"] = pd.to_numeric(ev.events["volume"], errors="coerce").fillna(0)
    _enrich_hosts(ev)
    return ev


def _enrich_hosts(ev: Evidence):
    """Attach the private-link host label (from the flow log) to API/helpdesk events by IP."""
    flows = ev.events[ev.events.system == "link"]
    if flows.empty:
        return
    ipmap = flows.groupby("ip").host.agg(lambda s: s.mode().iat[0]).to_dict()
    mask = ev.events.system != "link"
    ev.events.loc[mask, "host"] = ev.events.loc[mask, "ip"].map(ipmap).where(
        ev.events.loc[mask, "system"].isin(["ledger", "helpdesk", "vendormaster"]),
        ev.events.loc[mask, "host"])
