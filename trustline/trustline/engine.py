"""TrustLine engine: learned behaviour contracts for non-human identities.

Every integration credential (API key, service account, storage key, private-link
host) gets a contract that is LEARNED from its own history: where it connects from,
which software version it reports, which hours it works, which operations and data
areas it touches.  After a warm-up period each new event is checked against the
contract.  Clean events extend the contract (so legitimate upgrades and schedule
shifts are absorbed); events that break it raise signals and are NOT learned (so an
attacker cannot train the baseline by repeating themselves).

Human activity is not profiled the same way (people roam; residential IPs are
shared), but money-moving changes and sign-in bursts are still checked.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

import pandas as pd

UA_RE = re.compile(r"^([A-Za-z0-9_.\-]+)/(\d+(?:\.\d+)*)")


def ua_parse(ua):
    if not isinstance(ua, str):
        return None, None
    m = UA_RE.match(ua.strip())
    if not m:
        return ua.strip()[:40], None
    return m.group(1), tuple(int(x) for x in m.group(2).split("."))


def net24(ip):
    if not isinstance(ip, str) or ip.count(".") != 3:
        return None
    return ip.rsplit(".", 1)[0]


def storage_prefix(path):
    if not isinstance(path, str):
        return None
    parts = [p for p in path.split("/") if p]
    return "/" + parts[0] if parts else "/"


@dataclass
class Profile:
    ips: set = field(default_factory=set)
    nets: set = field(default_factory=set)
    hosts: set = field(default_factory=set)
    ua_max: dict = field(default_factory=dict)      # family -> max version tuple
    ua_count: Counter = field(default_factory=Counter)  # (family, version) -> n
    ops: set = field(default_factory=set)
    hours: Counter = field(default_factory=Counter)
    prefixes: set = field(default_factory=set)
    n: int = 0

    def learn(self, ev, fam, ver, prefix):
        if isinstance(ev.ip, str):
            self.ips.add(ev.ip)
            self.nets.add(net24(ev.ip))
        if isinstance(ev.host, str):
            self.hosts.add(ev.host)
        if fam:
            self.ua_count[(fam, ver)] += 1
            if ver and (fam not in self.ua_max or ver > self.ua_max[fam]):
                self.ua_max[fam] = ver
            elif fam not in self.ua_max:
                self.ua_max[fam] = ver
        self.ops.add(ev.op)
        self.hours[ev.ts.hour] += 1
        if prefix:
            self.prefixes.add(prefix)
        self.n += 1


def next_payment_run(ts, run_days):
    d = ts.normalize()
    for add in range(0, 40):
        day = d + pd.Timedelta(days=add)
        if day.day in run_days and (add > 0 or ts.hour < 12):
            return day
    return None


class Engine:
    def __init__(self, cfg, register=None, roster=None):
        self.cfg = cfg
        self.w = cfg["weights"]
        self.profiles: dict = defaultdict(Profile)
        self.register = register
        self.roster = roster
        self.secret_re = re.compile("|".join(re.escape(k) for k in cfg["secret_keywords"]), re.I)
        self.sensitive = set(cfg["sensitive_ops"])
        self.apr_re = re.compile(cfg["approval_ref_pattern"])
        self.approved = cfg.get("approved_changes", [])

    # ------------------------------------------------------------------ helpers
    def _approved(self, ev, prof):
        for a in self.approved:
            if a.get("actor") == ev.actor and a.get("op") == ev.op and ev.ts >= pd.Timestamp(a["from"], tz="UTC"):
                if a.get("only_from_known_hosts") and not (ev.ip in prof.ips):
                    return False
                return True
        return False

    def _off_window(self, prof, hour):
        support = {h for h, c in prof.hours.items() if c >= self.cfg["min_hour_support"]}
        if not support:
            return False
        m = self.cfg["hour_margin"]
        return not any(min((hour - h) % 24, (h - hour) % 24) <= m for h in support)

    @staticmethod
    def _priv_user(user, roles):
        return any(k in roles.get(user, "") for k in ("Security", "Admin", "IT "))

    def _register_check(self, ev):
        """A credential appearing for the first time: is it registered, and was it dormant?"""
        if self.register is None:
            return []
        cid = str(ev.actor)[4:] if str(ev.actor).startswith("key:") else str(ev.actor)
        reg = self.register[self.register.credential_id == cid]
        if reg.empty:
            return ["UNREGISTERED_CREDENTIAL"]
        last = pd.Timestamp(reg.last_used.iat[0], tz="UTC") if pd.notna(reg.last_used.iat[0]) else None
        if last is not None and (ev.ts - last).days > 180:
            return ["DORMANT_CREDENTIAL"]
        return []

    # ------------------------------------------------------------------ main
    def run(self, events: pd.DataFrame) -> pd.DataFrame:
        cfg = self.cfg
        start = events.ts.min()
        warm_end = start + pd.Timedelta(days=cfg["warmup_days"])
        out_sig, out_score = [], []
        export_open = defaultdict(list)             # (system, actor) -> [create ts]
        fail_hist = defaultdict(list)               # user -> [(ts, ip)]
        good_ip = defaultdict(set)                  # user -> ips with successful sign-in
        apr_max = 0
        apr_seen = set()
        req_flag = {}                               # req_id -> signals (ledger)
        drift_hist = defaultdict(list)
        sys_fams = defaultdict(set)                 # system -> client families seen in clean traffic
        burst_pos = defaultdict(list)               # user -> positions of failures in current burst
        priv = tuple(cfg["private_ranges"])
        roles = {}
        if self.roster is not None:
            roles = dict(zip(self.roster.username, self.roster.role.astype(str) + " " + self.roster.department.astype(str)))

        for ev in events.itertuples(index=False):
            sig = []
            key = (ev.system, ev.actor)
            prof = self.profiles[key]
            fam, ver = ua_parse(ev.ua) if ev.system == "ledger" else (None, None)
            prefix = storage_prefix(ev.target) if ev.system == "storage" else None
            warm = ev.ts < warm_end

            # ---------------- integration behaviour contract ----------------
            if ev.actor_kind == "integration" and ev.system in ("ledger", "helpdesk", "storage", "link"):
                if not warm:
                    if prof.n == 0:
                        sig.append("NEW_LINK_HOST" if ev.system == "link" else "NEW_ORIGIN")
                        peer = self.profiles.get((ev.system, "peer:" + str(ev.op)))
                        if peer is not None and peer.n >= 50 and self._off_window(peer, ev.ts.hour):
                            sig.append("PEER_OFF_WINDOW")
                        if ev.system != "link":
                            sig.extend(self._register_check(ev))
                            if fam is not None and fam not in sys_fams[ev.system]:
                                sig.append("UA_NEW_FAMILY")
                    else:
                        if isinstance(ev.ip, str) and ev.ip not in prof.ips and ev.system != "link":
                            sig.append("NEW_ORIGIN")
                        if fam is not None:
                            if fam not in prof.ua_max:
                                sig.append("UA_NEW_FAMILY")
                            elif ver and prof.ua_max[fam] and ver < prof.ua_max[fam] \
                                    and prof.ua_count[(fam, prof.ua_max[fam])] >= 20:
                                sig.append("UA_DOWNGRADE")
                        if self._off_window(prof, ev.ts.hour):
                            sig.append("OFF_WINDOW")
                        if ev.op not in prof.ops and not self._approved(ev, prof):
                            sig.append("NEW_CAPABILITY")
                            base = ev.op.split()[0] if ev.op else ""
                            if ev.op in self.sensitive or base in self.sensitive:
                                sig.append("SENSITIVE_CAPABILITY")
                        if prefix and prefix not in prof.prefixes:
                            sig.append("PATH_SCOPE_DRIFT")
                            h = [t for t in drift_hist[key] if ev.ts - t <= pd.Timedelta(hours=1)] + [ev.ts]
                            drift_hist[key] = h
                            if len(h) >= 3:
                                sig.append("DRIFT_REPEAT")
                if ev.system == "helpdesk" and ev.op == "ticket.search" and isinstance(ev.detail, str) \
                        and self.secret_re.search(ev.detail):
                    sig.append("SECRET_HUNT")

            # ---------------- export -> erase chain (any identity) -------------
            if ev.op == "export.create":
                export_open[key].append(ev.ts)
            elif ev.op == "export.delete" and ev.result in ("ok", "204", "200", "error"):
                win = pd.Timedelta(minutes=cfg["export_chain_window_minutes"])
                if any(ev.ts - t <= win for t in export_open[key]):
                    sig.append("EXPORT_ERASE_INTEGRATION" if ev.actor_kind == "integration" else "EXPORT_ERASE_HUMAN")

            # ---------------- money: vendor master changes --------------------
            if ev.system == "vendormaster" and "bank" in str(ev.op):
                if str(ev.channel).upper() == "API" or ev.actor_kind == "integration":
                    sig.append("BANK_CHANGE_VIA_INTEGRATION")
                ref = ev.approval_ref if isinstance(ev.approval_ref, str) else ""
                m = self.apr_re.match(ref)
                if not ref:
                    sig.append("BANK_CHANGE_NO_APPROVAL")
                elif m:
                    num = int(m.group(1))
                    if ref in apr_seen or num < apr_max - cfg["approval_ref_max_age_steps"]:
                        sig.append("STALE_APPROVAL_REF")
                if sig:
                    run = next_payment_run(ev.ts, cfg["payment_run_days"])
                    if run is not None and (run - ev.ts.normalize()).days <= cfg["payment_run_lookahead_days"]:
                        sig.append("NEAR_PAYMENT_RUN")
                if isinstance(ev.req_id, str) and req_flag.get(ev.req_id):
                    sig.append("LINKED_TO_FLAGGED_REQUEST")
            if ev.system == "vendormaster" and isinstance(ev.approval_ref, str):
                m = self.apr_re.match(ev.approval_ref)
                if m:
                    apr_max = max(apr_max, int(m.group(1)))
                    apr_seen.add(ev.approval_ref)

            # ---------------- sign-in bursts from a never-used address ---------
            if ev.system == "sso":
                if ev.result == "success":
                    good_ip[ev.actor].add(ev.ip)
                elif ev.ip not in good_ip[ev.actor] and isinstance(ev.ip, str) and not ev.ip.startswith(priv):
                    h = [x for x in fail_hist[ev.actor] if ev.ts - x[0] <= pd.Timedelta(minutes=10) and x[1] == ev.ip]
                    h.append((ev.ts, ev.ip))
                    fail_hist[ev.actor] = h
                    burst_pos[ev.actor] = [x for x in (burst_pos[ev.actor] or []) if ev.ts - x[1] <= pd.Timedelta(minutes=10)]
                    if len(h) >= 3:
                        sig.append("SIGNIN_FAIL_BURST_NEW_IP")
                        for pos, _ in burst_pos[ev.actor]:
                            if "SIGNIN_FAIL_BURST_NEW_IP" not in out_sig[pos]:
                                out_sig[pos] = ";".join(filter(None, [out_sig[pos], "SIGNIN_FAIL_BURST_NEW_IP"]))
                                out_score[pos] += self.w["SIGNIN_FAIL_BURST_NEW_IP"] + int(out_score[pos] == 0 and self._priv_user(ev.actor, roles))
                    burst_pos[ev.actor].append((len(out_sig), ev.ts))

            score = sum(self.w.get(s, 0) for s in sig)
            if ev.system == "sso" and sig and self._priv_user(ev.actor, roles):
                score += 1
            if ev.system == "ledger" and score >= 2 and isinstance(ev.req_id, str):
                req_flag[ev.req_id] = sig
            out_sig.append(";".join(sig))
            out_score.append(score)

            # learn only from clean (or nearly clean) behaviour
            if ev.actor_kind == "integration" and (warm or score < 2):
                prof.learn(ev, fam, ver, prefix)
                if fam:
                    sys_fams[ev.system].add(fam)
                if ev.system == "link":
                    self.profiles[(ev.system, "peer:" + str(ev.op))].learn(ev, None, None, None)

        res = events.copy()
        res["signals"] = out_sig
        res["score"] = out_score
        thr = cfg["alert_threshold"]
        res["level"] = pd.cut(res.score, [-1, 1, thr - 1, 999], labels=["none", "review", "alert"]).astype(str)
        return res

    # ------------------------------------------------------------------ hygiene
    def hygiene(self, events):
        """Governance findings that are not attacks: leavers, stale register entries."""
        rows = []
        if self.roster is not None:
            r = self.roster
            left = r[r.termination_date.notna()]
            for x in left.itertuples():
                term = pd.Timestamp(x.termination_date, tz="UTC") + pd.Timedelta(days=1)
                s = events[(events.system == "sso") & (events.actor == x.username) & (events.ts >= term) & (events.result == "success")]
                if str(x.status).lower() == "active":
                    rows.append({"finding": "ROSTER_LEAVER_STILL_ACTIVE", "subject": x.username,
                                 "detail": f"terminated {x.termination_date} but roster status '{x.status}'", "eids": ""})
                if len(s):
                    rows.append({"finding": "LEAVER_SIGNIN_AFTER_EXIT", "subject": x.username,
                                 "detail": f"{len(s)} successful sign-ins after {x.termination_date}; methods {sorted(set(s.ua))}",
                                 "eids": ",".join(s.eid)})
            known = set(r.username)
            sso_users = set(events[events.system == "sso"].actor)
            for u in sorted(sso_users - known):
                s = events[(events.system == "sso") & (events.actor == u)]
                rows.append({"finding": "IDENTITY_NOT_IN_ROSTER", "subject": u,
                             "detail": f"{len(s)} sign-ins, methods {sorted(set(s.ua))}, results {dict(Counter(s.result))}", "eids": ""})
        sso = events[events.system == "sso"]
        if len(sso):
            pw = sso[sso.ua == "password"]
            if len(pw):
                rows.append({"finding": "PASSWORD_ONLY_SIGNINS", "subject": ",".join(sorted(set(pw.actor))),
                             "detail": f"{len(pw)} sign-ins without MFA (contradicts 'MFA enforced, no exceptions')", "eids": ""})
        if self.register is not None:
            for x in self.register.itertuples():
                issues = []
                if not x.ip_restriction:
                    issues.append("no IP restriction")
                if pd.isna(x.token_lifetime_days):
                    issues.append("never expires")
                if any(k in str(x.scope) for k in ("admin", "all-modules", "all-folders", "read:all")):
                    issues.append(f"broad scope '{x.scope}'")
                try:
                    if (pd.Timestamp("2026-09-02") - pd.Timestamp(x.last_review)).days > 365:
                        issues.append(f"last review {x.last_review}")
                    if (pd.Timestamp("2026-09-02") - pd.Timestamp(x.last_used)).days > 180 and x.status == "active":
                        issues.append(f"dormant since {x.last_used} but active")
                except Exception:
                    pass
                if issues:
                    rows.append({"finding": "CREDENTIAL_CONTROL_GAP", "subject": x.credential_id,
                                 "detail": "; ".join(issues), "eids": ""})
        return pd.DataFrame(rows)
