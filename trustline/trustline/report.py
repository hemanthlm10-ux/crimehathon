"""Self-contained HTML report (no external assets) for the analyst and the GM."""
from __future__ import annotations

import html
import json

import pandas as pd

SYS_COLOR = {"ledger": "#2563eb", "helpdesk": "#9333ea", "storage": "#d97706", "link": "#0d9488",
             "vendormaster": "#dc2626", "sso": "#475569"}


def _e(x):
    return html.escape(str(x)) if x is not None and not (isinstance(x, float) and pd.isna(x)) else ""


def _timeline_svg(sub):
    if sub.empty:
        return ""
    t0, t1 = sub.ts.min(), sub.ts.max()
    span = max((t1 - t0).total_seconds(), 1)
    systems = [s for s in SYS_COLOR if s in set(sub.system)]
    W, rowh, left = 900, 26, 110
    H = rowh * len(systems) + 40
    out = [f'<svg viewBox="0 0 {W} {H}" width="100%" role="img" aria-label="incident timeline">']
    for i, s in enumerate(systems):
        y = 20 + i * rowh
        out.append(f'<text x="4" y="{y + 4}" class="lbl">{s}</text>'
                   f'<line x1="{left}" x2="{W - 10}" y1="{y}" y2="{y}" class="axis"/>')
        for r in sub[sub.system == s].itertuples():
            x = left + (W - left - 20) * (r.ts - t0).total_seconds() / span
            rad = 5 if r.level == "alert" else 3
            out.append(f'<circle cx="{x:.1f}" cy="{y}" r="{rad}" fill="{SYS_COLOR[s]}" fill-opacity="0.75">'
                       f'<title>{_e(r.ts)} {_e(r.actor)} {_e(r.op)} {_e(r.ip)} [{_e(r.signals)}]</title></circle>')
    days = pd.date_range(t0.normalize(), t1.normalize(), freq="D")
    step = max(1, len(days) // 10)
    for d in days[::step]:
        x = left + (W - left - 20) * max((d - t0).total_seconds(), 0) / span
        out.append(f'<text x="{x:.1f}" y="{H - 6}" class="tick">{d:%d %b}</text>')
    out.append("</svg>")
    return "".join(out)


def write_html(path, ev, scored, incidents, acts, hyg, cfg):
    flagged = scored[scored.level != "none"]
    lv = scored.level.value_counts()
    parts = [f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>TrustLine Report</title>
<style>
:root{{--bg:#f8fafc;--fg:#0f172a;--mut:#64748b;--card:#fff;--bd:#e2e8f0;--alert:#dc2626;--rev:#d97706}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0b1220;--fg:#e2e8f0;--mut:#94a3b8;--card:#111a2e;--bd:#1e293b}}}}
body{{background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,sans-serif;margin:0;padding:16px}}
main{{max-width:1100px;margin:auto}} h1{{font-size:22px;margin:0 0 4px}} h2{{font-size:17px;margin:28px 0 8px}}
.card{{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px 16px;margin:10px 0}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}}
.kpi b{{display:block;font-size:22px}} .mut{{color:var(--mut)}}
table{{border-collapse:collapse;width:100%;font-size:12.5px}} th,td{{border-bottom:1px solid var(--bd);padding:4px 6px;text-align:left;vertical-align:top}}
.scroll{{overflow-x:auto}} .tag{{display:inline-block;border-radius:4px;padding:0 5px;font-size:11.5px;margin:1px;background:var(--bd)}}
.alert{{color:var(--alert);font-weight:600}} .review{{color:var(--rev)}}
svg .lbl{{font-size:11px;fill:var(--mut)}} svg .tick{{font-size:10px;fill:var(--mut)}} svg .axis{{stroke:var(--bd)}}
code{{font-size:12px}}
</style></head><body><main>
<h1>TrustLine &mdash; integration identity investigation</h1>
<div class="mut">Learned behaviour contracts for non-human identities, correlated across systems. All times UTC.</div>
<div class="kpis">
<div class="card kpi"><b>{len(ev.events):,}</b><span class="mut">events, {len(ev.files)} files</span></div>
<div class="card kpi"><b class="alert">{lv.get('alert', 0)}</b><span class="mut">alerts</span></div>
<div class="card kpi"><b class="review">{lv.get('review', 0)}</b><span class="mut">review items</span></div>
<div class="card kpi"><b>{len(incidents)}</b><span class="mut">incidents</span></div>
</div>"""]
    for inc, act in zip(incidents, acts):
        sub = scored[scored.eid.isin(inc["eids"])].sort_values("ts")
        parts.append(f"""<h2>{inc['id']} &middot; {inc['first']:%d %b %H:%M} &rarr; {inc['last']:%d %b %Y %H:%M} UTC</h2>
<div class="card"><div>Systems: {' '.join(f'<span class="tag">{_e(s)}</span>' for s in inc['systems'])}</div>
<div>Identities: {' '.join(f'<span class="tag">{_e(s)}</span>' for s in inc['identities'])}</div>
<div>Origins: {' '.join(f'<span class="tag">{_e(s)}</span>' for s in inc['ips'][:20])}</div>
<div class="mut">First precursor (review level): {_e(inc.get('first_precursor'))}</div>
<div class="mut">Signals: {_e(', '.join(f'{k}×{v}' for k, v in inc['signals'].items()))}</div>
{_timeline_svg(sub)}</div>
<div class="card"><b>Containment playbook</b><table><tr><th>Action</th><th>Target</th><th>Why / detail</th></tr>""")
        for s in act["steps"]:
            extra = ""
            if s.get("reissue_with"):
                c = s["reissue_with"]
                extra = (f"<br><span class='mut'>Re-issue with IPs {_e(', '.join(c['allow_ips'][:8]))}; "
                         f"hours {_e(c['allow_hours_utc'])}; ops {_e(', '.join(c['allow_ops'][:8]))}</span>")
            if s.get("next_run"):
                extra = f"<br><span class='alert'>Hold before payment run {s['next_run']}; revert to {_e(s.get('revert_to'))}</span>"
            parts.append(f"<tr><td><b>{_e(s['do'])}</b></td><td>{_e(s['target'])}</td><td>{_e(s['why'])}{extra}</td></tr>")
        ex = act["exposure"]
        parts.append(f"""</table><p><b>Exposure for Legal</b>: first alert {_e(ex['first_malicious_utc'])};
ledger records returned {ex['ledger_records_returned']:,}; helpdesk exports {ex['helpdesk_exports']};
storage bytes read {ex['storage_bytes_read']:,}; files: {_e(', '.join(ex['storage_files_read']))}</p></div>
<details class="card"><summary>Evidence rows ({len(sub)})</summary><div class="scroll"><table>
<tr><th>UTC</th><th>sys</th><th>record</th><th>identity</th><th>origin</th><th>op</th><th>vol</th><th>signals</th><th>score</th></tr>""")
        for r in sub.itertuples():
            parts.append(f"<tr><td>{r.ts:%m-%d %H:%M:%S}</td><td>{_e(r.system)}</td><td><code>{_e(r.eid)}</code></td>"
                         f"<td>{_e(r.actor)}</td><td>{_e(r.ip)} {_e(r.host) if isinstance(r.host, str) and r.system != 'sso' else ''}</td>"
                         f"<td>{_e(r.op)}<br><span class='mut'>{_e(r.detail) if r.system in ('helpdesk', 'vendormaster') else _e(r.target)}</span></td>"
                         f"<td>{int(r.volume):,}</td><td>{_e(r.signals)}</td><td class='{r.level}'>{r.score}</td></tr>")
        parts.append("</table></div></details>")
    rest = flagged[flagged.incident.isna()] if "incident" in flagged else flagged
    if len(rest):
        parts.append(f"<h2>Review queue ({len(rest)})</h2><div class='card scroll'><table>"
                     "<tr><th>UTC</th><th>sys</th><th>record</th><th>identity</th><th>op</th><th>signals</th></tr>")
        for r in rest.itertuples():
            parts.append(f"<tr><td>{r.ts:%Y-%m-%d %H:%M}</td><td>{_e(r.system)}</td><td><code>{_e(r.eid)}</code></td>"
                         f"<td>{_e(r.actor)}</td><td>{_e(r.op)} {_e(r.target)}</td><td>{_e(r.signals)}</td></tr>")
        parts.append("</table></div>")
    if len(hyg):
        parts.append("<h2>Governance gaps</h2><div class='card scroll'><table><tr><th>Finding</th><th>Subject</th><th>Detail</th></tr>")
        for r in hyg.itertuples():
            parts.append(f"<tr><td>{_e(r.finding)}</td><td>{_e(r.subject)}</td><td>{_e(r.detail)}</td></tr>")
        parts.append("</table></div>")
    parts.append("<p class='mut'>Generated by TrustLine from the supplied synthetic evidence only.</p></main></body></html>")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(parts))
