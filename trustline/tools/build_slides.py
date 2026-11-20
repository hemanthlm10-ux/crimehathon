"""Build Tier 2 (10-slide) and Tier 3 (one-page) decks with python-pptx."""
import json
import os

import pandas as pd
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Inches, Pt

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
OUTD = os.path.join(ROOT, "docs", "submission")
CH = os.path.join(OUTD, "charts")
INK, ACC, RED, MUT, BG2, TEAL = (RGBColor(0x0F, 0x17, 0x2A), RGBColor(0x25, 0x63, 0xEB), RGBColor(0xDC, 0x26, 0x26),
                                 RGBColor(0x64, 0x74, 0x8B), RGBColor(0xF1, 0xF5, 0xF9), RGBColor(0x0D, 0x94, 0x88))
WHITE = RGBColor(255, 255, 255)
EV = json.load(open(os.path.join(ROOT, "out", "evaluation.json")))
VAR = pd.read_csv(os.path.join(ROOT, "out", "variation_summary.csv"))


def new_deck():
    p = Presentation()
    p.slide_width, p.slide_height = Inches(13.333), Inches(7.5)
    return p


def text(slide, x, y, w, h, paras, size=16, color=INK, bold=False, align=None, fill=None, line=None):
    shp = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h)) if fill is None else \
        slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x), Inches(y), Inches(w), Inches(h))
    if fill is not None:
        shp.fill.solid(); shp.fill.fore_color.rgb = fill
        if line is None:
            shp.line.fill.background()
        else:
            shp.line.color.rgb = line
        shp.adjustments[0] = 0.08
    tf = shp.text_frame
    tf.word_wrap = True
    if fill is not None:
        tf.vertical_anchor = MSO_ANCHOR.TOP
        if align is None:
            align = PP_ALIGN.LEFT
    tf.margin_left = tf.margin_right = Inches(0.12)
    tf.margin_top = tf.margin_bottom = Inches(0.06)
    if isinstance(paras, str):
        paras = [paras]
    for i, para in enumerate(paras):
        pg = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        if align:
            pg.alignment = align
        runs = para if isinstance(para, list) else [(para, {})] if isinstance(para, str) else [para]
        for r in runs:
            t, o = (r, {}) if isinstance(r, str) else r
            run = pg.add_run()
            run.text = t
            run.font.size = Pt(o.get("size", size))
            run.font.bold = o.get("bold", bold)
            run.font.color.rgb = o.get("color", color)
            run.font.name = "Segoe UI"
        pg.space_after = Pt(o.get("after", 4) if isinstance(runs[-1], tuple) else 4)
    return shp


def header(slide, n, title, sub=None):
    bar = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(0.18), Inches(7.5))
    bar.fill.solid(); bar.fill.fore_color.rgb = ACC; bar.line.fill.background()
    text(slide, 0.45, 0.3, 11.5, 0.7, title, size=28, bold=True)
    if sub:
        text(slide, 0.45, 0.95, 12.3, 0.5, sub, size=14, color=MUT)
    text(slide, 11.6, 7.0, 1.6, 0.35, f"TrustLine · {n}", size=10, color=MUT, align=PP_ALIGN.RIGHT)


def table(slide, x, y, w, rows, widths, size=11, h=0.3):
    t = slide.shapes.add_table(len(rows), len(rows[0]), Inches(x), Inches(y), Inches(w), Inches(h * len(rows))).table
    for j, cw in enumerate(widths):
        t.columns[j].width = Inches(cw)
    for i, row in enumerate(rows):
        for j, val in enumerate(row):
            c = t.cell(i, j)
            c.text = str(val)
            c.margin_left = c.margin_right = Inches(0.06)
            c.margin_top = c.margin_bottom = Inches(0.025)
            for pg in c.text_frame.paragraphs:
                for r in pg.runs:
                    r.font.size = Pt(size); r.font.name = "Segoe UI"
                    r.font.bold = i == 0
                    r.font.color.rgb = WHITE if i == 0 else INK
            c.fill.solid()
            c.fill.fore_color.rgb = ACC if i == 0 else (BG2 if i % 2 else WHITE)
    return t


def bullets(items, size=15):
    return [[("•  ", {"color": ACC, "bold": True, "size": size}), (it, {"size": size})] if isinstance(it, str) else it
            for it in items]


def build_tier2():
    p = new_deck()
    blank = p.slide_layouts[6]
    a = EV["approaches"]

    # 1 title
    s = p.slides.add_slide(blank)
    bg = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, p.slide_width, p.slide_height)
    bg.fill.solid(); bg.fill.fore_color.rgb = INK; bg.line.fill.background()
    text(s, 0.8, 1.6, 11.5, 1.2, "TrustLine", size=60, bold=True, color=WHITE)
    text(s, 0.8, 2.75, 11.5, 0.8, "Who is really holding the key?  Behaviour contracts for integration identities",
         size=24, color=RGBColor(0x93, 0xC5, 0xFD))
    text(s, 0.8, 4.0, 11.5, 1.6, ["CRIMEATHON'26 · Case CR-26-047 · Harbor & Finch Freight",
                                   "Approach: DEFENSE · Tier 2 Technical Concept", "Team: Wi-Fight Club.exe"],
         size=16, color=RGBColor(0xCB, 0xD5, 0xE1))

    # 2 what happened
    s = p.slides.add_slide(blank)
    header(s, 2, "What happened: one campaign, hidden as five 'small things'",
           "TallyBridge's two keys + a pasted storage key, used 9 Aug → 6 Sep, ending in a bank change before the 8 Sep run")
    s.shapes.add_picture(os.path.join(CH, "timeline.png"), Inches(0.45), Inches(1.5), width=Inches(12.4))
    text(s, 0.45, 5.75, 12.4, 1.2, bullets([
        "Each department saw one fragment: Support saw 'weird exports', Finance an invoice, Accounts a vendor notice, IT a failed login.",
        "Nobody joined them. The vendor then declared the matter closed (E16), and every factual claim in that notice is contradicted by the logs."], 14))

    # 3 evidence
    s = p.slides.add_slide(blank)
    header(s, 3, "The evidence, joined across systems", "All times UTC · E02 converted from IST · E05 from an unsynced epoch clock")
    table(s, 0.45, 1.5, 12.4, [
        ["When", "What the records show", "Evidence IDs"],
        ["9 Aug", "key-tb-07 from home broadband, retired client 3.4.1: /me, /schema, limit=1 probes", "E01 req-c28d87e49d…; E20-C"],
        ["11 Aug", "tb-sync-svc searches tickets: password, api_key, token, bvk-; 10 export→delete cycles", "E02 EXP-5410…5419; E06 (14 = 4+10)"],
        ["12 Aug", "Vendor master exported ×2 (9,840 / 9,835 rows); export 9932 never deleted", "E01 req-c35c2ccaff, req-51b30fba51"],
        ["14–16 Aug", "Pasted key bvk-7f3a reads vendor-bank-details, payment template, statements", "E13, TKT-48213, E05"],
        ["15 Aug", "Same IP fails 3 sign-ins to the IT Security Admin; MFA holds", "E03 sso-74805f5dd1…"],
        ["17–19 Aug", "Vendor build host tb-build-02 on the private link: payments, bank details, export+delete", "E15; E01 req-fe4bd4fe93"],
        ["2 Sep", "Keys still the 2024 originals: no IP limit, no expiry, admin scope ('rotated' 24 Aug?)", "E04, E10 §2, E11 #4"],
        ["3 Sep", "Bank account of V-0412 Coastal Packaging changed via API, no approval ref", "E18 req-5f61b0de8 = E19 chg-8b9888c39b"],
    ], [1.3, 7.3, 3.8], size=12, h=0.42)
    text(s, 0.45, 5.6, 12.4, 1.2, bullets([
        "Integrity check: the August HelpDeskr invoice counts 14 export jobs, which is 4 weekly + exactly the 10 attacker jobs.",
        "The vendor's indicator 'python-requests/2.31.0' appears in no log. The attacker posed as the vendor's own client."], 13))

    # 4 alternatives
    s = p.slides.add_slide(blank)
    header(s, 4, "Other explanations we weighed", "Treating unusual ≠ malicious, and ordinary-looking ≠ safe")
    table(s, 0.45, 1.5, 12.4, [
        ["Explanation", "Verdict", "Why"],
        ["Legitimate sync / new release 3.5.0", "Ruled out", "Real sync: 6 known hosts, 01:30–02:15, 4 endpoints, newest version. Suspect calls break 3–6 of these"],
        ["Finance audit export (Farah, 22 Jul)", "Ordinary", "Announced in chat, office PC, staff UI session"],
        ["Support weekly export / 28 Jul delete", "Ordinary", "Tuesdays 09:10 from 172.16.8.12; delete explained in chat"],
        ["198.18.7.x = attacker range", "Too broad", "63 other staff sign in from that home-broadband range (E20-G: dynamic IPs)"],
        ["Former employee r.menon, contractor travel, svc-reporting loop", "Hygiene only", "Real gaps, no link to integration activity"],
        ["V-0233 bank change, recycled approval APR-1182", "Unresolved", "Flagged for verification, not accused"],
        ["9 Jul build host → sandbox", "Ambiguous", "Inside the vendor's announced maintenance window"],
    ], [4.2, 1.6, 6.6], size=12, h=0.45)
    text(s, 0.45, 5.45, 12.4, 1.4, bullets([
        "What would change our mind: TallyBridge proves the 10.20.4.77 jobs were sanctioned AND Coastal Packaging confirms the new account via call-back on its pre-change number.",
        "Open questions: was the 8 Sep payment released? How did the keys leave the vendor (SOC 2 carves out its credential vault)?"], 13))

    # 5 problem + obvious approach
    s = p.slides.add_slide(blank)
    header(s, 5, "The problem we chose, and the obvious fix we rejected")
    text(s, 0.45, 1.25, 6.0, 2.7, [[("Problem", {"bold": True, "size": 18, "color": ACC})],
                                   "Integration keys are trusted by possession alone. No system checks whether the software holding a key behaves like the software it was issued to, and each system sees only its own fragment.",
                                   [("Why this one: it is the common factor in every wave, and it is the one that moves money. Contracts and training fix it slowly; the 8 Sep payment run needs protection now.", {"size": 14, "color": MUT})]],
         size=16, fill=BG2)
    text(s, 6.75, 1.25, 6.1, 2.7, [[("Obvious approach", {"bold": True, "size": 18, "color": RED})],
                                   "Block the vendor's IOCs, add volume-threshold SIEM rules, rotate the keys.",
                                   [("Rotation was 'done' on 24 Aug; the key was abused on 3 Sep. IOCs miss the build host and the BlueVault addresses.", {"size": 14, "color": MUT})]],
         size=16, fill=BG2)
    s.shapes.add_picture(os.path.join(CH, "comparison.png"), Inches(1.2), Inches(4.15), width=Inches(10.6))

    # 6 idea
    s = p.slides.add_slide(blank)
    header(s, 6, "Our idea: the logs write the contract", "What is new compared with rules, blocklists and dashboards")
    cards = [("1  Learned behaviour contract", "Per non-human identity: origins, link host, client family + version, hours, operations, data folders. Clean events extend it, so upgrades and schedule shifts are absorbed. Violations are never learned, so the attacker cannot train it."),
             ("2  Cross-system stitching", "Union-find over register ownership (same vendor), request_id ↔ vendor change, private-link host labels, shared public IPs, and 'secret searched → secret used' (search 'bvk-' links to key bvk-7f3a)."),
             ("3  Money-aware response", "Bank changes via integration / no approval / recycled ref are scored against the next payment run (8th, 23rd). A HOLD with a revert value is generated, plus orphan exports and an exposure summary for Legal."),
             ("4  Same contract → prevention", "The contract becomes a least-privilege re-issue spec (IP allow-list, ops, hours). Replay enforces it and shows what it would have blocked, including what it would cost.")]
    for k, (t, d) in enumerate(cards):
        x = 0.45 + (k % 2) * 6.25
        y = 1.55 + (k // 2) * 2.65
        text(s, x, y, 6.0, 2.45, [[(t, {"bold": True, "size": 17, "color": ACC})], d], size=14, fill=BG2)

    # 7 architecture
    s = p.slides.add_slide(blank)
    header(s, 7, "Architecture and workflow")
    boxes = [("Evidence files\nE01–E19 (any name)", "column-signature loading"),
             ("Normaliser", "UTC alignment (IST, epoch skew), host enrichment from E15"),
             ("Contract engine", "per-identity learned contract → 20 signals, weighted score"),
             ("Correlator", "incident graph across 6 systems"),
             ("Responder", "revoke / re-issue spec / payment hold / purge / exposure"),
             ("Outputs", "report.html, incidents.json, playbook.json, replay")]
    for k, (t, d) in enumerate(boxes):
        x = 0.45 + k * 2.13
        text(s, x, 1.6, 1.95, 1.9, [[(t, {"bold": True, "size": 14, "color": WHITE})], [(d, {"size": 11.5, "color": WHITE})]],
             fill=ACC if k not in (2, 3) else TEAL, align=PP_ALIGN.CENTER)
        if k < 5:
            ar = s.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, Inches(x + 1.95), Inches(2.4), Inches(0.18), Inches(0.3))
            ar.fill.solid(); ar.fill.fore_color.rgb = MUT; ar.line.fill.background()
    table(s, 0.45, 3.85, 12.4, [
        ["Signal family", "Examples (weights in config/default.json)"],
        ["Origin", "NEW_ORIGIN, NEW_LINK_HOST, PEER_OFF_WINDOW, DORMANT / UNREGISTERED_CREDENTIAL"],
        ["Software identity", "UA_DOWNGRADE (retired client reappears), UA_NEW_FAMILY"],
        ["Behaviour", "NEW / SENSITIVE_CAPABILITY, OFF_WINDOW, PATH_SCOPE_DRIFT (+repeat), SECRET_HUNT, EXPORT_ERASE"],
        ["Money", "BANK_CHANGE_VIA_INTEGRATION, NO_APPROVAL, STALE_APPROVAL_REF, NEAR_PAYMENT_RUN, LINKED_TO_FLAGGED_REQUEST"],
        ["Governance", "leavers still active, password-only sign-ins, keys without IP limit / expiry / review"],
    ], [2.6, 9.8], size=12, h=0.42)
    text(s, 0.45, 6.55, 12.4, 0.4, "Alert ≥ 4 · Review 2–3 · two-tier output keeps analyst load small", size=12, color=MUT)

    # 8 built so far
    s = p.slides.add_slide(blank)
    header(s, 8, "What we have built, and what works now", "Python 3 · pandas · no network access · runs on 109k events in ~6 s")
    text(s, 0.45, 1.5, 5.6, 5.2, bullets([
        "analyse: incidents, playbook, HTML report",
        "evaluate: precision / recall vs labels and vs 3 obvious approaches",
        "replay: prevention, with learned contracts enforced",
        "run_variations: 7 randomised unseen-attack scenarios",
        "make_labels: analyst ground truth (explicit criteria)",
        "Loads renamed or re-ordered files by their columns",
        "Config-driven: no IP / key hard-coded in detection",
        "Stack: Python, pandas, matplotlib, reportlab, python-pptx"], 15))
    text(s, 6.3, 1.5, 6.55, 5.2, [[("Live output on the case evidence", {"bold": True, "size": 15, "color": ACC})],
                                  [("INC-001 9 Aug 03:12 → 6 Sep 01:36 · 6 systems · 237 alerts", {"size": 12})],
                                  [("identities: key-tb-07, tb-sync-svc, key:bvk-7f3a, tb-build-02, a.kapoor", {"size": 12})],
                                  [("HOLD_PAYMENT  V-0412 Coastal Packaging → revert ****4417, run 8 Sep", {"size": 12, "color": RED, "bold": True})],
                                  [("REVOKE_AND_REISSUE key-tb-07 → 6 IPs, 01–02 UTC, ops: GET invoices · GET vendors · GET payments/status · POST invoices", {"size": 12})],
                                  [("ISOLATE_LINK_HOST tb-build-02", {"size": 12})],
                                  [("LOCATE_AND_PURGE_EXPORT ledger:9932, helpdesk:EXP-5419", {"size": 12})],
                                  [("Exposure: ~40.9k ledger records, 10 ticket exports, 7 finance files", {"size": 12})],
                                  [("INC-002 V-0233 recycled approval ref → verify", {"size": 12, "color": MUT})]],
         size=12, fill=BG2)

    # 9 testing
    s = p.slides.add_slide(blank)
    header(s, 9, "How we test it, and the results")
    d = a["D_TrustLine_incident"]
    table(s, 0.45, 1.3, 6.2, [
        ["On supplied data (241 malicious)", "Found", "False alarms"],
        ["Vendor IOC list", f"{a['A_vendor_indicator_list']['recall']:.0%}", a["A_vendor_indicator_list"]["FP"]],
        ["Block IOC /24", f"{a['B_block_indicator_/24']['recall']:.0%}", a["B_block_indicator_/24"]["FP"]],
        ["Volume threshold", f"{a['C_volume_p99.5']['recall']:.0%}", a["C_volume_p99.5"]["FP"]],
        ["TrustLine", f"{d['recall']:.0%}", d["FP"]],
        ["Prevention replay", "177/177 blocked", "0 (+70 unapproved new-capability calls)"],
    ], [2.6, 1.5, 2.1], size=12, h=0.42)
    names = {"stolen_key_external": "Stolen key, real UA copied", "rogue_link_host": "Rogue host in sync window",
             "helpdesk_hunt": "Ticket hunt, new keywords", "storage_drift": "Storage key, normal IP, new folder",
             "dormant_key": "Dormant key wakes", "insider_bank_change": "Recycled approval ref",
             "mimic_sync": "Perfect mimic of real sync"}
    rows = [["Unseen variation (randomised)", "Caught", "FP"]]
    for r in VAR.itertuples():
        rows.append([names.get(r.scenario, r.scenario), f"{r.caught}/{r.runs}", r.false_alarms])
    table(s, 6.9, 1.3, 5.95, rows, [3.7, 1.25, 1.0], size=12, h=0.42)
    text(s, 0.45, 5.1, 12.4, 1.8, bullets([
        "Ground truth = our manual investigation, written as explicit indicators the detector never sees (tools/make_labels.py).",
        "Variations: every malicious row removed, then randomised attacks injected in each file's native format (IST, epoch, request-id joins).",
        "Honest caveats: we wrote the variations ourselves and tuned 3 weights after the first round. A perfect mimic of the real sync host is missed."], 13.5))

    # 10 limits + next
    s = p.slides.add_slide(blank)
    header(s, 10, "Limits, what Harbor & Finch should do, and next steps")
    text(s, 0.45, 1.3, 4.0, 5.5, [[("What it misses", {"bold": True, "size": 17, "color": RED})]] + bullets([
        "Perfect mimicry from a real sync host",
        "Attacks already present during the 21-day warm-up",
        "Humans only lightly profiled",
        "New legitimate features alert until approved",
        "BlueVault clock skew limits minute-level joins"], 13), size=13, fill=BG2)
    text(s, 4.65, 1.3, 4.1, 5.5, [[("Do now (before 8 Sep)", {"bold": True, "size": 17, "color": ACC})]] + bullets([
        "Hold V-0412; call back on the pre-change number",
        "Verify V-0233 / APR-1182",
        "Revoke key-tb-07, tb-sync-svc, bvk-7f3a + dormant keys",
        "Re-issue with the generated contract + 90-day expiry",
        "Legal: earliest exposure 9 Aug; get HelpDeskr per-job breakdown",
        "Re-rate TallyBridge HIGH; demand forensics on tb-build-02"], 13), size=13, fill=BG2)
    text(s, 8.95, 1.3, 3.9, 5.5, [[("Next steps", {"bold": True, "size": 17, "color": TEAL})]] + bullets([
        "Per-run call-count and sequence model (catch mimicry)",
        "Live mode: nightly run + payment-run guard in LedgerOne",
        "Contract export to gateway / key-restriction config",
        "Change-approval workflow for new vendor capabilities",
        "Feedback loop: analyst verdicts tune weights"], 13), size=13, fill=BG2)

    p.save(os.path.join(OUTD, "Tier2_Concept.pptx"))


def build_tier3():
    p = new_deck()
    s = p.slides.add_slide(p.slide_layouts[6])
    a = EV["approaches"]["D_TrustLine_incident"]
    bg = s.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, p.slide_width, Inches(1.15))
    bg.fill.solid(); bg.fill.fore_color.rgb = INK; bg.line.fill.background()
    text(s, 0.35, 0.08, 12.6, 0.6, "TrustLine: behaviour contracts for integration identities", size=26, bold=True, color=WHITE)
    text(s, 0.35, 0.65, 12.5, 0.45, "CRIMEATHON'26 · CR-26-047 · DEFENSE · Team Wi-Fight Club.exe   |   github: <repo link>   |   demo: <video link>",
         size=13, color=RGBColor(0x93, 0xC5, 0xFD))
    text(s, 0.35, 1.35, 4.2, 2.6, [[("Problem", {"bold": True, "size": 15, "color": ACC})],
                                   [("TallyBridge's keys, plus a storage key pasted into a ticket, were used 9 Aug → 6 Sep across 5 systems, ending in an unapproved bank change on V-0412 before the 8 Sep payment run. Keys are trusted by possession alone, and no one joined the fragments.", {"size": 12})]],
         fill=BG2)
    text(s, 0.35, 4.1, 4.2, 3.05, [[("Objectives", {"bold": True, "size": 15, "color": ACC})]] + bullets([
        "Detect misuse of any non-human identity without IOCs",
        "Join fragments across systems into one incident",
        "Contain: hold payments, revoke and re-issue least-privilege",
        "Work on data and attacks not seen before"], 12), fill=BG2)
    text(s, 4.75, 1.35, 4.2, 5.8, [[("Architecture and key features", {"bold": True, "size": 15, "color": ACC})]] + bullets([
        "Loader: any file name, by column signature; IST/epoch → UTC",
        "Contract engine: learned origins, host, client version, hours, ops, folders → 20 signals",
        "Correlator: register ownership, request_id joins, link hosts, shared IPs, 'secret searched → secret used'",
        "Responder: revoke + re-issue spec, payment HOLD with revert value, orphan exports, exposure for Legal",
        "Replay: enforce contracts as policy and show what is blocked",
        "Variation harness: 7 randomised attack scenarios",
        "Python · pandas · runs in ~6 s on 109k events"], 12), fill=BG2)
    text(s, 9.15, 1.35, 3.85, 5.8, [[("Results", {"bold": True, "size": 15, "color": ACC})],
                                    [(f"{a['TP']}/{a['TP'] + a['FN']} malicious events found, {a['FP']} false alarms", {"size": 13, "bold": True})],
                                    [("IOC list 28% · /24 block 291 false alarms · volume rule 4%", {"size": 11.5, "color": MUT})],
                                    [("Replay: 177/177 malicious requests blocked; 0 normal (70 unapproved new-feature calls)", {"size": 12})],
                                    [("Unseen variations: 6/7 attack types caught 4/4 runs, 0 FP; perfect sync-host mimic missed (stated limit)", {"size": 12})],
                                    [("Found: V-0412 hold (revert ****4417) · exports 9932 + EXP-5419 left behind · vendor notice false on 5 claims · V-0233 to verify", {"size": 12, "color": RED})]],
         fill=BG2)
    p.save(os.path.join(OUTD, "Tier3_One_Page.pptx"))


if __name__ == "__main__":
    build_tier2()
    build_tier3()
    print("decks written")
