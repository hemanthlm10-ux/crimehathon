"""Build submission files from docs/*.md and out/ results.

  docs/submission/Tier1_Problem_Statement.pdf   (one page)
  docs/submission/Final_Technical_Report.pdf
  docs/submission/Proof_Pack.pdf
  docs/submission/Tier2_Concept.pptx            (10 slides)
  docs/submission/Tier3_One_Page.pptx           (1 slide)
  docs/submission/charts/*.png
"""
import json
import os
import re
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402
from reportlab.lib import colors  # noqa: E402
from reportlab.lib.enums import TA_LEFT  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.lib.styles import ParagraphStyle  # noqa: E402
from reportlab.lib.units import mm  # noqa: E402
from reportlab.platypus import (Paragraph, Preformatted, SimpleDocTemplate,  # noqa: E402
                                Spacer, Table, TableStyle)

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
DOCS = os.path.join(ROOT, "docs")
OUTD = os.path.join(DOCS, "submission")
CH = os.path.join(OUTD, "charts")
os.makedirs(CH, exist_ok=True)
INK, ACC, RED, MUT = "#0f172a", "#2563eb", "#dc2626", "#64748b"


# ------------------------------------------------------------------ markdown -> PDF
def inline(t):
    t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    t = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?!\w)", r"<i>\1</i>", t)
    t = re.sub(r"`(.+?)`", r"<font face='Courier'>\1</font>", t)
    t = t.replace("→", "-&gt;").replace("↔", "&lt;-&gt;").replace("−", "-").replace("≈", "~")
    return t


def md_to_pdf(md_path, pdf_path, base=9.0, compact=False, footer=None):
    fs = base
    lead = fs * (1.22 if compact else 1.32)
    st = {
        "h1": ParagraphStyle("h1", fontName="Helvetica-Bold", fontSize=fs + 4.5, leading=fs + 7, textColor=INK, spaceAfter=3),
        "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=fs + 1.5, leading=fs + 4, textColor=ACC,
                             spaceBefore=4 if compact else 7, spaceAfter=2),
        "p": ParagraphStyle("p", fontName="Helvetica", fontSize=fs, leading=lead, textColor=INK,
                            spaceAfter=2.2 if compact else 4, alignment=TA_LEFT),
        "li": ParagraphStyle("li", fontName="Helvetica", fontSize=fs, leading=lead, leftIndent=9, bulletIndent=1,
                             textColor=INK, spaceAfter=1),
        "td": ParagraphStyle("td", fontName="Helvetica", fontSize=fs - 1.1, leading=(fs - 1.1) * 1.2, textColor=INK),
        "th": ParagraphStyle("th", fontName="Helvetica-Bold", fontSize=fs - 1.1, leading=(fs - 1.1) * 1.2, textColor="white"),
    }
    lines = open(md_path, encoding="utf-8").read().splitlines()
    story, i = [], 0
    W = A4[0] - 30 * mm
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("```"):
            j = i + 1
            buf = []
            while j < len(lines) and not lines[j].startswith("```"):
                buf.append(lines[j]); j += 1
            story.append(Preformatted("\n".join(buf), ParagraphStyle("pre", fontName="Courier", fontSize=fs - 1.6,
                                                                     leading=(fs - 1.6) * 1.25, backColor="#f1f5f9")))
            story.append(Spacer(1, 3)); i = j + 1; continue
        if ln.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-+:?", c) for c in cells):
                    rows.append(cells)
                i += 1
            n = len(rows[0])
            data = [[Paragraph(inline(c), st["th" if r == 0 else "td"]) for c in row + [""] * (n - len(row))]
                    for r, row in enumerate(rows)]
            lens = [max(len(row[k]) if k < len(row) else 0 for row in rows) for k in range(n)]
            tot = sum(min(x, 90) + 6 for x in lens)
            widths = [W * (min(x, 90) + 6) / tot for x in lens]
            t = Table(data, colWidths=widths, repeatRows=1)
            t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(ACC)),
                                   ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#cbd5e1")),
                                   ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
                                   ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                   ("TOPPADDING", (0, 0), (-1, -1), 1.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
                                   ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3)]))
            story.append(t); story.append(Spacer(1, 4)); continue
        if ln.startswith("# "):
            story.append(Paragraph(inline(ln[2:]), st["h1"]))
        elif ln.startswith("## "):
            story.append(Paragraph(inline(ln[3:]), st["h2"]))
        elif re.match(r"^\s*[\*\-] ", ln) or re.match(r"^\s*\d+\. ", ln):
            m = re.match(r"^\s*(?:[\*\-]|(\d+)\.) (.*)", ln)
            bullet = (m.group(1) + ".") if m.group(1) else "•"
            story.append(Paragraph(inline(m.group(2)), st["li"], bulletText=bullet))
        elif ln.strip():
            story.append(Paragraph(inline(ln), st["p"]))
        i += 1

    def on_page(c, d):
        c.saveState()
        c.setFont("Helvetica", 6.5)
        c.setFillColor(colors.HexColor(MUT))
        c.drawString(15 * mm, 8 * mm, footer or "CRIMEATHON'26 · CR-26-047 · Team Wi-Fight Club.exe · TrustLine (Defense) · synthetic case data")
        c.drawRightString(A4[0] - 15 * mm, 8 * mm, f"{d.page}")
        c.restoreState()

    m = 11 * mm if compact else 15 * mm
    doc = SimpleDocTemplate(pdf_path, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=m, bottomMargin=13 * mm)
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return doc.page


# ------------------------------------------------------------------ charts
def charts(evidence):
    sys.path.insert(0, ROOT)
    from trustline.cli import load_cfg
    from trustline.engine import Engine
    from trustline.loaders import load_dir
    ev = load_dir(evidence, load_cfg(None))
    lab = pd.read_csv(os.path.join(ROOT, "labels", "cr26047_labels.csv"))
    m = ev.events.merge(lab[["system", "eid", "label"]], on=["system", "eid"], how="left")
    mal = m[m.label == "malicious"]
    order = ["link", "ledger", "helpdesk", "storage", "sso", "vendormaster"]
    names = {"link": "Private link (E15)", "ledger": "LedgerOne API (E01/E18)", "helpdesk": "HelpDeskr (E02)",
             "storage": "BlueVault (E05)", "sso": "SSO (E03)", "vendormaster": "Vendor changes (E19)"}
    col = {"link": "#0d9488", "ledger": "#2563eb", "helpdesk": "#9333ea", "storage": "#d97706", "sso": "#475569",
           "vendormaster": "#dc2626"}
    fig, ax = plt.subplots(figsize=(11, 3.6), dpi=200)
    for k, s in enumerate(order):
        g = mal[mal.system == s]
        ax.scatter(g.ts, [k] * len(g), s=28 if s != "vendormaster" else 140, c=col[s], alpha=.7,
                   marker="o" if s != "vendormaster" else "X", edgecolors="none")
    ax.set_yticks(range(len(order)), [names[s] for s in order], fontsize=9)
    ax.axvline(pd.Timestamp("2026-09-08", tz="UTC"), color=RED, ls="--", lw=1)
    ax.text(pd.Timestamp("2026-09-08", tz="UTC"), 5.45, " payment run 8 Sep", color=RED, fontsize=8, va="center")
    ann = [("2026-08-09 03:30", 1, "9 Aug recon"), ("2026-08-11 18:20", 2, "11 Aug secret hunt\n+10 exports"),
           ("2026-08-15 08:00", 3, "14–16 Aug bank files"), ("2026-08-18 12:30", 0, "17–19 Aug build host"),
           ("2026-09-03 01:44", 5, "3 Sep V-0412\nbank change")]
    for t, y, txt in ann:
        ax.annotate(txt, (pd.Timestamp(t, tz="UTC"), y), xytext=(0, 12), textcoords="offset points",
                    fontsize=7.5, ha="center", color=INK)
    ax.set_xlim(pd.Timestamp("2026-08-06", tz="UTC"), pd.Timestamp("2026-09-10", tz="UTC"))
    ax.set_ylim(-0.6, 5.9)
    for sp in ("top", "right"):
        ax.spines[sp].set_visible(False)
    ax.grid(axis="x", alpha=.25)
    import matplotlib.dates as mdates
    ax.xaxis.set_major_locator(mdates.DayLocator(interval=4))
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d %b"))
    ax.set_title("One campaign across six log sources: every labelled malicious event (UTC)", fontsize=10, loc="left")
    fig.tight_layout()
    fig.savefig(os.path.join(CH, "timeline.png"))
    plt.close(fig)

    e = json.load(open(os.path.join(ROOT, "out", "evaluation.json")))["approaches"]
    rows = [("Vendor IOC list", e["A_vendor_indicator_list"]), ("Block IOC /24", e["B_block_indicator_/24"]),
            ("Volume p99.5", e["C_volume_p99.5"]), ("TrustLine", e["D_TrustLine_incident"])]
    fig, axs = plt.subplots(1, 2, figsize=(10, 3.2), dpi=200)
    lbl = [r[0] for r in rows]
    cc = ["#94a3b8", "#94a3b8", "#94a3b8", ACC]
    axs[0].barh(lbl, [r[1]["recall"] * 100 for r in rows], color=cc)
    axs[0].set_title("Malicious events found (%)", fontsize=10, loc="left")
    axs[0].set_xlim(0, 105)
    axs[1].barh(lbl, [r[1]["FP"] for r in rows], color=["#94a3b8", RED, "#94a3b8", ACC])
    axs[1].set_title("False alarms (events)", fontsize=10, loc="left")
    for ax, key, fmt in ((axs[0], "recall", lambda v: f"{v*100:.0f}%"), (axs[1], "FP", lambda v: f"{v}")):
        for k, r in enumerate(rows):
            ax.text(r[1][key] * (100 if key == "recall" else 1), k, " " + fmt(r[1][key]), va="center", fontsize=9)
        ax.invert_yaxis()
        for sp in ("top", "right"):
            ax.spines[sp].set_visible(False)
    axs[1].set_xlim(0, 340)
    fig.tight_layout()
    fig.savefig(os.path.join(CH, "comparison.png"))
    plt.close(fig)


if __name__ == "__main__":
    evidence = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "..", "drive-download-20261119T060920Z-1-001")
    charts(evidence)
    p = md_to_pdf(os.path.join(DOCS, "tier1_problem_statement.md"), os.path.join(OUTD, "Tier1_Problem_Statement.pdf"),
                  base=8.5, compact=True)
    print("Tier1 pages:", p)
    print("Report pages:", md_to_pdf(os.path.join(DOCS, "technical_report.md"), os.path.join(OUTD, "Final_Technical_Report.pdf"), base=8.2, compact=True))
    print("Proof pages:", md_to_pdf(os.path.join(DOCS, "proof_pack.md"), os.path.join(OUTD, "Proof_Pack.pdf"), base=8.4))
