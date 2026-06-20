#!/usr/bin/env python3
"""
report_to_pdf.py — Convertit un RAPPORT_PENTEST_*.md en PDF professionnel
dans le thème PenTest Hub (rouge #E63946, tableaux colorés, en-têtes/pieds
de page, page de garde, Table of Contents dédiée, Summary Dashboard).

Usage :
    python3 report_to_pdf.py                         # .md le plus récent
    python3 report_to_pdf.py RAPPORT_PENTEST_xxx.md  # fichier explicite
    python3 report_to_pdf.py -o output.pdf RAPPORT_PENTEST_xxx.md
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import sys
import time
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    HRFlowable,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

# Enrichissement CVE/PoC + Roadmap (optionnel : si le module est absent ou
# si le réseau est indisponible, le rapport est généré sans cette section).
try:
    import report_enrich
    _ENRICH_AVAILABLE = True
except Exception:
    _ENRICH_AVAILABLE = False

# Réinjection des valeurs réelles (mapping clé -> valeur). Optionnel.
try:
    import report_mapping
    _MAPPING_AVAILABLE = True
except Exception:
    _MAPPING_AVAILABLE = False

# Graphiques vectoriels (jauge, donut, histogramme, heatmap, matrice). Optionnel.
try:
    import report_visuals
    _VISUALS_AVAILABLE = True
except Exception:
    _VISUALS_AVAILABLE = False

# ── Palette ──────────────────────────────────────────────────────────────────
RED        = colors.HexColor("#E63946")
DARK_GRAY  = colors.HexColor("#2B2D42")
MID_GRAY   = colors.HexColor("#6C757D")
LIGHT_GRAY = colors.HexColor("#F8F9FA")
WHITE      = colors.white
HAIR_GRAY  = colors.HexColor("#DEE2E6")

SEV_COLORS = {
    "CRITICAL": colors.HexColor("#E63946"),
    "HIGH":     colors.HexColor("#F4845F"),
    "MEDIUM":   colors.HexColor("#F4D35E"),
    "LOW":      colors.HexColor("#06D6A0"),
    "INFO":     colors.HexColor("#118AB2"),
}
SEV_TEXT = {
    "CRITICAL": WHITE,
    "HIGH":     WHITE,
    "MEDIUM":   DARK_GRAY,
    "LOW":      DARK_GRAY,
    "INFO":     WHITE,
}

PAGE_W, PAGE_H = A4
MARGIN = 2 * cm


# ── Styles ────────────────────────────────────────────────────────────────────
def make_styles() -> dict:
    s: dict = {}

    def S(name, **kw) -> ParagraphStyle:
        return ParagraphStyle(name, **kw)

    # Cover
    s["cover_title"]  = S("cover_title",  fontName="Helvetica-Bold", fontSize=36,
                           textColor=DARK_GRAY, leading=44, spaceAfter=8)
    s["cover_sub"]    = S("cover_sub",    fontName="Helvetica",      fontSize=14,
                           textColor=MID_GRAY,  leading=20, spaceAfter=4)
    s["cover_label"]  = S("cover_label",  fontName="Helvetica-Bold", fontSize=9,
                           textColor=RED,       leading=14, spaceAfter=2)
    s["cover_value"]  = S("cover_value",  fontName="Helvetica",      fontSize=10,
                           textColor=DARK_GRAY, leading=14, spaceAfter=2)

    # Headings
    s["h1"] = S("h1", fontName="Helvetica-Bold", fontSize=18, textColor=DARK_GRAY,
                spaceBefore=18, spaceAfter=6,  leading=22)
    s["h2"] = S("h2", fontName="Helvetica-Bold", fontSize=14, textColor=RED,
                spaceBefore=14, spaceAfter=4,  leading=18)
    s["h3"] = S("h3", fontName="Helvetica-Bold", fontSize=11, textColor=DARK_GRAY,
                spaceBefore=10, spaceAfter=3,  leading=14)
    s["h4"] = S("h4", fontName="Helvetica-Bold", fontSize=10, textColor=DARK_GRAY,
                spaceBefore=8,  spaceAfter=2,  leading=13)

    # Body
    s["body"]      = S("body",      fontName="Helvetica", fontSize=9.5,
                        textColor=DARK_GRAY, leading=14, spaceAfter=6)
    s["body_bold"] = S("body_bold", fontName="Helvetica-Bold", fontSize=9.5,
                        textColor=DARK_GRAY, leading=14, spaceAfter=4)
    s["code"]      = S("code",      fontName="Courier",   fontSize=8,
                        textColor=DARK_GRAY, backColor=LIGHT_GRAY,
                        leading=11, spaceAfter=1, leftIndent=8, rightIndent=8)
    s["bullet"]    = S("bullet",    fontName="Helvetica", fontSize=9.5,
                        textColor=DARK_GRAY, leading=14, leftIndent=14,
                        spaceAfter=3, bulletIndent=4, bulletText="•")

    s["link"]      = S("link",      fontName="Helvetica", fontSize=8.5,
                        textColor=colors.HexColor("#118AB2"), leading=12,
                        leftIndent=10, spaceAfter=2)
    s["enrich_note"] = S("enrich_note", fontName="Helvetica-Oblique", fontSize=8,
                        textColor=MID_GRAY, leading=11, spaceAfter=6)

    # TOC
    s["toc_title"] = S("toc_title", fontName="Helvetica-Bold", fontSize=16,
                        textColor=DARK_GRAY, leading=20, spaceAfter=12)
    s["toc_h1"]    = S("toc_h1",   fontName="Helvetica-Bold", fontSize=10,
                        textColor=DARK_GRAY, leading=18, leftIndent=0)
    s["toc_h2"]    = S("toc_h2",   fontName="Helvetica",      fontSize=9.5,
                        textColor=DARK_GRAY, leading=16, leftIndent=14)
    s["toc_h3"]    = S("toc_h3",   fontName="Helvetica",      fontSize=9,
                        textColor=MID_GRAY,  leading=15, leftIndent=28)

    # Summary dashboard
    s["dash_label"] = S("dash_label", fontName="Helvetica-Bold", fontSize=9,
                         textColor=WHITE, alignment=TA_CENTER, leading=12)
    s["dash_count"] = S("dash_count", fontName="Helvetica-Bold", fontSize=26,
                         textColor=WHITE, alignment=TA_CENTER, leading=30)

    return s


# ── Document template ─────────────────────────────────────────────────────────
class PentestDoc(BaseDocTemplate):
    def __init__(self, filename: str, report_title: str = "Penetration Testing Report",
                 classification: str = "CONFIDENTIAL", watermark: bool = True):
        super().__init__(filename, pagesize=A4,
                         leftMargin=MARGIN, rightMargin=MARGIN,
                         topMargin=MARGIN,  bottomMargin=MARGIN + 1 * cm)
        self.report_title = report_title
        self.classification = classification
        self.watermark = watermark
        self._build_templates()

    def _build_templates(self):
        fw = PAGE_W - 2 * MARGIN
        fh = PAGE_H - 2 * MARGIN - 1.2 * cm
        cover_frame = Frame(MARGIN, MARGIN, fw, PAGE_H - 2 * MARGIN, id="cover")
        body_frame  = Frame(MARGIN, MARGIN + 1.2 * cm, fw, fh, id="body")
        self.addPageTemplates([
            PageTemplate(id="Cover", frames=[cover_frame]),
            PageTemplate(id="Body",  frames=[body_frame], onPage=self._draw_body_page),
        ])

    def _draw_body_page(self, canvas, doc):
        canvas.saveState()
        w = PAGE_W

        # Filigrane diagonal (classification) en arrière-plan
        if self.watermark and self.classification:
            canvas.saveState()
            canvas.translate(w / 2, PAGE_H / 2)
            canvas.rotate(45)
            canvas.setFont("Helvetica-Bold", 52)
            canvas.setFillColor(colors.Color(0.92, 0.27, 0.30, alpha=0.06))
            canvas.drawCentredString(0, 0, self.classification.upper())
            canvas.restoreState()

        # Top red bar
        canvas.setFillColor(RED)
        canvas.rect(0, PAGE_H - 1.2 * cm, w, 1.2 * cm, fill=1, stroke=0)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.setFillColor(WHITE)
        canvas.drawString(MARGIN, PAGE_H - 0.85 * cm, self.report_title)
        canvas.drawRightString(w - MARGIN, PAGE_H - 0.85 * cm,
                               self.classification or "Client Confidential")
        # Bottom dark bar
        canvas.setFillColor(DARK_GRAY)
        canvas.rect(0, 0, w, 1.2 * cm, fill=1, stroke=0)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(WHITE)
        canvas.drawString(MARGIN, 0.42 * cm, "www.rmw-penstrike.com")
        canvas.drawCentredString(w / 2, 0.42 * cm, f"Page No. {doc.page}")
        canvas.drawRightString(w - MARGIN, 0.42 * cm,
                               self.classification or "Client Confidential")
        canvas.restoreState()


# ── Helpers ───────────────────────────────────────────────────────────────────
def _escape(text: str) -> str:
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))


def _inline(text: str) -> str:
    text = _escape(text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"`([^`]+)`",     r"<font face='Courier'>\1</font>", text)
    return text


# ── Summary Dashboard ─────────────────────────────────────────────────────────
def build_summary_dashboard(md_text: str, styles: dict) -> list:
    """
    Compte les sévérités dans le MD et génère un bandeau visuel coloré
    avec le total par niveau (CRITICAL / HIGH / MEDIUM / LOW / INFO).
    """
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for line in md_text.splitlines():
        m = re.search(r"###\s+\d+\.\d+\s+.+?[—\-]\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)", line, re.IGNORECASE)
        if m:
            counts[m.group(1).upper()] += 1

    total = sum(counts.values())
    if total == 0:
        return []

    flowables = []
    flowables.append(Spacer(1, 6))

    # Titre du dashboard
    flowables.append(Paragraph("Vulnerability Summary", styles["h2"]))
    flowables.append(HRFlowable(width="100%", thickness=0.5,
                                color=colors.HexColor("#DEE2E6"), spaceAfter=8))

    # Cellules colorées
    cell_w = (PAGE_W - 2 * MARGIN) / 5
    cells  = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        bg = SEV_COLORS[sev]
        fg = SEV_TEXT[sev]
        cnt_style = ParagraphStyle(f"dc_{sev}", fontName="Helvetica-Bold",
                                   fontSize=28, textColor=fg,
                                   alignment=TA_CENTER, leading=32)
        lbl_style = ParagraphStyle(f"dl_{sev}", fontName="Helvetica-Bold",
                                   fontSize=9,  textColor=fg,
                                   alignment=TA_CENTER, leading=12)
        inner = Table(
            [[Paragraph(str(counts[sev]), cnt_style)],
             [Paragraph(sev, lbl_style)]],
            colWidths=[cell_w - 0.4 * cm],
        )
        inner.setStyle(TableStyle([
            ("BACKGROUND",   (0, 0), (-1, -1), bg),
            ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
            ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",   (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 10),
        ]))
        cells.append(inner)

    dash = Table([cells], colWidths=[cell_w] * 5)
    dash.setStyle(TableStyle([
        ("ALIGN",  (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
    ]))
    flowables.append(dash)
    flowables.append(Spacer(1, 16))

    # Total pill
    total_style = ParagraphStyle("total_pill", fontName="Helvetica-Bold",
                                 fontSize=10, textColor=WHITE,
                                 alignment=TA_CENTER, leading=14)
    pill = Table([[Paragraph(f"Total findings: {total}", total_style)]],
                 colWidths=[PAGE_W - 2 * MARGIN])
    pill.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), DARK_GRAY),
        ("TOPPADDING",    (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
    ]))
    flowables.append(pill)
    flowables.append(Spacer(1, 20))
    return flowables


# ── Table of Contents ─────────────────────────────────────────────────────────
def build_toc_page(md_text: str, styles: dict) -> list:
    """
    Extrait les titres ## et ### du Markdown (hors section TOC elle-même),
    et génère une page Table of Contents avec lignes pointillées.
    """
    flowables = []
    flowables.append(Paragraph("Table of Contents", styles["toc_title"]))
    flowables.append(HRFlowable(width="100%", thickness=2, color=RED, spaceAfter=14))

    # Parser les lignes du MD pour la TOC inline générée par le LLM
    # On cherche d'abord un bloc "## Table of Contents" dans le MD
    toc_block_match = re.search(
        r"##\s+Table of Contents\s*\n(.*?)(?=\n##\s|\Z)",
        md_text, re.DOTALL | re.IGNORECASE
    )

    entries: list[tuple[int, str]] = []   # (level, text)

    if toc_block_match:
        # Le LLM a généré une TOC textuelle — on la parse
        for line in toc_block_match.group(1).splitlines():
            line = line.strip()
            if not line:
                continue
            # Retirer les points de remplissage et numéros de page
            clean = re.sub(r"\.{3,}.*$", "", line).strip()
            clean = re.sub(r"\s*\d+\s*$", "", clean).strip()
            if not clean:
                continue
            # Détecter le niveau d'indentation
            if re.match(r"^\d+\.\d+\.\d+", clean):
                level = 3
            elif re.match(r"^\d+\.\d+", clean):
                level = 2
            elif re.match(r"^\d+\.", clean):
                level = 1
            elif line.startswith("    ") or line.startswith("\t\t"):
                level = 3
            elif line.startswith("  ") or line.startswith("\t"):
                level = 2
            else:
                level = 1
            entries.append((level, clean))
    else:
        # Fallback : extraire les titres ## / ### du document
        in_toc = False
        for line in md_text.splitlines():
            m2 = re.match(r"^(#{1,3})\s+(.+)", line)
            if not m2:
                continue
            depth = len(m2.group(1))
            title = m2.group(2).strip()
            if re.search(r"table of contents", title, re.IGNORECASE):
                in_toc = True
                continue
            if in_toc and depth == 2:
                in_toc = False
            if depth == 1:
                entries.append((1, title))
            elif depth == 2:
                entries.append((2, title))
            elif depth == 3:
                entries.append((3, title))

    avail = PAGE_W - 2 * MARGIN

    # Ajouter les sections générées par report_to_pdf lui-même (hors MD)
    if _ENRICH_AVAILABLE:
        entries.append((1, "Threat Intelligence & Public Exploits"))
        entries.append((1, "Remediation Roadmap"))

    for level, text in entries:
        if level == 1:
            st = styles["toc_h1"]
            indent = 0
        elif level == 2:
            st = styles["toc_h2"]
            indent = 14
        else:
            st = styles["toc_h3"]
            indent = 28

        # Ligne avec texte à gauche et points à droite
        dots = "· " * 40
        row = Table(
            [[Paragraph(_inline(text), st),
              Paragraph(f"<font color='#CCCCCC'>{dots}</font>",
                        ParagraphStyle("dots", fontName="Helvetica", fontSize=8,
                                       textColor=colors.HexColor("#CCCCCC"),
                                       leading=st.leading, alignment=TA_RIGHT))]],
            colWidths=[avail * 0.72, avail * 0.28],
        )
        row.setStyle(TableStyle([
            ("VALIGN",       (0, 0), (-1, -1), "BOTTOM"),
            ("LEFTPADDING",  (0, 0), (-1, -1), indent),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING",   (0, 0), (-1, -1), 1),
            ("BOTTOMPADDING",(0, 0), (-1, -1), 1),
            ("LINEBELOW",    (0, 0), (-1, -1), 0.3, colors.HexColor("#EEEEEE")),
        ]))
        flowables.append(row)

    flowables.append(PageBreak())
    return flowables


# ── MD → flowables ────────────────────────────────────────────────────────────
def parse_md_table(lines: list[str]) -> Table | None:
    rows = []
    for line in lines:
        if re.match(r"^\s*\|[-| :]+\|\s*$", line):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        rows.append(cells)
    if not rows:
        return None

    col_count = max(len(r) for r in rows)
    rows = [r + [""] * (col_count - len(r)) for r in rows]

    def cell_para(text: str, row_idx: int, col_idx: int):
        key = text.strip().upper()
        if key in SEV_COLORS and col_idx == col_count - 1:
            bg = SEV_COLORS[key]
            fg = SEV_TEXT[key]
            st = ParagraphStyle("bc", fontName="Helvetica-Bold", fontSize=8,
                                 textColor=fg, alignment=TA_CENTER, leading=11)
            t2 = Table([[Paragraph(key, st)]], colWidths=[2.5 * cm], rowHeights=[0.5 * cm])
            t2.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), bg),
                ("ALIGN",      (0, 0), (-1, -1), "CENTER"),
                ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
            ]))
            return t2
        fn       = "Helvetica-Bold" if row_idx == 0 else "Helvetica"
        txtcolor = WHITE if row_idx == 0 else DARK_GRAY
        return Paragraph(_inline(text),
                         ParagraphStyle("tc", fontName=fn, fontSize=8.5,
                                        textColor=txtcolor, leading=12))

    table_data = [[cell_para(c, ri, ci) for ci, c in enumerate(row)]
                  for ri, row in enumerate(rows)]

    col_w = (PAGE_W - 2 * MARGIN) / col_count
    t = Table(table_data, colWidths=[col_w] * col_count, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND",     (0, 0), (-1, 0),  DARK_GRAY),
        ("TEXTCOLOR",      (0, 0), (-1, 0),  WHITE),
        ("FONTNAME",       (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0, 0), (-1, 0),  9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_GRAY]),
        ("GRID",           (0, 0), (-1, -1), 0.4, colors.HexColor("#DEE2E6")),
        ("VALIGN",         (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",     (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
        ("LEFTPADDING",    (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",   (0, 0), (-1, -1), 6),
    ]))
    return t


def md_to_flowables(md_text: str, styles: dict,
                    skip_toc_section: bool = True) -> list:
    """Convertit le Markdown en flowables ReportLab.
    skip_toc_section=True : ignore la section ## Table of Contents du MD
    (elle est rendue séparément par build_toc_page).
    """
    flowables  = []
    lines      = md_text.splitlines()
    i          = 0
    in_code    = False
    code_buf: list[str] = []
    in_toc_section = False

    def flush_code():
        nonlocal code_buf
        if code_buf:
            for ln in code_buf:
                flowables.append(Paragraph(_escape(ln) or " ", styles["code"]))
            flowables.append(Spacer(1, 6))
            code_buf = []

    while i < len(lines):
        line = lines[i]

        # ── Blocs de code ───────────────────────────────────────────────────
        if line.strip().startswith("```"):
            if in_code:
                flush_code()
                in_code = False
            else:
                in_code = True
            i += 1
            continue
        if in_code:
            code_buf.append(line)
            i += 1
            continue

        # ── Titres ──────────────────────────────────────────────────────────
        m = re.match(r"^(#{1,4})\s+(.+)", line)
        if m:
            level = len(m.group(1))
            title = m.group(2).strip()

            # Détecter la section TOC pour la sauter si demandé
            if skip_toc_section and re.search(r"table of contents", title, re.IGNORECASE):
                in_toc_section = True
                i += 1
                continue
            if in_toc_section:
                if level <= 2 and not re.search(r"table of contents", title, re.IGNORECASE):
                    in_toc_section = False
                else:
                    i += 1
                    continue

            txt = _inline(title)
            key = {1: "h1", 2: "h2", 3: "h3", 4: "h4"}.get(level, "h3")
            if level == 1:
                flowables.append(HRFlowable(width="100%", thickness=2,
                                            color=RED, spaceAfter=4))
            flowables.append(Paragraph(txt, styles[key]))
            if level <= 2:
                flowables.append(HRFlowable(width="100%", thickness=0.5,
                                            color=colors.HexColor("#DEE2E6"),
                                            spaceAfter=4))
            i += 1
            continue

        if in_toc_section:
            i += 1
            continue

        # ── Tableaux ────────────────────────────────────────────────────────
        if line.strip().startswith("|"):
            tbl_lines = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                tbl_lines.append(lines[i])
                i += 1
            tbl = parse_md_table(tbl_lines)
            if tbl:
                flowables.append(Spacer(1, 4))
                flowables.append(tbl)
                flowables.append(Spacer(1, 8))
            continue

        # ── Séparateurs --- ─────────────────────────────────────────────────
        if re.match(r"^---+\s*$", line.strip()):
            flowables.append(HRFlowable(width="100%", thickness=0.5,
                                        color=colors.HexColor("#DEE2E6"), spaceAfter=4))
            i += 1
            continue

        # ── Listes à puces ──────────────────────────────────────────────────
        m = re.match(r"^(\s*)[-*+]\s+(.+)", line)
        if m:
            flowables.append(Paragraph(_inline(m.group(2)), styles["bullet"]))
            i += 1
            continue

        # ── Ligne vide ──────────────────────────────────────────────────────
        if not line.strip():
            flowables.append(Spacer(1, 6))
            i += 1
            continue

        # ── Texte courant ────────────────────────────────────────────────────
        flowables.append(Paragraph(_inline(line), styles["body"]))
        i += 1

    flush_code()
    return flowables


# ── Page de garde ─────────────────────────────────────────────────────────────
def build_cover(styles: dict, report_date: str, risk: dict | None = None,
                classification: str = "CONFIDENTIAL") -> list:
    cover = []

    bar = Table([[f"  PENETRATION TESTING REPORT  |  {classification}  |  www.rmw-penstrike.com"]],
                colWidths=[PAGE_W - 2 * MARGIN])
    bar.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, -1), RED),
        ("TEXTCOLOR",     (0, 0), (-1, -1), WHITE),
        ("FONTNAME",      (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("ALIGN",         (0, 0), (-1, -1), "CENTER"),
    ]))
    cover.append(bar)
    cover.append(Spacer(1, 2.2 * cm))

    cover.append(Paragraph("Penetration Testing", styles["cover_title"]))
    cover.append(Paragraph("Report",              styles["cover_title"]))
    cover.append(Spacer(1, 0.4 * cm))
    cover.append(Paragraph(report_date, styles["cover_sub"]))

    # Élément signature : jauge de risque global, centrée
    if risk and _VISUALS_AVAILABLE:
        cover.append(Spacer(1, 0.8 * cm))
        gauge = report_visuals.risk_gauge(risk["score"], risk["grade"],
                                          risk["level"], width=10*cm, height=5.6*cm)
        gwrap = Table([[gauge]], colWidths=[PAGE_W - 2*MARGIN])
        gwrap.setStyle(TableStyle([("ALIGN", (0,0), (-1,-1), "CENTER")]))
        cover.append(gwrap)
        cover.append(Spacer(1, 0.8 * cm))
    else:
        cover.append(Spacer(1, 3.5 * cm))

    for label, value in [
        ("Prepared by:", "RMW-PenStrike"),
        ("Email:",       "contact@rmw-penstrike.com"),
    ]:
        cover.append(Paragraph(label, styles["cover_label"]))
        cover.append(Paragraph(value, styles["cover_value"]))
        cover.append(Spacer(1, 0.15 * cm))

    cover.append(Spacer(1, 1 * cm))
    cover.append(HRFlowable(width="100%", thickness=1.5, color=RED))
    cover.append(Spacer(1, 0.3 * cm))
    cover.append(Paragraph(
        f"This document is classified {classification}. It may not be copied "
        "without written permission.",
        ParagraphStyle("disc", fontName="Helvetica", fontSize=8,
                       textColor=MID_GRAY, leading=12)))

    cover.append(NextPageTemplate("Body"))
    cover.append(PageBreak())
    return cover


# ── Section Threat Intelligence (CVE / PoC) ──────────────────────────────────
def build_enrichment_section(enrichment: dict, styles: dict) -> list:
    """
    Section listant, pour chaque finding, les CVE réels (NVD) et les sources
    de PoC publiques (liens ExploitDB/GitHub/Metasploit + dépôts GitHub live).
    """
    flowables = []
    findings  = enrichment.get("findings", [])
    if not findings:
        return flowables

    flowables.append(PageBreak())
    flowables.append(HRFlowable(width="100%", thickness=2, color=RED, spaceAfter=4))
    flowables.append(Paragraph("Threat Intelligence &amp; Public Exploits", styles["h1"]))
    flowables.append(HRFlowable(width="100%", thickness=0.5,
                                color=colors.HexColor("#DEE2E6"), spaceAfter=6))

    if enrichment.get("online"):
        flowables.append(Paragraph(
            "The following CVEs and public proof-of-concept sources were correlated "
            "automatically from the CWE of each finding (NVD, GitHub).",
            styles["enrich_note"]))
    else:
        flowables.append(Paragraph(
            "Network was unavailable during generation: live CVE/PoC lookup was skipped. "
            "Pre-built search links are provided so you can verify manually.",
            styles["enrich_note"]))

    for f in findings:
        # En-tête du finding
        sev = f["severity"]
        flowables.append(Spacer(1, 6))
        flowables.append(Paragraph(
            f"{f['ref']} — {_inline(f['title'])}",
            styles["h3"]))
        cwe_txt = f["cwe"] or "no CWE mapped"
        flowables.append(Paragraph(f"<b>CWE:</b> {cwe_txt} &nbsp;|&nbsp; "
                                   f"<b>Severity:</b> {sev}", styles["body"]))

        # CVE table
        cves = f.get("cves", [])
        if cves:
            data = [["CVE", "CVSS", "Description"]]
            for c in cves:
                score = str(c["score"]) if c["score"] is not None else "—"
                data.append([
                    Paragraph(f"<link href='{c['url']}'><font color='#118AB2'>{c['id']}</font></link>",
                              ParagraphStyle("cve", fontName="Helvetica", fontSize=8, leading=11)),
                    Paragraph(score, ParagraphStyle("sc", fontName="Helvetica-Bold",
                              fontSize=8, leading=11, alignment=TA_CENTER)),
                    Paragraph(_escape(c["desc"]), ParagraphStyle("ds", fontName="Helvetica",
                              fontSize=8, leading=11, textColor=DARK_GRAY)),
                ])
            avail = PAGE_W - 2 * MARGIN
            t = Table(data, colWidths=[avail*0.22, avail*0.12, avail*0.66], repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND",     (0,0), (-1,0),  DARK_GRAY),
                ("TEXTCOLOR",      (0,0), (-1,0),  WHITE),
                ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
                ("FONTSIZE",       (0,0), (-1,0),  8),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [WHITE, LIGHT_GRAY]),
                ("GRID",           (0,0), (-1,-1), 0.4, colors.HexColor("#DEE2E6")),
                ("VALIGN",         (0,0), (-1,-1), "MIDDLE"),
                ("TOPPADDING",     (0,0), (-1,-1), 4),
                ("BOTTOMPADDING",  (0,0), (-1,-1), 4),
                ("LEFTPADDING",    (0,0), (-1,-1), 5),
                ("RIGHTPADDING",   (0,0), (-1,-1), 5),
            ]))
            flowables.append(t)
            flowables.append(Spacer(1, 4))

        # Dépôts PoC GitHub (live)
        gpocs = f.get("github_pocs", [])
        if gpocs:
            flowables.append(Paragraph("<b>Public PoC repositories:</b>", styles["body"]))
            for p in gpocs:
                desc = f" — {_escape(p['desc'])}" if p["desc"] else ""
                flowables.append(Paragraph(
                    f"★ {p['stars']} &nbsp;<link href='{p['url']}'>"
                    f"<font color='#118AB2'>{_escape(p['name'])}</font></link>{desc}",
                    styles["link"]))

        # Liens de recherche (toujours présents)
        links = f.get("poc_links", {})
        if links:
            flowables.append(Paragraph("<b>Search PoC / exploits:</b>", styles["body"]))
            flowables.append(Paragraph(
                f"<link href='{links['exploitdb']}'><font color='#118AB2'>ExploitDB</font></link> &nbsp;•&nbsp; "
                f"<link href='{links['github']}'><font color='#118AB2'>GitHub</font></link> &nbsp;•&nbsp; "
                f"<link href='{links['metasploit']}'><font color='#118AB2'>Metasploit / Rapid7</font></link>",
                styles["link"]))

        flowables.append(HRFlowable(width="100%", thickness=0.3,
                                    color=colors.HexColor("#EEEEEE"), spaceAfter=4))

    return flowables


# ── Section Remediation Roadmap ──────────────────────────────────────────────
def build_roadmap_section(enrichment: dict, styles: dict) -> list:
    """
    Tableau de suivi des corrections : Ref | Vuln | Sévérité | Priorité |
    Urgence | Deadline | Status. Trié par sévérité décroissante.
    """
    flowables = []
    findings  = enrichment.get("findings", [])
    if not findings:
        return flowables

    prio_map = getattr(report_enrich, "REMEDIATION_PRIORITY", {}) if _ENRICH_AVAILABLE else {}
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    ordered = sorted(findings, key=lambda f: sev_order.get(f["severity"], 9))

    flowables.append(PageBreak())
    flowables.append(HRFlowable(width="100%", thickness=2, color=RED, spaceAfter=4))
    flowables.append(Paragraph("Remediation Roadmap", styles["h1"]))
    flowables.append(HRFlowable(width="100%", thickness=0.5,
                                color=colors.HexColor("#DEE2E6"), spaceAfter=6))
    flowables.append(Paragraph(
        "Prioritised action plan for development and operations teams. "
        "Priority and target timeframe are derived from each finding's severity.",
        styles["enrich_note"]))

    header = ["Ref", "Vulnerability", "Severity", "Priority", "Target", "Status"]
    data = [header]
    cell = ParagraphStyle("rm", fontName="Helvetica", fontSize=8,
                          textColor=DARK_GRAY, leading=11)
    cell_c = ParagraphStyle("rmc", fontName="Helvetica-Bold", fontSize=8,
                            textColor=DARK_GRAY, leading=11, alignment=TA_CENTER)

    sev_rows = []   # pour colorer la cellule sévérité
    for idx, f in enumerate(ordered, start=1):
        sev = f["severity"]
        p_code, p_label, p_deadline = prio_map.get(sev, ("P5", "—", "—"))
        sev_badge = Paragraph(
            sev,
            ParagraphStyle("sb", fontName="Helvetica-Bold", fontSize=7.5,
                           textColor=SEV_TEXT.get(sev, WHITE),
                           alignment=TA_CENTER, leading=10))
        data.append([
            Paragraph(f["ref"], cell_c),
            Paragraph(_inline(f["title"]), cell),
            sev_badge,
            Paragraph(f"{p_code} · {p_label}", cell_c),
            Paragraph(p_deadline, cell_c),
            Paragraph("☐ Open", cell_c),
        ])
        sev_rows.append((idx, SEV_COLORS.get(sev, MID_GRAY)))

    avail = PAGE_W - 2 * MARGIN
    widths = [avail*0.10, avail*0.38, avail*0.13, avail*0.16, avail*0.13, avail*0.10]
    t = Table(data, colWidths=widths, repeatRows=1)
    style = [
        ("BACKGROUND",     (0,0), (-1,0),  DARK_GRAY),
        ("TEXTCOLOR",      (0,0), (-1,0),  WHITE),
        ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",       (0,0), (-1,0),  8.5),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [WHITE, LIGHT_GRAY]),
        ("GRID",           (0,0), (-1,-1), 0.4, colors.HexColor("#DEE2E6")),
        ("VALIGN",         (0,0), (-1,-1), "MIDDLE"),
        ("ALIGN",          (2,1), (2,-1), "CENTER"),
        ("TOPPADDING",     (0,0), (-1,-1), 5),
        ("BOTTOMPADDING",  (0,0), (-1,-1), 5),
        ("LEFTPADDING",    (0,0), (-1,-1), 5),
        ("RIGHTPADDING",   (0,0), (-1,-1), 5),
    ]
    # Colorer la cellule sévérité de chaque ligne
    for row_idx, color in sev_rows:
        style.append(("BACKGROUND", (2, row_idx), (2, row_idx), color))
    t.setStyle(TableStyle(style))
    flowables.append(t)
    return flowables


# ── Page "Risk Posture" : tous les graphiques visuels ────────────────────────
def build_risk_posture_page(enrichment: dict, styles: dict) -> list:
    """Page de synthèse visuelle : jauge + donut + histogramme OWASP +
    heatmap + matrice de risque. Nécessite report_visuals + findings."""
    if not _VISUALS_AVAILABLE:
        return []
    findings = enrichment.get("findings", [])
    if not findings:
        return []

    from reportlab.platypus import KeepTogether
    flow = []
    risk = report_visuals.compute_risk(findings)

    flow.append(HRFlowable(width="100%", thickness=2, color=RED, spaceAfter=4))
    flow.append(Paragraph("Risk Posture", styles["h1"]))
    flow.append(HRFlowable(width="100%", thickness=0.5, color=HAIR_GRAY, spaceAfter=8))
    flow.append(Paragraph(
        "At-a-glance security posture derived from all findings: overall risk score, "
        "severity distribution, OWASP Top 10 coverage, and a likelihood × impact matrix.",
        styles["enrich_note"]))

    # Ligne 1 : jauge + donut côte à côte
    gauge = report_visuals.risk_gauge(risk["score"], risk["grade"], risk["level"],
                                      width=8.4 * cm, height=5.2 * cm)
    donut = report_visuals.severity_donut(risk["counts"],
                                          width=7.6 * cm, height=5.2 * cm)
    row1 = Table([[gauge, donut]], colWidths=[(PAGE_W - 2*MARGIN)/2]*2)
    row1.setStyle(TableStyle([
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
    ]))
    flow.append(row1)

    # Histogramme OWASP
    flow.append(Spacer(1, 6))
    flow.append(Paragraph("Findings by OWASP Top 10 Category", styles["h3"]))
    flow.append(report_visuals.owasp_bar(findings, width=PAGE_W - 2*MARGIN, height=5.4*cm))

    # Heatmap OWASP (nouvelle page pour respirer)
    flow.append(PageBreak())
    flow.append(Paragraph("OWASP Top 10 Coverage Heatmap", styles["h2"]))
    flow.append(HRFlowable(width="100%", thickness=0.5, color=HAIR_GRAY, spaceAfter=8))
    flow.append(Paragraph(
        "Intensity reflects how many findings map to each OWASP 2021 category.",
        styles["enrich_note"]))
    flow.append(report_visuals.owasp_heatmap(findings, page_w=PAGE_W - 2*MARGIN))

    # Matrice de risque
    flow.append(Spacer(1, 16))
    flow.append(Paragraph("Risk Matrix — Likelihood × Impact", styles["h2"]))
    flow.append(HRFlowable(width="100%", thickness=0.5, color=HAIR_GRAY, spaceAfter=8))
    flow.append(Paragraph(
        "Each numbered dot is a finding (by its reference), positioned by severity. "
        "Upper-right (red) is the highest priority.",
        styles["enrich_note"]))
    matrix = report_visuals.risk_matrix(findings, width=11.5*cm, height=9.5*cm)
    mwrap = Table([[matrix]], colWidths=[PAGE_W - 2*MARGIN])
    mwrap.setStyle(TableStyle([("ALIGN", (0,0), (-1,-1), "CENTER")]))
    flow.append(mwrap)

    flow.append(PageBreak())
    return flow


# ── Page d'intégrité (empreinte SHA-256) ─────────────────────────────────────
def build_integrity_page(md_real_text: str, styles: dict, meta: dict) -> list:
    """Dernière page : empreinte SHA-256 du contenu source + métadonnées,
    pour prouver l'intégrité du rapport livré."""
    import hashlib
    digest = hashlib.sha256(md_real_text.encode("utf-8", errors="replace")).hexdigest()

    flow = []
    flow.append(PageBreak())
    flow.append(HRFlowable(width="100%", thickness=2, color=RED, spaceAfter=4))
    flow.append(Paragraph("Document Integrity", styles["h1"]))
    flow.append(HRFlowable(width="100%", thickness=0.5, color=HAIR_GRAY, spaceAfter=8))
    flow.append(Paragraph(
        "The SHA-256 fingerprint below is computed over the report's source content. "
        "Any modification of the findings changes this value, allowing the recipient "
        "to verify the report has not been altered after delivery.",
        styles["body"]))
    flow.append(Spacer(1, 8))

    rows = [
        ["Report title", meta.get("title", "Penetration Testing Report")],
        ["Generated", meta.get("date", "")],
        ["Findings", str(meta.get("n_findings", "—"))],
        ["Classification", meta.get("classification", "CONFIDENTIAL")],
        ["SHA-256", digest],
    ]
    data = []
    for k, v in rows:
        data.append([
            Paragraph(f"<b>{k}</b>", ParagraphStyle("ik", fontName="Helvetica-Bold",
                      fontSize=8.5, textColor=WHITE, leading=12)),
            Paragraph(f"<font face='Courier'>{v}</font>" if k == "SHA-256" else _escape(str(v)),
                      ParagraphStyle("iv", fontName="Helvetica", fontSize=8.5,
                      textColor=DARK_GRAY, leading=12)),
        ])
    t = Table(data, colWidths=[(PAGE_W-2*MARGIN)*0.28, (PAGE_W-2*MARGIN)*0.72])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), DARK_GRAY),
        ("ROWBACKGROUNDS", (1,0), (1,-1), [WHITE, LIGHT_GRAY]),
        ("GRID", (0,0), (-1,-1), 0.4, HAIR_GRAY),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("RIGHTPADDING", (0,0), (-1,-1), 8),
    ]))
    flow.append(t)
    flow.append(Spacer(1, 10))
    flow.append(Paragraph(
        "Verify with:  <font face='Courier'>sha256sum &lt;source&gt;</font>",
        styles["enrich_note"]))
    return flow


# ── Pipeline ──────────────────────────────────────────────────────────────────
def convert(md_path: str, pdf_path: str, mapping_path: str | None = None,
            classification: str = "CONFIDENTIAL", redact_level: str = "real",
            watermark: bool = True) -> None:
    """
    redact_level :
      • "real"    -> réinjecte les vraies valeurs depuis le mapping (défaut).
      • "partial" -> réinjecte tout SAUF les secrets/tokens/passwords (masqués •••).
      • "full"    -> garde toutes les clés <CAT_###> (aucune réinjection).
    """
    md_text = Path(md_path).read_text(encoding="utf-8", errors="replace")

    # Réinjection des valeurs réelles AVANT tout rendu, selon le niveau choisi.
    if mapping_path and redact_level in ("real", "partial") and _MAPPING_AVAILABLE:
        try:
            full_map = report_mapping.load_mapping(mapping_path)
            if redact_level == "partial":
                # Masquer les catégories sensibles, réinjecter le reste
                SENSITIVE = ("SECRET", "TOKEN", "PASSWORD", "API_KEY", "JWT",
                             "CRED", "HASH", "AWS", "PRIVATE")
                masked = {}
                for k, v in full_map.items():
                    if any(s in k.upper() for s in SENSITIVE):
                        masked[k] = "••••••••(redacted)"
                    else:
                        masked[k] = v
                md_text, stats = report_mapping.apply_mapping(md_text, masked)
            else:
                md_text, stats = report_mapping.apply_mapping(md_text, full_map)
            print(f"[MAP] {stats['replaced']} valeurs réinjectées "
                  f"({stats['keys_used']} clés, niveau={redact_level}).")
            if stats["leftover"]:
                print(f"[MAP] ⚠ Placeholders non résolus : "
                      f"{', '.join(stats['leftover'][:10])}"
                      + (" …" if len(stats['leftover']) > 10 else ""))
        except FileNotFoundError as e:
            print(f"[WARN] {e} — mapping ignoré.")
    elif redact_level == "full":
        print("[MAP] Niveau 'full' : clés conservées (aucune réinjection).")

    # Date
    date_match = re.search(r"(\d{4})(\d{2})(\d{2})", Path(md_path).name)
    if date_match:
        y, mo, d  = date_match.groups()
        report_date = f"{d}/{mo}/{y}"
    else:
        report_date = time.strftime("%d/%m/%Y")

    # Titre H1
    title_match = re.search(r"^#\s+(.+)", md_text, re.MULTILINE)
    report_title = (title_match.group(1).strip()
                    if title_match else "Penetration Testing Report")

    styles = make_styles()
    doc    = PentestDoc(pdf_path, report_title=report_title,
                        classification=classification, watermark=watermark)

    # Enrichissement (findings, CVE, PoC) — calculé une fois, réutilisé partout
    enrichment = None
    if _ENRICH_AVAILABLE:
        try:
            enrichment = report_enrich.get_enrichment(md_text)
        except Exception as e:
            print(f"[WARN] Enrichissement ignoré : {e}")

    # Score de risque (pour la jauge en couverture)
    risk = None
    if _VISUALS_AVAILABLE and enrichment and enrichment.get("findings"):
        try:
            risk = report_visuals.compute_risk(enrichment["findings"])
        except Exception:
            risk = None

    story: list = []
    # 1) Page de garde (avec jauge signature si dispo)
    story += build_cover(styles, report_date, risk=risk, classification=classification)
    # 2) Table of Contents
    story += build_toc_page(md_text, styles)
    # 3) Risk Posture (jauge + donut + histogramme + heatmap + matrice)
    if enrichment:
        try:
            story += build_risk_posture_page(enrichment, styles)
        except Exception as e:
            print(f"[WARN] Page Risk Posture ignorée : {e}")
    # 4) Summary Dashboard (bandeau de sévérités)
    story += build_summary_dashboard(md_text, styles)
    # 5) Corps du rapport
    story += md_to_flowables(md_text, styles, skip_toc_section=True)

    # 6) Threat Intelligence (CVE/PoC) + Remediation Roadmap
    if enrichment:
        try:
            story += build_enrichment_section(enrichment, styles)
            story += build_roadmap_section(enrichment, styles)
        except Exception as e:
            print(f"[WARN] Enrichissement ignoré : {e}")

    # 7) Page d'intégrité (SHA-256)
    try:
        meta = {
            "title": report_title, "date": report_date,
            "n_findings": len(enrichment["findings"]) if enrichment else "—",
            "classification": classification,
        }
        story += build_integrity_page(md_text, styles, meta)
    except Exception as e:
        print(f"[WARN] Page d'intégrité ignorée : {e}")

    doc.multiBuild(story)
    print(f"[PDF] Rapport généré : {pdf_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────
def find_latest_md() -> str | None:
    candidates = sorted(glob.glob("RAPPORT_PENTEST_*.md"), reverse=True)
    return candidates[0] if candidates else None


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convertit RAPPORT_PENTEST_*.md en PDF thème PenTest Hub."
    )
    parser.add_argument("md_file", nargs="?", default=None)
    parser.add_argument("-o", "--output", default=None)
    parser.add_argument("-m", "--mapping", default=None,
                        help="Fichier de mapping clé->valeur (ex: mapping.txt) "
                             "pour réinjecter les vraies valeurs avant le rendu PDF.")
    parser.add_argument("--redact-level", default="real",
                        choices=["real", "partial", "full"],
                        help="real=vraies valeurs, partial=secrets masqués, full=clés conservées.")
    parser.add_argument("--classification", default="CONFIDENTIAL",
                        help="Mention de classification (filigrane + bandeaux).")
    parser.add_argument("--no-watermark", action="store_true",
                        help="Désactiver le filigrane de classification.")
    args = parser.parse_args()

    md_file = args.md_file or find_latest_md()
    if not md_file:
        print("Aucun fichier RAPPORT_PENTEST_*.md trouvé.")
        sys.exit(1)
    if not os.path.exists(md_file):
        print(f"Fichier introuvable : {md_file}")
        sys.exit(1)

    print(f"[INFO] Source : {md_file}")
    pdf_file = args.output or Path(md_file).with_suffix(".pdf").name
    convert(md_file, pdf_file, mapping_path=args.mapping,
            classification=args.classification, redact_level=args.redact_level,
            watermark=not args.no_watermark)


if __name__ == "__main__":
    main()
