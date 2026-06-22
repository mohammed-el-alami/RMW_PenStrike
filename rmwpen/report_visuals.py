#!/usr/bin/env python3
"""
report_visuals.py — Composants graphiques professionnels pour le rapport PDF.

Tout est rendu en vectoriel (ReportLab graphics) -> net à toute résolution.
Fournit :
  • compute_risk(findings)        -> dict {score, grade, counts, level}
  • risk_gauge(...)               -> jauge semi-circulaire (élément signature)
  • severity_donut(...)           -> anneau de répartition par sévérité
  • owasp_bar(...)                -> histogramme findings par catégorie OWASP
  • owasp_heatmap(...)            -> grille OWASP Top 10 colorée par intensité
  • risk_matrix(...)              -> matrice probabilité × impact avec les findings
  • cwe_to_owasp(cwe)             -> mappe un CWE vers une catégorie OWASP 2021

Toutes les fonctions de dessin renvoient un flowable ReportLab (Drawing/Table).
"""
from __future__ import annotations

import math

from reportlab.graphics.shapes import (
    Drawing, Wedge, Polygon, Circle, String, Rect, Line, Group,
)
from reportlab.lib import colors
from reportlab.lib.units import cm
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.platypus import Table, TableStyle, Paragraph

# ── Palette (cohérente avec report_to_pdf) ───────────────────────────────────
RED        = colors.HexColor("#E63946")
DARK       = colors.HexColor("#2B2D42")
MID        = colors.HexColor("#6C757D")
LIGHT      = colors.HexColor("#F8F9FA")
HAIR       = colors.HexColor("#DEE2E6")
WHITE      = colors.white

SEV_COLORS = {
    "CRITICAL": colors.HexColor("#E63946"),
    "HIGH":     colors.HexColor("#F4845F"),
    "MEDIUM":   colors.HexColor("#F4D35E"),
    "LOW":      colors.HexColor("#06D6A0"),
    "INFO":     colors.HexColor("#118AB2"),
}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0.2}


# ── Mapping CWE -> OWASP Top 10 (2021) ───────────────────────────────────────
OWASP_2021 = {
    "A01": "Broken Access Control",
    "A02": "Cryptographic Failures",
    "A03": "Injection",
    "A04": "Insecure Design",
    "A05": "Security Misconfiguration",
    "A06": "Vulnerable Components",
    "A07": "Auth Failures",
    "A08": "Integrity Failures",
    "A09": "Logging Failures",
    "A10": "SSRF",
}
# CWE -> code OWASP (liste indicative, étendue aux CWE courants du projet)
_CWE_OWASP = {
    "22": "A01", "284": "A01", "285": "A01", "639": "A01", "552": "A01",
    "548": "A01", "200": "A01", "497": "A01",
    "259": "A02", "327": "A02", "319": "A02",
    "79": "A03", "89": "A03", "94": "A03", "917": "A03", "78": "A03",
    "601": "A04", "434": "A04", "352": "A04", "1021": "A04",
    "16": "A05", "693": "A05", "942": "A05", "614": "A05", "1004": "A05",
    "1104": "A06",
    "287": "A07", "307": "A07", "384": "A07", "640": "A07",
    "345": "A08", "502": "A08", "565": "A08",
    "778": "A09", "544": "A09",
    "918": "A10",
}


def cwe_to_owasp(cwe: str | None) -> str | None:
    if not cwe:
        return None
    digits = "".join(ch for ch in str(cwe) if ch.isdigit())
    return _CWE_OWASP.get(digits)


# ── Calcul du score / grade de risque ────────────────────────────────────────
def compute_risk(findings: list[dict]) -> dict:
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        sev = (f.get("severity") or "").upper()
        if sev in counts:
            counts[sev] += 1
    total = sum(counts.values())

    # Niveau global = sévérité maximale présente
    if counts["CRITICAL"]:
        level, grade, zone = "CRITICAL", "F", (85, 100)
    elif counts["HIGH"]:
        level, grade, zone = "HIGH", "D", (65, 85)
    elif counts["MEDIUM"]:
        level, grade, zone = "MEDIUM", "C", (40, 65)
    elif counts["LOW"]:
        level, grade, zone = "LOW", "B", (15, 40)
    elif counts["INFO"]:
        level, grade, zone = "INFO", "A", (5, 15)
    else:
        level, grade, zone = "CLEAN", "A+", (0, 5)

    # Score numérique dans la zone, modulé par le nombre de findings du niveau
    lo, hi = zone
    n_level = counts.get(level, 0) if level not in ("CLEAN",) else 0
    frac = min(1.0, math.log1p(n_level) / math.log1p(6)) if n_level else 0.0
    score = round(lo + (hi - lo) * frac)
    score = max(0, min(100, score))

    return {
        "counts": counts, "total": total,
        "level": level, "grade": grade, "score": score,
    }


# ── Élément signature : jauge de risque semi-circulaire ──────────────────────
def risk_gauge(score: int, grade: str, level: str,
               width: float = 9 * cm, height: float = 5.4 * cm) -> Drawing:
    d = Drawing(width, height)
    cx, cy = width / 2.0, height * 0.34
    r_out = min(width, height * 1.7) * 0.46
    r_in  = r_out * 0.66

    # Bandes colorées (de gauche=0 à droite=100, donc 180°->0°)
    bands = [
        (0,  15, SEV_COLORS["LOW"]),
        (15, 40, SEV_COLORS["LOW"]),
        (40, 65, SEV_COLORS["MEDIUM"]),
        (65, 85, SEV_COLORS["HIGH"]),
        (85, 100, SEV_COLORS["CRITICAL"]),
    ]
    def val_to_ang(v):       # 0->180°, 100->0°
        return 180.0 - (v / 100.0) * 180.0
    for v0, v1, col in bands:
        a0, a1 = val_to_ang(v1), val_to_ang(v0)  # wedge va de a0 à a1 (ccw)
        d.add(Wedge(cx, cy, r_out, a0, a1, yradius=r_out,
                    fillColor=col, strokeColor=WHITE, strokeWidth=1.2))
    # Trou central (anneau)
    d.add(Wedge(cx, cy, r_in, 0, 180, yradius=r_in,
                fillColor=WHITE, strokeColor=None))

    # Aiguille
    ang = math.radians(val_to_ang(score))
    nx = cx + (r_out * 0.96) * math.cos(ang)
    ny = cy + (r_out * 0.96) * math.sin(ang)
    # base de l'aiguille (petit triangle)
    perp = ang + math.pi / 2
    bw = r_in * 0.14
    bx1, by1 = cx + bw * math.cos(perp), cy + bw * math.sin(perp)
    bx2, by2 = cx - bw * math.cos(perp), cy - bw * math.sin(perp)
    d.add(Polygon([bx1, by1, nx, ny, bx2, by2],
                  fillColor=DARK, strokeColor=DARK))
    d.add(Circle(cx, cy, bw * 1.5, fillColor=DARK, strokeColor=WHITE, strokeWidth=1))

    # Texte central : score + grade
    d.add(String(cx, cy + r_in * 0.20, str(score),
                 fontName="Helvetica-Bold", fontSize=30,
                 fillColor=DARK, textAnchor="middle"))
    d.add(String(cx, cy + r_in * 0.20 - 16, "RISK SCORE / 100",
                 fontName="Helvetica", fontSize=6.5,
                 fillColor=MID, textAnchor="middle"))

    # Badge grade à droite
    gcol = SEV_COLORS.get(level, MID)
    d.add(String(cx, cy - r_in * 0.62, f"GRADE  {grade}   ·   {level}",
                 fontName="Helvetica-Bold", fontSize=10,
                 fillColor=gcol, textAnchor="middle"))
    # Repères 0 et 100
    d.add(String(cx - r_out, cy - 12, "0", fontName="Helvetica",
                 fontSize=7, fillColor=MID, textAnchor="middle"))
    d.add(String(cx + r_out, cy - 12, "100", fontName="Helvetica",
                 fontSize=7, fillColor=MID, textAnchor="middle"))
    return d


# ── Donut de répartition par sévérité ────────────────────────────────────────
def severity_donut(counts: dict, width: float = 7 * cm, height: float = 6 * cm) -> Drawing:
    d = Drawing(width, height)
    data, labels, cols = [], [], []
    for s in SEV_ORDER:
        if counts.get(s, 0) > 0:
            data.append(counts[s]); labels.append(s); cols.append(SEV_COLORS[s])
    if not data:
        data, labels, cols = [1], ["NONE"], [MID]

    cx, cy = width * 0.42, height * 0.5
    r_out = min(width, height) * 0.40
    total = sum(data)
    start = 90.0
    for val, col in zip(data, cols):
        sweep = 360.0 * val / total
        d.add(Wedge(cx, cy, r_out, start - sweep, start, yradius=r_out,
                    fillColor=col, strokeColor=WHITE, strokeWidth=1.5))
        start -= sweep
    d.add(Circle(cx, cy, r_out * 0.58, fillColor=WHITE, strokeColor=None))
    d.add(String(cx, cy + 4, str(total), fontName="Helvetica-Bold",
                 fontSize=22, fillColor=DARK, textAnchor="middle"))
    d.add(String(cx, cy - 12, "FINDINGS", fontName="Helvetica",
                 fontSize=6.5, fillColor=MID, textAnchor="middle"))

    # Légende à droite
    lx = width * 0.74
    ly = cy + r_out * 0.7
    for val, lab, col in zip(data, labels, cols):
        d.add(Rect(lx, ly, 9, 9, fillColor=col, strokeColor=None))
        d.add(String(lx + 14, ly + 1, f"{lab}  ({val})",
                     fontName="Helvetica", fontSize=7.5, fillColor=DARK))
        ly -= 15
    return d


# ── Histogramme par catégorie OWASP ──────────────────────────────────────────
def owasp_bar(findings: list[dict], width: float = 16 * cm, height: float = 6 * cm) -> Drawing:
    cat_counts = {code: 0 for code in OWASP_2021}
    for f in findings:
        code = cwe_to_owasp(f.get("cwe"))
        if code:
            cat_counts[code] += 1
    codes = list(OWASP_2021.keys())
    values = [cat_counts[c] for c in codes]
    maxv = max(values + [1])

    d = Drawing(width, height)
    pad_l, pad_b, pad_t = 0.6 * cm, 1.4 * cm, 0.4 * cm
    plot_w = width - pad_l - 0.3 * cm
    plot_h = height - pad_b - pad_t
    n = len(codes)
    gap = plot_w / n
    bw = gap * 0.62

    # axe
    d.add(Line(pad_l, pad_b, pad_l + plot_w, pad_b, strokeColor=HAIR, strokeWidth=1))
    for i, (code, v) in enumerate(zip(codes, values)):
        x = pad_l + i * gap + (gap - bw) / 2
        bh = (v / maxv) * plot_h if maxv else 0
        col = RED if v > 0 else HAIR
        d.add(Rect(x, pad_b, bw, max(bh, 0.5), fillColor=col, strokeColor=None))
        if v > 0:
            d.add(String(x + bw / 2, pad_b + bh + 3, str(v),
                         fontName="Helvetica-Bold", fontSize=7,
                         fillColor=DARK, textAnchor="middle"))
        d.add(String(x + bw / 2, pad_b - 11, code,
                     fontName="Helvetica-Bold", fontSize=6.5,
                     fillColor=MID, textAnchor="middle"))
        d.add(String(x + bw / 2, pad_b - 19, OWASP_2021[code][:14],
                     fontName="Helvetica", fontSize=5,
                     fillColor=MID, textAnchor="middle"))
    return d


# ── Heatmap OWASP Top 10 ─────────────────────────────────────────────────────
def owasp_heatmap(findings: list[dict], styles: dict | None = None,
                  page_w: float = 17 * cm) -> Table:
    cat_counts = {code: 0 for code in OWASP_2021}
    for f in findings:
        code = cwe_to_owasp(f.get("cwe"))
        if code:
            cat_counts[code] += 1
    maxv = max(list(cat_counts.values()) + [1])

    def shade(v):
        if v == 0:
            return LIGHT
        t = 0.35 + 0.65 * (v / maxv)
        return colors.Color(0.90 * t + (1 - t), 0.22 * t + (1 - t) * 0.95,
                            0.27 * t + (1 - t) * 0.95)  # vers le rouge

    cells = []
    for code in OWASP_2021:
        v = cat_counts[code]
        txtcol = WHITE if v > 0 and v >= maxv * 0.6 else DARK
        inner = Table(
            [[Paragraph(f"<b>{code}</b>",
                        ParagraphStyle("hc", fontName="Helvetica-Bold", fontSize=9,
                                       textColor=txtcol, alignment=TA_CENTER))],
             [Paragraph(OWASP_2021[code],
                        ParagraphStyle("hl", fontName="Helvetica", fontSize=5.5,
                                       textColor=txtcol, alignment=TA_CENTER, leading=7))],
             [Paragraph(str(v),
                        ParagraphStyle("hv", fontName="Helvetica-Bold", fontSize=12,
                                       textColor=txtcol, alignment=TA_CENTER))]],
            colWidths=[page_w / 5 - 0.3 * cm], rowHeights=[0.45*cm, 0.7*cm, 0.55*cm],
        )
        inner.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), shade(v)),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 1),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
            ("BOX", (0, 0), (-1, -1), 2, WHITE),
        ]))
        cells.append(inner)

    # 2 lignes de 5
    rows = [cells[0:5], cells[5:10]]
    grid = Table(rows, colWidths=[page_w / 5] * 5)
    grid.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
    ]))
    return grid


# ── Matrice de risque (probabilité × impact) ─────────────────────────────────
# Position dérivée de la sévérité (impact) + heuristique de probabilité.
_SEV_POS = {
    "CRITICAL": (4, 4), "HIGH": (4, 3), "MEDIUM": (3, 3),
    "LOW": (2, 2), "INFO": (1, 1),
}
_MATRIX_BG = [  # 5x5 (ligne 0 = impact faible en bas), couleur par zone de risque
    ["#06D6A0", "#06D6A0", "#F4D35E", "#F4845F", "#F4845F"],
    ["#06D6A0", "#F4D35E", "#F4D35E", "#F4845F", "#E63946"],
    ["#F4D35E", "#F4D35E", "#F4845F", "#F4845F", "#E63946"],
    ["#F4D35E", "#F4845F", "#F4845F", "#E63946", "#E63946"],
    ["#F4845F", "#F4845F", "#E63946", "#E63946", "#E63946"],
]


def risk_matrix(findings: list[dict], width: float = 11 * cm,
                height: float = 9.5 * cm) -> Drawing:
    d = Drawing(width, height)
    pad_l, pad_b = 1.5 * cm, 1.5 * cm
    grid_w = width - pad_l - 0.5 * cm
    grid_h = height - pad_b - 0.5 * cm
    cw, ch = grid_w / 5, grid_h / 5

    # cellules colorées
    for r in range(5):
        for c in range(5):
            x = pad_l + c * cw
            y = pad_b + r * ch
            col = colors.HexColor(_MATRIX_BG[r][c])
            d.add(Rect(x, y, cw, ch, fillColor=col, strokeColor=WHITE,
                       strokeWidth=1.2, fillOpacity=0.55))

    # axes
    d.add(String(pad_l + grid_w / 2, pad_b - 26, "LIKELIHOOD →",
                 fontName="Helvetica-Bold", fontSize=8, fillColor=DARK,
                 textAnchor="middle"))
    g = Group()
    g.add(String(0, 0, "IMPACT →", fontName="Helvetica-Bold", fontSize=8,
                 fillColor=DARK, textAnchor="middle"))
    g.translate(pad_l - 24, pad_b + grid_h / 2)
    g.rotate(90)
    d.add(g)

    labels = ["Very Low", "Low", "Medium", "High", "Critical"]
    for i, lab in enumerate(labels):
        d.add(String(pad_l + i * cw + cw / 2, pad_b - 12, lab[:4],
                     fontName="Helvetica", fontSize=6, fillColor=MID,
                     textAnchor="middle"))
        d.add(String(pad_l - 8, pad_b + i * ch + ch / 2 - 3, lab[:4],
                     fontName="Helvetica", fontSize=6, fillColor=MID,
                     textAnchor="end"))

    # points (findings) avec léger éclatement pour éviter le chevauchement
    from collections import defaultdict
    bucket = defaultdict(list)
    for f in findings:
        sev = (f.get("severity") or "").upper()
        pos = _SEV_POS.get(sev)
        if pos:
            bucket[pos].append(f)

    for (cx_i, cy_i), items in bucket.items():
        base_x = pad_l + cx_i * cw + cw / 2
        base_y = pad_b + cy_i * ch + ch / 2
        k = len(items)
        for j, f in enumerate(items):
            # disposition en petite spirale/grille
            ox = ((j % 3) - 1) * (cw * 0.22)
            oy = ((j // 3) - 1) * (ch * 0.22)
            px, py = base_x + ox, base_y + oy
            sev = (f.get("severity") or "").upper()
            d.add(Circle(px, py, 7, fillColor=SEV_COLORS.get(sev, MID),
                         strokeColor=WHITE, strokeWidth=1.4))
            ref = (f.get("ref") or "").replace("PT-1-", "")
            d.add(String(px, py - 2.5, ref, fontName="Helvetica-Bold",
                         fontSize=5.5, fillColor=WHITE, textAnchor="middle"))
    return d


if __name__ == "__main__":
    # mini-test de rendu
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Spacer
    sample = [
        {"ref": "PT-1-1", "severity": "CRITICAL", "cwe": "CWE-79"},
        {"ref": "PT-1-2", "severity": "CRITICAL", "cwe": "CWE-601"},
        {"ref": "PT-1-3", "severity": "HIGH", "cwe": "CWE-548"},
        {"ref": "PT-1-4", "severity": "HIGH", "cwe": "CWE-693"},
        {"ref": "PT-1-5", "severity": "MEDIUM", "cwe": "CWE-942"},
        {"ref": "PT-1-6", "severity": "LOW", "cwe": "CWE-1021"},
    ]
    risk = compute_risk(sample)
    print("risk:", risk)
    doc = SimpleDocTemplate("/tmp/visuals_test.pdf", pagesize=A4)
    story = [
        risk_gauge(risk["score"], risk["grade"], risk["level"]), Spacer(1, 20),
        severity_donut(risk["counts"]), Spacer(1, 20),
        owasp_bar(sample), Spacer(1, 20),
        owasp_heatmap(sample), Spacer(1, 20),
        risk_matrix(sample),
    ]
    doc.build(story)
    print("OK -> /tmp/visuals_test.pdf")
