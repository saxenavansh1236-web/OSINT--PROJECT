"""
export_pdf.py — OSINT report PDF generator (v2).

Improvements over v1:
  • Cover page with severity summary badge
  • Per-section colour-coded severity rows
  • Breach data_classes and record counts in table
  • Subdomain HTTP status column
  • WHOIS registrar + registrant sections separated
  • Scan metadata block (target, timestamp, sources used)
  • Page numbers in footer
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ─────────────────────────────────────────────
# Palette
# ─────────────────────────────────────────────

C = {
    "bg":           colors.HexColor("#0f172a"),   # deep navy (header fill)
    "accent":       colors.HexColor("#3b82f6"),   # blue
    "critical":     colors.HexColor("#ef4444"),   # red
    "high":         colors.HexColor("#f97316"),   # orange
    "medium":       colors.HexColor("#eab308"),   # yellow
    "info":         colors.HexColor("#22c55e"),   # green
    "label_bg":     colors.HexColor("#f0f4ff"),
    "row_alt":      colors.HexColor("#f8fafc"),
    "border":       colors.HexColor("#e2e8f0"),
    "text":         colors.HexColor("#1e293b"),
    "muted":        colors.HexColor("#64748b"),
    "white":        colors.white,
}

SEVERITY_COLORS = {
    "critical": C["critical"],
    "high":     C["high"],
    "medium":   C["medium"],
    "info":     C["info"],
    "error":    C["muted"],
}


# ─────────────────────────────────────────────
# Style factory
# ─────────────────────────────────────────────

def _styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("T_title", parent=base["Title"],
                                fontSize=24, textColor=C["white"],
                                spaceAfter=4, alignment=TA_CENTER),
        "title_sub": ParagraphStyle("T_sub", parent=base["Normal"],
                                    fontSize=10, textColor=colors.HexColor("#94a3b8"),
                                    spaceAfter=0, alignment=TA_CENTER),
        "section": ParagraphStyle("T_section", parent=base["Heading2"],
                                  fontSize=12, textColor=C["bg"],
                                  spaceBefore=18, spaceAfter=6,
                                  fontName="Helvetica-Bold"),
        "body": ParagraphStyle("T_body", parent=base["Normal"],
                               fontSize=8.5, textColor=C["text"],
                               leading=13, spaceAfter=3),
        "cell": ParagraphStyle("T_cell", parent=base["Normal"],
                               fontSize=8, textColor=C["text"], leading=12),
        "cell_key": ParagraphStyle("T_key", parent=base["Normal"],
                                   fontSize=8, textColor=C["text"],
                                   fontName="Helvetica-Bold", leading=12),
        "meta": ParagraphStyle("T_meta", parent=base["Normal"],
                               fontSize=8, textColor=C["muted"],
                               leading=12, alignment=TA_LEFT),
        "footer": ParagraphStyle("T_footer", parent=base["Normal"],
                                 fontSize=7, textColor=C["muted"],
                                 alignment=TA_CENTER),
    }


# ─────────────────────────────────────────────
# Page template with footer
# ─────────────────────────────────────────────

class _FooterCanvas:
    """Mixin that draws a page-number footer on each page."""
    # Injected by SimpleDocTemplate
    def _draw_footer(self, canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(C["muted"])
        page_text = f"Page {doc.page}"
        canvas.drawCentredString(A4[0] / 2, 1.2 * cm, page_text)
        canvas.restoreState()


def _on_page(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C["muted"])
    canvas.drawCentredString(A4[0] / 2, 1.0 * cm, f"Page {doc.page}  •  OSINT Investigation Report")
    canvas.restoreState()


# ─────────────────────────────────────────────
# Table builders
# ─────────────────────────────────────────────

_COL_W = [4.5 * cm, 12 * cm]
_COL_W_3 = [4.5 * cm, 8 * cm, 2.5 * cm]


def _kv_table(rows: list[tuple], style=None) -> Table:
    """Generic 2-col key/value table."""
    s = style or _styles()
    data = [
        [Paragraph(f"<b>{k}</b>", s["cell_key"]),
         Paragraph(_safe(v), s["cell"])]
        for k, v in rows
    ]
    tbl = Table(data, colWidths=_COL_W)
    tbl.setStyle(_base_table_style())
    return tbl


def _breach_table(breaches: list[dict], style=None) -> Table:
    """Breach table with severity badge column."""
    s = style or _styles()
    header = [
        Paragraph("<b>Source</b>", s["cell_key"]),
        Paragraph("<b>Breach / Note</b>", s["cell_key"]),
        Paragraph("<b>Date</b>", s["cell_key"]),
        Paragraph("<b>Records</b>", s["cell_key"]),
        Paragraph("<b>Severity</b>", s["cell_key"]),
    ]
    rows = [header]
    row_styles: list[tuple] = []

    for i, b in enumerate(breaches, start=1):
        sev = b.get("severity", "info")
        sev_color = SEVERITY_COLORS.get(sev, C["muted"])
        classes = ", ".join(b.get("data_classes", [])) or "—"
        records = f"{b.get('records', 0):,}" if b.get("records") else "—"
        rows.append([
            Paragraph(_safe(b.get("source")), s["cell"]),
            Paragraph(f"{_safe(b.get('name'))}<br/><font color='#64748b' size='7'>{classes}</font>", s["cell"]),
            Paragraph(_safe(b.get("date")), s["cell"]),
            Paragraph(records, s["cell"]),
            Paragraph(f"<b>{sev.upper()}</b>", ParagraphStyle(
                f"sev_{i}", parent=getSampleStyleSheet()["Normal"],
                fontSize=7, textColor=sev_color, fontName="Helvetica-Bold")),
        ])
        row_styles.append(("BACKGROUND", (0, i), (-1, i),
                           colors.HexColor("#fff7ed") if sev == "high"
                           else colors.HexColor("#fef2f2") if sev == "critical"
                           else colors.HexColor("#f8fafc")))

    tbl = Table(rows, colWidths=[3 * cm, 6 * cm, 2.5 * cm, 2.5 * cm, 2 * cm])
    style_cmds = _base_table_style(has_header=True)
    tbl.setStyle(TableStyle(style_cmds + row_styles))
    return tbl


def _subdomain_table(subs: list[dict | str], style=None) -> Table:
    """Subdomain table with IP and HTTP status columns."""
    s = style or _styles()
    header = [
        Paragraph("<b>#</b>", s["cell_key"]),
        Paragraph("<b>Hostname</b>", s["cell_key"]),
        Paragraph("<b>IP</b>", s["cell_key"]),
        Paragraph("<b>HTTP</b>", s["cell_key"]),
    ]
    rows = [header]
    for i, sub in enumerate(subs, start=1):
        if isinstance(sub, dict):
            host  = sub.get("host", "—")
            ip    = sub.get("ip", "—")
            hstat = str(sub.get("status", "")) or "—"
        else:
            host, ip, hstat = str(sub), "—", "—"
        rows.append([
            Paragraph(str(i), s["cell"]),
            Paragraph(host, s["cell"]),
            Paragraph(ip, s["cell"]),
            Paragraph(hstat, s["cell"]),
        ])
    tbl = Table(rows, colWidths=[1 * cm, 7 * cm, 4 * cm, 2 * cm])
    tbl.setStyle(TableStyle(_base_table_style(has_header=True)))
    return tbl


def _base_table_style(has_header: bool = False) -> list:
    cmds = [
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
        ("PADDING",    (0, 0), (-1, -1), 5),
        ("GRID",       (0, 0), (-1, -1), 0.4, C["border"]),
        ("BACKGROUND", (0, 0), (0, -1), C["label_bg"]),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
         [colors.white, C["row_alt"]]),
        ("TEXTCOLOR",  (0, 0), (-1, -1), C["text"]),
    ]
    if has_header:
        cmds += [
            ("BACKGROUND", (0, 0), (-1, 0), C["bg"]),
            ("TEXTCOLOR",  (0, 0), (-1, 0), C["white"]),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, C["row_alt"]]),
        ]
    return cmds


# ─────────────────────────────────────────────
# Cover block
# ─────────────────────────────────────────────

def _cover_block(target: str, timestamp: str, summary: dict, s: dict) -> list:
    """Returns a list of flowables for the cover page header."""
    story = []

    # Dark header banner
    banner_data = [[
        Paragraph("OSINT", ParagraphStyle("cvt1", fontSize=28, textColor=C["white"],
                                          fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph("Investigation Report", ParagraphStyle("cvt2", fontSize=14,
                                                         textColor=colors.HexColor("#94a3b8"),
                                                         fontName="Helvetica", alignment=TA_CENTER)),
        Paragraph(f"Target: {target}", ParagraphStyle("cvt3", fontSize=10,
                                                       textColor=C["accent"],
                                                       fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(timestamp, ParagraphStyle("cvt4", fontSize=8,
                                            textColor=colors.HexColor("#64748b"),
                                            alignment=TA_CENTER)),
    ]]
    # Flatten into single-col banner
    banner_rows = [
        [Paragraph("🔍  OSINT Investigation Report", ParagraphStyle(
            "bh", fontSize=20, textColor=C["white"],
            fontName="Helvetica-Bold", alignment=TA_CENTER))],
        [Paragraph(f"Target: <b>{target}</b>  •  {timestamp}", ParagraphStyle(
            "bs", fontSize=9, textColor=colors.HexColor("#94a3b8"),
            alignment=TA_CENTER))],
    ]
    banner = Table(banner_rows, colWidths=[16.5 * cm])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), C["bg"]),
        ("PADDING",    (0, 0), (-1, -1), 14),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, 0), 18),
        ("BOTTOMPADDING", (0, -1), (-1, -1), 18),
    ]))
    story.append(banner)
    story.append(Spacer(1, 10))

    # Severity summary badges
    sev_rows = [[
        Paragraph(f"<b>{summary.get('critical', 0)}</b><br/>Critical", ParagraphStyle(
            "sbc", fontSize=9, textColor=C["white"], alignment=TA_CENTER)),
        Paragraph(f"<b>{summary.get('high', 0)}</b><br/>High", ParagraphStyle(
            "sbh", fontSize=9, textColor=C["white"], alignment=TA_CENTER)),
        Paragraph(f"<b>{summary.get('medium', 0)}</b><br/>Medium", ParagraphStyle(
            "sbm", fontSize=9, textColor=C["white"], alignment=TA_CENTER)),
        Paragraph(f"<b>{summary.get('subdomains', 0)}</b><br/>Subdomains", ParagraphStyle(
            "sbs", fontSize=9, textColor=C["white"], alignment=TA_CENTER)),
        Paragraph(f"<b>{summary.get('breaches', 0)}</b><br/>Breaches", ParagraphStyle(
            "sbb", fontSize=9, textColor=C["white"], alignment=TA_CENTER)),
    ]]
    badge_tbl = Table(sev_rows, colWidths=[3.3 * cm] * 5)
    badge_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), C["critical"]),
        ("BACKGROUND", (1, 0), (1, 0), C["high"]),
        ("BACKGROUND", (2, 0), (2, 0), C["medium"]),
        ("BACKGROUND", (3, 0), (3, 0), C["accent"]),
        ("BACKGROUND", (4, 0), (4, 0), colors.HexColor("#8b5cf6")),
        ("PADDING",    (0, 0), (-1, -1), 8),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
        ("TEXTCOLOR",  (0, 0), (-1, -1), C["white"]),
    ]))
    story.append(badge_tbl)
    story.append(Spacer(1, 14))
    story.append(HRFlowable(width="100%", thickness=1, color=C["border"]))
    story.append(Spacer(1, 8))
    return story


# ─────────────────────────────────────────────
# Main export function
# ─────────────────────────────────────────────

def export_report(data: dict, output_path: str = "report.pdf") -> str:
    """
    Generate a PDF OSINT report.

    Args:
        data:        Result dict from run_scan() — see schema below.
        output_path: Where to write the PDF.

    Data schema
    -----------
    {
        "target":   str,
        "ip":       str,
        "geo":      dict,             # {city, region, country, lat, lon, isp, …}
        "whois":    dict,             # from whois_lookup.whois_data()
        "subs":     list[dict|str],   # SubdomainResult.to_dict() or plain hostnames
        "breach":   list[dict],       # BreachResult.to_dict()
        "username": list[str] | str,  # sites where username found
        "ports":    list[dict],       # optional: [{port, service, state}]
    }
    """
    os.makedirs(
        os.path.dirname(output_path) if os.path.dirname(output_path) else ".",
        exist_ok=True,
    )

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    s = _styles()
    story: list = []

    target    = data.get("target", "Unknown")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    breaches  = data.get("breach", [])
    subs      = data.get("subs", [])

    # Severity summary for cover badges
    sev_summary = {
        "critical":  sum(1 for b in breaches if isinstance(b, dict) and b.get("severity") == "critical"),
        "high":      sum(1 for b in breaches if isinstance(b, dict) and b.get("severity") == "high"),
        "medium":    sum(1 for b in breaches if isinstance(b, dict) and b.get("severity") == "medium"),
        "subdomains": len(subs),
        "breaches":  len(breaches),
    }

    # ── Cover
    story.extend(_cover_block(target, timestamp, sev_summary, s))

    # ── Scan Metadata
    story.append(Paragraph("Scan Metadata", s["section"]))
    meta_rows = [
        ("Target",     target),
        ("IP Address", data.get("ip", "—")),
        ("Timestamp",  timestamp),
        ("Sources",    "WHOIS/RDAP · DNS · HaveIBeenPwned / LeakCheck · EmailRep.io · IntelX"),
    ]
    geo = data.get("geo", {})
    if geo:
        loc_parts = [geo.get("city"), geo.get("region"), geo.get("country")]
        meta_rows.append(("Location", ", ".join(p for p in loc_parts if p) or "—"))
        if geo.get("isp"):
            meta_rows.append(("ISP / ASN", geo["isp"]))
    story.append(_kv_table(meta_rows, s))

    # ── WHOIS
    story.append(Paragraph("WHOIS & Registration", s["section"]))
    whois = data.get("whois", {})
    if whois:
        registrar_rows = [
            ("Registrar",       whois.get("registrar", "—")),
            ("Registrar URL",   whois.get("registrar_url", "—")),
            ("Registrar Email", whois.get("registrar_email", "—")),
            ("IANA ID",         whois.get("registrar_iana_id", "—")),
        ]
        registrant_rows = [
            ("Org / Name",    whois.get("registrant_org") or whois.get("registrant_name") or "—"),
            ("Country",       whois.get("registrant_country", "—")),
            ("Created",       whois.get("creation_date", "—")),
            ("Updated",       whois.get("updated_date", "—")),
            ("Expires",       whois.get("expiry_date", "—")),
            ("Domain Age",    (whois.get("age_days", "—") + " days") if whois.get("age_days", "—") != "—" else "—"),
            ("Name Servers",  whois.get("name_servers", "—")),
            ("DNSSEC",        whois.get("dnssec", "—")),
            ("Status",        whois.get("status", "—")),
        ]
        story.append(Paragraph("<b>Registrar</b>", s["body"]))
        story.append(_kv_table(registrar_rows, s))
        story.append(Spacer(1, 6))
        story.append(Paragraph("<b>Domain Details</b>", s["body"]))
        story.append(_kv_table(registrant_rows, s))
    else:
        story.append(_kv_table([("Result", "No WHOIS data available")], s))

    # ── Subdomains
    story.append(Paragraph(f"Subdomains  ({len(subs)} found)", s["section"]))
    if subs:
        story.append(_subdomain_table(subs, s))
    else:
        story.append(Paragraph("No live subdomains found.", s["body"]))

    # ── Breach Check
    story.append(Paragraph(f"Breach Check  ({len(breaches)} found)", s["section"]))
    if breaches:
        breach_dicts = [b if isinstance(b, dict) else {"source": "—", "name": str(b),
                        "date": "—", "records": 0, "data_classes": [], "severity": "medium",
                        "description": str(b)} for b in breaches]
        story.append(_breach_table(breach_dicts, s))
    else:
        story.append(Paragraph("No breach records found for this target.", s["body"]))

    # ── Username Search
    username_val = data.get("username")
    if username_val:
        story.append(Paragraph("Username Search", s["section"]))
        if isinstance(username_val, list) and username_val:
            rows = [(f"#{i+1}", site) for i, site in enumerate(username_val)]
        else:
            rows = [("Result", _safe(username_val))]
        story.append(_kv_table(rows, s))

    # ── Optional: Open Ports
    ports = data.get("ports")
    if ports:
        story.append(Paragraph(f"Open Ports  ({len(ports)} found)", s["section"]))
        header = [
            Paragraph("<b>Port</b>", s["cell_key"]),
            Paragraph("<b>Service</b>", s["cell_key"]),
            Paragraph("<b>State</b>", s["cell_key"]),
        ]
        port_rows = [header] + [
            [Paragraph(str(p.get("port", "—")), s["cell"]),
             Paragraph(_safe(p.get("service")), s["cell"]),
             Paragraph(_safe(p.get("state")), s["cell"])]
            for p in ports
        ]
        ptbl = Table(port_rows, colWidths=[3 * cm, 9 * cm, 4 * cm])
        ptbl.setStyle(TableStyle(_base_table_style(has_header=True)))
        story.append(ptbl)

    # ── Footer
    story.append(Spacer(1, 24))
    story.append(HRFlowable(width="100%", thickness=0.5, color=C["border"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "This report was generated automatically by the OSINT Investigation Platform. "
        "Data accuracy depends on third-party APIs and public sources. "
        "For investigative or legal purposes, verify all findings independently.",
        s["footer"],
    ))

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return output_path


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def _safe(val: Any) -> str:
    if val is None:
        return "—"
    if isinstance(val, list):
        return ", ".join(str(v) for v in val) if val else "—"
    if isinstance(val, dict):
        return "; ".join(f"{k}: {v}" for k, v in val.items())
    return str(val) or "—"