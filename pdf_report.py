"""
export_pdf.py — OSINT report PDF generator (v3).

v3 changes (fixes PDF only including a fraction of the scan result):
  • Risk Score section (score, level, top factors, recommendations)
  • Identity Confidence Score section
  • AI Investigation Summary section (with confidence label)
  • Phone Intelligence section
  • Email OSINT section
  • DNS / SSL / Tech Stack section
  • Threat Intelligence Grid (VirusTotal, AbuseIPDB, OTX, URLScan)
  • Dark Web Monitor + Paste Monitor section
  • Related Entities section
  • Every new section fails gracefully — a missing/empty key just skips
    that section rather than crashing the whole report.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
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
    "bg":       colors.HexColor("#0f172a"),
    "accent":   colors.HexColor("#3b82f6"),
    "critical": colors.HexColor("#ef4444"),
    "high":     colors.HexColor("#f97316"),
    "medium":   colors.HexColor("#eab308"),
    "info":     colors.HexColor("#22c55e"),
    "purple":   colors.HexColor("#8b5cf6"),
    "label_bg": colors.HexColor("#f0f4ff"),
    "row_alt":  colors.HexColor("#f8fafc"),
    "border":   colors.HexColor("#e2e8f0"),
    "text":     colors.HexColor("#1e293b"),
    "muted":    colors.HexColor("#64748b"),
    "white":    colors.white,
}

SEVERITY_COLORS = {
    "critical": C["critical"],
    "high":     C["high"],
    "medium":   C["medium"],
    "low":      C["info"],
    "info":     C["info"],
    "error":    C["muted"],
}

RISK_LEVEL_COLORS = {
    "CRITICAL": C["critical"],
    "HIGH":     C["high"],
    "MEDIUM":   C["medium"],
    "LOW":      C["info"],
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
        "section": ParagraphStyle("T_section", parent=base["Heading2"],
                                  fontSize=12, textColor=C["bg"],
                                  spaceBefore=18, spaceAfter=6,
                                  fontName="Helvetica-Bold"),
        "subsection": ParagraphStyle("T_subsection", parent=base["Heading3"],
                                     fontSize=9.5, textColor=C["text"],
                                     spaceBefore=8, spaceAfter=4,
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


def _on_page(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(C["muted"])
    canvas.drawCentredString(A4[0] / 2, 1.0 * cm, f"Page {doc.page}  •  OSINT Investigation Report")
    canvas.restoreState()


# ─────────────────────────────────────────────
# Generic table builders
# ─────────────────────────────────────────────

_COL_W = [4.5 * cm, 12 * cm]


def _base_table_style(has_header: bool = False) -> list:
    cmds = [
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
        ("PADDING",    (0, 0), (-1, -1), 5),
        ("GRID",       (0, 0), (-1, -1), 0.4, C["border"]),
        ("BACKGROUND", (0, 0), (0, -1), C["label_bg"]),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, C["row_alt"]]),
        ("TEXTCOLOR",  (0, 0), (-1, -1), C["text"]),
    ]
    if has_header:
        cmds += [
            ("BACKGROUND", (0, 0), (-1, 0), C["bg"]),
            ("TEXTCOLOR",  (0, 0), (-1, 0), C["white"]),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, C["row_alt"]]),
        ]
    return cmds


def _kv_table(rows: list[tuple], style=None) -> Table | None:
    s = style or _styles()
    clean_rows = [(k, v) for k, v in rows if v not in (None, "", "—") or True]
    if not clean_rows:
        return None
    data = [
        [Paragraph(f"<b>{_safe(k)}</b>", s["cell_key"]), Paragraph(_safe(v), s["cell"])]
        for k, v in clean_rows
    ]
    tbl = Table(data, colWidths=_COL_W)
    tbl.setStyle(TableStyle(_base_table_style()))
    return tbl


def _generic_rows_table(headers: list[str], rows: list[list], col_widths: list, style=None) -> Table:
    s = style or _styles()
    header_row = [Paragraph(f"<b>{h}</b>", s["cell_key"]) for h in headers]
    data = [header_row]
    for r in rows:
        data.append([Paragraph(_safe(c), s["cell"]) for c in r])
    tbl = Table(data, colWidths=col_widths)
    tbl.setStyle(TableStyle(_base_table_style(has_header=True)))
    return tbl


def _breach_table(breaches: list[dict], style=None) -> Table:
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
        sev = (b.get("severity") or "info").lower()
        sev_color = SEVERITY_COLORS.get(sev, C["muted"])
        classes = ", ".join(b.get("data_classes", [])) if b.get("data_classes") else "—"
        records = f"{b.get('records', 0):,}" if b.get("records") else "—"
        name = b.get("name") or b.get("breach_name") or "Unknown"
        rows.append([
            Paragraph(_safe(b.get("source")), s["cell"]),
            Paragraph(f"{_safe(name)}<br/><font color='#64748b' size='7'>{classes}</font>", s["cell"]),
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
    tbl.setStyle(TableStyle(_base_table_style(has_header=True) + row_styles))
    return tbl


def _subdomain_table(subs: list, style=None) -> Table:
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


# ─────────────────────────────────────────────
# Risk / badge style rows (used for Risk Score + Identity Score)
# ─────────────────────────────────────────────

def _score_badge_row(score: Any, level: str, label: str, s: dict) -> Table:
    color = RISK_LEVEL_COLORS.get(str(level).upper(), C["accent"])
    tbl = Table([[
        Paragraph(f"<font size='22' color='{color.hexval()}'><b>{_safe(score)}</b></font>"
                   f"<font size='9' color='{C['muted'].hexval()}'> /100</font>",
                   ParagraphStyle("scorebig", alignment=TA_CENTER)),
        Paragraph(f"<font size='11' color='{color.hexval()}'><b>{_safe(level).upper()}</b></font>"
                   f"<br/><font size='8' color='{C['muted'].hexval()}'>{label}</font>",
                   ParagraphStyle("scorelbl", alignment=TA_LEFT)),
    ]], colWidths=[5 * cm, 11.5 * cm])
    tbl.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (-1, -1), C["label_bg"]),
        ("PADDING", (0, 0), (-1, -1), 10),
        ("BOX", (0, 0), (-1, -1), 0.5, C["border"]),
    ]))
    return tbl


def _factor_list_table(factors: list[dict], s: dict) -> Table:
    header = [
        Paragraph("<b>Factor</b>", s["cell_key"]),
        Paragraph("<b>Severity</b>", s["cell_key"]),
        Paragraph("<b>Points</b>", s["cell_key"]),
        Paragraph("<b>Category</b>", s["cell_key"]),
    ]
    rows = [header]
    for f in factors:
        sev = (f.get("severity") or "info").lower()
        sev_color = SEVERITY_COLORS.get(sev, C["muted"])
        detail = f.get("detail") or f.get("description") or f.get("factor") or ""
        rows.append([
            Paragraph(_safe(detail), s["cell"]),
            Paragraph(f"<font color='{sev_color.hexval()}'><b>{sev.upper()}</b></font>", s["cell"]),
            Paragraph(_safe(f.get("points", "—")), s["cell"]),
            Paragraph(_safe(f.get("category", "—")), s["cell"]),
        ])
    tbl = Table(rows, colWidths=[8 * cm, 2.5 * cm, 2 * cm, 4 * cm])
    tbl.setStyle(TableStyle(_base_table_style(has_header=True)))
    return tbl


# ─────────────────────────────────────────────
# Cover block
# ─────────────────────────────────────────────

def _cover_block(target: str, timestamp: str, summary: dict, s: dict) -> list:
    story = []
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
        Paragraph(f"<b>{summary.get('risk_score', '—')}</b><br/>Risk Score", ParagraphStyle(
            "sbr", fontSize=9, textColor=C["white"], alignment=TA_CENTER)),
    ]]
    badge_tbl = Table(sev_rows, colWidths=[2.75 * cm] * 6)
    badge_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), C["critical"]),
        ("BACKGROUND", (1, 0), (1, 0), C["high"]),
        ("BACKGROUND", (2, 0), (2, 0), C["medium"]),
        ("BACKGROUND", (3, 0), (3, 0), C["accent"]),
        ("BACKGROUND", (4, 0), (4, 0), C["purple"]),
        ("BACKGROUND", (5, 0), (5, 0), C["bg"]),
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
    Generate a full PDF OSINT report from a run_osint_scan() result dict.
    Every section is optional — a missing/empty key just skips that
    section instead of raising or silently under-reporting.
    """
    os.makedirs(
        os.path.dirname(output_path) if os.path.dirname(output_path) else ".",
        exist_ok=True,
    )

    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm, bottomMargin=2 * cm,
    )

    s = _styles()
    story: list = []

    target    = data.get("target", "Unknown")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    breaches  = data.get("breach") or []
    subs      = data.get("subs") or []
    risk      = data.get("risk_score") or {}

    sev_summary = {
        "critical":   sum(1 for b in breaches if isinstance(b, dict) and b.get("severity") == "critical"),
        "high":       sum(1 for b in breaches if isinstance(b, dict) and b.get("severity") == "high"),
        "medium":     sum(1 for b in breaches if isinstance(b, dict) and b.get("severity") == "medium"),
        "subdomains": len(subs),
        "breaches":   len(breaches),
        "risk_score": risk.get("score", "—") if isinstance(risk, dict) else "—",
    }

    # ── Cover
    story.extend(_cover_block(target, timestamp, sev_summary, s))

    # ── Scan Metadata
    story.append(Paragraph("Scan Metadata", s["section"]))
    meta_rows = [
        ("Target",     target),
        ("IP Address", data.get("ip", "—")),
        ("Timestamp",  timestamp),
        ("Sources",    "WHOIS/RDAP · DNS · HaveIBeenPwned/LeakCheck · VT · AbuseIPDB · "
                        "URLScan · OTX · Dark Web · Paste Monitor"),
    ]
    geo = data.get("geo") or {}
    if isinstance(geo, dict) and geo and "error" not in geo:
        loc_parts = [geo.get("city"), geo.get("region"), geo.get("country")]
        loc = ", ".join(p for p in loc_parts if p)
        if loc:
            meta_rows.append(("Location", loc))
        if geo.get("isp"):
            meta_rows.append(("ISP / ASN", geo["isp"]))
    tbl = _kv_table(meta_rows, s)
    if tbl:
        story.append(tbl)

    # ── Risk Score
    if isinstance(risk, dict) and risk and "error" not in risk:
        story.append(Paragraph("Risk Score", s["section"]))
        story.append(_score_badge_row(
            risk.get("score", "—"), risk.get("risk_level", risk.get("level", "—")),
            "Composite risk assessment", s,
        ))
        story.append(Spacer(1, 6))
        factors = risk.get("top_factors") or risk.get("factors") or []
        if factors:
            story.append(Paragraph("Top Risk Factors", s["subsection"]))
            story.append(_factor_list_table(factors, s))
        recs = risk.get("recommendations") or []
        if recs:
            story.append(Paragraph("Recommendations", s["subsection"]))
            for r in recs:
                story.append(Paragraph(f"→ {_safe(r)}", s["body"]))

    # ── Identity Confidence Score
    identity = data.get("identity_score")
    if isinstance(identity, dict) and identity and "error" not in identity:
        story.append(Paragraph("Identity Confidence Score", s["section"]))
        story.append(_score_badge_row(
            identity.get("score", identity.get("confidence", "—")),
            identity.get("level", identity.get("strength", "—")),
            "Digital footprint strength", s,
        ))
        story.append(Spacer(1, 6))
        categories = identity.get("categories") or identity.get("signals") or {}
        if isinstance(categories, dict) and categories:
            rows = [(k.replace("_", " ").title(), v) for k, v in categories.items()]
            tbl = _kv_table(rows, s)
            if tbl:
                story.append(tbl)

    # ── AI Investigation Summary
    ai_summary = data.get("ai_summary")
    if isinstance(ai_summary, dict) and ai_summary and "error" not in ai_summary:
        story.append(Paragraph("AI Investigation Summary", s["section"]))
        conf = ai_summary.get("confidence", "—")
        story.append(Paragraph(f"<b>Confidence:</b> {_safe(conf)}", s["body"]))
        narrative = ai_summary.get("narrative") or ai_summary.get("summary") or ""
        if narrative:
            story.append(Paragraph(_safe(narrative), s["body"]))
        basis = ai_summary.get("basis") or ai_summary.get("confidence_note")
        if basis:
            story.append(Paragraph(f"<i>Basis: {_safe(basis)}</i>", s["meta"]))

    # ── WHOIS
    whois = data.get("whois") or {}
    if isinstance(whois, dict) and whois and "error" not in whois:
        story.append(Paragraph("WHOIS & Registration", s["section"]))
        registrar_rows = [
            ("Registrar",       whois.get("registrar", "—")),
            ("Registrar URL",   whois.get("registrar_url", "—")),
            ("Registrar Email", whois.get("registrar_email", "—")),
            ("IANA ID",         whois.get("registrar_iana_id", "—")),
        ]
        registrant_rows = [
            ("Org / Name",   whois.get("registrant_org") or whois.get("registrant_name") or "—"),
            ("Country",      whois.get("registrant_country", "—")),
            ("Created",      whois.get("creation_date", "—")),
            ("Updated",      whois.get("updated_date", "—")),
            ("Expires",      whois.get("expiry_date", "—")),
            ("Name Servers", whois.get("name_servers", "—")),
            ("DNSSEC",       whois.get("dnssec", "—")),
            ("Status",       whois.get("status", "—")),
        ]
        story.append(Paragraph("Registrar", s["subsection"]))
        t = _kv_table(registrar_rows, s)
        if t:
            story.append(t)
        story.append(Spacer(1, 6))
        story.append(Paragraph("Domain Details", s["subsection"]))
        t = _kv_table(registrant_rows, s)
        if t:
            story.append(t)

    # ── DNS / SSL / Tech Stack
    dns  = data.get("dns") or {}
    ssl_ = data.get("ssl") or {}
    tech = data.get("tech") or {}
    if any(isinstance(x, dict) and x and "error" not in x for x in (dns, ssl_, tech)):
        story.append(Paragraph("DNS, SSL & Technology", s["section"]))
        if isinstance(dns, dict) and dns and "error" not in dns:
            story.append(Paragraph("DNS Records", s["subsection"]))
            rows = [(k.upper(), v) for k, v in dns.items() if v]
            t = _kv_table(rows, s)
            if t:
                story.append(t)
        if isinstance(ssl_, dict) and ssl_ and "error" not in ssl_:
            story.append(Paragraph("SSL Certificate", s["subsection"]))
            rows = [(k.replace("_", " ").title(), v) for k, v in ssl_.items() if v]
            t = _kv_table(rows, s)
            if t:
                story.append(t)
        if isinstance(tech, dict) and tech and "error" not in tech:
            story.append(Paragraph("Technology Stack", s["subsection"]))
            rows = [(k.replace("_", " ").title(), v) for k, v in tech.items() if v]
            t = _kv_table(rows, s)
            if t:
                story.append(t)

    # ── Subdomains
    story.append(Paragraph(f"Subdomains  ({len(subs)} found)", s["section"]))
    if subs:
        story.append(_subdomain_table(subs, s))
    else:
        story.append(Paragraph("No live subdomains found.", s["body"]))

    # ── Breach Check
    story.append(Paragraph(f"Breach Check  ({len(breaches)} found)", s["section"]))
    if breaches:
        breach_dicts = [
            b if isinstance(b, dict) else
            {"source": "—", "name": str(b), "date": "—", "records": 0,
             "data_classes": [], "severity": "medium", "description": str(b)}
            for b in breaches
        ]
        story.append(_breach_table(breach_dicts, s))
    else:
        story.append(Paragraph("No breach records found for this target.", s["body"]))

    # ── Phone Intelligence
    phone = data.get("phone")
    if isinstance(phone, dict) and phone and "error" not in phone:
        story.append(Paragraph("Phone Intelligence", s["section"]))
        rows = [
            ("Valid",       phone.get("valid", "—")),
            ("Carrier",     phone.get("carrier", "—")),
            ("Line Type",   phone.get("line_type", "—")),
            ("Region",      phone.get("region", "—")),
            ("Timezone",    phone.get("timezone", "—")),
            ("International", phone.get("international", "—")),
            ("Fraud Score", phone.get("fraud_score", "—")),
            ("VOIP",        phone.get("is_voip", "—")),
        ]
        t = _kv_table(rows, s)
        if t:
            story.append(t)

    # ── Email OSINT
    email_osint = data.get("email_osint")
    if isinstance(email_osint, dict) and email_osint and "error" not in email_osint:
        story.append(Paragraph("Email Intelligence", s["section"]))
        rows = [(k.replace("_", " ").title(), v) for k, v in email_osint.items()
                if not isinstance(v, (list, dict)) and v not in (None, "")]
        t = _kv_table(rows, s)
        if t:
            story.append(t)

    # ── Threat Intelligence Grid
    vt      = data.get("virustotal") or {}
    abuse   = data.get("abuse") or {}
    otx     = data.get("otx") or {}
    urlscan = data.get("urlscan") or {}
    if any(isinstance(x, dict) and x and "error" not in x for x in (vt, abuse, otx, urlscan)):
        story.append(Paragraph("Threat Intelligence Grid", s["section"]))
        if isinstance(vt, dict) and vt and "error" not in vt:
            story.append(Paragraph("VirusTotal", s["subsection"]))
            rows = [
                ("Malicious",   vt.get("malicious", 0)),
                ("Suspicious",  vt.get("suspicious", 0)),
                ("Harmless",    vt.get("harmless", 0)),
                ("Threat Names", ", ".join(vt.get("threat_names", [])) or "—"),
            ]
            t = _kv_table(rows, s)
            if t:
                story.append(t)
        if isinstance(abuse, dict) and abuse and "error" not in abuse:
            story.append(Paragraph("AbuseIPDB", s["subsection"]))
            rows = [
                ("Abuse Confidence Score", abuse.get("abuse_confidence_score", "—")),
                ("Is Tor Exit Node",       abuse.get("is_tor", "—")),
                ("Total Reports",          abuse.get("total_reports", "—")),
            ]
            t = _kv_table(rows, s)
            if t:
                story.append(t)
        if isinstance(otx, dict) and otx and "error" not in otx:
            story.append(Paragraph("AlienVault OTX", s["subsection"]))
            rows = [
                ("Pulse Count",      otx.get("pulse_count", 0)),
                ("Malware Families", ", ".join(otx.get("malware_families", [])) or "—"),
                ("Adversaries",      ", ".join(otx.get("adversaries", [])) or "—"),
            ]
            t = _kv_table(rows, s)
            if t:
                story.append(t)
        if isinstance(urlscan, dict) and urlscan and "error" not in urlscan:
            story.append(Paragraph("URLScan.io", s["subsection"]))
            rows = [
                ("Verdict", urlscan.get("verdict", "—")),
                ("Score",   urlscan.get("score", "—")),
            ]
            t = _kv_table(rows, s)
            if t:
                story.append(t)

    # ── Dark Web / Paste Monitor
    dark  = data.get("dark") or {}
    paste = data.get("paste_monitor") or {}
    if (isinstance(dark, dict) and dark.get("flagged")) or \
       (isinstance(paste, dict) and paste.get("mentions")):
        story.append(Paragraph("Dark Web & Paste Monitor", s["section"]))
        if isinstance(dark, dict) and dark.get("flagged"):
            story.append(Paragraph(
                f"<font color='{C['critical'].hexval()}'><b>⚠ Dark web mentions flagged.</b></font>",
                s["body"]))
            for f in (dark.get("findings") or [])[:10]:
                if isinstance(f, dict):
                    label = f.get("malware") or f.get("threat_type") or f.get("threat") or "Finding"
                    story.append(Paragraph(f"• {_safe(label)}", s["body"]))
        if isinstance(paste, dict) and paste.get("mentions"):
            story.append(Paragraph("Paste Site Mentions", s["subsection"]))
            for m in paste["mentions"][:10]:
                if isinstance(m, dict):
                    story.append(Paragraph(
                        f"• [{_safe(m.get('severity', 'medium')).upper()}] "
                        f"{_safe(m.get('source', '?'))} — {_safe(m.get('snippet', ''))}",
                        s["body"]))

    # ── Related Entities
    related = data.get("related_entities")
    if isinstance(related, dict) and related and "error" not in related:
        story.append(Paragraph("Related Entities", s["section"]))
        for key in ("emails", "domains", "usernames"):
            vals = related.get(key) or []
            if vals:
                story.append(Paragraph(key.title(), s["subsection"]))
                story.append(Paragraph(", ".join(str(v) for v in vals[:25]), s["body"]))
        prior_cases = related.get("cases") or []
        if prior_cases:
            story.append(Paragraph("Previous Cases on This Target", s["subsection"]))
            for c in prior_cases[:10]:
                if isinstance(c, dict):
                    story.append(Paragraph(f"• Case #{c.get('id')}: {_safe(c.get('title'))} "
                                           f"({_safe(c.get('status'))})", s["body"]))

    # ── Username Search
    username_val = data.get("username")
    if username_val:
        story.append(Paragraph("Username Search", s["section"]))
        if isinstance(username_val, list) and username_val:
            rows = []
            for i, site in enumerate(username_val):
                if isinstance(site, dict):
                    label = f"{site.get('name', '?')} ({site.get('category', '—')})"
                    rows.append((f"#{i+1}", f"{label} — {site.get('url', '')}"))
                else:
                    rows.append((f"#{i+1}", site))
        else:
            rows = [("Result", _safe(username_val))]
        t = _kv_table(rows, s)
        if t:
            story.append(t)

    # ── Open Ports
    ports = data.get("port_scan")
    if isinstance(ports, dict):
        ports = ports.get("open_ports") or ports.get("ports")
    if ports:
        story.append(Paragraph(f"Open Ports  ({len(ports)} found)", s["section"]))
        rows = [
            (str(p.get("port", "—")), _safe(p.get("service")), _safe(p.get("state")))
            for p in ports if isinstance(p, dict)
        ]
        if rows:
            story.append(_generic_rows_table(
                ["Port", "Service", "State"], rows,
                [3 * cm, 9 * cm, 4 * cm], s,
            ))

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
    if isinstance(val, bool):
        return "Yes" if val else "No"
    if isinstance(val, list):
        return ", ".join(str(v) for v in val) if val else "—"
    if isinstance(val, dict):
        return "; ".join(f"{k}: {v}" for k, v in val.items()) if val else "—"
    return str(val) or "—"
