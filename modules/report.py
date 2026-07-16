"""
report.py — PDF export for the OSINT Investigation Platform.

Two entry points:
  export_report(data, path)            — single scan result → PDF
  export_historical_pdf(report, path)  — dashboard report dict → PDF
                                         (bridges report_dashboard.build_historical_report())

Usage
-----
    from report import export_report, export_historical_pdf
    from report_dashboard import build_historical_report

    # Single scan
    export_report(scan_data, "/tmp/scan.pdf")

    # Historical dashboard report
    report = build_historical_report(days=30)
    export_historical_pdf(report, "/tmp/history.pdf")
"""

from __future__ import annotations

import os
from datetime import datetime

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
# Shared helpers
# ─────────────────────────────────────────────

def _safe_str(value) -> str:
    """Convert any value to a clean string for the PDF."""
    if value is None:
        return "N/A"
    if isinstance(value, list):
        return "\n".join(str(v) for v in value) if value else "None found"
    if isinstance(value, dict):
        return "\n".join(f"{k}: {v}" for k, v in value.items())
    return str(value)


def _make_styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle", parent=base["Title"],
            fontSize=22, textColor=colors.HexColor("#1a1a2e"),
            spaceAfter=6, alignment=TA_CENTER,
        ),
        "subtitle": ParagraphStyle(
            "ReportSubtitle", parent=base["Normal"],
            fontSize=10, textColor=colors.HexColor("#666666"),
            spaceAfter=20, alignment=TA_CENTER,
        ),
        "section": ParagraphStyle(
            "SectionHeading", parent=base["Heading2"],
            fontSize=13, textColor=colors.HexColor("#16213e"),
            spaceBefore=16, spaceAfter=6, borderPad=4,
        ),
        "subsection": ParagraphStyle(
            "SubSectionHeading", parent=base["Heading3"],
            fontSize=11, textColor=colors.HexColor("#16213e"),
            spaceBefore=10, spaceAfter=4,
        ),
        "body": ParagraphStyle(
            "BodyText", parent=base["Normal"],
            fontSize=9, textColor=colors.HexColor("#333333"),
            spaceAfter=4, leading=14,
        ),
    }


def _kv_table(rows: list[tuple]) -> Table:
    """Create a two-column key/value table."""
    base = getSampleStyleSheet()
    data = [
        [
            Paragraph(f"<b>{k}</b>", base["Normal"]),
            Paragraph(_safe_str(v),   base["Normal"]),
        ]
        for k, v in rows
    ]
    table = Table(data, colWidths=[4.5 * cm, 12 * cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f4ff")),
        ("TEXTCOLOR",  (0, 0), (-1, -1), colors.HexColor("#222222")),
        ("FONTSIZE",   (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1),
         [colors.HexColor("#ffffff"), colors.HexColor("#f8f9ff")]),
        ("GRID",    (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("VALIGN",  (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def _wide_table(headers: list[str], rows: list[list]) -> Table:
    """Multi-column table for list data (recent scans, top targets, etc.)."""
    base  = getSampleStyleSheet()
    head  = [Paragraph(f"<b>{h}</b>", base["Normal"]) for h in headers]
    data  = [head] + [
        [Paragraph(_safe_str(cell), base["Normal"]) for cell in row]
        for row in rows
    ]
    col_w = (16.5 * cm) / len(headers)
    table = Table(data, colWidths=[col_w] * len(headers))
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#16213e")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1),
         [colors.HexColor("#ffffff"), colors.HexColor("#f8f9ff")]),
        ("GRID",    (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("VALIGN",  (0, 0), (-1, -1), "TOP"),
        ("PADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def _doc(output_path: str) -> SimpleDocTemplate:
    os.makedirs(
        os.path.dirname(output_path) if os.path.dirname(output_path) else ".",
        exist_ok=True,
    )
    return SimpleDocTemplate(
        output_path, pagesize=A4,
        leftMargin=2 * cm, rightMargin=2 * cm,
        topMargin=2 * cm,  bottomMargin=2 * cm,
    )


def _footer(styles: dict) -> list:
    return [
        Spacer(1, 20),
        HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cccccc")),
        Spacer(1, 6),
        Paragraph(
            "This report was generated automatically by the OSINT Investigation Platform. "
            "Data accuracy depends on third-party APIs and public sources.",
            styles["body"],
        ),
    ]


# ─────────────────────────────────────────────
# Entry point 1 — single scan
# ─────────────────────────────────────────────

def export_report(data: dict, output_path: str = "report.pdf") -> str:
    """
    Generate a PDF OSINT report from a single scan result dict.

    Args:
        data:        Result dict from run_scan() in app.py
        output_path: Where to save the PDF

    Returns:
        output_path on success
    """
    styles    = _make_styles()
    story     = []
    target    = data.get("target", "Unknown")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    story.append(Paragraph("OSINT Investigation Report", styles["title"]))
    story.append(Paragraph(
        f"Target: {target}  |  Generated: {timestamp}", styles["subtitle"]
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#16213e")))
    story.append(Spacer(1, 12))

    # Username
    story.append(Paragraph("Username Search", styles["section"]))
    uval = data.get("username", "No data")
    rows = ([(site, "Found") for site in uval] or [("Result", "None found")]
            if isinstance(uval, list) else [("Result", uval)])
    story.append(_kv_table(rows))

    # WHOIS
    story.append(Paragraph("WHOIS Lookup", styles["section"]))
    wval = data.get("whois", {})
    rows = list(wval.items()) if isinstance(wval, dict) and wval else [("Result", _safe_str(wval))]
    story.append(_kv_table(rows))

    # Subdomains
    story.append(Paragraph("Subdomains", styles["section"]))
    subs = data.get("subs", [])
    rows = ([(f"#{i+1}", s) for i, s in enumerate(subs)]
            if isinstance(subs, list) and subs else [("Result", _safe_str(subs))])
    story.append(_kv_table(rows))

    # IP & Geo
    story.append(Paragraph("IP & Geolocation", styles["section"]))
    geo  = data.get("geo", {})
    rows = [("IP Address", data.get("ip", "N/A"))]
    rows += list(geo.items()) if isinstance(geo, dict) else [("Location", _safe_str(geo))]
    story.append(_kv_table(rows))

    # Breach
    story.append(Paragraph("Breach Check", styles["section"]))
    bval = data.get("breach", "No data")
    rows = ([(f"Breach #{i+1}", b) for i, b in enumerate(bval)]
            if isinstance(bval, list) and bval else [("Result", _safe_str(bval))])
    story.append(_kv_table(rows))

    # ── Phone Intelligence ──────────────────────────────────────────────
    phone = data.get("phone")
    if isinstance(phone, dict) and not phone.get("error"):
        story.append(Paragraph("Phone Intelligence", styles["section"]))
        rows = [
            ("Valid",          "Yes" if phone.get("valid") else "No"),
            ("International",  phone.get("international", "—")),
            ("E.164",          phone.get("e164", "—")),
            ("National",       phone.get("national", "—")),
            ("Country",        phone.get("country_name", "—")),
            ("Region",         phone.get("region", "—") or "—"),
            ("Carrier",        phone.get("carrier_name", "—") or "—"),
            ("Line Type",      phone.get("line_type", "unknown")),
            ("Timezone",       (phone.get("timezones") or ["—"])[0]),
            ("Confidence",     f"{phone.get('confidence', 0)}% ({phone.get('confidence_label', 'LOW')})"),
        ]
        story.append(_kv_table(rows))

        risk = phone.get("risk")
        if isinstance(risk, dict):
            story.append(Paragraph("Phone Risk Assessment", styles["subsection"]))
            rows = [
                ("Risk Level", risk.get("level", "—")),
                ("Risk Score", f"{risk.get('score', 0)}/100"),
                ("Reasons",    risk.get("reasons", [])),
            ]
            story.append(_kv_table(rows))

        whatsapp = phone.get("whatsapp")
        if isinstance(whatsapp, dict) and whatsapp.get("checked"):
            story.append(Paragraph("WhatsApp Presence", styles["subsection"]))
            reg = whatsapp.get("registered")
            reg_str = "Registered" if reg is True else "Not registered" if reg is False else "Undetermined"
            story.append(_kv_table([
                ("Status", reg_str),
                ("Method", whatsapp.get("method", "—")),
                ("Note",   whatsapp.get("note", "—")),
            ]))

        spam = phone.get("spam")
        if isinstance(spam, dict):
            story.append(Paragraph("Spam Reputation", styles["subsection"]))
            story.append(_kv_table([
                ("Available", "Yes" if spam.get("available") else "No"),
                ("Reports",   spam.get("reports", 0)),
                ("Note",      spam.get("note", "—")),
            ]))

        business = phone.get("business")
        if isinstance(business, dict):
            story.append(Paragraph("Business Directory", styles["subsection"]))
            story.append(_kv_table([
                ("Available", "Yes" if business.get("available") else "No"),
                ("Name",      business.get("name") or "—"),
                ("Note",      business.get("note", "—")),
            ]))

        corr = phone.get("correlation")
        if isinstance(corr, dict):
            story.append(Paragraph("Cross-Correlation", styles["subsection"]))
            rows = [
                ("Confidence", f"{corr.get('confidence', 0)}% ({corr.get('confidence_label', 'LOW')})"),
            ]
            unames = corr.get("usernames") or []
            if unames:
                rows.append(("Usernames Found", [
                    (u.get("name") if isinstance(u, dict) else u) for u in unames
                ]))
            leaks = corr.get("leaks") or []
            if leaks:
                rows.append(("Leaks Found", [
                    (l.get("breach_name") or l.get("name") if isinstance(l, dict) else l) for l in leaks
                ]))
            story.append(_kv_table(rows))
    elif isinstance(phone, dict) and phone.get("error"):
        story.append(Paragraph("Phone Intelligence", styles["section"]))
        story.append(_kv_table([("Error", phone.get("error"))]))

    # ── Risk Score ──────────────────────────────────────────────────────
    risk_score = data.get("risk_score")
    if isinstance(risk_score, dict) and not risk_score.get("error"):
        story.append(Paragraph("Risk Score", styles["section"]))
        rows = [
            ("Total Score", f"{risk_score.get('total_score', 0)}/100"),
            ("Risk Level",  risk_score.get("risk_level", "Low")),
        ]
        story.append(_kv_table(rows))
        factors = risk_score.get("factors", [])
        if factors:
            story.append(Paragraph("Risk Factors", styles["subsection"]))
            story.append(_wide_table(
                ["Factor", "Severity", "Points", "Category"],
                [[f.get("name", "?"), f.get("severity", "?"), f.get("score", 0), f.get("category", "")]
                 for f in factors],
            ))
        recs = risk_score.get("recommendations", [])
        if recs:
            story.append(Paragraph("Recommendations", styles["subsection"]))
            story.append(_kv_table([(f"#{i+1}", r) for i, r in enumerate(recs)]))

    # ── Identity Confidence Score ───────────────────────────────────────
    identity = data.get("identity_score")
    if isinstance(identity, dict) and not identity.get("error"):
        story.append(Paragraph("Identity Confidence Score", styles["section"]))
        rows = [
            ("Total",      f"{identity.get('total', 0)}/100"),
            ("Confidence", identity.get("confidence", "MINIMAL")),
        ]
        story.append(_kv_table(rows))
        breakdown = identity.get("breakdown", [])
        if breakdown:
            story.append(Paragraph("Signal Breakdown", styles["subsection"]))
            story.append(_wide_table(
                ["Signal", "Category", "Points"],
                [[b.get("label", "?"), b.get("category", "?"), b.get("points", 0)] for b in breakdown],
            ))

    # ── Investigation Timeline ───────────────────────────────────────────
    timeline = data.get("timeline")
    if isinstance(timeline, dict) and not timeline.get("error") and timeline.get("total_events", 0) > 0:
        story.append(Paragraph("Investigation Timeline", styles["section"]))
        events = timeline.get("events", [])
        story.append(_wide_table(
            ["Date", "Type", "Detail", "Severity"],
            [[e.get("date", "?"), e.get("event_type", "?"), e.get("detail", "") or "",
              e.get("severity", "info")] for e in events[:40]],
        ))

    # ── DNS / SSL (domain scans) ─────────────────────────────────────────
    dns = data.get("dns")
    if isinstance(dns, dict) and not dns.get("error"):
        rows = []
        if dns.get("a"):    rows.append(("A Records",    dns.get("a")))
        if dns.get("aaaa"): rows.append(("AAAA Records", dns.get("aaaa")))
        if dns.get("mx"):
            rows.append(("MX Records", [m.get("host", str(m)) if isinstance(m, dict) else m for m in dns.get("mx")]))
        if dns.get("ns"):   rows.append(("NS Records", dns.get("ns")))
        if rows:
            story.append(Paragraph("DNS Records", styles["section"]))
            story.append(_kv_table(rows))

    ssl = data.get("ssl")
    if isinstance(ssl, dict) and not ssl.get("error"):
        story.append(Paragraph("SSL Certificate", styles["section"]))
        story.append(_kv_table([
            ("Subject",    ssl.get("subject_cn", "—")),
            ("Issuer",     ssl.get("issuer_cn", "—")),
            ("Valid From", ssl.get("not_before", "—")),
            ("Expires",    ssl.get("not_after", "—")),
            ("Expired",    "Yes" if ssl.get("expired") else "No"),
        ]))

    # ── Threat Monitoring ────────────────────────────────────────────────
    dark = data.get("dark")
    if isinstance(dark, dict) and dark:
        story.append(Paragraph("Threat Monitoring", styles["section"]))
        story.append(_kv_table([
            ("Flagged",      "Yes" if dark.get("flagged") else "No"),
            ("Threat Score", f"{dark.get('threat_score', 0)}/100"),
        ]))

    story.extend(_footer(styles))
    _doc(output_path).build(story)
    return output_path


# ─────────────────────────────────────────────
# Entry point 2 — historical dashboard report
# ─────────────────────────────────────────────

def export_historical_pdf(
    report: dict | None = None,
    output_path: str = "historical_report.pdf",
    *,
    days: int = 30,
) -> str:
    """
    Generate a PDF from the structured dict returned by
    report_dashboard.build_historical_report().

    Args:
        report:      Dict from build_historical_report(). If None, it is
                     called automatically with *days*.
        output_path: Where to save the PDF.
        days:        Only used when *report* is None.

    Returns:
        output_path on success.

    Example:
        from report_dashboard import build_historical_report
        from report import export_historical_pdf

        pdf = export_historical_pdf(build_historical_report(30), "/tmp/history.pdf")
    """
    if report is None:
        from report_dashboard import build_historical_report
        report = build_historical_report(days)

    styles    = _make_styles()
    story     = []
    generated = report.get("generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))
    period    = report.get("period", f"Last {days} days")

    # ── Title ────────────────────────────────────────────────────────────────
    story.append(Paragraph("OSINT Platform — Historical Report", styles["title"]))
    story.append(Paragraph(f"{period}  |  Generated: {generated}", styles["subtitle"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#16213e")))
    story.append(Spacer(1, 12))

    # ── Overview stats ────────────────────────────────────────────────────────
    overview = report.get("overview", {})
    if overview:
        story.append(Paragraph("Overview Statistics", styles["section"]))
        story.append(_kv_table([
            ("Total Scans",         overview.get("total_scans", 0)),
            ("Flagged Scans",       overview.get("flagged_scans", 0)),
            ("Scans Today",         overview.get("scans_today", 0)),
            ("Scans This Week",     overview.get("scans_this_week", 0)),
            ("Scans This Month",    overview.get("scans_this_month", 0)),
            ("Unique Targets",      overview.get("unique_targets", 0)),
            ("Total Cases",         overview.get("total_cases", 0)),
            ("Open Cases",          overview.get("open_cases", 0)),
            ("Scheduled Targets",   overview.get("scheduled_targets", 0)),
            ("Alerts Sent",         overview.get("alerts_sent", 0)),
            ("Alerts Failed",       overview.get("alerts_failed", 0)),
        ]))

    # ── Top targets ───────────────────────────────────────────────────────────
    top = report.get("top_targets", [])
    if top:
        story.append(Paragraph("Top Scanned Targets", styles["section"]))
        story.append(_wide_table(
            ["Target", "Scan Count", "Ever Flagged"],
            [[t["target"], t["count"], "Yes" if t.get("flagged") else "No"] for t in top],
        ))

    # ── Recent scans ──────────────────────────────────────────────────────────
    recent = report.get("recent_scans", [])
    if recent:
        story.append(Paragraph("Recent Scans", styles["section"]))
        story.append(_wide_table(
            ["ID", "Target", "Type", "Flagged", "Scanned At"],
            [[s["id"], s["target"], s.get("scan_type", "full"),
              "Yes" if s.get("flagged") else "No", s.get("scanned_at", "")]
             for s in recent],
        ))

    # ── Scan type distribution ────────────────────────────────────────────────
    dist = report.get("scan_type_distribution", {})
    if dist:
        story.append(Paragraph("Scan Type Distribution", styles["section"]))
        story.append(_kv_table(list(dist.items())))

    # ── Case stats ────────────────────────────────────────────────────────────
    cases = report.get("case_stats", {})
    if cases:
        story.append(Paragraph("Case Statistics", styles["section"]))
        rows = [("Total Cases", cases.get("total", 0))]
        rows += [(f"Status: {k}", v) for k, v in cases.get("by_status", {}).items()]
        rows += [(f"Priority: {k}", v) for k, v in cases.get("by_priority", {}).items()]
        story.append(_kv_table(rows))

    # ── Alert stats ───────────────────────────────────────────────────────────
    alerts = report.get("alert_stats", {})
    if alerts:
        story.append(Paragraph("Alert Statistics", styles["section"]))
        rows = [
            ("Total Alerts",      alerts.get("total", 0)),
            ("Successful",        alerts.get("successful", 0)),
            ("Failed",            alerts.get("failed", 0)),
        ]
        rows += [(f"Type: {k}", v) for k, v in alerts.get("by_type", {}).items()]
        rows += [(f"Severity: {k}", v) for k, v in alerts.get("by_severity", {}).items()]
        story.append(_kv_table(rows))

    # ── Recent alerts ─────────────────────────────────────────────────────────
    recent_alerts = report.get("recent_alerts", [])
    if recent_alerts:
        story.append(Paragraph("Recent Alerts", styles["section"]))
        story.append(_wide_table(
            ["ID", "Target", "Type", "Severity", "Success", "Sent At"],
            [[a["id"], a["target"], a.get("alert_type", ""),
              a.get("severity", ""), "Yes" if a.get("success") else "No",
              a.get("sent_at", "")]
             for a in recent_alerts],
        ))

    # ── Scheduled targets ─────────────────────────────────────────────────────
    scheduled = report.get("scheduled_overview", [])
    if scheduled:
        story.append(Paragraph("Scheduled Targets", styles["section"]))
        story.append(_wide_table(
            ["Target", "Frequency", "Last Run", "Changes", "Run Count"],
            [[t["target"], t.get("frequency", ""), t.get("last_run", "Never"),
              "Yes" if t.get("change_detected") else "No", t.get("run_count", 0)]
             for t in scheduled],
        ))

    story.extend(_footer(styles))
    _doc(output_path).build(story)
    return output_path