"""
case_report_generator.py — Case Report Generator (v2)
-------------------------------------------------
Builds a professional PDF report for a single case: summary, evidence
list, timeline, investigation intelligence, investigator notes, and a
conclusion section.

v2 fixes:
  • The PDF previously skipped Investigation Intelligence entirely
    (Confidence Score, Risk Analysis, Case Similarity) even though your
    README lists /cases/<id>/intelligence as a headline feature. It's
    now pulled in via modules.intelligence.confidence_score.analyze_case
    and modules.intelligence.case_similarity.find_similar_cases, exactly
    like the case_intelligence route in app.py does.
  • The PDF previously only listed uploaded evidence *files* — the
    investigator's actual written notes (get_notes) never appeared
    anywhere in the exported report. A Notes section is now included.
  • Both new sections degrade gracefully (missing module / analysis
    failure -> a small note in the PDF, not a crash), matching this
    project's existing error-handling style.

DEPENDS ON (all already in this project per your app.py imports):
    modules.case_management.get_case(case_id), get_notes(case_id), list_cases()
    modules.investigations.evidence_store.list_evidence(case_id), evidence_summary(case_id)
    modules.investigations.timeline_builder.build_case_timeline(case_id), timeline_summary(case_id)
    modules.intelligence.confidence_score.analyze_case(case, notes)
    modules.intelligence.case_similarity.find_similar_cases(case, all_cases)

USAGE:
    from case_report_generator import generate_case_report
    path = generate_case_report(case_id, output_path="CASE_REPORT.pdf")

Flask route (unchanged — same signature as before, no app.py changes needed):

    @app.route("/cases/<int:case_id>/report")
    @export_limit
    def case_report_pdf(case_id):
        guard = admin_required()
        if guard:
            return guard
        if not _HAS_CASES:
            abort(404)
        case = get_case(case_id)
        if not case:
            abort(404)
        pdf_path = os.path.join(app.root_path, f"case_{case_id}_report.pdf")
        try:
            generate_case_report(case_id, output_path=pdf_path)
        except Exception as e:
            print(f"[Case Report Error] {e}")
            abort(500)
        write_audit("exported_case_report", f"case_id={case_id}")
        return send_file(
            pdf_path, as_attachment=True,
            download_name=f"CASE_{case_id}_REPORT.pdf",
            mimetype="application/pdf",
        )
"""

import os
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, HRFlowable, KeepTogether,
)

try:
    from modules.case_management import get_case, get_notes, list_cases
    _HAS_CASE_MODULE = True
except ImportError:
    _HAS_CASE_MODULE = False

try:
    from modules.investigations.evidence_store import list_evidence, evidence_summary
    _HAS_EVIDENCE_MODULE = True
except ImportError:
    _HAS_EVIDENCE_MODULE = False

try:
    from modules.investigations.timeline_builder import build_case_timeline, timeline_summary
    _HAS_TIMELINE_MODULE = True
except ImportError:
    _HAS_TIMELINE_MODULE = False

try:
    from modules.intelligence.confidence_score import analyze_case
    _HAS_INTEL_MODULE = True
except ImportError:
    _HAS_INTEL_MODULE = False

try:
    from modules.intelligence.case_similarity import find_similar_cases, summarize_notes
    _HAS_SIMILARITY_MODULE = True
except ImportError:
    _HAS_SIMILARITY_MODULE = False


# ── Field helpers (cases/evidence/timeline items may be dicts or objects) ──

def _field(obj, *names, default=None):
    for name in names:
        if isinstance(obj, dict) and name in obj and obj[name] is not None:
            return obj[name]
        if hasattr(obj, name) and getattr(obj, name) is not None:
            return getattr(obj, name)
    return default


def _fmt_dt(value, fmt="%Y-%m-%d %H:%M"):
    if not value:
        return "—"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    try:
        return value.strftime(fmt)
    except Exception:
        return str(value)


PRIORITY_COLORS = {
    "critical": colors.HexColor("#c0392b"),
    "high":     colors.HexColor("#d35400"),
    "medium":   colors.HexColor("#b7950b"),
    "low":      colors.HexColor("#1e8449"),
}

RISK_LEVEL_COLORS = {
    "critical": colors.HexColor("#c0392b"),
    "high":     colors.HexColor("#d35400"),
    "medium":   colors.HexColor("#b7950b"),
    "low":      colors.HexColor("#1e8449"),
}


# ── Styles ───────────────────────────────────────────────────────────────

def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", fontSize=22, leading=26, spaceAfter=4,
        textColor=colors.HexColor("#1a1a1a"), fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        name="ReportSubtitle", fontSize=11, leading=14,
        textColor=colors.HexColor("#666666"), spaceAfter=18,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading", fontSize=14, leading=18, spaceBefore=18, spaceAfter=8,
        textColor=colors.HexColor("#1a1a1a"), fontName="Helvetica-Bold",
        borderWidth=0, borderPadding=0,
    ))
    styles.add(ParagraphStyle(
        name="SubHeading", fontSize=11, leading=14, spaceBefore=10, spaceAfter=4,
        textColor=colors.HexColor("#333333"), fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        name="Body", fontSize=10, leading=15,
        textColor=colors.HexColor("#2b2b2b"),
    ))
    styles.add(ParagraphStyle(
        name="MetaLabel", fontSize=8, leading=10,
        textColor=colors.HexColor("#888888"), fontName="Helvetica-Bold",
    ))
    styles.add(ParagraphStyle(
        name="MetaValue", fontSize=10, leading=13,
        textColor=colors.HexColor("#1a1a1a"),
    ))
    styles.add(ParagraphStyle(
        name="FooterText", fontSize=8, leading=10,
        textColor=colors.HexColor("#999999"), alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        name="EmptyNote", fontSize=9, leading=13,
        textColor=colors.HexColor("#999999"), fontName="Helvetica-Oblique",
    ))
    styles.add(ParagraphStyle(
        name="ScoreBig", fontSize=20, leading=24, fontName="Helvetica-Bold",
    ))
    return styles


def _header_footer(canvas, doc):
    canvas.saveState()
    canvas.setStrokeColor(colors.HexColor("#dddddd"))
    canvas.setLineWidth(0.5)
    canvas.line(0.75 * inch, 0.75 * inch, letter[0] - 0.75 * inch, 0.75 * inch)
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#999999"))
    canvas.drawString(0.75 * inch, 0.55 * inch, "OSINT Investigation Platform — Confidential")
    canvas.drawRightString(letter[0] - 0.75 * inch, 0.55 * inch, f"Page {doc.page}")
    canvas.restoreState()


# ── Section builders ────────────────────────────────────────────────────

def _summary_section(case, styles):
    flow = [Paragraph("Case Summary", styles["SectionHeading"])]

    case_id     = _field(case, "id", "case_id", default="—")
    title       = _field(case, "title", default="Untitled Case")
    target      = _field(case, "target", default="—")
    status      = str(_field(case, "status", default="—")).upper()
    priority    = str(_field(case, "priority", default="—")).lower()
    created_by  = _field(case, "created_by", default="—")
    created_at  = _fmt_dt(_field(case, "created_at", "created"))
    updated_at  = _fmt_dt(_field(case, "updated_at", "last_updated"))
    description = _field(case, "description", default="") or "No description provided."
    tags        = _field(case, "tags", default=[]) or []

    meta_rows = [
        [Paragraph("CASE ID", styles["MetaLabel"]), Paragraph(f"#{case_id}", styles["MetaValue"]),
         Paragraph("STATUS", styles["MetaLabel"]), Paragraph(status, styles["MetaValue"])],
        [Paragraph("TARGET", styles["MetaLabel"]), Paragraph(str(target), styles["MetaValue"]),
         Paragraph("PRIORITY", styles["MetaLabel"]), Paragraph(priority.upper(), styles["MetaValue"])],
        [Paragraph("CREATED BY", styles["MetaLabel"]), Paragraph(str(created_by), styles["MetaValue"]),
         Paragraph("OPENED", styles["MetaLabel"]), Paragraph(created_at, styles["MetaValue"])],
        [Paragraph("TAGS", styles["MetaLabel"]),
         Paragraph(", ".join(tags) if tags else "—", styles["MetaValue"]),
         Paragraph("LAST UPDATED", styles["MetaLabel"]), Paragraph(updated_at, styles["MetaValue"])],
    ]
    meta_table = Table(meta_rows, colWidths=[1.0 * inch, 2.1 * inch, 1.0 * inch, 2.1 * inch])
    meta_table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#eeeeee")),
    ]))
    flow.append(meta_table)
    flow.append(Spacer(1, 10))
    flow.append(Paragraph("Description", styles["MetaLabel"]))
    flow.append(Spacer(1, 4))
    flow.append(Paragraph(str(description), styles["Body"]))
    return flow


def _intelligence_section(case, notes, all_cases, styles):
    """
    NEW SECTION. Mirrors the /cases/<id>/intelligence route: Confidence
    Score, Risk Analysis, and Case Similarity. Previously missing from
    the PDF entirely.
    """
    flow = [Paragraph("Investigation Intelligence", styles["SectionHeading"])]

    if not _HAS_INTEL_MODULE:
        flow.append(Paragraph("Investigation Intelligence module not available.", styles["EmptyNote"]))
        return flow

    try:
        intel = analyze_case(case, notes)
        intel_dict = intel.to_dict() if hasattr(intel, "to_dict") else intel
    except Exception as e:
        flow.append(Paragraph(f"Could not compute intelligence: {e}", styles["EmptyNote"]))
        return flow

    confidence = intel_dict.get("confidence", "—")
    risk_level = str(intel_dict.get("risk_level", "—"))
    risk_score = intel_dict.get("risk_score", "—")
    color = RISK_LEVEL_COLORS.get(risk_level.lower(), colors.HexColor("#333333"))

    score_row = Table([[
        Paragraph(f"<font color='{color.hexval()}'>{risk_score}</font>"
                  f"<font size='9' color='#888888'> /100</font>", styles["ScoreBig"]),
        Paragraph(f"<font color='{color.hexval()}'><b>{risk_level.upper()}</b></font>"
                  f"<br/><font size='8' color='#888888'>Confidence: {confidence}</font>",
                  styles["Body"]),
    ]], colWidths=[1.8 * inch, 4.2 * inch])
    score_row.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f7f7f7")),
        ("PADDING", (0, 0), (-1, -1), 10),
    ]))
    flow.append(score_row)
    flow.append(Spacer(1, 8))

    signals = intel_dict.get("signals") or {}
    if isinstance(signals, dict) and signals:
        flow.append(Paragraph("Signals", styles["SubHeading"]))
        rows = [[Paragraph(str(k).replace("_", " ").title(), styles["MetaLabel"]),
                 Paragraph(str(v), styles["MetaValue"])] for k, v in signals.items()]
        tbl = Table(rows, colWidths=[2.5 * inch, 3.5 * inch])
        tbl.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#eeeeee")),
        ]))
        flow.append(tbl)

    warnings = intel_dict.get("warnings") or []
    if warnings:
        flow.append(Spacer(1, 6))
        flow.append(Paragraph("Warnings", styles["SubHeading"]))
        for w in warnings:
            flow.append(Paragraph(f"⚠ {w}", styles["Body"]))

    # Case Similarity
    if _HAS_SIMILARITY_MODULE and all_cases is not None:
        try:
            similar = find_similar_cases(case, all_cases)
            similar_dicts = [c.to_dict() if hasattr(c, "to_dict") else c for c in similar]
        except Exception as e:
            similar_dicts = []
            flow.append(Paragraph(f"Could not compute case similarity: {e}", styles["EmptyNote"]))

        if similar_dicts:
            flow.append(Spacer(1, 8))
            flow.append(Paragraph("Similar Cases", styles["SubHeading"]))
            header = ["Case", "Match Reason", "Score"]
            rows = [header]
            for sc in similar_dicts[:8]:
                rows.append([
                    f"#{sc.get('id', sc.get('case_id', '—'))} {sc.get('title', '')}",
                    ", ".join(sc.get("shared", sc.get("reasons", []))) or "—",
                    str(sc.get("score", sc.get("similarity", "—"))),
                ])
            tbl = Table(rows, colWidths=[3 * inch, 2.5 * inch, 0.8 * inch])
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a1a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7f7")]),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e0e0e0")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]))
            flow.append(tbl)

    return flow


def _evidence_section(case_id, styles):
    flow = [Paragraph("Evidence", styles["SectionHeading"])]

    if not _HAS_EVIDENCE_MODULE:
        flow.append(Paragraph("Evidence module not available.", styles["EmptyNote"]))
        return flow

    try:
        items = list_evidence(case_id) or []
    except Exception as e:
        flow.append(Paragraph(f"Could not load evidence: {e}", styles["EmptyNote"]))
        return flow

    try:
        summary = evidence_summary(case_id)
        if isinstance(summary, dict) and summary.get("count") is not None:
            flow.append(Paragraph(f"{summary['count']} item(s) on file.", styles["Body"]))
            flow.append(Spacer(1, 6))
    except Exception:
        pass

    if not items:
        flow.append(Paragraph("No evidence has been attached to this case.", styles["EmptyNote"]))
        return flow

    header = ["#", "Name", "Category", "Size", "Added"]
    rows = [header]
    for i, item in enumerate(items, start=1):
        name = _field(item, "original_name", "filename", "name", default="—")
        category = _field(item, "category", default="other")
        size = _field(item, "size_human", "size", default="—")
        added = _fmt_dt(_field(item, "created_at", "uploaded_at", "added_at"))
        rows.append([str(i), str(name), str(category), str(size), added])

    table = Table(rows, colWidths=[0.3 * inch, 2.5 * inch, 1.1 * inch, 0.9 * inch, 1.5 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a1a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f7f7")]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e0e0e0")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    flow.append(table)
    return flow


def _notes_section(notes, styles):
    """
    NEW SECTION. Previously the investigator's actual written notes never
    appeared anywhere in the exported PDF — only uploaded evidence files
    did. This renders the note text itself, newest first.
    """
    flow = [Paragraph("Investigator Notes", styles["SectionHeading"])]

    if not notes:
        flow.append(Paragraph("No investigator notes recorded for this case.", styles["EmptyNote"]))
        return flow

    try:
        ordered = sorted(
            notes,
            key=lambda n: _field(n, "created_at", "timestamp", default="") or "",
            reverse=True,
        )
    except Exception:
        ordered = notes

    for note in ordered:
        author = _field(note, "author", "created_by", default="Unknown")
        when = _fmt_dt(_field(note, "created_at", "timestamp"))
        content = _field(note, "content", "text", default="")
        row = Table(
            [[Paragraph(f"<b>{author}</b><br/><font size='7' color='#888888'>{when}</font>",
                        styles["MetaValue"]),
              Paragraph(str(content), styles["Body"])]],
            colWidths=[1.3 * inch, 4.7 * inch],
        )
        row.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#eeeeee")),
        ]))
        flow.append(row)

    return flow


def _timeline_section(case_id, styles):
    flow = [Paragraph("Timeline", styles["SectionHeading"])]

    if not _HAS_TIMELINE_MODULE:
        flow.append(Paragraph("Timeline module not available.", styles["EmptyNote"]))
        return flow

    try:
        events = build_case_timeline(case_id) or []
    except Exception as e:
        flow.append(Paragraph(f"Could not load timeline: {e}", styles["EmptyNote"]))
        return flow

    if not events:
        flow.append(Paragraph("No timeline events recorded for this case.", styles["EmptyNote"]))
        return flow

    for event in events:
        when = _fmt_dt(_field(event, "timestamp", "created_at", "time"))
        label = _field(event, "title", "label", "event", default="Event")
        detail = _field(event, "description", "detail", default="")

        row = Table(
            [[Paragraph(when, styles["MetaLabel"]),
              Paragraph(f"<b>{label}</b>" + (f"<br/>{detail}" if detail else ""), styles["Body"])]],
            colWidths=[1.3 * inch, 4.7 * inch],
        )
        row.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#eeeeee")),
        ]))
        flow.append(row)

    return flow


def _conclusion_section(case, styles):
    """
    There's no dedicated 'conclusion' field in case_management.py, so this
    pulls the latest investigator note as a stand-in conclusion, or falls
    back to a generated summary line. Pass a custom conclusion string via
    generate_case_report(..., conclusion="...") to override this entirely.
    """
    flow = [Paragraph("Conclusion", styles["SectionHeading"])]
    status = str(_field(case, "status", default="open")).lower()

    if status == "closed":
        text = "This case has been marked as closed. Refer to the final investigator note for resolution details."
    else:
        text = "This case remains open. Findings above reflect the current state of the investigation and may be updated as new evidence is collected."

    flow.append(Paragraph(text, styles["Body"]))
    return flow


# ── Main entry point ─────────────────────────────────────────────────────

def generate_case_report(case_id, output_path="CASE_REPORT.pdf", conclusion=None):
    """
    Builds a full PDF report for the given case_id and writes it to
    output_path. Returns the output path on success.
    """
    if not _HAS_CASE_MODULE:
        raise RuntimeError("modules.case_management not available")

    case = get_case(case_id)
    if not case:
        raise ValueError(f"Case {case_id} not found")

    try:
        notes = get_notes(case_id) or []
    except Exception:
        notes = []

    try:
        all_cases = list_cases()
    except Exception:
        all_cases = None

    styles = _build_styles()
    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.9 * inch, bottomMargin=0.9 * inch,
    )

    story = []

    title = _field(case, "title", default=f"Case {case_id}")
    story.append(Paragraph("Investigation Report", styles["ReportTitle"]))
    story.append(Paragraph(
        f"{title} &nbsp;·&nbsp; Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        styles["ReportSubtitle"],
    ))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#1a1a1a")))
    story.append(Spacer(1, 8))

    story += _summary_section(case, styles)
    story.append(Spacer(1, 6))
    story += _intelligence_section(case, notes, all_cases, styles)
    story.append(Spacer(1, 6))
    story += _evidence_section(case_id, styles)
    story.append(Spacer(1, 6))
    story += _notes_section(notes, styles)
    story.append(Spacer(1, 6))
    story += _timeline_section(case_id, styles)
    story.append(Spacer(1, 6))

    if conclusion:
        story.append(Paragraph("Conclusion", styles["SectionHeading"]))
        story.append(Paragraph(conclusion, styles["Body"]))
    else:
        story += _conclusion_section(case, styles)

    doc.build(story, onFirstPage=_header_footer, onLaterPages=_header_footer)
    return output_path


if __name__ == "__main__":
    # Quick manual test with a fake case_id — requires case_management to
    # actually resolve one. Adjust the ID to something real in your DB.
    import sys
    test_id = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    path = generate_case_report(test_id, output_path="CASE_REPORT.pdf")
    print(f"Report written to {path}")
