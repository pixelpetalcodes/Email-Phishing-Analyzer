from __future__ import annotations

from datetime import datetime
from html import escape
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from .models import EmailData, Finding, Verdict

AUTH_METHODS = ("spf", "dkim", "dmarc")


def auth_status(raw_result: str | None) -> str:
    """Map a reported authentication result to PASS, FAIL, or UNKNOWN."""
    value = (raw_result or "").strip().lower().split()[0:1]
    result = value[0] if value else ""
    if result == "pass":
        return "PASS"
    if result in {"fail", "softfail"}:
        return "FAIL"
    return "UNKNOWN"


def authentication_statuses(email: EmailData) -> dict[str, dict[str, str]]:
    statuses: dict[str, dict[str, str]] = {}
    for method in AUTH_METHODS:
        raw = email.auth_results.get(method, "")
        statuses[method] = {
            "status": auth_status(raw),
            "reported": raw or "No result reported",
        }
    return statuses


def _safe(value: object) -> str:
    return escape(str(value).encode("cp1252", "replace").decode("cp1252"))


def _paragraph(value: object, style: ParagraphStyle) -> Paragraph:
    return Paragraph(_safe(value).replace("\n", "<br/>"), style)


def build_pdf_report(
    source_name: str,
    email: EmailData,
    verdict: Verdict,
    findings: list[Finding],
    auth_results: dict[str, dict[str, str]] | None = None,
) -> bytes:
    """Create a compact printable report; email HTML is never rendered."""
    auth_results = auth_results or authentication_statuses(email)
    buffer = BytesIO()
    navy = colors.HexColor("#16253b")
    teal = colors.HexColor("#167c80")
    muted = colors.HexColor("#657286")
    line = colors.HexColor("#dce3e8")
    pale = colors.HexColor("#f3f7f8")
    status_colors = {
        "PASS": colors.HexColor("#24704a"),
        "FAIL": colors.HexColor("#a33e39"),
        "UNKNOWN": colors.HexColor("#946319"),
    }

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", parent=styles["Title"], fontName="Helvetica-Bold",
        fontSize=21, leading=25, textColor=navy, alignment=TA_LEFT,
        spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="Eyebrow", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=8, leading=11, textColor=teal, spaceAfter=7,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeading", parent=styles["Heading2"], fontName="Helvetica-Bold",
        fontSize=12, leading=15, textColor=navy, spaceBefore=14, spaceAfter=7,
    ))
    styles.add(ParagraphStyle(
        name="BodyCopy", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=9, leading=13, textColor=navy, spaceAfter=3,
    ))
    styles.add(ParagraphStyle(
        name="SmallCopy", parent=styles["BodyText"], fontName="Helvetica",
        fontSize=7.5, leading=10, textColor=muted,
    ))
    styles.add(ParagraphStyle(
        name="TableHeader", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=7.5, leading=10, textColor=colors.white,
    ))
    styles.add(ParagraphStyle(
        name="TableStrong", parent=styles["Normal"], fontName="Helvetica-Bold",
        fontSize=8.5, leading=11, textColor=navy,
    ))
    styles.add(ParagraphStyle(
        name="TableCopy", parent=styles["Normal"], fontName="Helvetica",
        fontSize=8, leading=11, textColor=navy,
    ))

    def draw_footer(canvas, doc) -> None:
        canvas.saveState()
        canvas.setStrokeColor(line)
        canvas.line(18 * mm, 15 * mm, A4[0] - 18 * mm, 15 * mm)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(muted)
        canvas.drawString(18 * mm, 10 * mm, "Email Phishing Analyzer · Links and attachments were not opened")
        canvas.drawRightString(A4[0] - 18 * mm, 10 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buffer, pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm,
        topMargin=17 * mm, bottomMargin=21 * mm,
        title="Email Phishing Analysis Report", author="Email Phishing Analyzer",
    )
    story = [
        _paragraph("EMAIL SECURITY · ANALYSIS REPORT", styles["Eyebrow"]),
        _paragraph("Email threat assessment", styles["ReportTitle"]),
        _paragraph(f"Generated {datetime.now().astimezone().strftime('%d %b %Y, %H:%M %Z')}", styles["SmallCopy"]),
        Spacer(1, 8),
    ]

    metadata = [
        [_paragraph("SOURCE FILE", styles["TableHeader"]), _paragraph("SUBJECT", styles["TableHeader"])],
        [_paragraph(source_name, styles["TableCopy"]), _paragraph(email.subject or "(no subject)", styles["TableCopy"])],
        [_paragraph("FROM", styles["TableHeader"]), _paragraph("TO · DATE", styles["TableHeader"])],
        [_paragraph(email.from_header or "(missing)", styles["TableCopy"]),
         _paragraph(" · ".join(v for v in (email.to, email.date) if v) or "(missing)", styles["TableCopy"])],
    ]
    metadata_table = Table(metadata, colWidths=[87 * mm, 87 * mm], hAlign="LEFT")
    metadata_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy), ("BACKGROUND", (0, 2), (-1, 2), navy),
        ("BACKGROUND", (0, 1), (-1, 1), pale), ("BACKGROUND", (0, 3), (-1, 3), pale),
        ("BOX", (0, 0), (-1, -1), 0.6, line), ("INNERGRID", (0, 0), (-1, -1), 0.35, line),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.extend([metadata_table, _paragraph("Verdict", styles["SectionHeading"])])

    verdict_label = verdict.verdict.upper()
    verdict_color = {
        "SAFE": colors.HexColor("#347255"),
        "SUSPICIOUS": colors.HexColor("#946319"),
        "PHISHING": colors.HexColor("#a33e39"),
    }.get(verdict_label, muted)
    verdict_box = Table([
        [_paragraph(verdict_label, ParagraphStyle(
            "VerdictLabel", parent=styles["TableStrong"], textColor=verdict_color,
            fontSize=12, leading=15,
        )), _paragraph(f"Risk score: {verdict.risk_score}/100", styles["TableStrong"])],
        [_paragraph(verdict.summary, styles["BodyCopy"]), ""],
    ], colWidths=[89 * mm, 85 * mm], hAlign="LEFT")
    verdict_box.setStyle(TableStyle([
        ("SPAN", (0, 1), (1, 1)), ("BACKGROUND", (0, 0), (-1, -1), pale),
        ("BOX", (0, 0), (-1, -1), 0.7, line), ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 9), ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.extend([verdict_box, _paragraph("Authentication results", styles["SectionHeading"])])

    auth_rows = [[_paragraph("METHOD", styles["TableHeader"]),
                  _paragraph("STATUS", styles["TableHeader"]),
                  _paragraph("REPORTED RESULT", styles["TableHeader"])]]
    for method in AUTH_METHODS:
        result = auth_results[method]
        auth_rows.append([
            _paragraph(method.upper(), styles["TableStrong"]),
            _paragraph(result["status"], ParagraphStyle(
                f"Auth{method}", parent=styles["TableStrong"],
                textColor=status_colors[result["status"]],
            )),
            _paragraph(result["reported"], styles["TableCopy"]),
        ])
    auth_table = Table(auth_rows, colWidths=[44 * mm, 37 * mm, 93 * mm], repeatRows=1, hAlign="LEFT")
    auth_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), navy), ("BACKGROUND", (0, 1), (-1, -1), colors.white),
        ("BOX", (0, 0), (-1, -1), 0.6, line), ("INNERGRID", (0, 0), (-1, -1), 0.35, line),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.extend([auth_table, _paragraph(
        "PASS means an explicit pass; FAIL means fail or softfail. Missing or inconclusive values are UNKNOWN.",
        styles["SmallCopy"],
    )])

    suspicious_heading = _paragraph("Suspicious indicators", styles["SectionHeading"])
    if findings:
        finding_rows = [[_paragraph("LEVEL", styles["TableHeader"]),
                         _paragraph("INDICATOR AND EVIDENCE", styles["TableHeader"])]]
        for finding in findings:
            finding_rows.append([
                _paragraph(finding.severity.upper(), styles["TableStrong"]),
                Paragraph(f"<b>{_safe(finding.title)}</b><br/>{_safe(finding.evidence).replace(chr(10), '<br/>')}",
                          styles["TableCopy"]),
            ])
        finding_table = Table(finding_rows, colWidths=[30 * mm, 144 * mm], repeatRows=1, hAlign="LEFT")
        finding_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), navy), ("BACKGROUND", (0, 1), (-1, -1), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.6, line), ("INNERGRID", (0, 0), (-1, -1), 0.35, line),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ]))
        story.append(KeepTogether([suspicious_heading, finding_table]))
    else:
        story.extend([suspicious_heading, _paragraph("No configured rule matched this email.", styles["BodyCopy"])])

    story.append(_paragraph("Recommended actions", styles["SectionHeading"]))
    actions = verdict.recommended_actions or [
        "Treat this verdict as a signal, not a guarantee.",
        "Verify important requests through an independently known official channel.",
    ]
    for action in actions:
        story.append(_paragraph(f"- {action}", styles["BodyCopy"]))
    story.extend([Spacer(1, 8), _paragraph(
        "Safety note: links and attachments were not opened. Authentication and rule results can be incomplete.",
        styles["SmallCopy"],
    )])
    doc.build(story, onFirstPage=draw_footer, onLaterPages=draw_footer)
    return buffer.getvalue()
