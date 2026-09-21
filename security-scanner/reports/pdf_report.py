import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)

SEVERITY_COLORS = {
    "critical": colors.HexColor("#C93A3F"),
    "high": colors.HexColor("#C85A28"),
    "medium": colors.HexColor("#B37A1A"),
    "low": colors.HexColor("#1F8F7D"),
    "info": colors.HexColor("#5B6770"),
}


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", fontSize=20, leading=24, spaceAfter=6, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="ReportSub", fontSize=11, textColor=colors.HexColor("#555555"), spaceAfter=16))
    styles.add(ParagraphStyle(name="FindingTitle", fontSize=12.5, leading=15, fontName="Helvetica-Bold", spaceBefore=14, spaceAfter=2))
    styles.add(ParagraphStyle(name="FindingBody", fontSize=9.5, leading=13, spaceAfter=4))
    styles.add(ParagraphStyle(name="FindingLabel", fontSize=8.5, leading=11, textColor=colors.HexColor("#555555"), fontName="Helvetica-Bold"))
    return styles


def build_pdf(scan) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=LETTER,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
    )
    styles = _styles()
    story = []

    story.append(Paragraph("Vulnerability Scan Report", styles["ReportTitle"]))
    story.append(Paragraph(scan.target_url, styles["ReportSub"]))

    counts = scan.severity_counts()
    summary_data = [["Risk score", "Risk level", "Critical", "High", "Medium", "Low", "Info"]]
    summary_data.append([
        f"{scan.risk_score:.1f} / 100", scan.risk_level.upper(),
        str(counts["critical"]), str(counts["high"]), str(counts["medium"]),
        str(counts["low"]), str(counts["info"]),
    ])
    summary_table = Table(summary_data, hAlign="LEFT")
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#131920")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_table)

    scanned_at = scan.finished_at or scan.started_at
    story.append(Paragraph(
        f"Scanned {scanned_at.strftime('%Y-%m-%d %H:%M UTC') if scanned_at else 'unknown'} · "
        f"{len(scan.findings)} findings",
        styles["ReportSub"],
    ))
    story.append(Spacer(1, 10))

    story.append(Paragraph(
        "This report is generated for educational and authorized security-testing "
        "purposes only. It documents observed conditions and does not constitute a "
        "warranty of security; verify all findings manually before acting on them.",
        styles["FindingBody"],
    ))
    story.append(PageBreak())

    story.append(Paragraph("Findings", styles["ReportTitle"]))
    for f in scan.findings:
        color = SEVERITY_COLORS.get(f.severity, colors.grey)
        badge = Table([[f.severity.upper()]], colWidths=[0.9 * inch])
        badge.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), color),
            ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(badge)
        story.append(Paragraph(f.title, styles["FindingTitle"]))
        story.append(Paragraph(f"Category: {f.category}", styles["FindingLabel"]))
        story.append(Paragraph(f.description or "", styles["FindingBody"]))
        if f.evidence:
            story.append(Paragraph("Evidence", styles["FindingLabel"]))
            story.append(Paragraph(f.evidence, styles["FindingBody"]))
        if f.recommendation:
            story.append(Paragraph("Recommendation", styles["FindingLabel"]))
            story.append(Paragraph(f.recommendation, styles["FindingBody"]))

    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
