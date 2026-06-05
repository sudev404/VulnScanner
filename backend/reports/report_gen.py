from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                 Table, TableStyle, HRFlowable)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
import datetime, os, tempfile

SEVERITY_COLORS = {
    "Critical": colors.HexColor("#dc2626"),
    "High":     colors.HexColor("#ea580c"),
    "Medium":   colors.HexColor("#ca8a04"),
    "Low":      colors.HexColor("#2563eb"),
    "Info":     colors.HexColor("#6b7280"),
}

def generate_pdf_report(scan: dict, findings: list) -> str:
    out_dir = tempfile.gettempdir()
    path = os.path.join(out_dir, f"report_{scan['id'][:8]}.pdf")

    doc = SimpleDocTemplate(path, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    story  = []

    # ── Title ─────────────────────────────────────────────────────────────────
    title_style = ParagraphStyle("title", parent=styles["Title"],
                                  fontSize=22, textColor=colors.HexColor("#0f172a"),
                                  spaceAfter=6)
    sub_style   = ParagraphStyle("sub", parent=styles["Normal"],
                                  fontSize=11, textColor=colors.HexColor("#475569"),
                                  spaceAfter=2)
    body_style  = ParagraphStyle("body", parent=styles["Normal"],
                                  fontSize=9, textColor=colors.HexColor("#1e293b"),
                                  spaceAfter=4, leading=14)

    story.append(Paragraph("Vulnerability Assessment Report", title_style))
    story.append(Paragraph(f"Target: <b>{scan['target']}</b>", sub_style))
    story.append(Paragraph(f"Scan ID: {scan['id']}", sub_style))
    story.append(Paragraph(f"Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}", sub_style))
    story.append(HRFlowable(width="100%", thickness=1,
                             color=colors.HexColor("#e2e8f0"), spaceAfter=12))

    # ── Executive Summary ──────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", styles["Heading1"]))

    sev_counts = {s: sum(1 for f in findings if f.get("severity") == s)
                  for s in ("Critical", "High", "Medium", "Low", "Info")}

    summary_data = [
        ["Risk Score", "Risk Level", "Total Findings",
         "Critical", "High", "Medium", "Low"],
        [
            f"{scan.get('risk_score', 0)}/100",
            scan.get("risk_level", "Unknown"),
            str(len(findings)),
            str(sev_counts["Critical"]),
            str(sev_counts["High"]),
            str(sev_counts["Medium"]),
            str(sev_counts["Low"]),
        ]
    ]
    summary_table = Table(summary_data, colWidths=[2.5*cm]*7)
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
        ("FONTSIZE",   (0,0), (-1,-1), 8),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f8fafc"), colors.white]),
        ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.5*cm))

    # ── Findings ───────────────────────────────────────────────────────────────
    story.append(Paragraph("Detailed Findings", styles["Heading1"]))

    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        group = [f for f in findings if f.get("severity") == sev]
        if not group:
            continue

        sev_color = SEVERITY_COLORS.get(sev, colors.gray)
        story.append(Paragraph(
            f'<font color="{sev_color.hexval()}">{sev} ({len(group)})</font>',
            styles["Heading2"]
        ))

        for idx, f in enumerate(group, 1):
            # Finding header
            header_data = [[
                f"{idx}. {f.get('title','')}",
                f"{f.get('category','')} | Port: {f.get('port') or 'N/A'} | Service: {f.get('service') or 'N/A'}"
            ]]
            ht = Table(header_data, colWidths=[10*cm, 7*cm])
            ht.setStyle(TableStyle([
                ("BACKGROUND",  (0,0), (-1,-1), colors.HexColor("#f1f5f9")),
                ("FONTNAME",    (0,0), (0,0), "Helvetica-Bold"),
                ("FONTSIZE",    (0,0), (-1,-1), 8),
                ("LEFTPADDING", (0,0), (-1,-1), 6),
                ("TOPPADDING",  (0,0), (-1,-1), 4),
                ("BOTTOMPADDING",(0,0), (-1,-1), 4),
                ("LINEBELOW",   (0,0), (-1,0), 2, sev_color),
            ]))
            story.append(ht)

            # CVE + CVSS
            if f.get("cve_id"):
                story.append(Paragraph(
                    f"<b>CVE:</b> {f['cve_id']}  |  <b>CVSS:</b> {f.get('cvss_score','N/A')}",
                    body_style
                ))

            # Description
            story.append(Paragraph(
                f"<b>Description:</b> {f.get('description','')}", body_style))

            # Remediation
            if f.get("remediation"):
                story.append(Paragraph(
                    f"<b>Remediation:</b> {f['remediation']}", body_style))

            story.append(Spacer(1, 0.3*cm))

    # ── Footer ─────────────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#e2e8f0"), spaceBefore=12))
    story.append(Paragraph(
        "Generated by VulnScanner — For authorized security testing only.",
        ParagraphStyle("footer", parent=styles["Normal"],
                        fontSize=7, textColor=colors.gray, alignment=TA_CENTER)
    ))

    doc.build(story)
    return path
