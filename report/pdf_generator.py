"""
report/pdf_generator.py — Generate the audit PDF report using ReportLab Platypus.
"""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import List

from report.models import AnalysisReport, Severity

# Colors matching Severity.color
SEV_COLORS = {
    "critical": (0.851, 0.188, 0.145),
    "high":     (0.957, 0.318, 0.118),
    "medium":   (0.976, 0.659, 0.145),
    "low":      (0.118, 0.533, 0.898),
    "info":     (0.459, 0.580, 0.620),
}

RISK_COLORS = {
    "Critical": SEV_COLORS["critical"],
    "High":     SEV_COLORS["high"],
    "Medium":   SEV_COLORS["medium"],
    "Low":      SEV_COLORS["low"],
}


def generate(report: AnalysisReport, output_path: str) -> None:
    try:
        _generate_pdf(report, output_path)
        size_kb = Path(output_path).stat().st_size / 1024
        print(f"[✓] PDF report: {output_path} ({size_kb:.1f} KB)")
    except Exception as exc:
        print(f"[!] PDF generation failed: {exc}. HTML report is still valid.")


def _generate_pdf(report: AnalysisReport, output_path: str) -> None:
    from reportlab.platypus import (
        BaseDocTemplate, PageTemplate, Frame, Paragraph, Spacer, Table,
        TableStyle, PageBreak, HRFlowable,
    )
    from reportlab.platypus.tableofcontents import TableOfContents
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

    W, H = A4
    MARGIN = 2 * cm

    # ------------------------------------------------------------------ Styles
    base_styles = getSampleStyleSheet()

    def style(name, **kw):
        return ParagraphStyle(name, parent=base_styles["Normal"], **kw)

    S = {
        "cover_title": style("CoverTitle", fontSize=28, fontName="Helvetica-Bold",
                              textColor=colors.HexColor("#e6edf3"), leading=34, spaceAfter=8),
        "cover_sub":   style("CoverSub", fontSize=14, fontName="Helvetica",
                              textColor=colors.HexColor("#8b949e"), leading=18, spaceAfter=4),
        "cover_conf":  style("CoverConf", fontSize=10, fontName="Helvetica-Bold",
                              textColor=colors.HexColor("#f4511e"), leading=14),
        "h1":          style("H1", fontSize=16, fontName="Helvetica-Bold", leading=20,
                              spaceBefore=20, spaceAfter=8),
        "h2":          style("H2", fontSize=13, fontName="Helvetica-Bold", leading=17,
                              spaceBefore=14, spaceAfter=6),
        "body":        style("Body", fontSize=10, fontName="Helvetica", leading=14, spaceAfter=6),
        "small":       style("Small", fontSize=9, fontName="Helvetica",
                              textColor=colors.HexColor("#8b949e"), leading=12),
        "evidence":    style("Evidence", fontSize=8, fontName="Courier", leading=11),
        "footer":      style("Footer", fontSize=8, fontName="Helvetica",
                              textColor=colors.HexColor("#8b949e"), alignment=TA_CENTER),
    }

    # ------------------------------------------------------------------ Page templates
    doc = BaseDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN + 0.5 * cm, bottomMargin=MARGIN + 0.5 * cm,
        title=f"AD Attack Surface Analysis — {report.domain}",
        author="AD Attack Surface Analyzer",
    )

    def cover_page(canvas, doc):
        canvas.saveState()
        canvas.setFillColorRGB(0.051, 0.067, 0.090)
        canvas.rect(0, 0, W, H, fill=1, stroke=0)
        canvas.restoreState()

    def body_page(canvas, doc):
        canvas.saveState()
        # Header line
        canvas.setStrokeColorRGB(0.188, 0.224, 0.271)
        canvas.setLineWidth(0.5)
        canvas.line(MARGIN, H - MARGIN + 0.2 * cm, W - MARGIN, H - MARGIN + 0.2 * cm)
        # Footer
        canvas.setFont("Helvetica", 8)
        canvas.setFillColorRGB(0.545, 0.580, 0.620)
        footer_text = f"Seguridad de la Informacion · Departamento de IT  |  {report.domain}  |  Pagina {doc.page}"
        canvas.drawCentredString(W / 2, MARGIN - 0.6 * cm, footer_text)
        canvas.restoreState()

    cover_frame = Frame(0, 0, W, H, leftPadding=3*cm, rightPadding=3*cm,
                        topPadding=H*0.3, bottomPadding=3*cm)
    body_frame  = Frame(MARGIN, MARGIN, W - 2*MARGIN, H - 2*MARGIN - 0.3*cm)

    doc.addPageTemplates([
        PageTemplate("cover", frames=[cover_frame], onPage=cover_page),
        PageTemplate("body",  frames=[body_frame],  onPage=body_page),
    ])

    # ------------------------------------------------------------------ Content
    story: List = []
    rc = RISK_COLORS.get(report.risk_label, SEV_COLORS["info"])
    risk_color = colors.Color(*rc)

    # Cover
    story.append(Paragraph("CONFIDENTIAL — INTERNAL USE ONLY", S["cover_conf"]))
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph("Active Directory<br/>Attack Surface Analysis", S["cover_title"]))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(f"Domain: {report.domain}", S["cover_sub"]))
    story.append(Paragraph(f"DC: {report.dc_hostname}", S["cover_sub"]))
    story.append(Paragraph(f"Date: {report.scan_time_utc[:10]}", S["cover_sub"]))
    story.append(Spacer(1, 0.5*cm))

    # Risk badge table
    risk_tbl = Table([[f"Risk Score: {report.risk_score}/100  —  {report.risk_label}"]],
                     colWidths=[8*cm])
    risk_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), risk_color),
        ("TEXTCOLOR",  (0,0), (-1,-1), colors.white),
        ("FONTNAME",   (0,0), (-1,-1), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 16),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("TOPPADDING", (0,0), (-1,-1), 10),
        ("BOTTOMPADDING", (0,0), (-1,-1), 10),
        ("ROUNDEDCORNERS", [6]),
    ]))
    story.append(risk_tbl)

    story.append(PageBreak())
    story.append(Paragraph("", ParagraphStyle("Switch", parent=base_styles["Normal"])))
    # Switch to body template
    from reportlab.platypus import NextPageTemplate
    story.insert(len(story)-1, NextPageTemplate("body"))

    # TOC
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle("TOC1", fontSize=11, fontName="Helvetica-Bold", leading=16),
        ParagraphStyle("TOC2", fontSize=10, fontName="Helvetica", leading=14, leftIndent=20),
    ]
    story.append(Paragraph("Table of Contents", S["h1"]))
    story.append(toc)
    story.append(PageBreak())

    def h1(text):
        p = Paragraph(text, S["h1"])
        p._bookmarkName = text
        story.append(p)

    def h2(text):
        p = Paragraph(text, S["h2"])
        story.append(p)

    def body(text):
        story.append(Paragraph(text, S["body"]))

    # 1. Executive Summary
    h1("1. Executive Summary")
    counts = report.summary
    body(
        f"This report presents the results of a read-only Active Directory security assessment "
        f"performed against <b>{report.domain}</b> on {report.scan_time_utc[:10]}. "
        f"The analysis identified {len(report.findings)} findings across {len(set(f.analyzer for f in report.findings))} modules."
    )
    story.append(Spacer(1, 0.3*cm))

    sev_data = [["Severity", "Count"]]
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        if n:
            sev_data.append([sev.title(), str(n)])
    tbl = Table(sev_data, colWidths=[6*cm, 3*cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#21262d")),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.HexColor("#8b949e")),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 10),
        ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#30363d")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#161b22"), colors.HexColor("#0d1117")]),
        ("TEXTCOLOR",  (0,1), (-1,-1), colors.HexColor("#e6edf3")),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(tbl)

    # 2. Methodology
    story.append(PageBreak())
    h1("2. Methodology")
    body(
        "This assessment uses read-only LDAP/LDAPS enumeration against the domain controller. "
        "No exploitation was performed. All queries use paged search controls (1000 entries per page) "
        "to avoid impacting AD performance. Authentication methods supported: Simple Bind, NTLM, and Kerberos."
    )
    body(
        "The tool checks for seven attack categories: Kerberoasting, AS-REP Roasting, "
        "Kerberos delegation abuse, dangerous ACL configurations, password policy weaknesses, "
        "stale accounts, and excessive privileged group membership."
    )

    # 3. Scope & Limitations
    h1("3. Scope &amp; Limitations")
    body(f"<b>Domain:</b> {report.domain}<br/>"
         f"<b>Domain Controller:</b> {report.dc_hostname}<br/>"
         f"<b>Scan Date:</b> {report.scan_time_utc[:10]}<br/>"
         f"<b>OS Version:</b> {report.os_version or 'N/A'}<br/>"
         f"<b>Functional Level:</b> {report.functional_level}")
    body(
        "This assessment is limited to what is visible via LDAP enumeration with the provided credentials. "
        "GPO settings, forest trusts, and network-level controls are outside scope. "
        "Findings reflect configuration at the time of the scan."
    )

    # 4. Environment Overview
    h1("4. Environment Overview")
    env_data = [
        ["Parameter", "Value"],
        ["Domain FQDN", report.domain],
        ["Domain Controller", report.dc_hostname],
        ["OS Version", report.os_version or "N/A"],
        ["Domain Functional Level", str(report.functional_level)],
        ["Scan Time (UTC)", report.scan_time_utc],
        ["Total Findings", str(len(report.findings))],
    ]
    env_tbl = Table(env_data, colWidths=[5*cm, 10*cm])
    env_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#21262d")),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.HexColor("#8b949e")),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 10),
        ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#30363d")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#161b22"), colors.HexColor("#0d1117")]),
        ("TEXTCOLOR",  (0,1), (-1,-1), colors.HexColor("#e6edf3")),
        ("TOPPADDING", (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(env_tbl)

    # 5. Findings
    story.append(PageBreak())
    h1("5. Findings")
    for i, f in enumerate(report.findings, 1):
        sev_rgb = SEV_COLORS.get(f.severity.value, SEV_COLORS["info"])
        sev_color = colors.Color(*sev_rgb)

        h2(f"{i}. {f.title}")
        # Severity badge as small table
        badge = Table([[f"  {f.severity.value.upper()}  "]], colWidths=[3*cm])
        badge.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,-1), sev_color),
            ("TEXTCOLOR",  (0,0), (-1,-1), colors.white),
            ("FONTNAME",   (0,0), (-1,-1), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 9),
            ("ALIGN",      (0,0), (-1,-1), "CENTER"),
            ("TOPPADDING", (0,0), (-1,-1), 3),
            ("BOTTOMPADDING", (0,0), (-1,-1), 3),
        ]))
        story.append(badge)
        if f.mitre_id:
            story.append(Paragraph(f"MITRE ATT&amp;CK: {f.mitre_id}", S["small"]))
        story.append(Spacer(1, 0.2*cm))

        body(f.description)

        if f.evidence:
            story.append(Paragraph("Evidence:", S["h2"]))
            ev_rows = [[Paragraph(e, S["evidence"])] for e in f.evidence[:30]]
            if len(f.evidence) > 30:
                ev_rows.append([Paragraph(f"... and {len(f.evidence)-30} more", S["small"])])
            ev_tbl = Table(ev_rows, colWidths=[W - 2*MARGIN - 1*cm])
            ev_tbl.setStyle(TableStyle([
                ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#161b22")),
                ("TEXTCOLOR",  (0,0), (-1,-1), colors.HexColor("#e6edf3")),
                ("FONTSIZE",   (0,0), (-1,-1), 8),
                ("GRID",       (0,0), (-1,-1), 0.3, colors.HexColor("#30363d")),
                ("TOPPADDING", (0,0), (-1,-1), 3),
                ("BOTTOMPADDING", (0,0), (-1,-1), 3),
            ]))
            story.append(ev_tbl)

        if f.remediation:
            story.append(Paragraph("Remediation:", S["h2"]))
            body(f.remediation)

        story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#30363d"), spaceAfter=6))

    # 6. Recommendations Summary
    story.append(PageBreak())
    h1("6. Recommendations Summary")
    rec_data = [["Finding", "Severity", "Priority"]]
    for f in report.findings:
        if f.severity.value in ("critical", "high"):
            rec_data.append([
                Paragraph(f.title[:80], S["small"]),
                f.severity.value.title(),
                "Immediate",
            ])
    for f in report.findings:
        if f.severity.value == "medium":
            rec_data.append([
                Paragraph(f.title[:80], S["small"]),
                "Medium",
                "30 days",
            ])
    if len(rec_data) == 1:
        rec_data.append(["No critical/high/medium findings", "", ""])
    rec_tbl = Table(rec_data, colWidths=[9*cm, 3*cm, 3*cm])
    rec_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#21262d")),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.HexColor("#8b949e")),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",   (0,0), (-1,-1), 9),
        ("GRID",       (0,0), (-1,-1), 0.5, colors.HexColor("#30363d")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#161b22"), colors.HexColor("#0d1117")]),
        ("TEXTCOLOR",  (0,1), (-1,-1), colors.HexColor("#e6edf3")),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("VALIGN",     (0,0), (-1,-1), "TOP"),
    ]))
    story.append(rec_tbl)

    # 7. Conclusions
    story.append(PageBreak())
    h1("7. Conclusions")
    body(
        f"The Active Directory environment of <b>{report.domain}</b> received a risk score of "
        f"<b>{report.risk_score}/100 ({report.risk_label})</b>. "
        f"A total of {len(report.findings)} findings were identified, including "
        f"{report.summary.get('critical',0)} critical and {report.summary.get('high',0)} high severity issues."
    )
    body(
        "It is recommended to address Critical and High findings within 30 days, "
        "Medium findings within 90 days, and establish a continuous monitoring process "
        "to detect new misconfigurations as the environment evolves."
    )
    body(
        "This report should be treated as CONFIDENTIAL and shared only with authorized "
        "personnel responsible for Active Directory security."
    )

    # Build with TOC
    doc.multiBuild(story)
