"""
report/pdf_generator.py — Generate the audit PDF report using ReportLab.

Document structure (match IAM Risk Analyzer PDF style)
------------------------------------------------------
1. Cover page
   - SGP logo (top-center)
   - Title: "Active Directory Attack Surface Analysis"
   - Subtitle: domain, DC hostname, date
   - Risk score badge (large, color-coded)
   - Classification: CONFIDENTIAL — INTERNAL USE ONLY

2. Table of Contents (auto-generated)

3. Section 1 — Executive Summary
   Paragraph + risk score gauge graphic (ReportLab Drawing).
   Finding count table per severity.

4. Section 2 — Methodology
   Description of LDAP-based enumeration, no exploitation performed,
   read-only analysis.

5. Section 3 — Scope & Limitations
   What was and wasn't analyzed. Auth method used. LDAP vs LDAPS note.

6. Section 4 — Environment Overview
   Domain, DC, functional level, OS version (from Root DSE).

7. Section 5 — Findings
   One sub-section per finding, ordered by severity.
   Each finding: title, severity badge, description, evidence table,
   remediation, MITRE ATT&CK reference.

8. Section 6 — Recommendations Summary
   Table: Finding | Severity | Effort | Priority.

9. Section 7 — Conclusions

Page layout
-----------
- Logo in header of every page (small, top-right).
- Footer: "Seguridad de la Informacion · Departamento de IT | {domain} | Page N of M"
- A4 format, 2 cm margins.
- Fonts: Helvetica family (built-in ReportLab, no external fonts needed).

Public API
----------
    generate(report: AnalysisReport, output_path: str) -> None

TODO (Devin): full implementation with ReportLab Platypus (BaseDocTemplate,
PageTemplate, Frames, Paragraph, Table, Drawing). Mirror the structure from
the IAM Risk Analyzer's pdf_generator.py if available in the repo.
Wrap everything in try/except so HTML still generates on PDF failure.
"""

from __future__ import annotations

from report.models import AnalysisReport


def generate(report: AnalysisReport, output_path: str) -> None:
    """
    Render the audit PDF and write it to output_path.

    TODO (Devin): implement using ReportLab Platypus.
    On any exception, print a warning and return (don't crash main.py).
    """
    try:
        raise NotImplementedError("pdf_generator.generate() not yet implemented")
    except NotImplementedError:
        raise
    except Exception as exc:
        print(f"[!] PDF generation failed: {exc}. HTML report is still valid.")
