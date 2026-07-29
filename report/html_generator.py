"""
report/html_generator.py — Interactive HTML report generator.
TODO (Devin): implement generate() and TEMPLATE — see HANDOFF.md Issue 10

Design spec:
- Single self-contained HTML (inline CSS + JS, no CDN)
- Dark header: tool name, domain, scan date, risk score badge
- Risk score SVG arc gauge (0-100), color-coded
- Collapsible finding cards, color-coded by severity
- Language toggle ES/EN (data-es / data-en attributes on elements)
- Evidence: monospace scrollable pre block per card
- MITRE ATT&CK badge on cards with mitre_id
- Print-friendly: @media print hides toggle, expands cards
- Logo: img src='logo_sgp.png' in header (hide gracefully if missing)
- Footer: Seguridad de la Informacion - Departamento de IT | {domain} | {date}
"""
from __future__ import annotations
from pathlib import Path
from jinja2 import BaseLoader, Environment
from report.models import AnalysisReport

TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8">
<title>AD Attack Surface Analyzer - {{ report.domain }}</title>
<style>
:root {
  --color-critical:#d93025;--color-high:#f4511e;
  --color-medium:#f9a825;--color-low:#1e88e5;--color-info:#757575;
}
/* TODO (Devin): full CSS here — match IAM Risk Analyzer visual style */
</style></head>
<body>
<!-- TODO (Devin): full HTML — header, gauge, finding cards, ES/EN toggle, footer -->
<h1>AD Attack Surface Analyzer</h1>
<p>Domain: {{ report.domain }} | Score: {{ report.risk_score }}/100 ({{ report.risk_label }})</p>
{% for f in report.findings %}
<div class="finding-{{ f.severity.value }}">
  <h3>{{ f.title }} [{{ f.severity.value|upper }}]</h3>
  <p>{{ f.description }}</p>
  {% if f.evidence %}<pre>{{ f.evidence|join('\n') }}</pre>{% endif %}
</div>
{% endfor %}
</body></html>"""


def generate(report: AnalysisReport, output_path: str) -> None:
    """TODO (Devin): render TEMPLATE with report, write UTF-8 to output_path."""
    raise NotImplementedError
