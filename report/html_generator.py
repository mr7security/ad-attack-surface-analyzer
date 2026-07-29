"""
report/html_generator.py — Generate the interactive HTML report.
Single self-contained file: inline CSS + JS, no CDN dependencies.
"""
from __future__ import annotations

from pathlib import Path
from jinja2 import Environment, BaseLoader

from report.models import AnalysisReport

TEMPLATE = """<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AD Attack Surface Analyzer — {{ report.domain }}</title>
<style>
:root{
  --c-critical:#d93025;--c-high:#f4511e;--c-medium:#f9a825;
  --c-low:#1e88e5;--c-info:#757575;
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;
  --text:#e6edf3;--text2:#8b949e;--border:#30363d;
  --radius:8px;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;line-height:1.6}
header{background:var(--bg2);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
header img{height:36px;object-fit:contain}
header img.hidden{display:none}
.header-info{flex:1}
.header-info h1{font-size:18px;font-weight:700}
.header-info .meta{color:var(--text2);font-size:12px;margin-top:2px}
.lang-btn{background:var(--bg3);border:1px solid var(--border);color:var(--text);border-radius:6px;padding:6px 12px;cursor:pointer;font-size:13px}
.lang-btn:hover{background:var(--border)}
main{max-width:1100px;margin:0 auto;padding:24px}
.summary-grid{display:grid;grid-template-columns:200px 1fr;gap:24px;margin-bottom:32px;align-items:start}
.gauge-wrap{display:flex;flex-direction:column;align-items:center;gap:8px}
.gauge-label{font-size:22px;font-weight:700}
.stats-table{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;width:100%}
.stats-table th,.stats-table td{padding:10px 16px;text-align:left;border-bottom:1px solid var(--border)}
.stats-table th{background:var(--bg3);font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--text2)}
.stats-table tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:600;text-transform:uppercase;color:#fff}
.badge-critical{background:var(--c-critical)}
.badge-high{background:var(--c-high)}
.badge-medium{background:var(--c-medium);color:#000}
.badge-low{background:var(--c-low)}
.badge-info{background:var(--c-info)}
.section-title{font-size:16px;font-weight:600;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid var(--border)}
.finding-card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:12px;overflow:hidden;border-left:4px solid transparent}
.finding-card.critical{border-left-color:var(--c-critical)}
.finding-card.high{border-left-color:var(--c-high)}
.finding-card.medium{border-left-color:var(--c-medium)}
.finding-card.low{border-left-color:var(--c-low)}
.finding-card.info{border-left-color:var(--c-info)}
.card-header{padding:14px 16px;cursor:pointer;display:flex;align-items:center;gap:10px;user-select:none}
.card-header:hover{background:var(--bg3)}
.card-title{flex:1;font-weight:600;font-size:14px}
.mitre-badge{background:var(--bg3);border:1px solid var(--border);border-radius:4px;padding:1px 6px;font-size:11px;color:var(--text2);font-family:monospace}
.chevron{color:var(--text2);transition:transform .2s;flex-shrink:0}
.card-body{display:none;padding:16px;border-top:1px solid var(--border)}
.card-body.open{display:block}
.card-body p{margin-bottom:10px;color:var(--text2)}
.card-body h4{font-size:12px;text-transform:uppercase;letter-spacing:.5px;color:var(--text2);margin-bottom:6px;margin-top:12px}
.card-body h4:first-child{margin-top:0}
pre{background:var(--bg3);border:1px solid var(--border);border-radius:6px;padding:12px;font-size:12px;overflow-x:auto;max-height:200px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;color:var(--text)}
.remediation{background:#0d2137;border:1px solid #1c4a6e;border-radius:6px;padding:10px 12px;font-size:13px;color:#a8d8f0}
.refs a{color:#58a6ff;font-size:12px;text-decoration:none}
.refs a:hover{text-decoration:underline}
footer{text-align:center;padding:24px;color:var(--text2);font-size:12px;border-top:1px solid var(--border)}
@media print{
  body{background:#fff;color:#000}
  header,footer{background:#fff;color:#000;border-color:#ccc}
  .lang-btn{display:none}
  .card-body{display:block!important}
  .chevron{display:none}
  .finding-card{break-inside:avoid;border-color:#ccc}
  pre{background:#f5f5f5;color:#000}
  .remediation{background:#e8f4fd;color:#000}
}
</style>
</head>
<body>
<header>
  <img id="logo" src="logo_sgp.png" alt="SGP" onerror="this.classList.add('hidden')">
  <div class="header-info">
    <h1>AD Attack Surface Analyzer</h1>
    <div class="meta">{{ report.domain }} &bull; {{ report.dc_hostname }} &bull; {{ report.scan_time_utc[:10] }}</div>
  </div>
  <span class="badge badge-{{ report.risk_label|lower }}">{{ report.risk_label }} &mdash; {{ report.risk_score }}/100</span>
  <button class="lang-btn" onclick="toggleLang()" id="lang-btn">EN</button>
</header>

<main>
  <div class="summary-grid">
    <div class="gauge-wrap">
      <svg viewBox="0 0 120 70" width="200">
        {%- set r=50; cx=60; cy=60 -%}
        {%- set circ = 3.14159 * r -%}
        {%- set dash = (report.risk_score / 100) * circ -%}
        {%- set color = {'Critical':'#d93025','High':'#f4511e','Medium':'#f9a825','Low':'#1e88e5'}[report.risk_label] or '#757575' -%}
        <path d="M10,60 A50,50 0 0,1 110,60" fill="none" stroke="#21262d" stroke-width="12"/>
        <path d="M10,60 A50,50 0 0,1 110,60" fill="none" stroke="{{ color }}" stroke-width="12"
              stroke-dasharray="{{ dash|round(1) }} {{ circ|round(1) }}"
              stroke-linecap="round"/>
        <text x="60" y="56" text-anchor="middle" fill="{{ color }}" font-size="22" font-weight="bold">{{ report.risk_score }}</text>
      </svg>
      <div class="gauge-label" style="color:{{ color }}">{{ report.risk_label }}</div>
    </div>

    <table class="stats-table">
      <thead><tr>
        <th data-es="Severidad" data-en="Severity">Severidad</th>
        <th data-es="Hallazgos" data-en="Findings">Hallazgos</th>
      </tr></thead>
      <tbody>
        {% for sev, label_es, label_en in [
            ('critical','Critico','Critical'),
            ('high','Alto','High'),
            ('medium','Medio','Medium'),
            ('low','Bajo','Low'),
            ('info','Info','Info')] %}
        {% if report.summary.get(sev, 0) > 0 %}
        <tr>
          <td><span class="badge badge-{{ sev }}" data-es="{{ label_es }}" data-en="{{ label_en }}">{{ label_es }}</span></td>
          <td>{{ report.summary.get(sev, 0) }}</td>
        </tr>
        {% endif %}
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="section-title" data-es="Hallazgos de Seguridad" data-en="Security Findings">Hallazgos de Seguridad</div>

  {% for f in report.findings %}
  <div class="finding-card {{ f.severity.value }}" id="f{{ loop.index }}">
    <div class="card-header" onclick="toggle('f{{ loop.index }}')">
      <span class="badge badge-{{ f.severity.value }}">{{ f.severity.value }}</span>
      <span class="card-title">{{ f.title }}</span>
      {% if f.mitre_id %}<span class="mitre-badge">{{ f.mitre_id }}</span>{% endif %}
      <span class="chevron" id="ch{{ loop.index }}">&#9660;</span>
    </div>
    <div class="card-body" id="cb{{ loop.index }}">
      <h4 data-es="Descripcion" data-en="Description">Descripcion</h4>
      <p>{{ f.description }}</p>

      {% if f.evidence %}
      <h4 data-es="Evidencia" data-en="Evidence">Evidencia</h4>
      <pre>{{ f.evidence[:50] | join('\n') }}{% if f.evidence|length > 50 %}
... y {{ f.evidence|length - 50 }} mas{% endif %}</pre>
      {% endif %}

      {% if f.remediation %}
      <h4 data-es="Remediacion" data-en="Remediation">Remediacion</h4>
      <div class="remediation">{{ f.remediation }}</div>
      {% endif %}

      {% if f.references %}
      <h4 data-es="Referencias" data-en="References">Referencias</h4>
      <div class="refs">{% for r in f.references %}<a href="{{ r }}" target="_blank">{{ r }}</a> {% endfor %}</div>
      {% endif %}
    </div>
  </div>
  {% endfor %}
</main>

<footer>
  <span data-es="Seguridad de la Informacion · Departamento de IT" data-en="Information Security · IT Department">Seguridad de la Informacion · Departamento de IT</span>
  &bull; {{ report.domain }} &bull; {{ report.scan_time_utc[:10] }}
</footer>

<script>
var lang = 'es';
function toggle(id){
  var cb=document.getElementById('cb'+id.slice(1));
  var ch=document.getElementById('ch'+id.slice(1));
  if(cb.classList.contains('open')){cb.classList.remove('open');ch.innerHTML='&#9660;'}
  else{cb.classList.add('open');ch.innerHTML='&#9650;'}
}
function toggleLang(){
  lang = lang==='es' ? 'en' : 'es';
  document.getElementById('lang-btn').textContent = lang==='es' ? 'EN' : 'ES';
  document.querySelectorAll('[data-es]').forEach(function(el){
    el.textContent = el.getAttribute('data-'+lang);
  });
}
// Open first finding by default
var first = document.querySelector('.card-body');
if(first){first.classList.add('open');}
var firstCh = document.querySelector('.chevron');
if(firstCh){firstCh.innerHTML='&#9650;';}
</script>
</body>
</html>"""


def generate(report: AnalysisReport, output_path: str) -> None:
    env = Environment(loader=BaseLoader())
    tmpl = env.from_string(TEMPLATE)
    html = tmpl.render(report=report)
    out = Path(output_path)
    out.write_text(html, encoding="utf-8")
    size_kb = out.stat().st_size / 1024
    print(f"[✓] HTML report: {output_path} ({size_kb:.1f} KB)")
