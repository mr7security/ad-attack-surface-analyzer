# HANDOFF — AD Attack Surface Analyzer

> **For Devin (AI Software Engineer)**
> This document is the complete spec for implementing the `ad-attack-surface-analyzer` project.
> The scaffolding is already in place. Your job is to replace every `raise NotImplementedError` with a working implementation.

---

## 1. What this tool does

A read-only Active Directory security assessment tool. It connects to a domain controller via LDAP(S), runs a suite of security analyzers, and generates two output files:

- `report.html` — interactive HTML report (dark header, collapsible findings, ES/EN toggle, risk score gauge)
- `report_auditoria.pdf` — audit-grade PDF (cover page, table of contents, 7 sections, logo on every page)

**No exploitation.** No writes to AD. Strictly read-only LDAP queries.

---

## 2. Repo structure

```
ad-attack-surface-analyzer/
├── main.py                    ← CLI entry point (implemented, don't change API)
├── requirements.txt           ← dependencies (add if needed, don't remove)
├── config.py                  ← constants and ConnectionConfig dataclass
├── connectors/
│   └── ldap_connector.py      ← LDAP connection + search (TODO)
├── analyzers/
│   ├── base.py                ← BaseAnalyzer ABC (don't modify)
│   ├── kerberoast.py          ← TODO
│   ├── asrep.py               ← TODO
│   ├── delegation.py          ← TODO
│   ├── acl.py                 ← TODO
│   ├── password_policy.py     ← TODO
│   ├── stale_accounts.py      ← TODO
│   └── privileged_groups.py   ← TODO
└── report/
    ├── models.py              ← Finding + AnalysisReport (compute_risk TODO)
    ├── html_generator.py      ← HTML report (TODO)
    └── pdf_generator.py       ← PDF report (TODO)
```

---

## 3. Implementation order (priority)

Implement in this order — each layer depends on the one above:

### Issue 1 — `connectors/ldap_connector.py`
All analyzers depend on this. Without it nothing runs.

**Simple bind:**
```python
conn = Connection(server, user=cfg.username, password=cfg.password,
                  authentication=SIMPLE, auto_bind=True)
```
Warn if not SSL (cleartext password). Raise `LDAPConnectorError` on bind failure.

**NTLM:**
```python
conn = Connection(server, user=cfg.username, password=cfg.password,
                  authentication=NTLM, auto_bind=True)
```
Validate that username contains `\\` or `@`. Raise helpful error if not.

**Kerberos:**
```python
import os
if cfg.ccache:
    os.environ["KRB5CCNAME"] = cfg.ccache
# If keytab: use gssapi to call kinit programmatically
conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS,
                  auto_bind=True)
```

**Paged search** (required — AD returns max 1000 entries without paging):
```python
from ldap3.controls import SimplePagedResultsControl
cookie = b""
results = []
while True:
    ctrl = SimplePagedResultsControl(True, size=PAGE_SIZE, cookie=cookie)
    conn.search(base, ldap_filter, search_scope, attributes=attributes,
                controls=[ctrl])
    results.extend(conn.entries)
    cookie = conn.result["controls"]["1.2.840.113556.1.4.319"]["value"]["cookie"]
    if not cookie:
        break
return results
```

**get_root_dse():** After bind, `server.info` is populated. Extract:
`defaultNamingContext`, `dnsHostName`, `domainFunctionality`, `forestFunctionality`.
Also do a BASE search on `""` for `operatingSystem`.

---

### Issue 2 — `report/models.py` → `compute_risk()`

```python
from config import RISK_WEIGHTS
counts = {s.value: 0 for s in Severity}
for f in self.findings:
    counts[f.severity.value] += 1
score = sum(RISK_WEIGHTS[sev] * cnt for sev, cnt in counts.items())
self.risk_score = min(100, score)
self.risk_label = (
    "Critical" if score >= 80 else
    "High"     if score >= 60 else
    "Medium"   if score >= 40 else "Low"
)
self.summary = counts
self.findings.sort(key=lambda f: f.severity.order)
```

---

### Issue 3 — All analyzers

Each analyzer follows the same pattern:
1. Call `self.connector.search(FILTER, ATTRS)`.
2. Process entries.
3. Return `list[Finding]`.

**Key implementation notes across all analyzers:**

**Windows FILETIME conversion** (needed in stale_accounts, kerberoast, asrep):
```python
from datetime import datetime, timezone, timedelta
FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

def filetime_to_dt(filetime: int) -> datetime:
    return FILETIME_EPOCH + timedelta(microseconds=filetime // 10)

def days_since(dt: datetime) -> int:
    return (datetime.now(timezone.utc) - dt).days
```

**UAC flag helpers:**
```python
UAC_DISABLED           = 0x00000002
UAC_DONT_EXPIRE_PASSWD = 0x00010000
UAC_DONT_REQ_PREAUTH   = 0x00400000
UAC_TRUSTED_FOR_DELEG  = 0x00080000
UAC_TRUSTED_TO_AUTH    = 0x01000000  # constrained delegation
UAC_SERVER_TRUST       = 0x00002000  # DC

def has_flag(uac: int, flag: int) -> bool:
    return bool(uac & flag)
```

**ACL analyzer** — parsing the security descriptor:
```python
from impacket.ldap import ldaptypes

def parse_sd(raw_sd: bytes) -> ldaptypes.SR_SECURITY_DESCRIPTOR:
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd.fromString(raw_sd)
    return sd

# Fetch nTSecurityDescriptor:
from ldap3.protocol.microsoft import security_descriptor_control
conn.search(dn, "(objectClass=*)", BASE,
            attributes=["nTSecurityDescriptor"],
            controls=security_descriptor_control(sdflags=0x04))
```

**Large group membership** (ranging):
```python
# If group has > 1500 members, AD returns member;range=0-1499
# Request: member;range=0-* to get all
attrs = ["member;range=0-*"]
```

---

### Issue 4 — `report/html_generator.py`

Build a self-contained HTML file. Key requirements:

- **No external dependencies** — inline all CSS and JS.
- **Risk score gauge** — SVG arc gauge (0-100), color matches risk_label.
- **Finding cards** — click to expand/collapse. Show severity badge, MITRE ID if set.
- **Language toggle** — button in header. All UI strings in both ES and EN.
  Use `data-es="Hallazgos"` and `data-en="Findings"` pattern, toggle with JS.
- **Evidence block** — `<pre>` inside card, max-height 200px, scrollable.
- **Print** — `@media print { .lang-toggle { display: none; } .card { break-inside: avoid; } }`
- **Logo** — `<img src="logo_sgp.png">` in header. If file not present, hide gracefully.
- **Footer** — "Seguridad de la Informacion · Departamento de IT | {domain} | {date}"

Render via Jinja2:
```python
env = Environment(loader=BaseLoader())
tmpl = env.from_string(TEMPLATE)
html = tmpl.render(report=report)
Path(output_path).write_text(html, encoding="utf-8")
```

---

### Issue 5 — `report/pdf_generator.py`

Use `reportlab.platypus`. Structure: `BaseDocTemplate` with two `PageTemplate`s (cover + body).

Cover page: full-page frame, logo, title, domain, date, risk score badge.
Body pages: header (logo small right) + footer (domain | page N of M).

Sections: use `Heading1` / `Heading2` styles + `TableOfContents`.
Findings: one `Heading2` per finding, a `Table` for evidence (max 30 rows, truncate with note).

**Colors** — match `Severity.color` property from `report/models.py`.

**Graceful failure:**
```python
try:
    # ... full implementation ...
    print(f"[OK] PDF report: {output_path} ({size:.1f} KB)")
except Exception as exc:
    print(f"[!] PDF generation failed: {exc}. HTML report is still valid.")
```

---

## 4. Testing

No formal test suite required for MVP. Verify manually:

```bash
# Unit smoke test (no AD needed) — check imports and instantiation
python -c "
from config import ConnectionConfig
from report.models import AnalysisReport, Finding, Severity
f = Finding('Test', Severity.HIGH, 'desc', ['evidence1'])
r = AnalysisReport('corp.local', 'dc01', '2026-01-01T00:00:00+00:00')
r.findings = [f]
r.compute_risk()
print(r.risk_score, r.risk_label)
"

# Full run (requires AD access or a lab DC)
python main.py --target 127.0.0.1 --domain lab.local \
               --auth simple --username Administrator --password 'Admin123!' \
               --output /tmp/report.html --pdf /tmp/report.pdf
```

---

## 5. GitHub Issues to create

Create the following issues in `mr7security/ad-attack-surface-analyzer`:

| # | Title | Label |
|---|-------|-------|
| 1 | Implement LDAPConnector (simple, NTLM, Kerberos) | `core` |
| 2 | Implement compute_risk() in AnalysisReport | `core` |
| 3 | Implement KerberoastAnalyzer | `analyzer` |
| 4 | Implement ASREPAnalyzer | `analyzer` |
| 5 | Implement DelegationAnalyzer (unconstrained/constrained/RBCD) | `analyzer` |
| 6 | Implement ACLAnalyzer (dangerous ACEs + DCSync) | `analyzer` |
| 7 | Implement PasswordPolicyAnalyzer | `analyzer` |
| 8 | Implement StaleAccountsAnalyzer | `analyzer` |
| 9 | Implement PrivilegedGroupsAnalyzer + LAPS check | `analyzer` |
| 10 | Implement HTML report generator | `report` |
| 11 | Implement PDF audit report generator | `report` |

---

## 6. Key dependencies and gotchas

| Issue | Notes |
|-------|-------|
| `impacket` on Windows | May need `pip install impacket --pre` or build from source |
| `gssapi` on Windows | Use `winkerberos` instead of `gssapi` for Kerberos on Windows |
| LDAP paging | Always page — production DCs have >10k objects |
| nTSecurityDescriptor | Requires `OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION` (0x04) flag |
| FILETIME = 0 | means "never" — treat as None, not epoch |
| Large evidence lists | Cap at 50 items in HTML, 30 in PDF table. Add "(and N more)" |
| PSO container | May not exist on older domains — handle `NO_SUCH_OBJECT` gracefully |

---

## 7. Conventions

- All findings must have a non-empty `title`, `description`, `remediation`.
- Evidence items: plain strings, one item per line in the HTML `<pre>`.
- Analyzer errors: catch `LDAPException`, return a single `INFO` finding with the error text.
- No `print()` in analyzers — use `Finding` with severity INFO for non-critical messages.
- Do not write to AD. If you accidentally discover a write attempt, stop and raise `RuntimeError`.

---

*This scaffold was designed by Claude (Anthropic) in collaboration with @mr7security.*
*Questions → open a GitHub Discussion in the repo.*
