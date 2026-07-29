# AD Attack Surface Analyzer

> Read-only Active Directory security assessment tool for pentesters and red teamers.

Connects to a domain controller via LDAP(S) and generates a comprehensive attack surface report. No exploitation, no writes, pure enumeration.

## What it detects

| Module | Check | MITRE |
|--------|-------|-------|
| `kerberoast` | Service accounts with SPNs (Kerberoastable) | T1558.003 |
| `asrep` | Accounts with no Kerberos pre-auth (AS-REP Roastable) | T1558.004 |
| `delegation` | Unconstrained / constrained / RBCD delegation | T1558 |
| `acl` | Dangerous ACEs on sensitive objects + DCSync rights | T1003.006 |
| `password_policy` | Default + fine-grained policy gaps, spray risk | -- |
| `stale_accounts` | Inactive users/computers (>90 days) | T1078 |
| `privileged_groups` | DA/EA/SA membership, LAPS, Protected Users | T1078.002 |

## Output

- `report.html` -- interactive report (collapsible findings, ES/EN toggle, risk gauge)
- `report_auditoria.pdf` -- 7-section audit PDF with cover page, TOC, and evidence

## Installation

```
git clone https://github.com/mr7security/ad-attack-surface-analyzer
cd ad-attack-surface-analyzer
pip install -r requirements.txt
```

## Usage

```
# Simple bind (use --ssl in production)
python main.py --target dc01.corp.local --domain corp.local --auth simple --username pentest --password P@ss! --ssl

# NTLM (no Kerberos setup needed)
python main.py --target 192.168.1.10 --domain corp.local --auth ntlm --username CORP\pentest --password P@ss!

# Kerberos with existing ccache (stealthiest)
export KRB5CCNAME=/tmp/pentest.ccache
python main.py --target dc01.corp.local --domain corp.local --auth kerberos

# Run only specific checks
python main.py ... --only kerberoast,asrep,delegation

# Skip PDF generation
python main.py ... --no-pdf
```

## Authentication methods

| Method | Requirements | Notes |
|--------|-------------|-------|
| `simple` | username + password | Use with `--ssl`. Cleartext without it. |
| `ntlm` | username (DOMAIN\user) + password | No Kerberos setup needed. Works from Linux/Windows. |
| `kerberos` | Valid TGT (ccache or keytab) | Most silent. Use after kinit or pass --ccache. |

## Risk scoring

| Score | Label |
|-------|-------|
| >= 80 | Critical |
| >= 60 | High |
| >= 40 | Medium |
| < 40  | Low |

## Related tools

- **IAM Risk Analyzer** (`mr7security/iam-risk-analyzer`) -- Entra ID / Azure AD equivalent of this tool

## Legal notice

This tool is intended for authorized security assessments only. Use against systems you own or have explicit written permission to test. The authors are not responsible for misuse.

---

*Part of the mr7security red team toolkit.*
