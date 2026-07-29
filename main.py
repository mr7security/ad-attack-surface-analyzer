#!/usr/bin/env python3
"""main.py — AD Attack Surface Analyzer entry point."""
from __future__ import annotations
import argparse, sys
from datetime import datetime, timezone
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from config import ConnectionConfig
from connectors.ldap_connector import LDAPConnector, LDAPConnectorError
from analyzers import ALL_ANALYZERS
from report.models import AnalysisReport
from report import html_generator, pdf_generator

console = Console()

def parse_args():
    p = argparse.ArgumentParser(description="AD Attack Surface Analyzer — LDAP-based read-only AD security assessment")
    p.add_argument("--target",   required=True, help="DC hostname or IP")
    p.add_argument("--domain",   required=True, help="Domain FQDN (e.g. corp.local)")
    p.add_argument("--auth",     required=True, choices=["simple","ntlm","kerberos"])
    p.add_argument("--username", help="Username")
    p.add_argument("--password", help="Password")
    p.add_argument("--ccache",   help="Kerberos ccache path")
    p.add_argument("--keytab",   help="Kerberos keytab path")
    p.add_argument("--ssl",      action="store_true")
    p.add_argument("--port",     type=int)
    p.add_argument("--only",     help="Comma-separated analyzer names")
    p.add_argument("--output",   default="report.html")
    p.add_argument("--pdf",      default="report_auditoria.pdf")
    p.add_argument("--no-pdf",   action="store_true")
    return p.parse_args()

def main():
    args = parse_args()
    cfg = ConnectionConfig(
        target=args.target, domain=args.domain, auth_method=args.auth,
        username=args.username, password=args.password,
        ccache=args.ccache, keytab=args.keytab, use_ssl=args.ssl, port=args.port,
    )
    console.rule("[bold cyan]AD Attack Surface Analyzer")
    analyzers_to_run = ALL_ANALYZERS
    if args.only:
        names = {n.strip().lower() for n in args.only.split(",")}
        analyzers_to_run = [a for a in ALL_ANALYZERS if a.NAME in names]
        if not analyzers_to_run:
            console.print(f"[red]No matching analyzers for: {args.only}"); return 1
    try:
        connector = LDAPConnector(cfg)
        connector.connect()
    except LDAPConnectorError as exc:
        console.print(f"[red][!] Connection failed: {exc}"); return 1
    root_dse = connector.get_root_dse()
    report = AnalysisReport(
        domain=args.domain, dc_hostname=root_dse.get("dnsHostName", args.target),
        scan_time_utc=datetime.now(timezone.utc).isoformat(),
        os_version=root_dse.get("os_version",""),
        functional_level=int(root_dse.get("domainFunctionality",0)),
    )
    all_findings = []
    with Progress(SpinnerColumn(), TextColumn("{task.description}"), console=console) as prog:
        for analyzer_cls in analyzers_to_run:
            analyzer = analyzer_cls(connector)
            task = prog.add_task(f"[cyan]{analyzer.DESCRIPTION}...")
            try:
                findings = analyzer.run()
                all_findings.extend(findings)
                prog.update(task, description=f"[green]✓ {analyzer.DESCRIPTION}")
            except Exception as exc:
                prog.update(task, description=f"[red]✗ {analyzer.NAME}: {exc}")
            prog.remove_task(task)
    connector.disconnect()
    report.findings = all_findings
    report.compute_risk()
    console.print()
    html_generator.generate(report, args.output)
    if not args.no_pdf:
        pdf_generator.generate(report, args.pdf)
    console.rule(f"[bold]Risk Score: {report.risk_score}/100 ({report.risk_label}) | {len(report.findings)} findings")
    return 0

if __name__ == "__main__":
    sys.exit(main())
