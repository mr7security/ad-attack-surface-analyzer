"""
analyzers/kerberoast.py — Detect Kerberoastable accounts (T1558.003).
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import List

from analyzers.base import BaseAnalyzer
from report.models import Finding, Severity
from config import PRIVILEGED_GROUPS

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime_to_dt(ft: int) -> datetime:
    return FILETIME_EPOCH + timedelta(microseconds=ft // 10)


class KerberoastAnalyzer(BaseAnalyzer):
    NAME        = "kerberoast"
    DESCRIPTION = "Kerberoastable accounts (SPNs)"

    LDAP_FILTER = (
        "(&(objectClass=user)"
        "(servicePrincipalName=*)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    )
    ATTRS = [
        "sAMAccountName", "servicePrincipalName", "userAccountControl",
        "memberOf", "pwdLastSet", "lastLogonTimestamp", "distinguishedName",
    ]

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        try:
            entries = self.connector.search(self.LDAP_FILTER, self.ATTRS)
        except Exception as exc:
            return [Finding(
                title="KerberoastAnalyzer: LDAP error",
                severity=Severity.INFO,
                description=str(exc),
                analyzer=self.NAME,
            )]

        for entry in entries:
            sam = str(entry.sAMAccountName)
            spns = list(entry.servicePrincipalName.values) if entry.servicePrincipalName else []
            uac = int(str(entry.userAccountControl)) if entry.userAccountControl else 0
            groups = [str(g).upper() for g in (entry.memberOf.values if entry.memberOf else [])]

            # Skip krbtgt itself
            if sam.lower() == "krbtgt":
                continue

            # Privileged group check
            is_privileged = any(
                pg.upper() in grp for pg in PRIVILEGED_GROUPS for grp in groups
            )

            # Password age check
            pwd_never_expires = bool(uac & 0x10000)
            pwd_old = False
            if entry.pwdLastSet:
                try:
                    ft = int(str(entry.pwdLastSet))
                    if ft > 0:
                        dt = _filetime_to_dt(ft)
                        pwd_old = (datetime.now(timezone.utc) - dt).days > 365
                except Exception:
                    pass

            if is_privileged:
                severity = Severity.CRITICAL
            elif pwd_never_expires or pwd_old:
                severity = Severity.HIGH
            else:
                severity = Severity.MEDIUM

            evidence = [f"sAMAccountName: {sam}"]
            evidence += [f"SPN: {spn}" for spn in spns[:10]]
            if pwd_never_expires:
                evidence.append("Password: NEVER EXPIRES")
            if pwd_old:
                evidence.append("Password: last set >365 days ago")
            if is_privileged:
                evidence.append("Member of privileged group")

            findings.append(Finding(
                title=f"Kerberoastable account: {sam}",
                severity=severity,
                description=(
                    f"Account '{sam}' has registered Service Principal Names (SPNs) and is enabled. "
                    "An attacker can request a Kerberos TGS ticket for the account and crack it "
                    "offline to recover the plaintext password."
                ),
                evidence=evidence,
                remediation=(
                    "Replace with Managed Service Accounts (gMSA) where possible. "
                    "If regular accounts must be used, ensure passwords are >25 characters and rotated regularly. "
                    "Remove unnecessary SPNs. Consider enabling AES-only encryption for service accounts."
                ),
                references=["https://attack.mitre.org/techniques/T1558/003/"],
                analyzer=self.NAME,
                mitre_id="T1558.003",
            ))

        return findings
