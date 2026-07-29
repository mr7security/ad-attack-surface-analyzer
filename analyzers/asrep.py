"""
analyzers/asrep.py — Detect AS-REP Roastable accounts (T1558.004).
Accounts with DONT_REQ_PREAUTH UAC flag set do not require Kerberos pre-authentication,
allowing an attacker to request an AS-REP and crack it offline.
"""
from __future__ import annotations

from typing import List

from analyzers.base import BaseAnalyzer
from report.models import Finding, Severity
from config import PRIVILEGED_GROUPS

# UAC flag: DONT_REQ_PREAUTH = 0x400000 = 4194304
DONT_REQ_PREAUTH = 0x400000


class ASREPAnalyzer(BaseAnalyzer):
    NAME        = "asrep"
    DESCRIPTION = "AS-REP Roastable accounts (no pre-auth)"

    LDAP_FILTER = (
        "(&(objectClass=user)"
        "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    )
    ATTRS = [
        "sAMAccountName", "userAccountControl", "memberOf",
        "lastLogonTimestamp", "distinguishedName",
    ]

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        try:
            entries = self.connector.search(self.LDAP_FILTER, self.ATTRS)
        except Exception as exc:
            return [Finding(
                title="ASREPAnalyzer: LDAP error",
                severity=Severity.INFO,
                description=str(exc),
                analyzer=self.NAME,
            )]

        for entry in entries:
            sam = str(entry.sAMAccountName)
            groups = [str(g).upper() for g in (entry.memberOf.values if entry.memberOf else [])]

            is_privileged = any(
                pg.upper() in grp for pg in PRIVILEGED_GROUPS for grp in groups
            )

            severity = Severity.CRITICAL if is_privileged else Severity.HIGH

            evidence = [
                f"sAMAccountName: {sam}",
                "UAC flag: DONT_REQ_PREAUTH is set",
            ]
            if is_privileged:
                evidence.append("Member of privileged group")

            findings.append(Finding(
                title=f"AS-REP Roastable account: {sam}",
                severity=severity,
                description=(
                    f"Account '{sam}' does not require Kerberos pre-authentication "
                    "(DONT_REQ_PREAUTH UAC flag is set). An unauthenticated attacker can request "
                    "an AS-REP for this account and crack it offline to recover the password."
                ),
                evidence=evidence,
                remediation=(
                    "Enable Kerberos pre-authentication for this account by clearing the "
                    "'Do not require Kerberos preauthentication' flag in Active Directory. "
                    "Audit why this flag was set and whether it is still necessary."
                ),
                references=["https://attack.mitre.org/techniques/T1558/004/"],
                analyzer=self.NAME,
                mitre_id="T1558.004",
            ))

        return findings
