"""
analyzers/kerberoast.py — Detect Kerberoastable accounts (SPN enumeration).
MITRE ATT&CK: T1558.003
TODO (Devin): implement run() — see HANDOFF.md Issue 3
"""
from typing import List
from analyzers.base import BaseAnalyzer
from report.models import Finding, Severity


class KerberoastAnalyzer(BaseAnalyzer):
    NAME = "kerberoast"
    DESCRIPTION = "Kerberoastable service accounts (SPN enumeration)"

    _FILTER = (
        "(&(objectClass=user)(!(objectClass=computer))"
        "(servicePrincipalName=*)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    )
    _ATTRS = ["sAMAccountName","distinguishedName","servicePrincipalName",
              "pwdLastSet","userAccountControl","memberOf","description"]

    def run(self) -> List[Finding]:
        """
        TODO (Devin):
        1. search(_FILTER, _ATTRS)
        2. For each entry: decode UAC, compute password age, check privileged group membership
        3. Severity: CRITICAL if in privileged group, HIGH if pwd never expires or age>365d, MEDIUM otherwise
        4. mitre_id="T1558.003"
        5. Return INFO finding if none found
        """
        raise NotImplementedError
