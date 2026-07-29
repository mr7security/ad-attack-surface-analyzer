"""
analyzers/asrep.py — AS-REP Roastable accounts (no Kerberos pre-auth).
MITRE ATT&CK: T1558.004
TODO (Devin): implement run() — see HANDOFF.md Issue 4
"""
from typing import List
from analyzers.base import BaseAnalyzer
from report.models import Finding, Severity


class ASREPAnalyzer(BaseAnalyzer):
    NAME = "asrep"
    DESCRIPTION = "AS-REP Roastable accounts (no Kerberos pre-auth required)"

    _FILTER = (
        "(&(objectClass=user)(!(objectClass=computer))"
        "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    )
    _ATTRS = ["sAMAccountName","distinguishedName","userAccountControl","memberOf","pwdLastSet"]

    def run(self) -> List[Finding]:
        """
        TODO (Devin):
        1. search(_FILTER, _ATTRS)
        2. CRITICAL if in privileged group, HIGH otherwise
        3. mitre_id="T1558.004"
        4. INFO if none found
        """
        raise NotImplementedError
