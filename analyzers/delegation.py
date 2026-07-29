"""
analyzers/delegation.py — Kerberos delegation (unconstrained/constrained/RBCD).
MITRE ATT&CK: T1558, T1134.001
TODO (Devin): implement run() — see HANDOFF.md Issue 5
"""
from typing import List
from analyzers.base import BaseAnalyzer
from report.models import Finding, Severity


class DelegationAnalyzer(BaseAnalyzer):
    NAME = "delegation"
    DESCRIPTION = "Kerberos delegation (unconstrained/constrained/RBCD)"

    # Unconstrained: TRUSTED_FOR_DELEGATION set, SERVER_TRUST_ACCOUNT not set
    _FILTER_UNCONSTRAINED = (
        "(&(|(objectClass=user)(objectClass=computer))"
        "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=8192)))"
    )
    # Constrained: msDS-AllowedToDelegateTo present
    _FILTER_CONSTRAINED = (
        "(&(|(objectClass=user)(objectClass=computer))(msDS-AllowedToDelegateTo=*))"
    )
    # RBCD: msDS-AllowedToActOnBehalfOfOtherIdentity present
    _FILTER_RBCD = (
        "(&(objectClass=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
    )
    SENSITIVE_SPN_PREFIXES = ("cifs/","ldap/","krbtgt/","GC/","host/")

    def run(self) -> List[Finding]:
        """
        TODO (Devin):
        1. Run 3 searches (unconstrained, constrained, RBCD)
        2. Unconstrained -> CRITICAL per account
        3. Constrained -> HIGH if SPN matches SENSITIVE_SPN_PREFIXES, MEDIUM otherwise
        4. RBCD -> parse security descriptor via impacket, MEDIUM/HIGH
        5. INFO if all three return zero results
        """
        raise NotImplementedError
