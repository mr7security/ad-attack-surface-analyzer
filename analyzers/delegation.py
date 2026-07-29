"""
analyzers/delegation.py — Detect dangerous Kerberos delegation configurations.

Checks:
  - Unconstrained delegation (TRUSTED_FOR_DELEGATION UAC flag) — CRITICAL
  - Constrained delegation (msDS-AllowedToDelegateTo)          — HIGH / MEDIUM
  - Resource-Based Constrained Delegation (RBCD)               — MEDIUM
"""
from __future__ import annotations

from typing import List

from analyzers.base import BaseAnalyzer
from report.models import Finding, Severity

# UAC flags
UAC_TRUSTED_FOR_DELEGATION = 0x80000   # unconstrained
UAC_TRUSTED_TO_AUTH        = 0x1000000  # constrained (protocol transition)
UAC_SERVER_TRUST           = 0x2000     # domain controller

SENSITIVE_SPN_PREFIXES = ("cifs", "ldap", "host", "krbtgt", "http", "gc", "dns")


class DelegationAnalyzer(BaseAnalyzer):
    NAME        = "delegation"
    DESCRIPTION = "Dangerous Kerberos delegation"

    FILTER_UNCONSTRAINED = (
        "(&(|(objectClass=user)(objectClass=computer))"
        "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    )
    FILTER_CONSTRAINED = (
        "(&(|(objectClass=user)(objectClass=computer))"
        "(msDS-AllowedToDelegateTo=*)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    )
    FILTER_RBCD = (
        "(&(|(objectClass=user)(objectClass=computer))"
        "(msDS-AllowedToActOnBehalfOfOtherIdentity=*))"
    )
    ATTRS_UC = ["sAMAccountName", "userAccountControl", "objectClass", "distinguishedName"]
    ATTRS_C  = ["sAMAccountName", "msDS-AllowedToDelegateTo", "userAccountControl", "objectClass"]
    ATTRS_RBCD = ["sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity", "objectClass"]

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        # --- Unconstrained ---
        try:
            entries = self.connector.search(self.FILTER_UNCONSTRAINED, self.ATTRS_UC)
            for entry in entries:
                sam = str(entry.sAMAccountName)
                uac = int(str(entry.userAccountControl)) if entry.userAccountControl else 0
                # Skip DCs (they always have unconstrained delegation)
                if uac & UAC_SERVER_TRUST:
                    continue
                findings.append(Finding(
                    title=f"Unconstrained delegation: {sam}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"'{sam}' has unconstrained Kerberos delegation enabled "
                        "(TRUSTED_FOR_DELEGATION UAC flag). If this account is compromised, "
                        "an attacker can impersonate ANY user in the domain by abusing the TGT "
                        "cached on this host (e.g., via PrinterBug / SpoolSS coercion)."
                    ),
                    evidence=[
                        f"sAMAccountName: {sam}",
                        f"UAC: TRUSTED_FOR_DELEGATION (0x80000) is set",
                        f"DN: {entry.distinguishedName}",
                    ],
                    remediation=(
                        "Remove unconstrained delegation. Migrate to constrained delegation "
                        "or RBCD. Mark sensitive accounts as 'Account is sensitive and cannot "
                        "be delegated'. Consider enabling Protected Users group membership."
                    ),
                    references=["https://attack.mitre.org/techniques/T1558/"],
                    analyzer=self.NAME,
                    mitre_id="T1558",
                ))
        except Exception as exc:
            findings.append(Finding(
                title="DelegationAnalyzer (unconstrained): LDAP error",
                severity=Severity.INFO,
                description=str(exc),
                analyzer=self.NAME,
            ))

        # --- Constrained ---
        try:
            entries = self.connector.search(self.FILTER_CONSTRAINED, self.ATTRS_C)
            for entry in entries:
                sam = str(entry.sAMAccountName)
                targets = list(entry["msDS-AllowedToDelegateTo"].values) if entry["msDS-AllowedToDelegateTo"] else []
                has_sensitive = any(
                    t.lower().startswith(prefix)
                    for t in targets
                    for prefix in SENSITIVE_SPN_PREFIXES
                )
                severity = Severity.HIGH if has_sensitive else Severity.MEDIUM
                findings.append(Finding(
                    title=f"Constrained delegation: {sam}",
                    severity=severity,
                    description=(
                        f"'{sam}' is configured for constrained Kerberos delegation to "
                        f"{len(targets)} SPN(s). If compromised, an attacker can impersonate "
                        "any user to those specific services."
                    ),
                    evidence=[f"sAMAccountName: {sam}"] + [f"Delegates to: {t}" for t in targets[:10]],
                    remediation=(
                        "Review and minimize the list of SPNs in msDS-AllowedToDelegateTo. "
                        "Use RBCD where possible. Ensure delegated accounts cannot delegate "
                        "to high-value services like CIFS/LDAP on DCs."
                    ),
                    references=["https://attack.mitre.org/techniques/T1558/"],
                    analyzer=self.NAME,
                    mitre_id="T1558",
                ))
        except Exception as exc:
            findings.append(Finding(
                title="DelegationAnalyzer (constrained): LDAP error",
                severity=Severity.INFO,
                description=str(exc),
                analyzer=self.NAME,
            ))

        # --- RBCD ---
        try:
            entries = self.connector.search(self.FILTER_RBCD, self.ATTRS_RBCD)
            for entry in entries:
                sam = str(entry.sAMAccountName)
                findings.append(Finding(
                    title=f"RBCD configured on: {sam}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"'{sam}' has msDS-AllowedToActOnBehalfOfOtherIdentity set "
                        "(Resource-Based Constrained Delegation). The principals listed in this "
                        "attribute can impersonate any user to this resource."
                    ),
                    evidence=[
                        f"sAMAccountName: {sam}",
                        "msDS-AllowedToActOnBehalfOfOtherIdentity is populated",
                    ],
                    remediation=(
                        "Review whether RBCD is intentionally configured on this object. "
                        "Any principal with write access to this attribute can add themselves "
                        "and impersonate domain users to this resource."
                    ),
                    references=["https://attack.mitre.org/techniques/T1558/"],
                    analyzer=self.NAME,
                    mitre_id="T1558",
                ))
        except Exception as exc:
            findings.append(Finding(
                title="DelegationAnalyzer (RBCD): LDAP error",
                severity=Severity.INFO,
                description=str(exc),
                analyzer=self.NAME,
            ))

        return findings
