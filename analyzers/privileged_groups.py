"""
analyzers/privileged_groups.py — Audit privileged group membership (T1078.002).

Checks:
  - Excessive membership in DA, EA, SA, Administrators, etc.
  - LAPS deployment (ms-Mcs-AdmPwd schema attribute)
  - Protected Users group membership
"""
from __future__ import annotations

from typing import List

from ldap3 import BASE

from analyzers.base import BaseAnalyzer
from report.models import Finding, Severity
from config import PRIVILEGED_GROUPS

# Thresholds for "too many" members
MAX_MEMBERS: dict = {
    "domain admins":      5,
    "enterprise admins":  3,
    "schema admins":      1,
    "administrators":     10,
    "account operators":  5,
    "backup operators":   5,
    "print operators":    5,
    "server operators":   5,
}

# Schema attribute that proves LAPS is deployed
LAPS_ATTR = "ms-Mcs-AdmPwd"


class PrivilegedGroupsAnalyzer(BaseAnalyzer):
    NAME        = "privileged_groups"
    DESCRIPTION = "Privileged group membership & LAPS"

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        # --- LAPS check ---
        try:
            schema_nc = self._get_schema_nc()
            if schema_nc:
                self.connector._conn.search(
                    search_base=schema_nc,
                    search_filter=f"(lDAPDisplayName={LAPS_ATTR})",
                    search_scope=BASE.__class__.__name__ and "SUBTREE",
                    attributes=["lDAPDisplayName"],
                )
                laps_deployed = bool(self.connector._conn.entries)
            else:
                laps_deployed = False
        except Exception:
            laps_deployed = False

        if not laps_deployed:
            findings.append(Finding(
                title="LAPS is not deployed",
                severity=Severity.HIGH,
                description=(
                    "Local Administrator Password Solution (LAPS) is not detected in the AD schema. "
                    "Without LAPS, local administrator accounts likely share the same password across "
                    "all workstations, enabling lateral movement after a single compromise."
                ),
                evidence=[f"Schema attribute '{LAPS_ATTR}' not found in AD schema"],
                remediation=(
                    "Deploy LAPS (or Windows LAPS for newer environments) to randomize local "
                    "administrator passwords on all domain-joined machines. "
                    "Download from: https://www.microsoft.com/en-us/download/details.aspx?id=46899"
                ),
                references=["https://attack.mitre.org/techniques/T1078/002/"],
                analyzer=self.NAME,
                mitre_id="T1078.002",
            ))
        else:
            findings.append(Finding(
                title="LAPS is deployed",
                severity=Severity.INFO,
                description="Local Administrator Password Solution (LAPS) schema attribute detected.",
                evidence=[f"Schema attribute '{LAPS_ATTR}' found"],
                analyzer=self.NAME,
            ))

        # --- Privileged group membership ---
        for group_cn in PRIVILEGED_GROUPS:
            try:
                members = self._get_group_members(group_cn)
                if members is None:
                    continue

                threshold = MAX_MEMBERS.get(group_cn.lower())
                group_lower = group_cn.lower()

                evidence = [f"Group: {group_cn}", f"Member count: {len(members)}"]
                evidence += [f"Member: {m}" for m in members[:20]]
                if len(members) > 20:
                    evidence.append(f"... and {len(members)-20} more")

                if threshold is not None and len(members) > threshold:
                    if "enterprise admins" in group_lower or "schema admins" in group_lower:
                        severity = Severity.CRITICAL
                    elif "domain admins" in group_lower:
                        severity = Severity.CRITICAL
                    else:
                        severity = Severity.HIGH

                    findings.append(Finding(
                        title=f"Excessive membership in {group_cn} ({len(members)} members)",
                        severity=severity,
                        description=(
                            f"'{group_cn}' has {len(members)} members, exceeding the recommended "
                            f"maximum of {threshold}. Excessive privileged group membership "
                            "increases the blast radius of credential compromise."
                        ),
                        evidence=evidence,
                        remediation=(
                            f"Reduce {group_cn} membership to <= {threshold} accounts. "
                            "Use tiered administration: Tier 0 (DCs), Tier 1 (servers), Tier 2 (workstations). "
                            "Remove service accounts and regular user accounts from privileged groups."
                        ),
                        references=["https://attack.mitre.org/techniques/T1078/002/"],
                        analyzer=self.NAME,
                        mitre_id="T1078.002",
                    ))
                elif len(members) == 0 and "schema admins" in group_lower:
                    findings.append(Finding(
                        title=f"{group_cn}: empty (good)",
                        severity=Severity.INFO,
                        description=f"'{group_cn}' has no members, which is the recommended state.",
                        evidence=evidence,
                        analyzer=self.NAME,
                    ))
                else:
                    findings.append(Finding(
                        title=f"{group_cn}: {len(members)} member(s)",
                        severity=Severity.INFO,
                        description=f"'{group_cn}' has {len(members)} member(s), within acceptable range.",
                        evidence=evidence,
                        analyzer=self.NAME,
                    ))

            except Exception as exc:
                findings.append(Finding(
                    title=f"PrivilegedGroupsAnalyzer: error querying {group_cn}",
                    severity=Severity.INFO,
                    description=str(exc),
                    analyzer=self.NAME,
                ))

        # --- Protected Users ---
        try:
            pu_members = self._get_group_members("Protected Users")
            if pu_members is not None:
                if len(pu_members) == 0:
                    findings.append(Finding(
                        title="Protected Users group is empty",
                        severity=Severity.MEDIUM,
                        description=(
                            "The 'Protected Users' security group is empty. Adding privileged accounts "
                            "to this group prevents NTLM auth, credential caching, and DES/RC4 Kerberos, "
                            "significantly reducing credential theft risk."
                        ),
                        evidence=["Protected Users group has 0 members"],
                        remediation=(
                            "Add all Tier 0 accounts (Domain Admins, service accounts with DA rights) "
                            "to the Protected Users group. Test for compatibility first."
                        ),
                        analyzer=self.NAME,
                    ))
                else:
                    findings.append(Finding(
                        title=f"Protected Users: {len(pu_members)} member(s)",
                        severity=Severity.INFO,
                        description=f"Protected Users group has {len(pu_members)} member(s).",
                        evidence=[f"Member: {m}" for m in pu_members[:10]],
                        analyzer=self.NAME,
                    ))
        except Exception:
            pass

        return findings

    def _get_schema_nc(self) -> str:
        """Return the schema naming context DN."""
        try:
            info = self.connector._server.info
            if info and info.other.get("schemaNamingContext"):
                nc = info.other["schemaNamingContext"]
                return nc[0] if isinstance(nc, list) else nc
        except Exception:
            pass
        return ""

    def _get_group_members(self, group_cn: str) -> List[str]:
        """Return list of member DNs for a group, handling range retrieval."""
        entries = self.connector.search(
            f"(&(objectClass=group)(cn={group_cn}))",
            ["member;range=0-*", "member", "cn"],
        )
        if not entries:
            return []
        entry = entries[0]
        # Try range attribute first
        members = []
        for attr_name in entry.entry_attributes:
            if attr_name.startswith("member"):
                vals = getattr(entry, attr_name, None)
                if vals:
                    members = [str(v) for v in vals.values]
                break
        return members
