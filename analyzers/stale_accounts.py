"""
analyzers/stale_accounts.py — Detect inactive/stale user and computer accounts (T1078).
Stale accounts are enabled but not used in >90 days — easy targets for abuse.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import List, Optional

from analyzers.base import BaseAnalyzer
from report.models import Finding, Severity
from config import STALE_USER_DAYS, PRIVILEGED_GROUPS

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime_to_dt(ft: int) -> Optional[datetime]:
    """Convert Windows FILETIME integer to UTC datetime. Returns None if ft == 0 (never)."""
    if ft <= 0:
        return None
    return FILETIME_EPOCH + timedelta(microseconds=ft // 10)


def _days_since(dt: datetime) -> int:
    return (datetime.now(timezone.utc) - dt).days


class StaleAccountsAnalyzer(BaseAnalyzer):
    NAME        = "stale_accounts"
    DESCRIPTION = "Stale / inactive accounts"

    # Enabled users not logged in for >STALE_USER_DAYS days
    FILTER_USERS = (
        "(&(objectClass=user)"
        "(objectCategory=person)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        "(lastLogonTimestamp=*))"
    )
    FILTER_COMPUTERS = (
        "(&(objectClass=computer)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"
        "(lastLogonTimestamp=*))"
    )

    ATTRS = [
        "sAMAccountName", "lastLogonTimestamp", "pwdLastSet",
        "memberOf", "distinguishedName",
    ]

    def run(self) -> List[Finding]:
        findings: List[Finding] = []
        stale_users:     List[str] = []
        stale_da:        List[str] = []
        stale_computers: List[str] = []
        total_users = 0
        total_computers = 0

        # --- Users ---
        try:
            entries = self.connector.search(self.FILTER_USERS, self.ATTRS)
            total_users = len(entries)
            for entry in entries:
                sam = str(entry.sAMAccountName)
                try:
                    ft = int(str(entry.lastLogonTimestamp))
                    dt = _filetime_to_dt(ft)
                    if dt is None:
                        continue
                    days = _days_since(dt)
                    if days < STALE_USER_DAYS:
                        continue
                except Exception:
                    continue

                stale_users.append(f"{sam} ({days}d)")

                # Check if member of DA
                groups = [str(g).upper() for g in (entry.memberOf.values if entry.memberOf else [])]
                if any("DOMAIN ADMINS" in g for g in groups):
                    stale_da.append(sam)

        except Exception as exc:
            findings.append(Finding(
                title="StaleAccountsAnalyzer: LDAP error (users)",
                severity=Severity.INFO,
                description=str(exc),
                analyzer=self.NAME,
            ))

        # --- Computers ---
        try:
            entries = self.connector.search(self.FILTER_COMPUTERS, self.ATTRS)
            total_computers = len(entries)
            for entry in entries:
                sam = str(entry.sAMAccountName)
                try:
                    ft = int(str(entry.lastLogonTimestamp))
                    dt = _filetime_to_dt(ft)
                    if dt is None:
                        continue
                    days = _days_since(dt)
                    if days < STALE_USER_DAYS:
                        continue
                except Exception:
                    continue
                stale_computers.append(f"{sam} ({days}d)")
        except Exception as exc:
            findings.append(Finding(
                title="StaleAccountsAnalyzer: LDAP error (computers)",
                severity=Severity.INFO,
                description=str(exc),
                analyzer=self.NAME,
            ))

        # --- Findings ---
        # Stale DA members — always CRITICAL
        for sam in stale_da:
            findings.append(Finding(
                title=f"Stale Domain Admin account: {sam}",
                severity=Severity.CRITICAL,
                description=(
                    f"'{sam}' is a member of Domain Admins but has not logged in for "
                    f">{STALE_USER_DAYS} days. Stale privileged accounts are prime targets "
                    "for password spray / credential stuffing attacks."
                ),
                evidence=[f"sAMAccountName: {sam}", f"No login in >{STALE_USER_DAYS} days"],
                remediation=(
                    "Disable or delete unused privileged accounts immediately. "
                    "Remove from Domain Admins if no longer needed."
                ),
                references=["https://attack.mitre.org/techniques/T1078/"],
                analyzer=self.NAME,
                mitre_id="T1078",
            ))

        # Stale users summary
        if stale_users:
            pct = (len(stale_users) / total_users * 100) if total_users else 0
            severity = Severity.HIGH if pct > 10 or len(stale_users) > 50 else Severity.MEDIUM
            findings.append(Finding(
                title=f"{len(stale_users)} stale user accounts (>{STALE_USER_DAYS}d inactive)",
                severity=severity,
                description=(
                    f"{len(stale_users)} enabled user accounts ({pct:.1f}% of {total_users} total) "
                    f"have not logged in for more than {STALE_USER_DAYS} days. "
                    "These accounts represent an unnecessary attack surface."
                ),
                evidence=(stale_users[:50] + [f"... and {len(stale_users)-50} more"] if len(stale_users) > 50 else stale_users),
                remediation=(
                    "Disable accounts inactive for >90 days and delete after 180 days. "
                    "Implement a joiner/mover/leaver process. "
                    "Use AD lifecycle management tools."
                ),
                references=["https://attack.mitre.org/techniques/T1078/"],
                analyzer=self.NAME,
                mitre_id="T1078",
            ))

        # Stale computers summary
        if stale_computers:
            pct = (len(stale_computers) / total_computers * 100) if total_computers else 0
            severity = Severity.MEDIUM if pct > 10 else Severity.LOW
            findings.append(Finding(
                title=f"{len(stale_computers)} stale computer accounts (>{STALE_USER_DAYS}d inactive)",
                severity=severity,
                description=(
                    f"{len(stale_computers)} computer accounts ({pct:.1f}% of {total_computers}) "
                    f"have not authenticated in >{STALE_USER_DAYS} days. "
                    "These may be decommissioned systems still in AD."
                ),
                evidence=(stale_computers[:30] + [f"... and {len(stale_computers)-30} more"] if len(stale_computers) > 30 else stale_computers),
                remediation="Disable and remove stale computer accounts. Audit via 'lastLogonTimestamp' regularly.",
                analyzer=self.NAME,
                mitre_id="T1078",
            ))

        return findings
