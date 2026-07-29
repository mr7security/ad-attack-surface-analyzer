"""
analyzers/password_policy.py — Detect password policy weaknesses.

Checks:
  - Default domain password policy (minLength, lockout, complexity, maxAge)
  - Fine-Grained Password Policies (PSOs)
  - Accounts with DONT_EXPIRE_PASSWORD UAC flag
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import List

from analyzers.base import BaseAnalyzer
from report.models import Finding, Severity
from config import PASSWORD_MIN_LENGTH, LOCKOUT_THRESHOLD

FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
# 100-nanosecond intervals in a day
DAY_INTERVALS = 864000000000

UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_DISABLED             = 0x2


def _intervals_to_days(intervals: int) -> int:
    """Convert negative LDAP time intervals to positive days."""
    if intervals == 0 or intervals == -9223372036854775808:
        return 0
    return abs(intervals) // DAY_INTERVALS


class PasswordPolicyAnalyzer(BaseAnalyzer):
    NAME        = "password_policy"
    DESCRIPTION = "Password policy weaknesses"

    FILTER_DOMAIN_POLICY = "(objectClass=domainDNS)"
    FILTER_PSO           = "(objectClass=msDS-PasswordSettings)"
    FILTER_NO_EXPIRE     = (
        "(&(objectClass=user)"
        "(userAccountControl:1.2.840.113556.1.4.803:=65536)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    )

    POLICY_ATTRS = [
        "minPwdLength", "lockoutThreshold", "lockoutObservationWindow",
        "lockoutDuration", "pwdProperties", "maxPwdAge", "minPwdAge",
        "pwdHistoryLength", "distinguishedName",
    ]
    PSO_ATTRS = [
        "name", "msDS-MinimumPasswordLength", "msDS-LockoutThreshold",
        "msDS-PasswordComplexityEnabled", "msDS-MaximumPasswordAge",
        "msDS-PasswordHistoryLength", "msDS-PSOAppliesTo",
        "msDS-PasswordSettingsPrecedence",
    ]
    NO_EXPIRE_ATTRS = ["sAMAccountName", "userAccountControl", "memberOf"]

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        # --- Default domain password policy ---
        try:
            entries = self.connector.search(
                self.FILTER_DOMAIN_POLICY,
                self.POLICY_ATTRS,
                search_base=self.connector.base_dn,
            )
            if entries:
                pol = entries[0]
                min_len      = int(str(pol.minPwdLength))      if pol.minPwdLength      else 0
                lockout_thr  = int(str(pol.lockoutThreshold))  if pol.lockoutThreshold  else 0
                pwd_props    = int(str(pol.pwdProperties))     if pol.pwdProperties     else 0
                max_age_raw  = int(str(pol.maxPwdAge))         if pol.maxPwdAge         else 0
                complexity   = bool(pwd_props & 0x1)
                max_age_days = _intervals_to_days(max_age_raw)

                evidence = [
                    f"Minimum password length: {min_len}",
                    f"Lockout threshold: {lockout_thr} ({'DISABLED' if lockout_thr == 0 else 'attempts'})",
                    f"Complexity required: {'Yes' if complexity else 'NO'}",
                    f"Maximum password age: {max_age_days} days ({'never' if max_age_days == 0 else ''})".strip(),
                ]

                if lockout_thr == 0:
                    findings.append(Finding(
                        title="Account lockout disabled (password spraying risk)",
                        severity=Severity.CRITICAL,
                        description=(
                            "The domain has no account lockout policy (lockoutThreshold = 0). "
                            "Attackers can perform unlimited password spraying attempts without "
                            "locking accounts, making brute-force attacks trivial."
                        ),
                        evidence=evidence,
                        remediation=(
                            "Set a lockout threshold of 5-10 failed attempts with a 30-minute observation window. "
                            "Consider using Microsoft's Fine-Grained Password Policies for service accounts."
                        ),
                        references=["https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold"],
                        analyzer=self.NAME,
                    ))
                elif min_len < 8 or not complexity:
                    findings.append(Finding(
                        title="Weak default password policy",
                        severity=Severity.HIGH,
                        description=(
                            f"Default password policy has minimum length {min_len} "
                            f"and complexity {'enabled' if complexity else 'DISABLED'}. "
                            "Weak passwords are easy to crack offline or via spraying."
                        ),
                        evidence=evidence,
                        remediation=(
                            "Set minimum password length to at least 12 characters and enable complexity. "
                            "Consider enforcing passphrases (14+ chars) without complexity for usability."
                        ),
                        analyzer=self.NAME,
                    ))
                elif min_len < PASSWORD_MIN_LENGTH:
                    findings.append(Finding(
                        title=f"Password minimum length below recommended ({min_len} < {PASSWORD_MIN_LENGTH})",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Default domain password policy requires only {min_len} characters. "
                            f"Recommended minimum is {PASSWORD_MIN_LENGTH}."
                        ),
                        evidence=evidence,
                        remediation=f"Increase minPwdLength to at least {PASSWORD_MIN_LENGTH}.",
                        analyzer=self.NAME,
                    ))
                else:
                    findings.append(Finding(
                        title="Default password policy: acceptable",
                        severity=Severity.INFO,
                        description="Default domain password policy meets minimum security requirements.",
                        evidence=evidence,
                        analyzer=self.NAME,
                    ))
        except Exception as exc:
            findings.append(Finding(
                title="PasswordPolicyAnalyzer: LDAP error (domain policy)",
                severity=Severity.INFO,
                description=str(exc),
                analyzer=self.NAME,
            ))

        # --- Fine-Grained Password Policies ---
        try:
            pso_base = f"CN=Password Settings Container,CN=System,{self.connector.base_dn}"
            pso_entries = self.connector.search(self.FILTER_PSO, self.PSO_ATTRS, search_base=pso_base)
            for pso in pso_entries:
                name     = str(pso.name)
                min_len  = int(str(pso["msDS-MinimumPasswordLength"])) if pso["msDS-MinimumPasswordLength"] else 0
                lockout  = int(str(pso["msDS-LockoutThreshold"]))       if pso["msDS-LockoutThreshold"]     else 0
                applies  = list(pso["msDS-PSOAppliesTo"].values)        if pso["msDS-PSOAppliesTo"]         else []

                evidence = [
                    f"PSO name: {name}",
                    f"Min length: {min_len}",
                    f"Lockout threshold: {lockout}",
                    f"Applies to: {len(applies)} object(s)",
                ]

                if lockout == 0 or min_len < 8:
                    findings.append(Finding(
                        title=f"Weak Fine-Grained Password Policy: {name}",
                        severity=Severity.HIGH,
                        description=(
                            f"PSO '{name}' has weak settings: min length={min_len}, lockout={lockout}. "
                            "This PSO overrides the domain default for the objects it applies to."
                        ),
                        evidence=evidence,
                        remediation="Update PSO to require at least 12 characters and lockout after 5-10 attempts.",
                        analyzer=self.NAME,
                    ))
        except Exception:
            pass  # PSO container may not exist on older domains

        # --- Accounts with password never expires ---
        try:
            no_expire = self.connector.search(self.FILTER_NO_EXPIRE, self.NO_EXPIRE_ATTRS)
            if len(no_expire) > 10:
                findings.append(Finding(
                    title=f"{len(no_expire)} enabled accounts with non-expiring passwords",
                    severity=Severity.MEDIUM,
                    description=(
                        f"{len(no_expire)} enabled user accounts have the 'Password Never Expires' "
                        "flag set. These accounts may have stale passwords that are easier to crack."
                    ),
                    evidence=[f"sAMAccountName: {str(e.sAMAccountName)}" for e in no_expire[:20]]
                             + ([f"... and {len(no_expire)-20} more"] if len(no_expire) > 20 else []),
                    remediation=(
                        "Enforce regular password changes or migrate accounts to gMSAs. "
                        "Clear the DONT_EXPIRE_PASSWORD flag for user accounts."
                    ),
                    analyzer=self.NAME,
                ))
        except Exception as exc:
            findings.append(Finding(
                title="PasswordPolicyAnalyzer: LDAP error (no-expire accounts)",
                severity=Severity.INFO,
                description=str(exc),
                analyzer=self.NAME,
            ))

        return findings
