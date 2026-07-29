"""
analyzers/password_policy.py — Default and fine-grained password policy gaps.
TODO (Devin): implement run() — see HANDOFF.md Issue 7
"""
from typing import List
from analyzers.base import BaseAnalyzer
from report.models import Finding, Severity
from config import PASSWORD_MIN_LENGTH, LOCKOUT_THRESHOLD, LOCKOUT_DURATION


class PasswordPolicyAnalyzer(BaseAnalyzer):
    NAME = "password_policy"
    DESCRIPTION = "Default and fine-grained password policy gaps"

    _ATTRS_DOMAIN = ["minPwdLength","pwdHistoryLength","maxPwdAge",
                     "lockoutThreshold","lockoutDuration","pwdProperties"]
    _ATTRS_PSO = ["cn","msDS-MinimumPasswordLength","msDS-PasswordHistoryLength",
                  "msDS-MaximumPasswordAge","msDS-LockoutThreshold",
                  "msDS-LockoutDuration","msDS-PasswordComplexityEnabled",
                  "msDS-PasswordSettingsPrecedence","msDS-PSOAppliesTo"]
    _FILTER_NOEXPIRE = (
        "(&(objectClass=user)(!(objectClass=computer))"
        "(userAccountControl:1.2.840.113556.1.4.803:=65536)"
        "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    )

    def run(self) -> List[Finding]:
        """
        TODO (Devin):
        Severity: CRITICAL=no lockout, HIGH=minLen<8 or no complexity or no maxAge,
        MEDIUM=minLen<12, MEDIUM=lockoutDuration<30min, LOW=historyLen<10
        Also check PSOs and accounts with DONT_EXPIRE_PASSWORD.
        Note: maxPwdAge/lockoutDuration stored as negative 100ns intervals.
        """
        raise NotImplementedError
