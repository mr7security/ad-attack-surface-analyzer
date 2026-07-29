"""
analyzers/stale_accounts.py — Stale user/computer accounts.
TODO (Devin): implement run() — see HANDOFF.md Issue 8
FILETIME conversion: EPOCH=datetime(1601,1,1,tzinfo=utc), dt=EPOCH+timedelta(microseconds=filetime//10)
"""
from typing import List
from analyzers.base import BaseAnalyzer
from report.models import Finding, Severity
from config import STALE_USER_DAYS, STALE_COMPUTER_DAYS


class StaleAccountsAnalyzer(BaseAnalyzer):
    NAME = "stale_accounts"
    DESCRIPTION = f"Stale user/computer accounts (>{STALE_USER_DAYS}d inactive)"

    _ATTRS = ["sAMAccountName","distinguishedName","lastLogonTimestamp","whenCreated","userAccountControl"]

    def run(self) -> List[Finding]:
        """
        TODO (Devin):
        1. Compute FILETIME threshold for STALE_USER_DAYS and STALE_COMPUTER_DAYS
        2. Search stale users, stale computers, never-logged-in users
        3. Get total enabled user count for percentage calculation
        4. HIGH if >10% stale or any DA member stale, MEDIUM if 1-10%, LOW otherwise
        5. Cap evidence at 50 items, append "(and N more)" if truncated
        """
        raise NotImplementedError
