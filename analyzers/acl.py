"""
analyzers/acl.py — Dangerous ACLs on sensitive objects and DCSync rights.
MITRE ATT&CK: T1003.006, T1222
TODO (Devin): implement run() — see HANDOFF.md Issue 6
"""
from typing import List
from analyzers.base import BaseAnalyzer
from report.models import Finding, Severity
from config import DANGEROUS_RIGHTS, DCSYNC_RIGHTS_GUIDS


class ACLAnalyzer(BaseAnalyzer):
    NAME = "acl"
    DESCRIPTION = "Dangerous ACLs on sensitive objects and DCSync rights"

    SENSITIVE_OBJECTS = [
        "{base_dn}",
        "CN=AdminSDHolder,CN=System,{base_dn}",
        "CN=Domain Admins,CN=Users,{base_dn}",
        "CN=Enterprise Admins,CN=Users,{base_dn}",
        "CN=Schema Admins,CN=Users,{base_dn}",
        "CN=krbtgt,CN=Users,{base_dn}",
    ]
    SKIP_SIDS = {"S-1-5-18","S-1-3-0","S-1-5-9","S-1-5-32-544"}

    def run(self) -> List[Finding]:
        """
        TODO (Devin):
        1. Fetch nTSecurityDescriptor for each SENSITIVE_OBJECTS entry
        2. Parse SD with impacket SR_SECURITY_DESCRIPTOR
        3. Flag ACEs matching DANGEROUS_RIGHTS (skip SKIP_SIDS)
        4. Check DCSYNC_RIGHTS_GUIDS on domain NC root
        5. CRITICAL: DCSync on non-builtin / GenericAll on DA
           HIGH: GenericWrite/AllExtendedRights on DA, any dangerous ACE on AdminSDHolder
           MEDIUM: dangerous ACEs on other sensitive objects
        6. INFO if nothing found
        """
        raise NotImplementedError
