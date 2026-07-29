"""
analyzers/acl.py — Detect dangerous ACEs on sensitive AD objects (T1003.006).

Checks:
  - DCSync rights (DS-Replication-Get-Changes-All + DS-Replication-Get-Changes)
  - GenericAll / WriteDacl / WriteOwner on sensitive objects
  - Dangerous ACEs on AdminSDHolder
"""
from __future__ import annotations

from typing import List, Set

from ldap3 import BASE
from ldap3.protocol.microsoft import security_descriptor_control

from analyzers.base import BaseAnalyzer
from report.models import Finding, Severity
from config import DCSYNC_RIGHTS_GUIDS, DANGEROUS_RIGHTS

# SIDs to skip (built-in, well-known)
SKIP_SID_PREFIXES = (
    "S-1-5-32-",   # Built-in groups
    "S-1-5-18",    # SYSTEM
    "S-1-5-19",    # LOCAL SERVICE
    "S-1-5-20",    # NETWORK SERVICE
    "S-1-3-",      # Creator Owner / Creator Group
    "S-1-1-0",     # Everyone (review separately)
    "S-1-5-10",    # SELF
    "S-1-5-9",     # Enterprise Domain Controllers
)

# GUIDs for DCSync extended rights
DCSYNC_GUID_GET_CHANGES     = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
DCSYNC_GUID_GET_CHANGES_ALL = "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2"

# Dangerous ACCESS_MASK values
GENERIC_ALL   = 0x10000000
WRITE_DACL    = 0x00040000
WRITE_OWNER   = 0x00080000
GENERIC_WRITE = 0x40000000


def _sid_str(sid_bytes: bytes) -> str:
    """Convert binary SID to string representation."""
    try:
        from impacket.ldap.ldaptypes import LDAP_SID
        s = LDAP_SID(sid_bytes)
        return s.formatCanonical()
    except Exception:
        return sid_bytes.hex()


def _should_skip(sid: str) -> bool:
    return any(sid.startswith(prefix) for prefix in SKIP_SID_PREFIXES)


class ACLAnalyzer(BaseAnalyzer):
    NAME        = "acl"
    DESCRIPTION = "Dangerous ACLs on sensitive objects"

    SENSITIVE_OBJECTS = [
        # (display_name, ldap_filter_for_dn_lookup)
        ("Domain Root", None),          # use base_dn directly
        ("AdminSDHolder", "(cn=AdminSDHolder)"),
        ("Domain Admins", "(cn=Domain Admins)"),
        ("Enterprise Admins", "(cn=Enterprise Admins)"),
        ("Schema Admins", "(cn=Schema Admins)"),
        ("krbtgt", "(sAMAccountName=krbtgt)"),
    ]

    def run(self) -> List[Finding]:
        findings: List[Finding] = []

        # Collect DNs of sensitive objects
        targets: List[tuple] = []

        # Domain root
        targets.append(("Domain Root", self.connector.base_dn))

        # AdminSDHolder is in CN=System
        system_dn = "CN=System," + self.connector.base_dn
        for display, ldap_filter in self.SENSITIVE_OBJECTS[1:]:
            if ldap_filter is None:
                continue
            try:
                entries = self.connector.search(
                    ldap_filter,
                    ["distinguishedName"],
                    search_base=system_dn if "AdminSDHolder" in display else self.connector.base_dn,
                )
                if entries:
                    targets.append((display, str(entries[0].distinguishedName)))
            except Exception:
                try:
                    entries = self.connector.search(ldap_filter, ["distinguishedName"])
                    if entries:
                        targets.append((display, str(entries[0].distinguishedName)))
                except Exception:
                    pass

        # Analyze each target's security descriptor
        for display, dn in targets:
            try:
                self.connector._conn.search(
                    search_base=dn,
                    search_filter="(objectClass=*)",
                    search_scope=BASE,
                    attributes=["nTSecurityDescriptor"],
                    controls=security_descriptor_control(sdflags=0x04),
                )
                if not self.connector._conn.entries:
                    continue
                entry = self.connector._conn.entries[0]
                sd_raw = entry["nTSecurityDescriptor"].raw_values
                if not sd_raw:
                    continue
                sd_bytes = sd_raw[0]
            except Exception:
                continue

            # Parse security descriptor
            try:
                from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
                sd = SR_SECURITY_DESCRIPTOR()
                sd.fromString(sd_bytes)
                dacl = sd["Dacl"]
                if dacl is None:
                    continue
            except Exception:
                continue

            dcsync_sids: Set[str] = set()
            dcsync_get_changes: Set[str] = set()

            for ace in dacl.aces:
                try:
                    ace_type = ace["AceType"]
                    # Only ACCESS_ALLOWED_OBJECT_ACE (0x05) and ACCESS_ALLOWED_ACE (0x00)
                    if ace_type not in (0x00, 0x05):
                        continue

                    sid = _sid_str(bytes(ace["Ace"]["Sid"].getData()))
                    if _should_skip(sid):
                        continue

                    mask = int(ace["Ace"]["Mask"]["MaskFields"])

                    # Check extended rights (object ACE with ObjectType GUID)
                    if ace_type == 0x05:
                        try:
                            import uuid
                            obj_type = str(uuid.UUID(bytes=bytes(ace["Ace"]["ObjectType"]))).lower()
                        except Exception:
                            obj_type = ""

                        if obj_type == DCSYNC_GUID_GET_CHANGES_ALL:
                            dcsync_sids.add(sid)
                        elif obj_type == DCSYNC_GUID_GET_CHANGES:
                            dcsync_get_changes.add(sid)

                    # Check dangerous masks
                    dangerous = []
                    if mask & GENERIC_ALL:
                        dangerous.append("GenericAll")
                    if mask & WRITE_DACL:
                        dangerous.append("WriteDACL")
                    if mask & WRITE_OWNER:
                        dangerous.append("WriteOwner")

                    if dangerous and display != "Domain Root":
                        sev = Severity.CRITICAL if "Domain Admins" in display or "AdminSDHolder" in display else Severity.HIGH
                        findings.append(Finding(
                            title=f"Dangerous ACE on {display}: {sid}",
                            severity=sev,
                            description=(
                                f"Principal '{sid}' has {', '.join(dangerous)} on '{display}'. "
                                "This allows full control over the object, enabling privilege escalation."
                            ),
                            evidence=[
                                f"Object: {display} ({dn})",
                                f"Principal SID: {sid}",
                                f"Permissions: {', '.join(dangerous)}",
                            ],
                            remediation=(
                                "Review and remove excessive permissions. Run 'Restore Default Permissions' "
                                "if AdminSDHolder is affected. Use AD ACL Scanner to audit regularly."
                            ),
                            references=["https://attack.mitre.org/techniques/T1003/006/"],
                            analyzer=self.NAME,
                            mitre_id="T1003.006",
                        ))

                except Exception:
                    continue

            # Report DCSync — principals that have BOTH rights
            dcsync_principals = dcsync_sids & dcsync_get_changes
            for sid in dcsync_principals:
                findings.append(Finding(
                    title=f"DCSync rights: {sid}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Principal '{sid}' has both DS-Replication-Get-Changes and "
                        "DS-Replication-Get-Changes-All on the domain root. "
                        "This allows replicating all domain secrets including NTLM hashes and Kerberos keys."
                    ),
                    evidence=[
                        f"Object: Domain Root ({dn})",
                        f"Principal SID: {sid}",
                        "Rights: DS-Replication-Get-Changes-All + DS-Replication-Get-Changes",
                    ],
                    remediation=(
                        "Remove DS-Replication-Get-Changes-All from any non-DC, non-AD-Sync account. "
                        "Only Domain Controllers and Azure AD Connect accounts should have this right. "
                        "Run: Get-ADUser -Filter * | where {$_.DistinguishedName -like '*<sid>*'}"
                    ),
                    references=["https://attack.mitre.org/techniques/T1003/006/"],
                    analyzer=self.NAME,
                    mitre_id="T1003.006",
                ))

        return findings
