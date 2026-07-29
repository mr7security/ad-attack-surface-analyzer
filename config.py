"""
config.py — Global configuration and constants for AD Attack Surface Analyzer.
"""

from dataclasses import dataclass, field
from typing import Optional


LDAP_PORT_PLAIN = 389
LDAP_PORT_SSL   = 636
LDAP_TIMEOUT    = 30
PAGE_SIZE       = 1000

STALE_USER_DAYS     = 90
STALE_COMPUTER_DAYS = 90
PASSWORD_MIN_LENGTH = 12
LOCKOUT_THRESHOLD   = 5
LOCKOUT_DURATION    = 30

PRIVILEGED_GROUPS = [
    "Domain Admins","Enterprise Admins","Schema Admins","Administrators",
    "Account Operators","Backup Operators","Print Operators","Server Operators",
    "Group Policy Creator Owners","Domain Controllers",
    "Read-only Domain Controllers","Cert Publishers","DnsAdmins",
]

DANGEROUS_RIGHTS = {
    0x000F01FF: "GenericAll",
    0x00020028: "GenericWrite",
    0x00040000: "WriteDACL",
    0x00080000: "WriteOwner",
    0x00000100: "AllExtendedRights",
}

DCSYNC_RIGHTS_GUIDS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "89e95b76-444d-4c62-991a-0facbeda640c": "DS-Replication-Get-Changes-In-Filtered-Set",
}

RISK_WEIGHTS = {
    "critical": 40, "high": 20, "medium": 10, "low": 5, "info": 1,
}

@dataclass
class ConnectionConfig:
    target: str
    domain: str
    auth_method: str = "simple"
    username: Optional[str] = None
    password: Optional[str] = None
    ccache: Optional[str] = None
    keytab: Optional[str] = None
    use_ssl: bool = False
    port: Optional[int] = None
    timeout: int = LDAP_TIMEOUT
    base_dn: str = field(default="", init=False)

    def __post_init__(self):
        if not self.base_dn:
            self.base_dn = ",".join(f"DC={part}" for part in self.domain.split("."))
        if self.port is None:
            self.port = LDAP_PORT_SSL if self.use_ssl else LDAP_PORT_PLAIN
