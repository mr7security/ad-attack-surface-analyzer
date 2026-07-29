"""
connectors/ldap_connector.py
Handles LDAP(S) connections to Active Directory.
Auth: simple bind, NTLM, Kerberos (ccache/keytab).
TODO (Devin): implement connect(), search(), get_root_dse() — see HANDOFF.md Issue 1
"""
from __future__ import annotations
from typing import Any, List, Optional
import ldap3
from ldap3 import ALL, NTLM, SASL, SIMPLE, Connection, Server, Tls, KERBEROS
from config import ConnectionConfig, PAGE_SIZE


class LDAPConnectorError(Exception):
    pass


class LDAPConnector:
    def __init__(self, config: ConnectionConfig) -> None:
        self.config = config
        self._conn: Optional[Connection] = None

    def __enter__(self):
        self.connect(); return self

    def __exit__(self, *_):
        self.disconnect()

    def connect(self) -> None:
        """TODO: simple/NTLM/Kerberos. See HANDOFF.md."""
        raise NotImplementedError

    def disconnect(self) -> None:
        if self._conn and self._conn.bound:
            self._conn.unbind()
        self._conn = None

    def search(self, ldap_filter, attributes, base_dn=None, search_scope=ldap3.SUBTREE):
        """TODO: paged search (PAGE_SIZE). See HANDOFF.md."""
        if not self._conn or not self._conn.bound:
            raise LDAPConnectorError("Not connected.")
        raise NotImplementedError

    def get_root_dse(self) -> dict:
        """TODO: return defaultNamingContext, dnsHostName, domainFunctionality."""
        if not self._conn:
            raise LDAPConnectorError("Not connected.")
        raise NotImplementedError
