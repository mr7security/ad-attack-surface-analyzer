"""
connectors/ldap_connector.py — LDAP connection and search helper.
Supports simple bind, NTLM, and Kerberos (ccache / keytab).
"""
from __future__ import annotations

import os
import warnings
from typing import Any, Dict, List, Optional

from ldap3 import (
    NTLM,
    SASL,
    SIMPLE,
    SUBTREE,
    BASE,
    Server,
    Connection,
    Tls,
    KERBEROS,
)
from ldap3.core.exceptions import LDAPException
from ldap3.controls import SimplePagedResultsControl

from config import ConnectionConfig

PAGE_SIZE = 1000


class LDAPConnectorError(Exception):
    """Raised when the LDAP connection or bind fails."""


class LDAPConnector:
    """Thin wrapper around ldap3 that handles auth, paging, and root DSE queries."""

    def __init__(self, cfg: ConnectionConfig) -> None:
        self.cfg = cfg
        self._conn: Optional[Connection] = None
        self._server: Optional[Server] = None
        self.base_dn: str = ""

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------
    def __enter__(self) -> "LDAPConnector":
        self.connect()
        return self

    def __exit__(self, *_: Any) -> None:
        self.disconnect()

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------
    def connect(self) -> None:
        cfg = self.cfg
        port = cfg.port or (636 if cfg.use_ssl else 389)
        tls = Tls(validate=0) if cfg.use_ssl else None
        self._server = Server(
            cfg.target, port=port, use_ssl=cfg.use_ssl, tls=tls, get_info="ALL"
        )

        if cfg.auth_method == "simple":
            if not cfg.use_ssl:
                warnings.warn(
                    "[!] Simple bind without SSL — password sent in cleartext. Use --ssl."
                )
            try:
                self._conn = Connection(
                    self._server,
                    user=cfg.username,
                    password=cfg.password,
                    authentication=SIMPLE,
                    auto_bind=True,
                )
            except LDAPException as exc:
                raise LDAPConnectorError(f"Simple bind failed: {exc}") from exc

        elif cfg.auth_method == "ntlm":
            bs = chr(92)
            if not cfg.username or (bs not in cfg.username and "@" not in cfg.username):
                raise LDAPConnectorError(
                    "NTLM requires username in DOMAIN" + bs + "user or user@domain.com format"
                )
            try:
                self._conn = Connection(
                    self._server,
                    user=cfg.username,
                    password=cfg.password,
                    authentication=NTLM,
                    auto_bind=True,
                )
            except LDAPException as exc:
                raise LDAPConnectorError(f"NTLM bind failed: {exc}") from exc

        elif cfg.auth_method == "kerberos":
            if cfg.ccache:
                os.environ["KRB5CCNAME"] = cfg.ccache
            try:
                self._conn = Connection(
                    self._server,
                    authentication=SASL,
                    sasl_mechanism=KERBEROS,
                    auto_bind=True,
                )
            except LDAPException as exc:
                raise LDAPConnectorError(f"Kerberos bind failed: {exc}") from exc

        else:
            raise LDAPConnectorError(f"Unknown auth method: {cfg.auth_method!r}")

        # Resolve base DN from server info
        info = self._server.info
        if info and info.other.get("defaultNamingContext"):
            nc = info.other["defaultNamingContext"]
            self.base_dn = nc[0] if isinstance(nc, list) else nc
        else:
            self.base_dn = ",".join(f"DC={p}" for p in cfg.domain.split("."))

    def disconnect(self) -> None:
        if self._conn:
            try:
                self._conn.unbind()
            except Exception:
                pass
            self._conn = None

    # ------------------------------------------------------------------
    # Paged search
    # ------------------------------------------------------------------
    def search(
        self,
        ldap_filter: str,
        attributes: List[str],
        search_base: Optional[str] = None,
        search_scope: str = SUBTREE,
    ) -> List[Any]:
        if not self._conn:
            raise LDAPConnectorError("Not connected — call connect() first")
        base = search_base or self.base_dn
        results: List[Any] = []
        cookie = b""
        while True:
            ctrl = SimplePagedResultsControl(True, size=PAGE_SIZE, cookie=cookie)
            self._conn.search(
                search_base=base,
                search_filter=ldap_filter,
                search_scope=search_scope,
                attributes=attributes,
                controls=[ctrl],
            )
            results.extend(self._conn.entries)
            try:
                ctrl_resp = self._conn.result["controls"][
                    "1.2.840.113556.1.4.319"
                ]["value"]
                cookie = ctrl_resp.get("cookie", b"")
            except (KeyError, TypeError):
                cookie = b""
            if not cookie:
                break
        return results

    # ------------------------------------------------------------------
    # Root DSE
    # ------------------------------------------------------------------
    def get_root_dse(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        info = self._server.info if self._server else None
        if info and info.other:
            for key in (
                "defaultNamingContext",
                "dnsHostName",
                "domainFunctionality",
                "forestFunctionality",
            ):
                val = info.other.get(key, "")
                if isinstance(val, list):
                    val = val[0] if val else ""
                result[key] = str(val) if val else ""
        # Try to get OS version
        try:
            self._conn.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=["operatingSystem"],
            )
            if self._conn.entries:
                entry = self._conn.entries[0]
                result["os_version"] = str(entry.operatingSystem) if entry.operatingSystem else ""
        except Exception:
            result["os_version"] = ""
        return result
