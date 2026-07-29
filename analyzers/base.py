"""analyzers/base.py — Abstract base class for all AD analyzers."""
from abc import ABC, abstractmethod
from typing import List
from connectors.ldap_connector import LDAPConnector
from report.models import Finding


class BaseAnalyzer(ABC):
    NAME: str = ""
    DESCRIPTION: str = ""

    def __init__(self, connector: LDAPConnector) -> None:
        self.connector = connector

    @abstractmethod
    def run(self) -> List[Finding]:
        """Execute analysis. Return list of Findings. Never raise — catch errors internally."""
        ...
