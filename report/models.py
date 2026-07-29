"""report/models.py — Shared data models for findings and the final report."""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

    @property
    def color(self):
        return {"critical":"#d93025","high":"#f4511e","medium":"#f9a825",
                "low":"#1e88e5","info":"#757575"}[self.value]

    @property
    def order(self):
        return {"critical":0,"high":1,"medium":2,"low":3,"info":4}[self.value]


@dataclass
class Finding:
    title:       str
    severity:    Severity
    description: str
    evidence:    List[str]      = field(default_factory=list)
    remediation: str            = ""
    references:  List[str]      = field(default_factory=list)
    analyzer:    str            = ""
    mitre_id:    Optional[str]  = None
    extra:       Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisReport:
    domain:          str
    dc_hostname:     str
    scan_time_utc:   str
    os_version:      str            = ""
    functional_level: int           = 0
    findings:        List[Finding]  = field(default_factory=list)
    risk_score:      int            = 0
    risk_label:      str            = "Low"
    summary:         Dict[str, int] = field(default_factory=dict)

    def compute_risk(self) -> None:
        from config import RISK_WEIGHTS
        counts: Dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        score = sum(RISK_WEIGHTS.get(sev, 0) * cnt for sev, cnt in counts.items())
        self.risk_score = min(100, score)
        self.risk_label = (
            "Critical" if self.risk_score >= 80 else
            "High"     if self.risk_score >= 60 else
            "Medium"   if self.risk_score >= 40 else "Low"
        )
        self.summary = counts
        self.findings.sort(key=lambda f: f.severity.order)
