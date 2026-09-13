"""Shared data structures used across LogSentinel."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

FINDING_SEVERITIES = ("critical", "high", "medium", "low")
SEVERITY_ORDER = {name: index for index, name in enumerate(FINDING_SEVERITIES)}

EVIDENCE_LIMIT = 10


@dataclass
class Record:
    """One normalized log entry, regardless of the source format."""

    raw: str
    line_no: int = 0
    timestamp: Optional[datetime] = None
    src_ip: Optional[str] = None
    user: Optional[str] = None
    event: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    query: Optional[str] = None
    status: Optional[int] = None
    ua: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    extra: dict = field(default_factory=dict)

    def full_url(self) -> str:
        """Path plus query string, if both are present."""
        if self.path and self.query:
            return "{}?{}".format(self.path, self.query)
        return self.path or ""


@dataclass
class Finding:
    """One detected issue, with the evidence that triggered it."""

    rule_id: str
    title: str
    severity: str  # one of FINDING_SEVERITIES
    category: str  # "rule" (signature) or "anomaly" (statistical)
    description: str
    recommendation: str
    count: int = 1
    src_ip: Optional[str] = None
    evidence: list = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    remediation_steps: list = field(default_factory=list)
    references: list = field(default_factory=list)  # [{"label", "url"}]

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "recommendation": self.recommendation,
            "count": self.count,
            "src_ip": self.src_ip,
            "evidence": self.evidence,
            "metrics": self.metrics,
            "remediation_steps": self.remediation_steps,
            "references": self.references,
        }


def make_evidence(records, limit: int = EVIDENCE_LIMIT) -> list:
    """Serialize a sample of records as evidence for a finding."""
    return [
        {
            "line_no": r.line_no,
            "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            "raw": r.raw,
        }
        for r in records[:limit]
    ]


@dataclass
class ParseResult:
    """Outcome of parsing a log file into normalized records."""

    fmt: str  # "apache", "syslog", "csv", "json", or "text"
    records: list
    total_lines: int = 0
    structured: int = 0  # lines parsed with format-specific structure
    warnings: list = field(default_factory=list)
