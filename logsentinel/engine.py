"""Ties parsers, signature rules, and anomaly detectors into one analysis."""

import os
from datetime import datetime, timezone

from . import __version__
from .knowledge import RULE_KNOWLEDGE
from .models import FINDING_SEVERITIES, SEVERITY_ORDER, ParseResult, Record
from .parsers import parse_text
from .rules import ALL_RULES
from .anomalies import ALL_ANOMALIES

RISK_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}
RISK_BANDS = ((60, "critical"), (30, "high"), (15, "elevated"),
              (5, "moderate"), (0, "low"))


def _run_detectors(records):
    """Run every detector; one broken detector never kills the analysis."""
    findings, warnings = [], []
    for detector in ALL_RULES + ALL_ANOMALIES:
        try:
            findings.extend(detector(records))
        except Exception as exc:  # defensive: surface it, keep going
            warnings.append(
                "Detector {} failed: {}".format(detector.__name__, exc)
            )
    for finding in findings:
        if finding.severity not in SEVERITY_ORDER:
            finding.severity = "low"
        entry = RULE_KNOWLEDGE.get(finding.rule_id)
        if entry:
            finding.remediation_steps = list(entry["steps"])
            finding.references = [dict(ref) for ref in entry["references"]]
    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], -f.count))
    return findings, warnings


def _flagged_ips(findings):
    per_ip = {}
    for finding in findings:
        if not finding.src_ip:
            continue
        entry = per_ip.setdefault(
            finding.src_ip, {"ip": finding.src_ip, "findings": 0,
                             "max_severity": "low"}
        )
        entry["findings"] += 1
        if SEVERITY_ORDER[finding.severity] < SEVERITY_ORDER[entry["max_severity"]]:
            entry["max_severity"] = finding.severity
    return sorted(
        per_ip.values(),
        key=lambda x: (SEVERITY_ORDER[x["max_severity"]], -x["findings"]),
    )[:10]


def _summary(records, findings):
    timestamps = [r.timestamp for r in records if r.timestamp]
    severity_counts = {s: 0 for s in FINDING_SEVERITIES}
    for finding in findings:
        severity_counts[finding.severity] += 1
    score = min(100, sum(RISK_WEIGHTS[f.severity] for f in findings))
    band = next(band for floor, band in RISK_BANDS if score >= floor)
    return {
        "total_records": len(records),
        "records_with_timestamp": len(timestamps),
        "records_with_ip": sum(1 for r in records if r.src_ip),
        "unique_ips": len({r.src_ip for r in records if r.src_ip}),
        "time_range": (
            {"start": min(timestamps).isoformat(),
             "end": max(timestamps).isoformat()}
            if timestamps else None
        ),
        "severity_counts": severity_counts,
        "findings_total": len(findings),
        "risk_score": score,
        "risk_band": band,
        "flagged_ips": _flagged_ips(findings),
    }


def analyze_text(filename, text, size_bytes=None):
    """Parse and analyze a raw log file; returns the full analysis dict."""
    parsed = parse_text(filename, text)
    findings, detector_warnings = _run_detectors(parsed.records)
    return {
        "meta": {
            "original_name": os.path.basename(filename or "unnamed"),
            "format": parsed.fmt,
            "size_bytes": (
                size_bytes if size_bytes is not None
                else len(text.encode("utf-8", errors="replace"))
            ),
            "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "analyzer": "LogSentinel {}".format(__version__),
        },
        "parse": {
            "total_lines": parsed.total_lines,
            "structured": parsed.structured,
        },
        "summary": _summary(parsed.records, findings),
        "findings": [f.to_dict() for f in findings],
        "warnings": parsed.warnings + detector_warnings,
    }
