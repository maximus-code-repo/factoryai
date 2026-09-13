"""Tests for the analysis engine (parse -> detect -> score)."""

import json

from logsentinel.engine import analyze_text

BRUTE_LOG = "\n".join(
    "Sep  9 02:13:00 web01 sshd[{}]: Failed password for root from "
    "203.0.113.66 port {} ssh2".format(i, 52000 + i)
    for i in range(15)
)

BENIGN_LOG = ("Sep  9 02:13:00 web01 sshd[1]: Accepted password for deploy "
              "from 10.0.0.15 port 49 ssh2\n")


def test_analysis_is_json_serializable():
    analysis = analyze_text("auth.log", BRUTE_LOG)
    round_tripped = json.loads(json.dumps(analysis))
    assert round_tripped["summary"]["findings_total"] >= 1


def test_findings_sorted_by_severity():
    analysis = analyze_text("auth.log", BRUTE_LOG)
    severities = [f["severity"] for f in analysis["findings"]]
    order = ["critical", "high", "medium", "low"]
    assert severities == sorted(severities, key=order.index)


def test_brute_force_flow_end_to_end():
    analysis = analyze_text("auth.log", BRUTE_LOG)
    assert analysis["meta"]["format"] == "syslog"
    assert analysis["summary"]["total_records"] == 15
    finding = next(
        f for f in analysis["findings"] if f["rule_id"] == "AUTH_BRUTE_FORCE"
    )
    assert finding["severity"] == "high"
    assert finding["evidence"]
    assert "Failed password" in finding["evidence"][0]["raw"]
    assert analysis["summary"]["severity_counts"]["high"] >= 1


def test_benign_log_is_low_risk():
    analysis = analyze_text("auth.log", BENIGN_LOG)
    assert analysis["summary"]["findings_total"] == 0
    assert analysis["summary"]["risk_score"] == 0
    assert analysis["summary"]["risk_band"] == "low"


def test_flagged_ips_summary():
    analysis = analyze_text("auth.log", BRUTE_LOG)
    ips = [entry["ip"] for entry in analysis["summary"]["flagged_ips"]]
    assert "203.0.113.66" in ips


def test_findings_include_remediation_and_references():
    log = ('203.0.113.7 - - [10/Sep/2026:14:02:00 +0000] "GET '
           '/products.php?id=1 UNION SELECT username,password FROM users-- '
           'HTTP/1.1" 500 512\n')
    analysis = analyze_text("access.log", log)
    finding = next(f for f in analysis["findings"]
                   if f["rule_id"] == "WEB_SQLI")
    assert len(finding["remediation_steps"]) >= 3
    assert len(finding["references"]) >= 2
    assert any("owasp.org" in ref["url"] for ref in finding["references"])
    for ref in finding["references"]:
        assert ref["url"].startswith("https://"), ref
        assert ref["label"], ref


def test_empty_log_analysis():
    analysis = analyze_text("empty.log", "")
    assert analysis["summary"]["total_records"] == 0
    assert analysis["summary"]["findings_total"] == 0
