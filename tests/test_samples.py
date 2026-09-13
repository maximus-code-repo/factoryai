"""Integration tests: the generated sample logs must surface their
planted attacks (and none of the web false positives on the syslog file)."""

import os

import pytest

from logsentinel.engine import analyze_text
from logsentinel.knowledge import RULE_KNOWLEDGE

SAMPLES = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples"
)

missing = pytest.mark.skipif(
    not os.path.isdir(SAMPLES), reason="samples/ not generated"
)


def load(name):
    with open(os.path.join(SAMPLES, name), encoding="utf-8") as fh:
        return fh.read()


def rule_ids(analysis):
    return {f["rule_id"] for f in analysis["findings"]}


@missing
def test_auth_syslog_sample():
    analysis = analyze_text("auth_syslog.log", load("auth_syslog.log"))
    ids = rule_ids(analysis)
    for expected in ("AUTH_BRUTE_FORCE", "AUTH_COMPROMISE", "SYS_BREAKIN",
                     "SYS_SUDO_ABUSE", "SYS_NEW_USER"):
        assert expected in ids, "missing {}".format(expected)
    brute = next(f for f in analysis["findings"]
                 if f["rule_id"] == "AUTH_BRUTE_FORCE")
    assert brute["severity"] == "critical"
    compromise = next(f for f in analysis["findings"]
                      if f["rule_id"] == "AUTH_COMPROMISE")
    assert compromise["severity"] == "critical"
    # syslog noise must not trip the web-attack signatures
    assert not ids & {"WEB_SQLI", "WEB_XSS", "WEB_TRAVERSAL", "WEB_RCE",
                      "WEB_SENSITIVE_HIGH", "WEB_SENSITIVE_MED"}


@missing
def test_access_apache_sample():
    analysis = analyze_text("access_apache.log", load("access_apache.log"))
    ids = rule_ids(analysis)
    for expected in ("WEB_SQLI", "WEB_XSS", "WEB_TRAVERSAL", "WEB_RCE",
                     "WEB_SENSITIVE_HIGH", "WEB_SENSITIVE_MED",
                     "WEB_DIR_SCAN", "WEB_SCANNER_UA", "ANOM_CRAWLER",
                     "ANOM_ERROR_RATE"):
        assert expected in ids, "missing {}".format(expected)
    # /.env and /.git/config returned HTTP 200 -> exposure is critical
    exposed = next(f for f in analysis["findings"]
                   if f["rule_id"] == "WEB_SENSITIVE_HIGH")
    assert exposed["severity"] == "critical"
    # normal browsing must not be flagged as brute force
    assert "AUTH_BRUTE_FORCE" not in ids


@missing
def test_syslog_baseline_sample_is_clean():
    analysis = analyze_text("syslog_baseline.log", load("syslog_baseline.log"))
    assert analysis["findings"] == []
    assert analysis["summary"]["risk_band"] == "low"
    assert analysis["summary"]["risk_score"] == 0


@missing
def test_syslog_firewall_sample():
    analysis = analyze_text("syslog_firewall.log", load("syslog_firewall.log"))
    ids = rule_ids(analysis)
    for expected in ("NET_PORT_SCAN", "NET_CLEARTEXT", "ANOM_VOLUME",
                     "ANOM_HOURLY", "ANOM_SPIKE"):
        assert expected in ids, "missing {}".format(expected)
    scan = next(f for f in analysis["findings"]
                if f["rule_id"] == "NET_PORT_SCAN")
    assert scan["src_ip"] == "185.23.44.10"
    assert scan["metrics"]["unique_ports"] >= 20
    # routine traffic must not be flagged as attacks
    assert "AUTH_BRUTE_FORCE" not in ids
    assert "WEB_SQLI" not in ids


@missing
def test_syslog_insider_sample():
    analysis = analyze_text("syslog_insider.log", load("syslog_insider.log"))
    ids = rule_ids(analysis)
    for expected in ("AUTH_BRUTE_FORCE", "SYS_SUDO_ABUSE", "ANOM_VOLUME",
                     "ANOM_HOURLY", "ANOM_SPIKE"):
        assert expected in ids, "missing {}".format(expected)
    brute = next(f for f in analysis["findings"]
                 if f["rule_id"] == "AUTH_BRUTE_FORCE")
    assert brute["severity"] == "high"
    volume = next(f for f in analysis["findings"]
                  if f["rule_id"] == "ANOM_VOLUME")
    assert volume["src_ip"] == "10.0.0.31"


@missing
def test_events_csv_sample():
    analysis = analyze_text("events.csv", load("events.csv"))
    ids = rule_ids(analysis)
    for expected in ("NET_PORT_SCAN", "NET_CLEARTEXT", "AUTH_BRUTE_FORCE",
                     "AUTH_COMPROMISE", "ANOM_VOLUME"):
        assert expected in ids, "missing {}".format(expected)
    scan = next(f for f in analysis["findings"]
                if f["rule_id"] == "NET_PORT_SCAN")
    assert scan["metrics"]["unique_ports"] >= 20


@missing
def test_every_finding_has_remediation_and_references():
    """Every finding carries remediation steps and reference links, and the
    sample corpus exercises every entry of the knowledge base (keeping the
    registry in sync with the rules)."""
    ids_seen = set()
    for name in ("auth_syslog.log", "access_apache.log", "events.csv",
                 "syslog_baseline.log", "syslog_firewall.log",
                 "syslog_insider.log"):
        analysis = analyze_text(name, load(name))
        for finding in analysis["findings"]:
            ids_seen.add(finding["rule_id"])
            assert finding["remediation_steps"], "{} / {}".format(name, finding["rule_id"])
            assert len(finding["references"]) >= 2, "{} / {}".format(name, finding["rule_id"])
            for ref in finding["references"]:
                assert ref["url"].startswith("https://"), ref
                assert ref["label"], ref
    assert ids_seen == set(RULE_KNOWLEDGE), (
        "samples and knowledge base are out of sync: "
        "{}".format(set(RULE_KNOWLEDGE) ^ ids_seen))
