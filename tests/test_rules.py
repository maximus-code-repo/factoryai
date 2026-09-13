"""Tests for the signature-based detection rules."""

from datetime import datetime, timedelta

from logsentinel.models import Record
from logsentinel.rules import (
    ALL_RULES,
    detect_auth_compromise,
    detect_brute_force,
    detect_cleartext,
    detect_dir_scan,
    detect_path_traversal,
    detect_port_scan,
    detect_rce,
    detect_scanner_uas,
    detect_sensitive_paths_high,
    detect_sensitive_paths_med,
    detect_sql_injection,
    detect_syslog_threats,
    detect_xss,
)


def auth_fail(i, ip="203.0.113.66", user="root", ts=None):
    return Record(
        raw="Sep  9 02:13:00 web01 sshd[{}]: Failed password for {} from {} "
            "port {} ssh2".format(i, user, ip, 52000 + i),
        line_no=i, timestamp=ts, src_ip=ip, user=user,
    )


def test_brute_force_medium():
    t0 = datetime(2026, 9, 9, 2, 13, 0)
    recs = [auth_fail(i, ts=t0 + timedelta(seconds=6 * i)) for i in range(6)]
    findings = detect_brute_force(recs)
    assert len(findings) == 1
    assert findings[0].rule_id == "AUTH_BRUTE_FORCE"
    assert findings[0].severity == "medium"
    assert findings[0].count == 6


def test_brute_force_critical():
    t0 = datetime(2026, 9, 9, 2, 13, 0)
    recs = [auth_fail(i, ts=t0 + timedelta(seconds=6 * i)) for i in range(30)]
    assert detect_brute_force(recs)[0].severity == "critical"


def test_brute_force_ignores_small():
    assert detect_brute_force([auth_fail(i) for i in range(3)]) == []


def test_brute_force_counts_http_401():
    recs = [
        Record(raw="GET /api/login", line_no=i, src_ip="9.9.9.9", status=401,
               timestamp=datetime(2026, 9, 9, 2, 0, 0) + timedelta(seconds=i))
        for i in range(12)
    ]
    findings = detect_brute_force(recs)
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_compromise_detected():
    t0 = datetime(2026, 9, 9, 2, 13, 0)
    fails = [auth_fail(i, ts=t0 + timedelta(seconds=6 * i)) for i in range(4)]
    ok = Record(
        raw="Sep  9 02:15:00 web01 sshd[99]: Accepted password for admin "
            "from 203.0.113.66 port 52200 ssh2",
        line_no=100, timestamp=t0 + timedelta(minutes=2),
        src_ip="203.0.113.66", user="admin",
    )
    findings = detect_auth_compromise(fails + [ok])
    assert len(findings) == 1
    assert findings[0].rule_id == "AUTH_COMPROMISE"
    assert findings[0].severity == "critical"


def test_brute_force_su_failures():
    t0 = datetime(2026, 9, 13, 3, 41, 0)
    recs = [
        Record(raw="Sep 13 03:41:00 app01 su[{}]: FAILED su for user root "
                   "by dev".format(2871 + i),
               line_no=i, timestamp=t0 + timedelta(seconds=45 * i))
        for i in range(6)
    ]
    findings = detect_brute_force(recs)
    assert len(findings) == 1
    assert findings[0].rule_id == "AUTH_BRUTE_FORCE"
    assert findings[0].src_ip is None  # su failures carry no source IP
    assert findings[0].severity == "medium"


def test_no_compromise_without_success():
    t0 = datetime(2026, 9, 9, 2, 13, 0)
    fails = [auth_fail(i, ts=t0 + timedelta(seconds=6 * i)) for i in range(4)]
    assert detect_auth_compromise(fails) == []


def test_sql_injection_detected():
    rec = Record(
        raw='203.0.113.7 - - [10/Sep/2026:14:02:00 +0000] "GET '
            '/products.php?id=1 UNION SELECT username,password FROM users-- '
            'HTTP/1.1" 500 512',
        line_no=1, src_ip="203.0.113.7", status=500,
    )
    findings = detect_sql_injection([rec])
    assert len(findings) == 1
    assert findings[0].rule_id == "WEB_SQLI"
    assert findings[0].severity == "high"


def test_sql_injection_url_encoded():
    rec = Record(
        raw="GET /search.php?q=1%27%20UNION%20SELECT%20password%20FROM%20users--",
        line_no=1, src_ip="1.2.3.4",
    )
    assert detect_sql_injection([rec])


def test_xss_detected():
    rec = Record(
        raw='192.0.2.88 - - [10/Sep/2026:14:02:00 +0000] "GET '
            '/search?q=<script>alert(document.cookie)</script> HTTP/1.1" 200 512',
        line_no=1, src_ip="192.0.2.88", status=200,
    )
    findings = detect_xss([rec])
    assert findings and findings[0].rule_id == "WEB_XSS"
    assert findings[0].severity == "high"


def test_traversal_high_for_system_files():
    rec = Record(raw="GET /download?file=../../../../etc/passwd",
                 line_no=1, src_ip="198.18.7.9")
    assert detect_path_traversal([rec])[0].severity == "high"


def test_traversal_medium_without_system_files():
    rec = Record(raw="GET /view?tpl=../../../app/config.py",
                 line_no=1, src_ip="198.18.7.9")
    assert detect_path_traversal([rec])[0].severity == "medium"


def test_rce_detected():
    rec = Record(raw="GET /api/exec?cmd=cat /etc/passwd",
                 line_no=1, src_ip="192.0.2.101")
    assert [f.rule_id for f in detect_rce([rec])] == ["WEB_RCE"]


def test_sensitive_env_exposed_is_critical():
    rec = Record(
        raw='45.33.32.156 - - [10/Sep/2026:14:02:00 +0000] "GET /.env '
            'HTTP/1.1" 200 270',
        line_no=1, src_ip="45.33.32.156", status=200,
    )
    findings = detect_sensitive_paths_high([rec])
    assert findings[0].severity == "critical"
    assert "exposed" in findings[0].description


def test_sensitive_env_probe_only_is_high():
    rec = Record(
        raw='45.33.32.156 - - [10/Sep/2026:14:02:00 +0000] "GET /.env '
            'HTTP/1.1" 404 270',
        line_no=1, src_ip="45.33.32.156", status=404,
    )
    assert detect_sensitive_paths_high([rec])[0].severity == "high"


def test_sensitive_med_paths():
    rec = Record(raw='GET /wp-login.php HTTP/1.1" 404',
                 line_no=1, src_ip="1.2.3.4", status=404)
    findings = detect_sensitive_paths_med([rec])
    assert findings and findings[0].rule_id == "WEB_SENSITIVE_MED"
    assert findings[0].severity == "medium"


def test_scanner_user_agent():
    rec = Record(raw="request", line_no=1, src_ip="203.0.113.7",
                 ua="sqlmap/1.7.2#stable (http://sqlmap.org)")
    findings = detect_scanner_uas([rec])
    assert findings[0].rule_id == "WEB_SCANNER_UA"


def test_dir_scan_detected():
    recs = [
        Record(raw="GET /p{}".format(i), line_no=i, src_ip="45.33.32.156",
               status=404, path="/p{}".format(i))
        for i in range(20)
    ]
    findings = detect_dir_scan(recs)
    assert len(findings) == 1
    assert findings[0].rule_id == "WEB_DIR_SCAN"
    assert findings[0].severity == "high"


def test_dir_scan_not_triggered_by_normal_traffic():
    recs = [
        Record(raw="GET /page{}".format(i), line_no=i, src_ip="10.0.0.15",
               status=200)
        for i in range(20)
    ]
    assert detect_dir_scan(recs) == []


def test_port_scan_detected():
    ports = [22, 80, 443, 3306, 8080, 3389, 5432, 6379, 21, 23, 25, 53, 110,
             143, 993]
    recs = [
        Record(raw="flow", line_no=i, src_ip="185.220.101.5", port=p)
        for i, p in enumerate(ports)
    ]
    findings = detect_port_scan(recs)
    assert len(findings) == 1
    assert findings[0].rule_id == "NET_PORT_SCAN"
    assert findings[0].count == len(ports)


def test_cleartext_detected():
    recs = [Record(raw="10.0.0.42 telnet session opened", line_no=1,
                   src_ip="10.0.0.42", port=23)]
    findings = detect_cleartext(recs)
    assert len(findings) == 1
    assert findings[0].rule_id == "NET_CLEARTEXT"


def test_syslog_threats():
    recs = [
        Record(raw="sudo: www-data : user NOT in sudoers", line_no=1),
        Record(raw="useradd[4750]: new user: name=backdoor, UID=1002",
               line_no=2),
        Record(raw="sshd[1]: reverse mapping checking getaddrinfo failed - "
                   "POSSIBLE BREAK-IN ATTEMPT!", line_no=3,
               src_ip="45.79.180.7"),
    ]
    ids = {f.rule_id for f in detect_syslog_threats(recs)}
    assert ids == {"SYS_SUDO_ABUSE", "SYS_NEW_USER", "SYS_BREAKIN"}


def test_benign_log_triggers_no_rules():
    benign = []
    ts = datetime(2026, 9, 10, 9, 0, 0)
    for i in range(25):
        ip = "10.0.0.{}".format(15 + i % 5)
        benign.append(Record(
            raw='{} - - [10/Sep/2026:09:00:00 +0000] "GET /page{} HTTP/1.1" '
                '200 512 "-" "Mozilla/5.0 Chrome/126.0.0.0"'.format(ip, i),
            line_no=i, timestamp=ts + timedelta(minutes=i), src_ip=ip,
            status=200, method="GET", path="/page{}".format(i),
            ua="Mozilla/5.0 Chrome/126.0.0.0",
        ))
    benign.append(Record(
        raw="Sep 10 09:00:00 web01 sshd[1]: Accepted password for deploy "
            "from 10.0.0.15 port 49 ssh2",
        line_no=99, timestamp=ts, src_ip="10.0.0.15",
    ))
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(benign))
    assert findings == []
