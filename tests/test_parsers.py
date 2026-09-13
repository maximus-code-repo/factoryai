"""Tests for format detection and the per-format parsers."""

import json
from datetime import datetime

from logsentinel.parsers import detect_format, parse_text

APACHE_COMBINED = (
    '10.0.0.15 - alice [10/Sep/2026:14:02:00 +0000] '
    '"GET /api/items?page=2 HTTP/1.1" 200 1043 '
    '"https://example.com/" "Mozilla/5.0 Chrome/126.0.0.0"'
)


def test_apache_combined():
    result = parse_text("access.log", APACHE_COMBINED)
    assert result.fmt == "apache"
    record = result.records[0]
    assert record.src_ip == "10.0.0.15"
    assert record.user == "alice"
    assert record.method == "GET"
    assert record.path == "/api/items"
    assert record.query == "page=2"
    assert record.status == 200
    assert "Chrome" in record.ua
    assert record.timestamp == datetime(2026, 9, 10, 14, 2, 0)
    assert record.extra["referer"] == "https://example.com/"


def test_apache_common_format():
    line = ('192.168.1.4 - - [10/Sep/2026:08:00:00 +0000] '
            '"GET / HTTP/1.1" 304 -')
    record = parse_text("access.log", line).records[0]
    assert record.status == 304
    assert record.ua is None
    assert record.timestamp == datetime(2026, 9, 10, 8, 0, 0)


def test_syslog_auth_line():
    line = ("Sep  9 02:13:00 web01 sshd[4400]: Failed password for root "
            "from 203.0.113.66 port 52000 ssh2")
    result = parse_text("auth.log", line)
    assert result.fmt == "syslog"
    record = result.records[0]
    assert record.src_ip == "203.0.113.66"
    assert record.user == "root"
    assert record.port is None  # sshd's 'port N' is the client source port
    assert record.host == "web01"
    assert record.timestamp.hour == 2
    assert record.extra["program"] == "sshd"


def test_syslog_iso_timestamp():
    line = ("2026-09-09T02:13:00.123Z web01 sshd[1]: Invalid user oracle "
            "from 198.51.100.23 port 41000 ssh2")
    record = parse_text("auth.log", line).records[0]
    assert record.timestamp == datetime(2026, 9, 9, 2, 13, 0, 123000)
    assert record.src_ip == "198.51.100.23"
    assert record.user == "oracle"


def test_syslog_netfilter_firewall_line():
    line = ("Sep 12 02:31:05 fw01 kernel: [412345.678901] DROP IN=eth0 "
            "SRC=185.23.44.10 DST=10.0.0.5 PROTO=TCP SPT=51434 DPT=23")
    result = parse_text("firewall.log", line)
    assert result.fmt == "syslog"
    record = result.records[0]
    assert record.src_ip == "185.23.44.10"  # SRC comes before DST
    assert record.port == 23                # DPT is a destination port
    assert record.host == "fw01"
    assert record.extra["program"] == "kernel"


def test_csv_column_mapping():
    text = ("timestamp,client ip,username,http status,request\n"
            "2026-09-10T09:00:00Z,10.0.0.5,bob,200,GET /home HTTP/1.1\n")
    result = parse_text("events.csv", text)
    assert result.fmt == "csv"
    record = result.records[0]
    assert record.src_ip == "10.0.0.5"
    assert record.user == "bob"
    assert record.status == 200
    assert record.method == "GET"
    assert record.path == "/home"
    assert record.timestamp == datetime(2026, 9, 10, 9, 0, 0)


def test_json_array_nested_ip():
    payload = json.dumps([{
        "client": {"ip": "203.0.113.7"},
        "@timestamp": "2026-09-10T09:00:00Z",
        "message": "GET /admin HTTP/1.1",
        "status": 404,
    }])
    result = parse_text("logs.json", payload)
    assert result.fmt == "json"
    record = result.records[0]
    assert record.src_ip == "203.0.113.7"
    assert record.timestamp == datetime(2026, 9, 10, 9, 0, 0)
    assert record.status == 404


def test_jsonl():
    lines = "\n".join([
        json.dumps({"src_ip": "1.1.1.1", "event": "login failed"}),
        json.dumps({"src_ip": "2.2.2.2", "event": "login ok"}),
    ])
    result = parse_text("events.jsonl", lines)
    assert result.fmt == "json"
    assert [r.src_ip for r in result.records] == ["1.1.1.1", "2.2.2.2"]
    assert "login failed" in result.records[0].raw


def test_format_detection_variants():
    assert detect_format("x.csv", "a,b,c\n1,2,3\n") == "csv"
    assert detect_format("x.json", "[{}]") == "json"
    assert detect_format("x.log", APACHE_COMBINED) == "apache"
    assert detect_format("x.txt", "just some text") == "text"


def test_text_fallback_extracts_ip():
    result = parse_text("weird.log", "connection from 8.8.8.8 blocked\n")
    assert result.fmt == "text"
    assert result.records[0].src_ip == "8.8.8.8"


def test_malformed_lines_are_kept():
    text = APACHE_COMBINED + "\nnot-an-apache-line at all\n"
    result = parse_text("access.log", text)
    assert len(result.records) == 2
    assert result.structured == 1
    assert any("did not match" in w for w in result.warnings)


def test_empty_file_warns():
    result = parse_text("x.log", "\n \n")
    assert result.records == []
    assert result.warnings
