"""Tests for the statistical anomaly detectors."""

from datetime import datetime, timedelta

from logsentinel.anomalies import (
    ALL_ANOMALIES,
    detect_crawler,
    detect_error_rate_anomaly,
    detect_hourly_anomaly,
    detect_traffic_spikes,
    detect_volume_anomaly,
)
from logsentinel.models import Record


def test_volume_anomaly():
    recs = [
        Record(raw="r", line_no=i, src_ip="10.0.0.77",
               timestamp=datetime(2026, 9, 10) + timedelta(seconds=i))
        for i in range(200)
    ]
    for n in range(5):
        recs += [
            Record(raw="r", line_no=len(recs), src_ip="10.0.0.{}".format(20 + n),
                   timestamp=datetime(2026, 9, 10) + timedelta(seconds=i))
            for i in range(10)
        ]
    findings = detect_volume_anomaly(recs)
    assert len(findings) == 1
    assert findings[0].rule_id == "ANOM_VOLUME"
    assert findings[0].src_ip == "10.0.0.77"
    assert findings[0].severity == "medium"


def test_error_rate_anomaly():
    recs = [
        Record(raw="404", line_no=i, src_ip="1.2.3.4", status=404,
               timestamp=datetime(2026, 9, 10, 9, 0, 0) + timedelta(seconds=i))
        for i in range(10)
    ]
    for n in range(5):
        recs += [
            Record(raw="ok", line_no=len(recs), src_ip="10.0.0.{}".format(30 + n),
                   status=200,
                   timestamp=datetime(2026, 9, 10, 9, 0, 0) + timedelta(seconds=len(recs)))
            for _ in range(10)
        ]
    findings = detect_error_rate_anomaly(recs)
    assert findings and findings[0].rule_id == "ANOM_ERROR_RATE"
    assert findings[0].src_ip == "1.2.3.4"


def test_hourly_offhours_anomaly():
    recs = []
    for hour in range(9, 18):
        recs += [
            Record(raw="day", line_no=len(recs),
                   timestamp=datetime(2026, 9, 10, hour, (i * 7) % 60))
            for i in range(8)
        ]
    recs += [
        Record(raw="night", line_no=len(recs),
               timestamp=datetime(2026, 9, 10, 3, 0) + timedelta(seconds=30 * i))
        for i in range(40)
    ]
    findings = detect_hourly_anomaly(recs)
    assert findings and findings[0].rule_id == "ANOM_HOURLY"
    assert findings[0].severity == "medium"
    assert "off-hours" in findings[0].title


def test_traffic_spike():
    recs = []
    t0 = datetime(2026, 9, 10, 9, 0, 0)
    for minute in range(40):  # 2-3 records per minute (>= 100 total)
        for _ in range(2 + minute % 2):
            recs.append(Record(raw="r", line_no=len(recs),
                               timestamp=t0 + timedelta(minutes=minute)))
    for _ in range(20):  # then 20 in one minute
        recs.append(Record(raw="burst", line_no=len(recs),
                           timestamp=t0 + timedelta(minutes=40)))
    findings = detect_traffic_spikes(recs)
    assert findings and findings[0].rule_id == "ANOM_SPIKE"
    assert findings[0].count == 20


def test_crawler_anomaly():
    recs = [
        Record(raw="GET /p{}".format(i), line_no=i, src_ip="45.33.32.156",
               path="/p{}".format(i))
        for i in range(60)
    ]
    for n in range(5):
        recs += [
            Record(raw="GET /same", line_no=len(recs),
                   src_ip="10.0.0.{}".format(n), path="/same")
            for _ in range(10)
        ]
    findings = detect_crawler(recs)
    assert findings and findings[0].rule_id == "ANOM_CRAWLER"
    assert findings[0].src_ip == "45.33.32.156"


def test_small_dataset_produces_no_anomalies():
    recs = [
        Record(raw="x", line_no=i, src_ip="1.2.3.{}".format(i))
        for i in range(3)
    ]
    findings = []
    for detector in ALL_ANOMALIES:
        findings.extend(detector(recs))
    assert findings == []
