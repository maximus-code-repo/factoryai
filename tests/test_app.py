"""Tests for the Flask app: upload, report, export, delete, API."""

import io
import json

AUTH_SAMPLE = "\n".join(
    "Sep  9 02:13:00 web01 sshd[{}]: Failed password for root from "
    "203.0.113.66 port {} ssh2".format(i, 52000 + i)
    for i in range(15)
)


def test_healthz(client):
    res = client.get("/healthz")
    assert res.status_code == 200
    assert res.get_json()["status"] == "ok"


def test_index_empty(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"Upload a security log" in res.data
    assert b"Summary of results" not in res.data  # no analyses -> no dashboard


def test_index_shows_overview_dashboard(client):
    client.post("/upload", data={
        "logfile": (io.BytesIO(AUTH_SAMPLE.encode()), "auth.log"),
    }, content_type="multipart/form-data")
    clean = (b"Sep 12 09:00:00 app01 sshd[1]: Accepted password for deploy "
             b"from 10.0.0.15 port 49 ssh2\n")
    client.post("/upload", data={
        "logfile": (io.BytesIO(clean), "baseline.log"),
    }, content_type="multipart/form-data")
    res = client.get("/")
    assert res.status_code == 200
    assert b"Summary of results" in res.data
    assert b"Findings by severity" in res.data
    assert b"Findings per analysis" in res.data
    # KPI tiles: 2 analyses, 16 records, 1 finding, 0 critical
    assert b'<div class="kpi-value">2</div>' in res.data
    assert b'<div class="kpi-value">16</div>' in res.data
    assert b'<div class="kpi-value">1</div>' in res.data
    assert b'<div class="kpi-value sev-critical">0</div>' in res.data
    # worst risk band badge (the auth sample has one high finding)
    assert b"worst: moderate" in res.data
    # stacked bar segments for the flagged analysis
    assert b"hbar-seg sev-high" in res.data


def test_upload_and_report(client):
    res = client.post("/upload", data={
        "logfile": (io.BytesIO(AUTH_SAMPLE.encode()), "auth.log"),
    }, content_type="multipart/form-data", follow_redirects=True)
    assert res.status_code == 200
    assert b"Brute-force" in res.data
    assert b"AUTH_BRUTE_FORCE" in res.data
    assert b"203.0.113.66" in res.data


def test_upload_empty_file_rejected(client):
    res = client.post("/upload", data={
        "logfile": (io.BytesIO(b"   \n"), "auth.log"),
    }, content_type="multipart/form-data", follow_redirects=True)
    assert res.status_code == 200
    assert b"appears to be empty" in res.data


def test_upload_unknown_extension_rejected(client):
    res = client.post("/upload", data={
        "logfile": (io.BytesIO(b"MZ\x90\x00"), "payload.exe"),
    }, content_type="multipart/form-data", follow_redirects=True)
    assert res.status_code == 200
    assert b"Unsupported file type" in res.data


def test_upload_without_file(client):
    res = client.post("/upload", data={},
                      content_type="multipart/form-data",
                      follow_redirects=True)
    assert res.status_code == 200
    assert b"Choose a log file" in res.data


def test_report_not_found(client):
    assert client.get("/report/aaaaaaaaaaaa").status_code == 404
    assert client.get("/report/never-exists").status_code == 404


def test_export_api_and_delete(client):
    res = client.post("/upload", data={
        "logfile": (io.BytesIO(AUTH_SAMPLE.encode()), "auth.log"),
    }, content_type="multipart/form-data")
    assert res.status_code == 302
    analysis_id = res.headers["Location"].rstrip("/").rsplit("/", 1)[-1]

    api = client.get("/api/analyses/{}".format(analysis_id))
    assert api.status_code == 200
    assert api.get_json()["summary"]["findings_total"] >= 1

    listing = client.get("/api/analyses")
    assert analysis_id in json.dumps(listing.get_json())

    exported = client.get("/report/{}/export".format(analysis_id))
    assert exported.status_code == 200
    parsed = json.loads(exported.data.decode("utf-8"))
    assert parsed["id"] == analysis_id

    deleted = client.post("/report/{}/delete".format(analysis_id))
    assert deleted.status_code == 302
    assert client.get("/report/{}".format(analysis_id)).status_code == 404


def test_severity_filter(client):
    res = client.post("/upload", data={
        "logfile": (io.BytesIO(AUTH_SAMPLE.encode()), "auth.log"),
    }, content_type="multipart/form-data")
    analysis_id = res.headers["Location"].rstrip("/").rsplit("/", 1)[-1]

    res = client.get("/report/{}?severity=high".format(analysis_id))
    assert res.status_code == 200
    assert b"AUTH_BRUTE_FORCE" in res.data

    res = client.get("/report/{}?severity=critical".format(analysis_id))
    assert res.status_code == 200
    assert b"AUTH_BRUTE_FORCE" not in res.data  # this sample is 'high'
