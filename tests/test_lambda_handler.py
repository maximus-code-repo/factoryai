"""Tests for the Amplify S3-triggered analysis function."""

import importlib.util
import io
import json
from pathlib import Path


HANDLER_PATH = (
    Path(__file__).parents[1]
    / "amplify"
    / "functions"
    / "analyze_logs"
    / "handler.py"
)


def load_handler_module():
    spec = importlib.util.spec_from_file_location("amplify_handler", HANDLER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeS3:
    def __init__(self, body, metadata=None):
        self.body = body
        self.metadata = metadata or {}
        self.puts = []
        self.deletes = []

    def get_object(self, Bucket, Key):
        return {
            "Body": io.BytesIO(self.body),
            "ContentLength": len(self.body),
            "Metadata": self.metadata,
        }

    def put_object(self, **kwargs):
        self.puts.append(kwargs)

    def delete_object(self, **kwargs):
        self.deletes.append(kwargs)


def test_s3_upload_creates_private_analysis_report(monkeypatch):
    handler = load_handler_module()
    log = "\n".join(
        "Sep  9 02:13:00 web01 sshd[{}]: Failed password for root from "
        "203.0.113.66 port {} ssh2".format(i, 52000 + i)
        for i in range(15)
    ).encode()
    fake_s3 = FakeS3(log, {"original-name": "auth%20sample.log"})
    monkeypatch.setattr(handler, "_s3_client", lambda: fake_s3)
    monkeypatch.setenv("logsentinelFiles_BUCKET_NAME", "private-bucket")

    result = handler.handler(
        {
            "Records": [
                {
                    "eventSource": "aws:s3",
                    "eventTime": "2026-09-13T12:00:00Z",
                    "s3": {
                        "bucket": {"name": "private-bucket"},
                        "object": {
                            "key": (
                                "uploads/us-east-1%3Auser-id/"
                                "123e4567-e89b-42d3-a456-426614174000/original.log"
                            )
                        },
                    },
                }
            ]
        },
        None,
    )

    assert result == {
        "reports": [
            (
                "analyses/us-east-1:user-id/"
                "123e4567-e89b-42d3-a456-426614174000/analysis.json"
            )
        ]
    }
    assert len(fake_s3.puts) == 1
    report = json.loads(fake_s3.puts[0]["Body"])
    assert report["status"] == "complete"
    assert report["meta"]["original_name"] == "auth sample.log"
    assert report["summary"]["findings_total"] >= 1
    assert fake_s3.puts[0]["ContentType"] == "application/json"


def test_unexpected_upload_path_is_rejected():
    handler = load_handler_module()
    try:
        handler._report_key("public/file.log")
    except ValueError as exc:
        assert "Unexpected upload path" in str(exc)
    else:
        raise AssertionError("Expected invalid upload path to fail")


def test_invalid_upload_is_deleted_and_records_real_metadata(monkeypatch):
    handler = load_handler_module()
    fake_s3 = FakeS3(b"", {"original-name": "empty.log"})
    monkeypatch.setattr(handler, "_s3_client", lambda: fake_s3)

    report_key = handler._analyze_object(
        "private-bucket",
        "uploads/us-east-1:user/123e4567-e89b-42d3-a456-426614174000/original.log",
        "2026-09-13T12:00:00Z",
    )

    assert report_key.endswith("/analysis.json")
    assert fake_s3.deletes == [
        {
            "Bucket": "private-bucket",
            "Key": (
                "uploads/us-east-1:user/"
                "123e4567-e89b-42d3-a456-426614174000/original.log"
            ),
        }
    ]
    report = json.loads(fake_s3.puts[0]["Body"])
    assert report["uploaded_at"] == "2026-09-13T12:00:00Z"
    assert report["meta"]["size_bytes"] == 0
    assert report["status"] == "failed"
