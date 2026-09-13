"""S3-triggered LogSentinel analyzer for AWS Amplify."""

import json
import logging
import os
import re
from datetime import datetime, timezone
from importlib.resources import files
from urllib.parse import unquote_plus

from logsentinel.engine import analyze_text
from logsentinel.models import FINDING_SEVERITIES

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)

MAX_UPLOAD_BYTES = 100 * 1024 * 1024
with files("logsentinel").joinpath("upload_policy.json").open(
    "r", encoding="utf-8"
) as _policy_file:
    ALLOWED_EXTENSIONS = set(json.load(_policy_file)["extensions"])

UPLOAD_KEY_RE = re.compile(
    r"^uploads/[^/]+/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}/original(?:\.[a-z0-9]+)?$"
)

_s3 = None


def _s3_client():
    global _s3
    if _s3 is None:
        import boto3

        _s3 = boto3.client("s3")
    return _s3


def _report_key(source_key):
    if not UPLOAD_KEY_RE.match(source_key):
        raise ValueError("Unexpected upload path")
    parts = source_key.split("/")
    return "analyses/{}/{}/analysis.json".format(parts[1], parts[2])


def _failed_analysis(
    analysis_id, filename, source_key, event_time, size_bytes, message
):
    return {
        "id": analysis_id,
        "status": "failed",
        "uploaded_at": event_time,
        "meta": {
            "original_name": filename,
            "format": "unknown",
            "size_bytes": size_bytes,
            "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "analyzer": "LogSentinel",
            "source_key": source_key,
        },
        "parse": {"total_lines": 0, "structured": 0},
        "summary": {
            "total_records": 0,
            "records_with_timestamp": 0,
            "records_with_ip": 0,
            "unique_ips": 0,
            "time_range": None,
            "severity_counts": {severity: 0 for severity in FINDING_SEVERITIES},
            "findings_total": 0,
            "risk_score": 0,
            "risk_band": "low",
            "flagged_ips": [],
        },
        "findings": [],
        "warnings": [message],
    }


def _analyze_object(bucket, source_key, event_time):
    s3 = _s3_client()
    report_key = _report_key(source_key)
    analysis_id = source_key.split("/")[2]
    response = s3.get_object(Bucket=bucket, Key=source_key)
    metadata = response.get("Metadata") or {}
    filename = unquote_plus(metadata.get("original-name", "uploaded.log"))
    size_bytes = response.get("ContentLength") or 0

    try:
        if size_bytes > MAX_UPLOAD_BYTES:
            raise ValueError("The uploaded file exceeds the 100 MB limit.")
        extension = os.path.splitext(filename)[1].lower()
        if extension and extension not in ALLOWED_EXTENSIONS:
            raise ValueError("The uploaded file type is not supported.")

        raw_bytes = response["Body"].read(MAX_UPLOAD_BYTES + 1)
        if len(raw_bytes) > MAX_UPLOAD_BYTES:
            raise ValueError("The uploaded file exceeds the 100 MB limit.")
        if not raw_bytes or raw_bytes.isspace():
            raise ValueError("The uploaded file is empty.")

        text = raw_bytes.decode("utf-8", errors="replace")
        del raw_bytes
        analysis = analyze_text(filename, text, size_bytes=size_bytes)
        analysis.update(
            {
                "id": analysis_id,
                "status": "complete",
                "uploaded_at": event_time,
            }
        )
        analysis["meta"]["source_key"] = source_key
    except Exception as exc:
        LOGGER.exception("Analysis failed for s3://%s/%s", bucket, source_key)
        analysis = _failed_analysis(
            analysis_id,
            filename,
            source_key,
            event_time,
            size_bytes,
            "Analysis failed: {}".format(exc),
        )
        s3.delete_object(Bucket=bucket, Key=source_key)

    s3.put_object(
        Bucket=bucket,
        Key=report_key,
        Body=json.dumps(
            analysis, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8"),
        ContentType="application/json",
    )
    return report_key


def handler(event, _context):
    """Analyze each newly uploaded S3 object and write its JSON report."""
    bucket_from_environment = os.environ.get("logsentinelFiles_BUCKET_NAME")
    completed = []

    for record in event.get("Records", []):
        if record.get("eventSource") != "aws:s3":
            continue
        bucket = record["s3"]["bucket"]["name"]
        if bucket_from_environment and bucket != bucket_from_environment:
            LOGGER.warning("Ignoring event from unexpected bucket %s", bucket)
            continue
        source_key = unquote_plus(record["s3"]["object"]["key"])
        if not UPLOAD_KEY_RE.match(source_key):
            LOGGER.warning("Ignoring unexpected upload key %s", source_key)
            continue
        completed.append(
            _analyze_object(
                bucket,
                source_key,
                record.get("eventTime")
                or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            )
        )

    return {"reports": completed}
