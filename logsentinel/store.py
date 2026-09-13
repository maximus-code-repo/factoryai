"""Filesystem-backed storage for analyses and their raw uploads.

Each analysis lives in <root>/<id>/ with two files:
- analysis.json : the full analysis result (what the report page shows)
- original.<ext>: the uploaded file, byte for byte
"""

import json
import os
import re
import shutil
import threading
import uuid
from datetime import datetime, timezone
from typing import Optional

_ID_RE = re.compile(r"^[0-9a-f]{12}$")


class AnalysisStore:
    def __init__(self, root):
        self.root = os.path.abspath(root)
        self._lock = threading.RLock()
        os.makedirs(self.root, exist_ok=True)

    def _path(self, analysis_id, name):
        return os.path.join(self.root, analysis_id, name)

    def _load(self, analysis_id) -> Optional[dict]:
        if not _ID_RE.match(analysis_id or ""):
            return None
        path = self._path(analysis_id, "analysis.json")
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def save(self, analysis: dict, raw_bytes: bytes, original_name: str) -> str:
        analysis_id = uuid.uuid4().hex[:12]
        analysis = dict(analysis)
        analysis["id"] = analysis_id
        analysis["uploaded_at"] = datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        )
        directory = os.path.join(self.root, analysis_id)
        with self._lock:
            os.makedirs(directory, exist_ok=True)
            ext = os.path.splitext(original_name or "")[1].lower()
            if not ext or len(ext) > 10:
                ext = ""
            with open(self._path(analysis_id, "original" + ext), "wb") as fh:
                fh.write(raw_bytes)
            with open(self._path(analysis_id, "analysis.json"), "w",
                      encoding="utf-8") as fh:
                json.dump(analysis, fh, ensure_ascii=False, indent=2)
        return analysis_id

    def get(self, analysis_id) -> Optional[dict]:
        with self._lock:
            return self._load(analysis_id)

    def summaries(self) -> list:
        """Lightweight rows for the home page, newest first."""
        out = []
        with self._lock:
            for name in os.listdir(self.root):
                analysis = self._load(name)
                if not analysis:
                    continue
                summary = analysis.get("summary", {})
                meta = analysis.get("meta", {})
                out.append({
                    "id": analysis.get("id", name),
                    "name": meta.get("original_name", "unknown"),
                    "format": meta.get("format", "text"),
                    "total_records": summary.get("total_records", 0),
                    "counts": summary.get("severity_counts", {}),
                    "findings_total": summary.get("findings_total", 0),
                    "risk_score": summary.get("risk_score", 0),
                    "risk_band": summary.get("risk_band", "low"),
                    "uploaded_at": analysis.get("uploaded_at", ""),
                })
        out.sort(key=lambda row: row["uploaded_at"], reverse=True)
        return out

    def delete(self, analysis_id) -> bool:
        if not _ID_RE.match(analysis_id or ""):
            return False
        directory = os.path.join(self.root, analysis_id)
        with self._lock:
            if not os.path.isdir(directory):
                return False
            shutil.rmtree(directory)
            return True
