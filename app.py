"""LogSentinel - a Flask web app for uploading and analyzing security logs.

Run locally with:  python app.py
then open          http://127.0.0.1:5000
"""

import io
import json
import os

from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, send_file, url_for)

from logsentinel import __version__
from logsentinel.engine import analyze_text
from logsentinel.models import SEVERITY_ORDER
from logsentinel.store import AnalysisStore

MAX_UPLOAD_BYTES = 50 * 1024 * 1024
with open(os.path.join(os.path.dirname(__file__), "logsentinel", "upload_policy.json"),
          encoding="utf-8") as _policy_file:
    ALLOWED_EXTENSIONS = set(json.load(_policy_file)["extensions"])

SEVERITIES = ("critical", "high", "medium", "low")
RISK_BAND_RANK = {"low": 0, "moderate": 1, "elevated": 2, "high": 3, "critical": 4}


def _build_overview(analyses):
    """Aggregate analysis summaries into chart-ready data for the home page."""
    if not analyses:
        return None
    severity_totals = {sev: 0 for sev in SEVERITIES}
    records = 0
    for row in analyses:
        counts = row.get("counts") or {}
        for sev in SEVERITIES:
            severity_totals[sev] += counts.get(sev) or 0
        records += row.get("total_records") or 0
    worst_band = max((row.get("risk_band", "low") for row in analyses),
                     key=lambda band: RISK_BAND_RANK.get(band, 0))
    peak = max(severity_totals.values()) or 1
    max_total = max((row.get("findings_total") or 0) for row in analyses) or 1
    bars = []
    for row in sorted(analyses, key=lambda r: r.get("findings_total") or 0,
                      reverse=True)[:8]:
        counts = row.get("counts") or {}
        total = row.get("findings_total") or 0
        segments = [
            {"severity": sev,
             "pct": round(100 * (counts.get(sev) or 0) / total, 1)}
            for sev in SEVERITIES if counts.get(sev)
        ]
        bars.append({
            "id": row["id"],
            "name": row.get("name", "unknown"),
            "total": total,
            "width": round(100 * total / max_total, 1),
            "segments": segments,
        })
    return {
        "analyses": len(analyses),
        "records": records,
        "findings": sum(severity_totals.values()),
        "critical": severity_totals["critical"],
        "worst_band": worst_band,
        "severity_totals": severity_totals,
        "severity_pct": {sev: round(100 * severity_totals[sev] / peak, 1)
                         for sev in SEVERITIES},
        "bars": bars,
    }


def create_app(data_dir=None, secret_key=None):
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
    app.config["SECRET_KEY"] = (
        secret_key or os.environ.get("SECRET_KEY", "logsentinel-dev-key")
    )
    store = AnalysisStore(data_dir or os.path.join(app.root_path, "data", "uploads"))

    @app.context_processor
    def _inject_version():
        return {"version": __version__}

    @app.route("/")
    def index():
        analyses = store.summaries()
        return render_template("index.html", analyses=analyses,
                               overview=_build_overview(analyses))

    @app.route("/upload", methods=["POST"])
    def upload():
        uploaded = request.files.get("logfile")
        if not uploaded or not uploaded.filename:
            flash("Choose a log file to upload first.")
            return redirect(url_for("index"))
        original_name = uploaded.filename
        ext = os.path.splitext(original_name)[1].lower()
        if ext and ext not in ALLOWED_EXTENSIONS:
            flash(
                "Unsupported file type '{}'. Supported: csv, json, jsonl, "
                "log, txt.".format(ext)
            )
            return redirect(url_for("index"))
        data = uploaded.read()
        if not data.strip():
            flash("That file appears to be empty.")
            return redirect(url_for("index"))
        text = data.decode("utf-8", errors="replace")
        try:
            analysis = analyze_text(original_name, text, size_bytes=len(data))
        except Exception as exc:
            flash("Analysis failed: {}".format(exc))
            return redirect(url_for("index"))
        analysis_id = store.save(analysis, data, original_name)
        flash(
            "Analyzed {:,} log records - {} finding(s).".format(
                analysis["summary"]["total_records"],
                analysis["summary"]["findings_total"],
            )
        )
        return redirect(url_for("report", analysis_id=analysis_id))

    @app.route("/report/<analysis_id>")
    def report(analysis_id):
        analysis = store.get(analysis_id)
        if analysis is None:
            abort(404)
        severity = request.args.get("severity", "all")
        findings = analysis.get("findings", [])
        if severity in SEVERITY_ORDER:
            findings = [f for f in findings if f["severity"] == severity]
        return render_template(
            "report.html", a=analysis, findings=findings, severity=severity
        )

    @app.route("/report/<analysis_id>/export")
    def export_report(analysis_id):
        analysis = store.get(analysis_id)
        if analysis is None:
            abort(404)
        payload = json.dumps(analysis, indent=2).encode("utf-8")
        return send_file(
            io.BytesIO(payload),
            as_attachment=True,
            download_name="logsentinel-{}.json".format(analysis_id),
            mimetype="application/json",
        )

    @app.route("/report/<analysis_id>/delete", methods=["POST"])
    def delete_report(analysis_id):
        if store.delete(analysis_id):
            flash("Analysis deleted.")
        else:
            flash("Analysis not found.")
        return redirect(url_for("index"))

    @app.route("/api/analyses")
    def api_analyses():
        return jsonify(store.summaries())

    @app.route("/api/analyses/<analysis_id>")
    def api_analysis(analysis_id):
        analysis = store.get(analysis_id)
        if analysis is None:
            abort(404)
        return jsonify(analysis)

    @app.route("/healthz")
    def healthz():
        return jsonify({"status": "ok", "version": __version__})

    @app.errorhandler(413)
    def too_large(_error):
        flash("File is too large (limit is 50 MB).")
        return redirect(url_for("index"))

    return app


if __name__ == "__main__":
    application = create_app()
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "1") != "0"
    print(" * LogSentinel running at http://127.0.0.1:{} (Ctrl+C to stop)".format(port))
    application.run(host="127.0.0.1", port=port, debug=debug)
