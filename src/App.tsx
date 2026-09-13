import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { ReportView } from "./ReportView";
import {
  ALLOWED_EXTENSIONS,
  deleteAnalysis,
  loadReports,
  MAX_UPLOAD_BYTES,
  uploadLog,
} from "./storage";
import { SEVERITIES } from "./types";
import type { Analysis, PendingAnalysis, Severity } from "./types";

interface AppProps {
  username?: string;
  signOut?: () => void;
}

export default function App({ username, signOut }: AppProps) {
  const [analyses, setAnalyses] = useState<Analysis[]>([]);
  const [pending, setPending] = useState<PendingAnalysis[]>([]);
  const [selected, setSelected] = useState<Analysis | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState(0);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [dragging, setDragging] = useState(false);
  const refreshGeneration = useRef(0);

  const sameItems = <T,>(current: T[], next: T[]) =>
    current.length === next.length &&
    current.every((item, index) => item === next[index]);

  const refresh = useCallback(async () => {
    const generation = ++refreshGeneration.current;
    try {
      const loaded = await loadReports();
      if (generation !== refreshGeneration.current) return;
      setAnalyses((current) =>
        sameItems(current, loaded.analyses) ? current : loaded.analyses,
      );
      setPending((current) =>
        sameItems(current, loaded.pending) ? current : loaded.pending,
      );
      setSelected((current) =>
        current
          ? loaded.analyses.find((item) => item.id === current.id) ?? null
          : null,
      );
    } catch (refreshError) {
      console.error(refreshError);
      setError("Could not load your saved analyses.");
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (pending.length === 0) return;
    let cancelled = false;
    let timer: number | undefined;
    const poll = async () => {
      await refresh();
      if (!cancelled) timer = window.setTimeout(poll, 5000);
    };
    timer = window.setTimeout(poll, 5000);
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [pending.length, refresh]);

  const overview = useMemo(() => {
    const counts = Object.fromEntries(
      SEVERITIES.map((severity) => [
        severity,
        analyses.reduce(
          (sum, analysis) =>
            sum + analysis.summary.severity_counts[severity],
          0,
        ),
      ]),
    ) as Record<Severity, number>;
    return {
      records: analyses.reduce(
        (sum, analysis) => sum + analysis.summary.total_records,
        0,
      ),
      findings: analyses.reduce(
        (sum, analysis) => sum + analysis.summary.findings_total,
        0,
      ),
      counts,
    };
  }, [analyses]);

  const chooseFile = (nextFile: File | undefined) => {
    if (!nextFile) return;
    setError("");
    const extension = nextFile.name.includes(".")
      ? `.${nextFile.name.split(".").pop()?.toLowerCase()}`
      : "";
    if (extension && !ALLOWED_EXTENSIONS.has(extension)) {
      setError("Unsupported file type. Choose a CSV, JSON, log, or text file.");
      setFile(null);
      return;
    }
    if (nextFile.size > MAX_UPLOAD_BYTES) {
      setError("That file exceeds the 100 MB upload limit.");
      setFile(null);
      return;
    }
    if (nextFile.size === 0) {
      setError("That file is empty.");
      setFile(null);
      return;
    }
    setFile(nextFile);
  };

  const submit = async () => {
    if (!file) {
      setError("Choose a log file first.");
      return;
    }
    setBusy(true);
    setError("");
    setMessage("");
    setProgress(0);
    try {
      await uploadLog(file, setProgress);
      setFile(null);
      setProgress(1);
      setMessage(
        "Upload complete. Analysis is running and this page will refresh automatically.",
      );
      await refresh();
    } catch (uploadError) {
      console.error(uploadError);
      setError("The upload failed. Check your connection and try again.");
    } finally {
      setBusy(false);
    }
  };

  const removeAnalysis = async (analysis: Analysis) => {
    if (!window.confirm(`Delete ${analysis.meta.original_name}?`)) {
      return;
    }
    setBusy(true);
    setError("");
    try {
      await deleteAnalysis(analysis);
      if (selected?.id === analysis.id) {
        setSelected(null);
      }
      await refresh();
    } catch (deleteError) {
      console.error(deleteError);
      setError("The analysis could not be completely deleted. Try again.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <header className="topbar">
        <div className="topbar-inner">
          <button className="brand brand-button" onClick={() => setSelected(null)}>
            <span className="brand-mark">▣</span> LogSentinel
          </button>
          <span className="tagline">
            Private cloud security-log analysis
          </span>
          <span className="user-menu">
            <span className="muted">{username}</span>
            <button className="btn small" onClick={signOut}>
              Sign out
            </button>
          </span>
        </div>
      </header>

      <main className="container">
        {error && <div className="flash error">{error}</div>}
        {message && <div className="flash">{message}</div>}

        {selected ? (
          <ReportView
            analysis={selected}
            onBack={() => setSelected(null)}
            onDelete={removeAnalysis}
          />
        ) : (
          <>
            <section className="card upload-card">
              <h2>Upload a security log</h2>
              <p className="muted">
                The file is uploaded directly to your private S3 folder and
                analyzed asynchronously. Maximum size: 100 MB.
              </p>
              <div className="upload-form">
                <label
                  className={`dropzone ${dragging ? "dragging" : ""}`}
                  onDragEnter={() => setDragging(true)}
                  onDragLeave={() => setDragging(false)}
                  onDragOver={(event) => event.preventDefault()}
                  onDrop={(event) => {
                    event.preventDefault();
                    setDragging(false);
                    chooseFile(event.dataTransfer.files[0]);
                  }}
                >
                  <input
                    type="file"
                    accept=".csv,.json,.jsonl,.ndjson,.log,.txt,.text,.out"
                    disabled={busy}
                    onChange={(event) => chooseFile(event.target.files?.[0])}
                  />
                  <p className="dz-big">
                    {file?.name ?? "Drop a log file here"}
                  </p>
                  <p className="muted dz-label">or click to browse</p>
                </label>
                {busy && progress > 0 && (
                  <div className="progress-track" aria-label="Upload progress">
                    <div
                      className="progress-fill"
                      style={{ width: `${Math.round(progress * 100)}%` }}
                    />
                  </div>
                )}
                <button
                  className="btn primary"
                  disabled={busy || !file}
                  onClick={() => void submit()}
                >
                  {busy ? `Uploading ${Math.round(progress * 100)}%` : "Analyze log"}
                </button>
              </div>
            </section>

            {(analyses.length > 0 || pending.length > 0) && (
              <section className="card overview-card">
                <div className="overview-head">
                  <h2>Summary of results</h2>
                  <button className="btn small" onClick={() => void refresh()}>
                    Refresh
                  </button>
                </div>
                <div className="kpi-row">
                  <div className="kpi">
                    <div className="kpi-value">{analyses.length}</div>
                    <div className="kpi-label">completed analyses</div>
                  </div>
                  <div className="kpi">
                    <div className="kpi-value">
                      {overview.records.toLocaleString()}
                    </div>
                    <div className="kpi-label">log records analyzed</div>
                  </div>
                  <div className="kpi">
                    <div className="kpi-value">
                      {overview.findings.toLocaleString()}
                    </div>
                    <div className="kpi-label">findings</div>
                  </div>
                  <div className="kpi">
                    <div className="kpi-value sev-critical">
                      {overview.counts.critical}
                    </div>
                    <div className="kpi-label">critical findings</div>
                  </div>
                </div>
              </section>
            )}

            <section className="card">
              <h2>Recent analyses</h2>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Risk</th>
                      <th>File</th>
                      <th>Format</th>
                      <th>Records</th>
                      <th>Findings</th>
                      <th>Uploaded</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {pending.map((item) => (
                      <tr key={item.id}>
                        <td>
                          <span className="badge processing">processing</span>
                        </td>
                        <td className="name-cell">{item.name}</td>
                        <td>—</td>
                        <td>—</td>
                        <td>—</td>
                        <td>{item.uploadedAt?.toLocaleString() ?? "Just now"}</td>
                        <td className="muted">Wait for analysis</td>
                      </tr>
                    ))}
                    {analyses.map((analysis) => (
                      <tr key={analysis.id}>
                        <td>
                          <button
                            className={`badge band-${analysis.summary.risk_band}`}
                            onClick={() => setSelected(analysis)}
                          >
                            {analysis.status === "failed"
                              ? "failed"
                              : `${analysis.summary.risk_band} · ${analysis.summary.risk_score}`}
                          </button>
                        </td>
                        <td className="name-cell">
                          <button
                            className="link-button"
                            onClick={() => setSelected(analysis)}
                          >
                            {analysis.meta.original_name}
                          </button>
                        </td>
                        <td>
                          <span className="chip">{analysis.meta.format}</span>
                        </td>
                        <td>{analysis.summary.total_records.toLocaleString()}</td>
                        <td>{analysis.summary.findings_total}</td>
                        <td>
                          {new Date(analysis.uploaded_at).toLocaleString()}
                        </td>
                        <td>
                          <button
                            className="btn danger small"
                            disabled={busy}
                            onClick={() => void removeAnalysis(analysis)}
                          >
                            Delete
                          </button>
                        </td>
                      </tr>
                    ))}
                    {analyses.length === 0 && pending.length === 0 && (
                      <tr>
                        <td colSpan={7} className="muted empty-note">
                          No analyses yet. Upload a log file to get started.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}
      </main>

      <footer className="footer">
        Files and reports are private to your signed-in account. Findings are
        heuristic indicators, not proof. Always review the evidence.
      </footer>
    </>
  );
}
