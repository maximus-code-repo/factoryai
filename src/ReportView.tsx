import { useMemo, useState } from "react";

import { downloadReport } from "./storage";
import { SEVERITIES } from "./types";
import type { Analysis, Severity } from "./types";

interface ReportViewProps {
  analysis: Analysis;
  onBack: () => void;
  onDelete: (analysis: Analysis) => Promise<void>;
}

export function ReportView({
  analysis,
  onBack,
  onDelete,
}: ReportViewProps) {
  const [severity, setSeverity] = useState<Severity | "all">("all");
  const findings = useMemo(
    () =>
      severity === "all"
        ? analysis.findings
        : analysis.findings.filter((finding) => finding.severity === severity),
    [analysis.findings, severity],
  );
  const counts = analysis.summary.severity_counts;
  const maxCount = Math.max(...SEVERITIES.map((item) => counts[item]), 1);

  return (
    <>
      <div className="report-header">
        <div>
          <h2>{analysis.meta.original_name}</h2>
          <p className="muted">
            <span className="chip">{analysis.meta.format}</span>{" "}
            {analysis.summary.total_records.toLocaleString()} records ·{" "}
            {analysis.summary.unique_ips} source IPs · analyzed{" "}
            {new Date(analysis.uploaded_at).toLocaleString()}
          </p>
        </div>
        <div className={`risk-box band-${analysis.summary.risk_band}`}>
          <div className="risk-score">{analysis.summary.risk_score}</div>
          <div className="risk-band">
            {analysis.summary.risk_band} risk
          </div>
        </div>
      </div>

      {analysis.warnings.map((warning) => (
        <div className="flash warn" key={warning}>
          {warning}
        </div>
      ))}

      <div className="chips-row">
        <button
          className={`chip ${severity === "all" ? "active" : ""}`}
          onClick={() => setSeverity("all")}
        >
          All {analysis.summary.findings_total}
        </button>
        {SEVERITIES.map((item) => (
          <button
            className={`chip sev-bg-${item} ${
              severity === item ? "active" : ""
            }`}
            key={item}
            onClick={() => setSeverity(item)}
          >
            {item} {counts[item]}
          </button>
        ))}
      </div>

      {analysis.summary.findings_total > 0 && (
        <div className="card">
          <h3>Findings by severity</h3>
          <div className="sev-bars">
            {SEVERITIES.map((item) => (
              <div className="sev-bar-row" key={item}>
                <span className="sev-label">{item}</span>
                <div className="sev-bar">
                  <div
                    className={`sev-fill sev-${item}`}
                    style={{ width: `${(100 * counts[item]) / maxCount}%` }}
                  />
                </div>
                <span className="sev-count">{counts[item]}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {analysis.summary.flagged_ips.length > 0 && (
        <div className="card">
          <h3>Most flagged source IPs</h3>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Source IP</th>
                  <th>Findings</th>
                  <th>Max severity</th>
                </tr>
              </thead>
              <tbody>
                {analysis.summary.flagged_ips.map((item) => (
                  <tr key={item.ip}>
                    <td className="mono">{item.ip}</td>
                    <td>{item.findings}</td>
                    <td>
                      <span className={`badge sev-${item.max_severity}`}>
                        {item.max_severity}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <section className="findings">
        {findings.map((finding, index) => (
          <article
            className={`finding card border-${finding.severity}`}
            key={`${finding.rule_id}-${finding.src_ip ?? "global"}-${index}`}
          >
            <header className="finding-head">
              <span className={`badge sev-${finding.severity}`}>
                {finding.severity}
              </span>
              <h3>{finding.title}</h3>
              <span className="chip">{finding.rule_id}</span>
              <span className="chip">
                {finding.category === "anomaly" ? "statistical" : "signature"}
              </span>
            </header>
            <p className="finding-desc">{finding.description}</p>
            {Object.keys(finding.metrics).length > 0 && (
              <div className="metrics">
                {Object.entries(finding.metrics).map(([key, value]) => (
                  <span className="metric" key={key}>
                    <b>{key}</b> {String(value)}
                  </span>
                ))}
              </div>
            )}
            <div className="callout">
              <b>Recommendation:</b> {finding.recommendation}
            </div>
            {finding.remediation_steps.length > 0 && (
              <div className="remediation">
                <h4>Remediation steps</h4>
                <ol className="step-list">
                  {finding.remediation_steps.map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ol>
              </div>
            )}
            {finding.references.length > 0 && (
              <div className="remediation">
                <h4>Learn more</h4>
                <ul className="ref-list">
                  {finding.references.map((reference) => (
                    <li key={reference.url}>
                      <a
                        href={reference.url}
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        {reference.label}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {finding.evidence.length > 0 && (
              <details className="evidence">
                <summary>
                  Show {finding.evidence.length} sample line
                  {finding.evidence.length === 1 ? "" : "s"}
                  {finding.count > finding.evidence.length
                    ? ` (of ${finding.count})`
                    : ""}
                </summary>
                <pre className="evidence-pre">
                  {finding.evidence
                    .map(
                      (item) =>
                        `${item.timestamp ? `[${item.timestamp}] ` : ""}${
                          item.raw
                        }`,
                    )
                    .join("\n")}
                </pre>
              </details>
            )}
          </article>
        ))}
        {findings.length === 0 && (
          <div className="card empty-note">
            <h3>
              {analysis.summary.findings_total
                ? "No findings at this severity"
                : "No vulnerability issues detected"}
            </h3>
            <p className="muted">
              Heuristics can miss activity. Review the source log and compare
              against a longer time range if you are suspicious.
            </p>
          </div>
        )}
      </section>

      <div className="actions">
        <button className="btn" onClick={() => void downloadReport(analysis)}>
          Download JSON report
        </button>
        <button className="btn" onClick={onBack}>
          Back to all analyses
        </button>
        <button
          className="btn danger"
          onClick={() => void onDelete(analysis)}
        >
          Delete
        </button>
      </div>
    </>
  );
}
