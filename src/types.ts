export const SEVERITIES = ["critical", "high", "medium", "low"] as const;
export type Severity = (typeof SEVERITIES)[number];

export interface Evidence {
  line_no: number;
  timestamp: string | null;
  raw: string;
}

export interface Finding {
  rule_id: string;
  title: string;
  severity: Severity;
  category: "rule" | "anomaly";
  description: string;
  recommendation: string;
  count: number;
  src_ip?: string | null;
  evidence: Evidence[];
  metrics: Record<string, string | number>;
  remediation_steps: string[];
  references: Array<{ label: string; url: string }>;
}

export interface Analysis {
  id: string;
  status: "complete" | "failed";
  uploaded_at: string;
  meta: {
    original_name: string;
    format: string;
    size_bytes: number;
    analyzed_at: string;
    analyzer: string;
    source_key: string;
  };
  parse: {
    total_lines: number;
    structured: number;
  };
  summary: {
    total_records: number;
    records_with_timestamp: number;
    records_with_ip: number;
    unique_ips: number;
    time_range: { start: string; end: string } | null;
    severity_counts: Record<Severity, number>;
    findings_total: number;
    risk_score: number;
    risk_band: "low" | "moderate" | "elevated" | "high" | "critical";
    flagged_ips: Array<{
      ip: string;
      findings: number;
      max_severity: Severity;
    }>;
  };
  findings: Finding[];
  warnings: string[];
  storagePath: string;
}

export interface PendingAnalysis {
  id: string;
  name: string;
  sourcePath: string;
  uploadedAt?: Date;
}
