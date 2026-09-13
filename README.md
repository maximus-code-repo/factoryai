# LogSentinel

A local web app for uploading security logs and finding vulnerability issues in
them. Upload a log file through the browser, get a report with attack
signatures, statistical anomalies, severity ratings, the exact log lines
that triggered each finding, step-by-step remediation advice, and links to
learn more (OWASP, MITRE ATT&CK, NIST, CWE).

Everything runs on your machine. Logs are never sent anywhere else.

## Quick start

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt      # (Linux/macOS: .venv/bin/pip)
python app.py
```

Then open http://127.0.0.1:5000 and upload a log — or try the files in
`samples/`, which contain planted attacks:

| File | What it demonstrates |
|---|---|
| `auth_syslog.log` | SSH brute force ending in a takeover, sudo abuse, persistence |
| `access_apache.log` | Web attacks: SQLi, XSS, traversal, RCE, dir scan, exposed `.env` |
| `events.csv` | Firewall flows: port scan, cleartext protocols, login attack |
| `syslog_firewall.log` | Netfilter syslog: port scan, Telnet/FTP probes, off-hours spike |
| `syslog_insider.log` | Off-hours bulk access, volume spike, `su` brute force, sudo abuse |
| `syslog_baseline.log` | A clean log — should produce **zero** findings (negative control) |

## Supported log formats (auto-detected)

| Format | Examples |
|---|---|
| Apache / Nginx access logs | combined and common log format |
| Syslog / auth logs | RFC 3164 (`Sep 9 02:13:00`) and ISO-8601 timestamps |
| CSV | firewall, EDR, SIEM exports — common column names are auto-mapped |
| JSON | a single array/object or newline-delimited JSONL |
| Plain text | any other text file (best-effort IP/timestamp extraction) |

For CSV/JSON, columns like `ip`, `src_ip`, `client_ip`, `timestamp`, `status`,
`dst_port`, `user_agent`, `url` (and many variants) are mapped automatically;
anything unmapped is still scanned as raw text.

## What it detects

**Signature rules** (explicit attack patterns):

| Rule | Severity | Looks for |
|---|---|---|
| `AUTH_BRUTE_FORCE` | medium–critical | repeated failed logins from one IP |
| `AUTH_COMPROMISE` | critical | successful login following repeated failures |
| `WEB_SQLI` | high | SQL injection in URLs/messages (encoded forms too) |
| `WEB_XSS` | high | cross-site scripting payloads |
| `WEB_TRAVERSAL` | medium–high | path traversal (`../../`, `/etc/passwd`) |
| `WEB_RCE` | high | command-injection probing |
| `WEB_SENSITIVE_HIGH` | high–critical | probes for `.env`, `.git`, SSH keys… (critical if served with HTTP 200) |
| `WEB_SENSITIVE_MED` | medium | probes for admin/backup/config paths |
| `WEB_SCANNER_UA` | medium | sqlmap, nikto, dirb, nuclei and friends |
| `WEB_DIR_SCAN` | high | 404-heavy content-discovery scans |
| `SYS_BREAKIN` / `SYS_SUDO_ABUSE` / `SYS_NEW_USER` / `SYS_ROOT_SESSION` | low–high | syslog threats (break-ins, sudo abuse, persistence) |
| `NET_PORT_SCAN` | high | one IP touching many destination ports |
| `NET_CLEARTEXT` | medium | Telnet/FTP/TFTP traffic |

**Statistical anomalies** (robust median/MAD z-scores, resistant to masking):

| Rule | Looks for |
|---|---|
| `ANOM_VOLUME` | a source IP generating an extreme share of traffic |
| `ANOM_ERROR_RATE` | an IP generating far more HTTP errors than its peers |
| `ANOM_HOURLY` | activity spikes, flagged separately for off-hours |
| `ANOM_SPIKE` | a single minute far above the per-minute norm |
| `ANOM_CRAWLER` | one IP touching far more distinct URLs than its peers |

Each analysis gets a 0–100 **risk score** (critical=10, high=5, medium=2, low=1)
and a band: low / moderate / elevated / high / critical.

Every finding also carries **remediation steps** and **reference links** to
OWASP, MITRE ATT&CK, NIST, and CWE pages describing the vulnerability behind
it (see `logsentinel/knowledge.py`).

## Pages and API

- `GET  /` — dashboard with a summary of all results (KPI tiles, findings by
  severity, findings per analysis stacked by severity) plus the upload form
  and list of analyses
- `POST /upload` — browser upload; redirects to the report
- `GET  /report/<id>` — interactive report (filter with `?severity=high`)
- `GET  /report/<id>/export` — download the full analysis as JSON
- `GET  /api/analyses` — list of analyses (JSON)
- `GET  /api/analyses/<id>` — one full analysis (JSON)
- `GET  /healthz` — health check

## Project layout

```
app.py                  Flask app and routes
logsentinel/
  parsers.py            format detection + CSV/JSON/syslog/Apache parsers
  rules.py              signature detectors
  anomalies.py          statistical detectors
  engine.py             orchestrates parse -> detect -> score
  store.py              filesystem storage for analyses
templates/, static/     UI (no external CSS/JS dependencies)
scripts/generate_samples.py   regenerates the samples/ files
tests/                  pytest suite
data/uploads/           runtime storage (created automatically)
```

## Tests

```bash
.venv\Scripts\pip install -r requirements-dev.txt
.venv\Scripts\python -m pytest -q
```

## Adding your own rule

Open `logsentinel/rules.py`, write a function that takes a list of `Record`
objects and returns `Finding` objects, then add it to `ALL_RULES`. Records are
normalized (`.src_ip`, `.status`, `.path`, `.raw`, …) so rules work across all
log formats. Statistical detectors live in `anomalies.py`.

## Notes

- The Flask dev server is for local use. For a shared deployment, run behind
  a production WSGI server, e.g. `waitress-serve --port 8000 app:create_app()`
  (wrap `create_app` accordingly), and set `SECRET_KEY`.
- Findings are heuristic indicators, not proof. Severity is a triage signal;
  always review the evidence lines before acting.
