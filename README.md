# LogSentinel

A web app for uploading security logs and finding vulnerability issues in
them. Run it locally with Flask, or deploy the full-stack version to AWS
Amplify. Upload a log file through the browser and get a report with attack
signatures, statistical anomalies, severity ratings, the exact log lines
that triggered each finding, step-by-step remediation advice, and links to
learn more (OWASP, MITRE ATT&CK, NIST, CWE).

The local Flask version keeps everything on your machine. The Amplify version
stores each signed-in user's logs and reports in private paths inside your AWS
account.

## Deploy to AWS Amplify

The Amplify Gen 2 deployment includes:

- a React/Vite frontend hosted by Amplify Hosting
- Cognito email/password sign-in
- private, per-user S3 storage
- direct multipart uploads up to 100 MB
- an S3-triggered Python 3.13 Lambda that reuses the existing analysis engine
- asynchronous reports stored as JSON in each user's private S3 path

### Deploy from GitHub

1. Open the [AWS Amplify console](https://console.aws.amazon.com/amplify/).
2. Choose **Create new app**, then select **GitHub**.
3. Select this repository and the branch you want to deploy.
4. Let Amplify use the repository's `amplify.yml` build settings.
5. Create or select an Amplify service role when prompted, then deploy.
6. Open the deployed URL and create an account. Cognito sends an email
   confirmation code before the first sign-in.

Amplify runs `ampx pipeline-deploy` before building the frontend, so it creates
`amplify_outputs.json` automatically with the deployed backend configuration.

### Develop the Amplify version locally

Requirements:

- Node.js 22
- AWS credentials with `AmplifyBackendDeployFullAccess`

```bash
npm install
npm run sandbox
```

Keep the sandbox running, then start Vite in another terminal:

```bash
npm run dev
```

The sandbox creates an ignored `amplify_outputs.json` file. If you only run
`npm run build`, the build script creates a nonfunctional placeholder so the
frontend can still be type-checked and bundled without AWS credentials.

### Cloud storage and limits

- Users can only read and delete objects under their own Cognito identity path.
- The analyzer Lambda can read uploads and write reports, but users cannot
  access another user's files through Amplify Storage.
- S3 automatically uses multipart uploads for files larger than 5 MB.
- The UI and Lambda both enforce a 100 MB file limit.
- Incomplete multipart uploads are removed after one day.
- The S3 bucket uses `keepOnDelete: true`, so deleting the Amplify backend does
  not delete stored security logs. Retained storage continues to incur charges
  until the bucket is removed manually.
- Processing is asynchronous. Large logs may take several minutes, and the
  dashboard polls for the completed report.

Security logs can contain sensitive data. Review IAM access, S3 retention,
Cognito signup settings, CloudWatch logs, and your AWS region's compliance
requirements before using the app with production logs.

## Run the local Flask version

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
app.py                  local Flask app and routes
src/                    Amplify React frontend
amplify/
  auth/                 Cognito email/password authentication
  storage/              private per-user S3 access rules
  functions/            S3-triggered Python analyzer Lambda
  backend.ts            Amplify backend and S3 event wiring
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
amplify.yml             Amplify Hosting build configuration
```

## Tests

```bash
.venv\Scripts\pip install -r requirements-dev.txt
.venv\Scripts\python -m pytest -q
npm install
npm run build
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
- The Amplify deployment sends uploaded logs to S3 in your AWS account.
- Findings are heuristic indicators, not proof. Severity is a triage signal;
  always review the evidence lines before acting.
