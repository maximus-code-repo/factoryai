# LogSentinel

LogSentinel analyzes security logs for attack signatures and unusual activity.
It normalizes several log formats, runs signature and statistical detectors,
assigns a risk score, and produces findings with evidence, remediation steps,
and links to OWASP, MITRE ATT&CK, NIST, and CWE guidance.

The repository contains two applications built on the same Python analysis
engine:

| Application | Intended use | Storage | Upload limit |
|---|---|---|---|
| Flask | Local analysis and development | Local filesystem | 50 MB |
| AWS Amplify Gen 2 | Authenticated cloud deployment | Private per-user S3 paths | 100 MB |

Findings are heuristic indicators, not proof that an attack succeeded. Review
the evidence and source logs before taking action.

## Features

- Automatic parsing for Apache/Nginx access logs, syslog/auth logs, CSV,
  JSON/JSONL, and plain text
- Signature detection for authentication, web, system, and network threats
- Robust median/MAD anomaly detection for traffic outliers
- Critical, high, medium, and low severity ratings
- A capped 0–100 risk score and low, moderate, elevated, high, or critical band
- Up to 10 source-log evidence lines per finding
- Remediation steps and authoritative reference links
- JSON report downloads
- A right-side chatbot powered by Amazon Nova 2 Lite
- Private, per-user saved chat sessions in the Amplify deployment
- Sample attack logs and a clean negative-control log
- A pytest suite covering parsers, rules, anomalies, Flask routes, sample logs,
  and the Amplify Lambda and Bedrock handlers

## Supported input

The shared upload policy accepts these extensions:

```text
.csv .json .jsonl .ndjson .log .txt .text .out
```

Files without an extension are also accepted. Text is decoded as UTF-8 with
replacement for invalid byte sequences. Files with more than 1,000,000 lines
are rejected.

| Detected format | Supported input |
|---|---|
| Apache/Nginx | Common and combined access-log layouts |
| Syslog | RFC 3164 and ISO-8601 timestamps, including auth and netfilter lines |
| CSV | Common SIEM, firewall, EDR, HTTP, identity, and port column names |
| JSON | A single object, an array, or newline-delimited JSON |
| Plain text | Best-effort IPv4 and ISO-8601 timestamp extraction |

CSV and JSON fields are normalized to a common record model. Recognized fields
include source IP, timestamp, user, event/message, HTTP method, path, query,
status, user agent, host, and destination port. Unmapped values remain
available to detectors as raw text or extra fields.

## Detection rules

### Signature detectors

| Rule | Severity | Detects |
|---|---|---|
| `AUTH_BRUTE_FORCE` | medium–critical | Repeated login failures from one source IP |
| `AUTH_COMPROMISE` | critical | A successful login after repeated failures |
| `WEB_SQLI` | high | SQL-injection payloads, including URL-encoded forms |
| `WEB_XSS` | high | Cross-site scripting payloads |
| `WEB_TRAVERSAL` | medium–high | Path traversal and system-file access attempts |
| `WEB_RCE` | high | Command-injection and remote-code-execution probes |
| `WEB_SENSITIVE_HIGH` | high–critical | Requests for `.env`, `.git`, SSH keys, and similar files |
| `WEB_SENSITIVE_MED` | medium | Requests for admin, backup, and configuration paths |
| `WEB_SCANNER_UA` | medium | Scanner user agents such as sqlmap, nikto, dirb, and nuclei |
| `WEB_DIR_SCAN` | high | High-volume, 404-heavy content discovery |
| `SYS_BREAKIN` | high | Possible system break-ins |
| `SYS_SUDO_ABUSE` | high | Suspicious sudo activity |
| `SYS_NEW_USER` | medium | New local-user creation |
| `SYS_ROOT_SESSION` | low | Root-session activity |
| `NET_PORT_SCAN` | high | One source touching many destination ports |
| `NET_CLEARTEXT` | medium | FTP, Telnet, and TFTP traffic |

### Statistical detectors

| Rule | Detects |
|---|---|
| `ANOM_VOLUME` | A source IP producing unusually high traffic volume |
| `ANOM_ERROR_RATE` | A source IP producing unusually many HTTP errors |
| `ANOM_HOURLY` | Unusual hourly activity, with separate off-hours handling |
| `ANOM_SPIKE` | A minute-level traffic spike |
| `ANOM_CRAWLER` | A source touching unusually many distinct URLs |

Statistical rules use median/MAD modified z-scores and minimum population
thresholds. Small or homogeneous logs may not provide enough baseline data for
anomaly detection.

## Risk scoring

Each finding contributes to the analysis score:

| Severity | Points |
|---|---:|
| Critical | 10 |
| High | 5 |
| Medium | 2 |
| Low | 1 |

The total is capped at 100. Risk bands begin at:

| Band | Minimum score |
|---|---:|
| Critical | 60 |
| High | 30 |
| Elevated | 15 |
| Moderate | 5 |
| Low | 0 |

## Run the local Flask application

The Flask application binds to `127.0.0.1`, uses port `5000` by default, and
enables Flask debug mode unless `FLASK_DEBUG=0` is set.

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

### Linux or macOS

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
./.venv/bin/python app.py
```

Open <http://127.0.0.1:5000>. Uploaded files and generated reports are saved
under `data/uploads/`, which is ignored by Git. Each analysis directory
contains the original upload and `analysis.json`.

### Flask pages and API

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/` | Upload form, aggregate dashboard, and recent analyses |
| `POST` | `/upload` | Analyze and save an uploaded log |
| `GET` | `/report/<id>` | View a report; filter with `?severity=<level>` |
| `GET` | `/report/<id>/export` | Download the JSON report |
| `POST` | `/report/<id>/delete` | Delete the original upload and report |
| `GET` | `/api/analyses` | List saved analysis summaries as JSON |
| `GET` | `/api/analyses/<id>` | Return one complete analysis as JSON |
| `GET` | `/healthz` | Return application status and version |

The Flask server and its default development secret are intended for local use,
not direct public exposure.

## Deploy the AWS Amplify application

The cloud application uses AWS Amplify Gen 2:

- **Amplify Hosting** serves the React 18 and Vite frontend.
- **Amazon Cognito** provides email/password signup, confirmation, and sign-in.
- **Amazon S3** stores uploads and reports under each Cognito identity ID.
- **AWS Lambda** runs the existing Python analysis engine after an S3 upload.
- **AWS AppSync and DynamoDB** provide authenticated chat operations and
  private, owner-authorized chat-session storage.
- **Amazon Bedrock** answers chat questions with the US cross-region Nova 2
  Lite inference profile, `us.amazon.nova-2-lite-v1:0`.

### Cloud processing flow

1. A signed-in user selects a file in the React application.
2. Amplify Storage uploads it directly to
   `uploads/{identityId}/{analysisId}/original.<extension>`.
3. S3 invokes the Python 3.13 Lambda for objects under `uploads/`.
4. The Lambda validates the upload, analyzes it, and writes
   `analyses/{identityId}/{analysisId}/analysis.json`.
5. The frontend polls every five seconds while work is pending, then displays
   the completed or failed report.

The frontend shows upload progress, aggregate totals, pending analyses, report
details, severity filters, evidence, remediation, references, JSON export, and
deletion. Deleting a completed analysis removes both its source upload and JSON
report.

### Chat processing flow

1. An authenticated user opens or creates a saved chat on the right side.
2. The frontend sends the question, the most recent 12 chat messages, and
   summaries of the user's loaded reports to an authenticated AppSync mutation.
3. AppSync invokes a Python 3.13 Lambda.
4. The Lambda validates and limits the input, then calls Bedrock's Converse API
   with `us.amazon.nova-2-lite-v1:0`.
5. The frontend displays the answer and saves the completed exchange through
   owner-authorized Amplify Data models.

The chatbot accepts general questions. Report context contains aggregate
metadata, risk scores, severity counts, finding totals, and most-flagged IPs.
It does not send raw evidence lines or original log files to the model. Report
context is capped before invocation, and log-derived text is explicitly treated
as untrusted data in the system prompt.

Saved sessions and exchanges are private to their Cognito owner. Exchanges use
separate records so concurrent browser tabs cannot overwrite a full transcript.
The model receives at most 12 previous messages for each answer.

### Cloud resource settings

- Uploads use Amplify Storage and S3 multipart upload support.
- The browser and Lambda enforce a 100 MB analysis limit.
- Invalid, empty, unsupported, or oversized uploads are removed by the Lambda,
  and a failed report is written with the error.
- The Lambda timeout is 15 minutes with 2,048 MB of memory.
- Users can read, write, and delete only within their own upload path.
- Users can read and delete only reports within their own analysis path.
- The Lambda can read/delete uploads and write reports across managed paths.
- The chat Lambda can invoke only the configured Nova 2 Lite inference profile
  and its underlying Nova 2 Lite foundation model.
- Chat mutations require Cognito authentication, and chat-session records use
  owner authorization.
- Chat usage is limited to 100 Bedrock requests per authenticated user per UTC
  day, with 10 reserved concurrent Lambda executions.
- Incomplete multipart uploads are aborted after one day.
- `keepOnDelete: true` retains the production S3 bucket when the Amplify
  backend is deleted. Retained data continues to incur S3 charges.

### Deploy from GitHub

Requirements:

- An AWS account
- A GitHub repository containing this code
- An Amplify service role allowed to deploy the Gen 2 backend
- A CDK-bootstrap stack version 6 or newer in the target account and region
- Amazon Bedrock access to Nova 2 Lite through the US cross-region inference
  profile

Deployment steps:

1. Open the [AWS Amplify console](https://console.aws.amazon.com/amplify/).
2. Choose **Create new app** and select **GitHub**.
3. Select the repository and branch to deploy.
4. Keep the repository's `amplify.yml` build settings.
5. Create or select an Amplify service role when prompted.
6. Save and deploy.
7. Open the generated URL, create an account, confirm the emailed code, and
   sign in.

For account `YOUR_ACCOUNT_ID` and deployment region `YOUR_REGION`, bootstrap
CDK once before the first deployment:

```bash
npx aws-cdk@latest bootstrap aws://YOUR_ACCOUNT_ID/YOUR_REGION
```

The Amplify deployment role must be able to read
`/cdk-bootstrap/hnb659fds/version` from Systems Manager Parameter Store. The
AWS-managed `AmplifyBackendDeployFullAccess` policy supplies the standard Gen 2
deployment permissions.

Nova 2 Lite uses US cross-region inference. Your organization policies must
allow Bedrock invocation in the destination regions used by the
`us.amazon.nova-2-lite-v1:0` inference profile.

The build uses Node.js 22. Its backend phase installs dependencies and runs:

```bash
npx ampx pipeline-deploy --branch $AWS_BRANCH --app-id $AWS_APP_ID
```

That command provisions the backend and generates `amplify_outputs.json` before
the frontend build. The generated file is ignored by Git.

`amplify.yml` currently uses `npm install` instead of `npm ci` because the
current Amplify backend packages contain bundled dependency metadata that
causes `npm ci` validation to fail. `npm install` still uses
`package-lock.json`.

### Develop the Amplify application locally

Requirements:

- Node.js 22
- AWS credentials with `AmplifyBackendDeployFullAccess`

Install dependencies:

```bash
npm install
```

Start a personal cloud sandbox:

```bash
npm run sandbox
```

In another terminal, start Vite:

```bash
npm run dev
```

The sandbox generates an ignored `amplify_outputs.json` containing its backend
configuration. To remove sandbox cloud resources when finished:

```bash
npx ampx sandbox delete
```

`npm run build` can run without AWS credentials. If
`amplify_outputs.json` is absent, the prebuild script creates an ignored,
nonfunctional placeholder so TypeScript and Vite can complete. Authentication
and storage require a real sandbox or deployed outputs file at runtime.

## Sample logs

The `samples/` directory contains generated demonstrations:

| File | Demonstrates |
|---|---|
| `auth_syslog.log` | SSH brute force, takeover, sudo abuse, and persistence |
| `access_apache.log` | SQLi, XSS, traversal, RCE, directory scans, and exposed `.env` access |
| `events.csv` | Firewall port scan, cleartext protocols, and login attack |
| `syslog_firewall.log` | Netfilter port scan, Telnet/FTP probes, and off-hours activity |
| `syslog_insider.log` | Off-hours bulk access, volume spike, `su` brute force, and sudo abuse |
| `syslog_baseline.log` | Clean negative control expected to produce zero findings |

Regenerate the sample files with:

```bash
python scripts/generate_samples.py
```

## Tests and validation

Install Python test dependencies and run pytest:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Install frontend/backend dependencies and create a production build:

```bash
npm install
npm run build
```

The Lambda tests use an in-memory S3 fake and do not require AWS credentials.
A real Amplify sandbox or branch deployment is still required to validate IAM,
Cognito, AppSync, DynamoDB, Bedrock, S3 notifications, and Lambda execution in
AWS.

## Project layout

```text
app.py                               Local Flask routes and upload handling
logsentinel/
  parsers.py                         Format detection and record normalization
  rules.py                           Signature detectors
  anomalies.py                       Statistical detectors
  engine.py                          Parse, detect, enrich, summarize, and score
  knowledge.py                       Remediation steps and reference links
  models.py                          Shared Python records and findings
  store.py                           Local filesystem analysis storage
  upload_policy.json                 Shared accepted-extension policy
amplify/
  auth/resource.ts                   Cognito email authentication
  storage/resource.ts                Per-user S3 authorization
  data/resource.ts                   Private chat sessions and chat mutation
  functions/analyze_logs/
    handler.py                       S3-triggered Python analysis handler
    resource.ts                      Lambda runtime, memory, timeout, and bundle
  functions/chat_agent/
    handler.py                       Nova 2 Lite Converse API handler
    resource.ts                      Chat Lambda and Bedrock IAM permission
  backend.ts                         Amplify resources, S3 trigger, lifecycle
src/
  App.tsx                            Cloud dashboard and upload workflow
  ChatPanel.tsx                      Saved right-side chatbot interface
  ReportView.tsx                     Cloud report UI
  storage.ts                         Amplify Storage operations and caching
  types.ts                           Analysis/report TypeScript types
  main.tsx                           Amplify and React initialization
templates/, static/                  Flask HTML, JavaScript, and shared styling
tests/                               Python, Flask, sample, and Lambda tests
samples/                             Generated demonstration logs
scripts/generate_samples.py          Sample-log generator
scripts/ensure-amplify-outputs.mjs    Credential-free build placeholder
amplify.yml                          Amplify Hosting build definition
package.json                         React, Amplify, Vite, and CDK dependencies
```

## Add a detector

Signature detectors are functions in `logsentinel/rules.py` that accept a list
of normalized `Record` objects and return `Finding` objects. Add new signature
detectors to `ALL_RULES`.

Statistical detectors live in `logsentinel/anomalies.py` and are registered in
`ALL_ANOMALIES`.

Add remediation steps and reference links for a new rule ID in
`logsentinel/knowledge.py`. The engine attaches that information to matching
findings automatically.

## Security and operational notes

- Security logs can contain credentials, internal addresses, personal data,
  session identifiers, and other sensitive material.
- The local Flask mode keeps logs on the local filesystem.
- The Amplify mode sends logs to S3 in your AWS account and emits failures to
  CloudWatch Logs.
- The chatbot sends questions, recent chat history, and aggregate report
  summaries to Amazon Bedrock. It does not send original logs or evidence
  lines.
- Saved chat sessions are stored in DynamoDB and count toward AWS usage costs.
- Bedrock responses can be incomplete or incorrect. Do not treat chatbot output
  as proof of compromise or as a substitute for professional security review.
- Review Cognito self-signup, IAM, S3 retention, CloudWatch retention, AWS
  region, Bedrock cross-region inference, compliance, and cost controls before
  accepting production logs.
- The Amplify browser check is not an S3 service quota. The Lambda removes
  uploads that exceed the application's 100 MB analysis limit after S3 creates
  the object.
- Statistical detectors need representative peer and time-bucket data.
- Always preserve the original logs and investigate findings in context.

## License

MIT, see [LICENSE](LICENSE).
