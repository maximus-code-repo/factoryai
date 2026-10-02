# LogSentinel Development Guide

This guide is for contributors and coding agents working in this repository.
LogSentinel has two delivery modes that share one Python analysis engine:

- A local Flask application in `app.py`, `templates/`, and `static/`
- An AWS Amplify application in `src/` and `amplify/`

Changes to parsing, detection, findings, or risk scoring should normally be
implemented in `logsentinel/` so both delivery modes receive the same behavior.

## Prerequisites

- Python 3.11 or newer
- Node.js 22 (see `.nvmrc`)
- npm
- AWS credentials only when running an Amplify sandbox or deployment

## Setup

### Python

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
```

Linux or macOS:

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements-dev.txt
```

### TypeScript

```bash
npm install
```

## Common Commands

| Task | Command |
|---|---|
| Run all Python tests | `python -m pytest -q` |
| Run one Python test file | `python -m pytest -q tests/test_rules.py` |
| Build the Amplify frontend/backend | `npm run build` |
| Run the local Flask app | `python app.py` |
| Run the Vite frontend | `npm run dev` |
| Provision a personal Amplify sandbox | `npm run sandbox` |
| Regenerate sample logs | `python scripts/generate_samples.py` |

Use the virtual environment's Python executable when the environment is not
activated.

## Architecture

The main analysis flow is:

1. `logsentinel/parsers.py` converts supported input formats into normalized
   `Record` objects from `logsentinel/models.py`.
2. `logsentinel/rules.py` runs deterministic signature and behavioral rules.
3. `logsentinel/anomalies.py` runs statistical detectors.
4. `logsentinel/engine.py` combines findings, attaches guidance from
   `logsentinel/knowledge.py`, and calculates the risk summary.
5. Flask stores reports through `logsentinel/store.py`; the Amplify Lambda
   stores them in private S3 paths.

The browser frontend never implements detection logic. Keep detection behavior
in the shared Python engine.

## Change Workflows

### Add or modify a detector

1. Implement the detector in `logsentinel/rules.py` or
   `logsentinel/anomalies.py`.
2. Register it in `ALL_RULES` or `ALL_ANOMALIES`.
3. Add remediation steps and authoritative references to
   `logsentinel/knowledge.py`.
4. Add positive, threshold, and negative tests under `tests/`.
5. Update the README rule table.
6. Update or regenerate sample logs when the rule should appear in the demo
   corpus.

Detectors must return `Finding` objects and should include concise evidence.
Avoid flagging a single weak indicator when a meaningful threshold can reduce
false positives.

### Change Flask behavior

- Routes and upload handling live in `app.py`.
- Templates live in `templates/`; shared browser behavior and styles live in
  `static/`.
- Add route-level tests to `tests/test_app.py`.

### Change Amplify behavior

- React UI code lives in `src/`.
- Authentication, storage, data, Lambda, and IAM definitions live in
  `amplify/`.
- Keep storage paths owner-scoped and use least-privilege resource access.
- Test Lambda handlers with local fakes; do not require live AWS credentials in
  the unit test suite.

## Coding Conventions

- Follow the existing formatting and naming style in each language.
- Use type annotations for shared Python models and TypeScript types for API
  and report shapes.
- Keep parsing and detection functions deterministic and free of network calls.
- Treat uploaded log text and chatbot report context as untrusted input.
- Never log raw credentials, tokens, or full sensitive log records.
- Keep rule identifiers stable because reports, tests, and knowledge entries
  reference them.
- Add comments for security constraints and non-obvious thresholds, not for
  straightforward control flow.

## Validation

Run the narrowest relevant test during development. Before finishing a change,
run:

```bash
python -m pytest -q
npm run build
```

The production build can run without AWS credentials. Live Cognito, S3,
AppSync, DynamoDB, Bedrock, IAM, and event-notification behavior requires an
Amplify sandbox or deployed branch.

For interactive Flask verification:

1. Run `python app.py`.
2. Open <http://127.0.0.1:5000>.
3. Upload a file from `samples/`.
4. Confirm the report, severity filtering, JSON export, and deletion flow.

## Security Boundaries

- The local app is a development server and is not intended for public
  exposure.
- Cloud uploads and reports must remain scoped to the authenticated Cognito
  identity.
- Preserve upload size and extension validation in both browser and Lambda
  paths.
- Do not send original logs or raw evidence to Bedrock.
- Preserve the chatbot's authentication, quota, input limits, and
  prompt-injection boundary.
- Do not commit `.env`, `amplify_outputs.json`, generated build output, uploaded
  logs, or analysis reports.
