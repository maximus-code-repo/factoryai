"""Signature-based detection rules.

Each rule scans normalized Records for known attack patterns and returns
Finding objects. Rules are intentionally simple and explainable: every
finding points at the concrete log lines that triggered it.
"""

import re
from collections import defaultdict
from datetime import timedelta
from urllib.parse import unquote_plus

from .models import Finding, Record, make_evidence

# --- thresholds -----------------------------------------------------------

BRUTE_FORCE_MIN = 5             # failures from one IP before we flag
BRUTE_FORCE_WINDOW = timedelta(minutes=10)
BRUTE_FORCE_CRITICAL = 25       # failures in window -> critical
BRUTE_FORCE_HIGH = 10            # failures in window -> high
DIR_SCAN_MIN_REQUESTS = 15      # requests before 404-ratio rule applies
DIR_SCAN_404_RATIO = 0.6        # share of 404s that means enumeration
PORT_SCAN_MIN_PORTS = 12        # unique destination ports -> port scan

NO_IP = "(no source IP)"

AUTH_FAIL_RE = re.compile(
    r"failed password|invalid user|authentication failure|failed login|"
    r"login failed|logon failure|failed publickey|password mismatch|"
    r"invalid credentials|failed authentication|auth failure|failed su\b",
    re.I,
)
AUTH_SUCCESS_RE = re.compile(
    r"accepted password|accepted publickey|session opened for user|"
    r"logged in successfully|login successful|login succeeded|"
    r"session started for user",
    re.I,
)

SQLI_REGEXES = [re.compile(p, re.I) for p in (
    r"union[\s+]+(?:all[\s+]+)?select",
    r"\bselect\b[^;]{0,80}\bfrom\b",
    r"\binsert\s+into\b",
    r"\bdrop\s+(?:table|database)\b",
    r"information_schema",
    r"(?:'|%27)\s*(?:or|and)\s+.{0,20}=",
    r"\b(?:or|and)\s+1\s*=\s*1\b",
    r"\bsleep\s*\(\s*\d+\s*\)",
    r"\bbenchmark\s*\(",
    r"\bload_file\s*\(",
    r"into\s+outfile",
    r"waitfor\s+delay",
    r"\bxp_cmdshell\b",
    r"'\s*--",
)]

XSS_REGEXES = [re.compile(p, re.I) for p in (
    r"<script\b",
    r"</script",
    r"javascript:",
    r"\bonerror\s*=",
    r"\bonload\s*=",
    r"\bonfocus\s*=",
    r"\bonmouseover\s*=",
    r"document\.cookie",
    r"<iframe\b",
    r"<svg\b",
)]

TRAVERSAL_REGEXES = [re.compile(p, re.I) for p in (
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e",
    r"\.\.;/",
    r"/etc/passwd",
    r"/etc/shadow",
    r"boot\.ini",
    r"win\.ini",
    r"c:\\windows",
)]
TRAVERSAL_SYSTEM_RE = re.compile(r"/etc/(?:passwd|shadow)|boot\.ini|win\.ini", re.I)

RCE_REGEXES = [re.compile(p, re.I) for p in (
    r"cat\s+/etc/(?:passwd|shadow|hosts)",
    r"\bwhoami\b",
    r"\buname\s+-a\b",
    r"\bwget\s+(?:http|ftp)",
    r"\bcurl\s+(?:http|ftp)",
    r"\bnc\s+-e\b",
    r"bash\s+-i\b",
    r"\$\([^)]{0,40}\)",
    r"(?:\?|&)(?:cmd|exec|command|run)=",
    r"powershell\s+-",
)]

SENSITIVE_HIGH_REGEXES = [re.compile(p, re.I) for p in (
    r"\.env\b",
    r"\.git\b",
    r"\.aws/credentials",
    r"\.ssh/",
    r"\bid_rsa\b",
    r"\.netrc\b",
    r"\.pgpass\b",
    r"\.bash_history",
)]

SENSITIVE_MED_REGEXES = [re.compile(p, re.I) for p in (
    r"wp-login",
    r"wp-admin",
    r"phpmyadmin",
    r"\.svn/",
    r"\.bak\b",
    r"\.sql\b",
    r"backup\.(?:zip|sql|tar|gz)\b",
    r"web\.config",
    r"\.htaccess",
    r"server-status",
    r"actuator",
    r"\.DS_Store",
    r"admin\.php",
    r"config\.php",
    r"php\.ini",
)]

SCANNER_UA_RE = re.compile(
    r"sqlmap|nikto|nmap|masscan|hydra|zgrab|dirbuster|dirb\b|gobuster|"
    r"wpscan|acunetix|nessus|burpsuite|burp\s+collaborator|metasploit|"
    r"havij|w3af|openvas|feroxbuster|ffuf|nuclei|whatweb",
    re.I,
)

CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 69: "TFTP"}
CLEARTEXT_RE = re.compile(r"\b(?:telnet|ftp|tftp)\b", re.I)

SYSLOG_THREATS = (
    ("SYS_BREAKIN",
     re.compile(r"possible\s+break-in\s+attempt", re.I),
     "high",
     "Possible break-in attempt detected",
     "Reverse-DNS validation failed for a connecting host, a classic sign of "
     "scanner or brute-force tooling. Investigate the source IP and check "
     "whether any of its logins succeeded."),
    ("SYS_SUDO_ABUSE",
     re.compile(r"NOT\s+in\s+sudoers|sudo:.*incorrect\s+password|sudo:.*authentication\s+failure", re.I),
     "medium",
     "Unauthorized privilege-escalation attempt",
     "A user tried to run commands via sudo without permission or with a "
     "wrong password. Review who ran it, from which session, and whether "
     "any sudo rule was changed around the same time."),
    ("SYS_NEW_USER",
     re.compile(r"new\s+user:\s*name=|useradd\s", re.I),
     "medium",
     "New local user account created",
     "Attackers often create accounts for persistence. Verify the account "
     "was created by an authorized administrator and check its shell, "
     "groups, and any later logins."),
    ("SYS_ROOT_SESSION",
     re.compile(r"session\s+opened\s+for\s+user\s+root", re.I),
     "low",
     "Root session opened",
     "A root shell session started. Confirm this was expected maintenance; "
     "root logins should be rare, logged, and ideally replaced by sudo "
     "with per-command rules."),
)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _blob(record: Record) -> str:
    """The raw line plus its URL-decoded form, so encoded attacks match too."""
    raw = record.raw or ""
    try:
        decoded = unquote_plus(raw)
    except Exception:
        decoded = raw
    return raw + "\n" + (decoded if decoded != raw else "")


def _is_auth_failure(record: Record) -> bool:
    return bool(AUTH_FAIL_RE.search(record.raw or "")) or record.status == 401


def _max_in_window(rows, window):
    """Largest run of failures inside a sliding time window (two pointers)."""
    best, best_rows, i = 0, [], 0
    for j in range(len(rows)):
        while rows[j].timestamp - rows[i].timestamp > window:
            i += 1
        if j - i + 1 > best:
            best = j - i + 1
            best_rows = rows[i : j + 1]
    return best, best_rows


def _pattern_rule(records, regexes, rule_id, base_title, default_severity,
                 recommendation, sev_fn=None, extra_desc=None):
    """Group records whose (decoded) lines match any pattern, per source IP."""
    by_ip = defaultdict(list)
    for record in records:
        blob = _blob(record)
        for rx in regexes:
            if rx.search(blob):
                by_ip[record.src_ip or NO_IP].append((record, rx))
                break
    findings = []
    for ip, hits in by_ip.items():
        rows = [r for r, _ in hits]
        severity = sev_fn(rows) if sev_fn else default_severity
        patterns = []
        for _, rx in hits:
            if rx.pattern not in patterns:
                patterns.append(rx.pattern)
        desc = "{} log line(s){} match {} signatures ({}).".format(
            len(rows),
            " from {}".format(ip) if ip != NO_IP else "",
            rule_id,
            ", ".join(patterns[:3]),
        )
        if extra_desc:
            desc += " " + extra_desc(rows)
        findings.append(
            Finding(
                rule_id=rule_id,
                title="{}{}".format(
                    base_title, " from {}".format(ip) if ip != NO_IP else ""
                ),
                severity=severity,
                category="rule",
                description=desc,
                recommendation=recommendation,
                count=len(rows),
                src_ip=None if ip == NO_IP else ip,
                evidence=make_evidence(rows),
                metrics={"matched_signatures": len(patterns)},
            )
        )
    return findings


def _ok2xx(rows) -> bool:
    return any(r.status is not None and 200 <= r.status < 300 for r in rows)


# --------------------------------------------------------------------------
# authentication rules
# --------------------------------------------------------------------------

def detect_brute_force(records):
    """Many failed logins from one IP inside a short window."""
    fails = [r for r in records if _is_auth_failure(r)]
    if len(fails) < BRUTE_FORCE_MIN:
        return []
    by_ip = defaultdict(list)
    for record in fails:
        by_ip[record.src_ip or NO_IP].append(record)
    findings = []
    for ip, rows in by_ip.items():
        with_ts = sorted((r for r in rows if r.timestamp), key=lambda r: r.timestamp)
        if with_ts:
            count, sample = _max_in_window(with_ts, BRUTE_FORCE_WINDOW)
            scope = "within a 10-minute window"
        else:
            count, sample = len(rows), rows
            scope = "in this log file"
        if count < BRUTE_FORCE_MIN:
            continue
        severity = (
            "critical" if count >= BRUTE_FORCE_CRITICAL
            else "high" if count >= BRUTE_FORCE_HIGH
            else "medium"
        )
        users = []
        for r in sample:
            if r.user and r.user not in users:
                users.append(r.user)
        desc = "{} failed authentication attempts from {} {}.".format(
            count, ip, scope
        )
        if users:
            desc += " Targeted accounts: {}.".format(", ".join(users[:5]))
        findings.append(
            Finding(
                rule_id="AUTH_BRUTE_FORCE",
                title="Brute-force login attempts from {}".format(ip),
                severity=severity,
                category="rule",
                description=desc,
                recommendation=(
                    "Block or rate-limit the source IP, enable account "
                    "lockouts and MFA, and verify none of the targeted "
                    "accounts were compromised."
                ),
                count=count,
                src_ip=None if ip == NO_IP else ip,
                evidence=make_evidence(sample),
                metrics={"failures": count},
            )
        )
    return findings


def detect_auth_compromise(records):
    """A successful login from an IP that also produced repeated failures."""
    fails_by_ip = defaultdict(list)
    succ_by_ip = defaultdict(list)
    for record in records:
        ip = record.src_ip or NO_IP
        if _is_auth_failure(record):
            fails_by_ip[ip].append(record)
        elif AUTH_SUCCESS_RE.search(record.raw or ""):
            succ_by_ip[ip].append(record)
    findings = []
    for ip, fails in fails_by_ip.items():
        if ip == NO_IP or len(fails) < 3:
            continue  # need a real source IP and a real attack pattern
        successes = succ_by_ip.get(ip, [])
        first_fail_line = min(r.line_no for r in fails)
        first_fail_ts = min(
            (r.timestamp for r in fails if r.timestamp), default=None
        )
        after = [
            s for s in successes
            if s.line_no > first_fail_line
            and (first_fail_ts is None or s.timestamp is None
                 or s.timestamp >= first_fail_ts)
        ]
        if not after:
            continue
        users = []
        for r in fails + after:
            if r.user and r.user not in users:
                users.append(r.user)
        findings.append(
            Finding(
                rule_id="AUTH_COMPROMISE",
                title="Credential attack appears to have succeeded from {}".format(ip),
                severity="critical",
                category="rule",
                description=(
                    "{} failed authentication attempts from {} were "
                    "followed by a successful login. The accounts involved "
                    "may be compromised ({}).".format(
                        len(fails), ip, ", ".join(users[:5]) or "unknown"
                    )
                ),
                recommendation=(
                    "Treat this as a possible intrusion: disable the "
                    "affected accounts, force password resets, review all "
                    "actions taken by those sessions, and check for "
                    "persistence (new users, SSH keys, cron jobs)."
                ),
                count=len(fails) + len(after),
                src_ip=ip,
                evidence=make_evidence(sorted(fails + after, key=lambda r: r.line_no)),
                metrics={"failures": len(fails), "successes": len(after)},
            )
        )
    return findings


# --------------------------------------------------------------------------
# web attack rules
# --------------------------------------------------------------------------

def detect_sql_injection(records):
    return _pattern_rule(
        records, SQLI_REGEXES, "WEB_SQLI", "SQL injection attempts", "high",
        "Treat these requests as hostile: confirm the application uses "
        "parameterized queries, check database logs for the exact queries "
        "executed, and consider a WAF rule plus input validation.",
    )


def detect_xss(records):
    return _pattern_rule(
        records, XSS_REGEXES, "WEB_XSS", "Cross-site scripting (XSS) attempts", "high",
        "Verify output encoding is applied for the parameters involved and "
        "that a Content-Security-Policy header is set. If any reflected or "
        "stored payload was served to users, investigate further.",
    )


def detect_path_traversal(records):
    return _pattern_rule(
        records, TRAVERSAL_REGEXES, "WEB_TRAVERSAL", "Path traversal attempts",
        "medium",
        "Check whether any file-read or download parameter validated these "
        "paths. Normalize and whitelist allowed paths, and never pass raw "
        "user input into filesystem APIs.",
        sev_fn=lambda rows: (
            "high" if any(TRAVERSAL_SYSTEM_RE.search(r.raw or "") for r in rows)
            else "medium"
        ),
    )


def detect_rce(records):
    return _pattern_rule(
        records, RCE_REGEXES, "WEB_RCE", "Possible remote command execution probing", "high",
        "Someone tried to execute operating-system commands through your "
        "application. Audit the parameters involved for command injection, "
        "and check the host for signs of the commands actually running.",
    )


def detect_sensitive_paths_high(records):
    findings = _pattern_rule(
        records, SENSITIVE_HIGH_REGEXES, "WEB_SENSITIVE_HIGH",
        "Probing for credential/sensitive files", "high",
        "Remove the resource from the web root (or deny access), rotate any "
        "credentials it contains, and check whether it was actually served.",
        sev_fn=lambda rows: "critical" if _ok2xx(rows) else "high",
        extra_desc=lambda rows: (
            "Some requests returned HTTP 2xx - the resource may be exposed."
            if _ok2xx(rows) else ""
        ),
    )
    return findings


def detect_sensitive_paths_med(records):
    return _pattern_rule(
        records, SENSITIVE_MED_REGEXES, "WEB_SENSITIVE_MED",
        "Probing for admin/backup/config paths", "medium",
        "These are reconnaissance requests. Make sure the paths return 404 "
        "or are access-controlled, and rate-limit heavy scanners.",
    )


def detect_scanner_uas(records):
    findings = []
    by_ip = defaultdict(list)
    for record in records:
        matched = SCANNER_UA_RE.search(record.ua or "") or \
            SCANNER_UA_RE.search(_blob(record))
        if matched:
            by_ip[record.src_ip or NO_IP].append(record)
    for ip, rows in by_ip.items():
        uas = []
        for r in rows:
            ua = r.ua or ""
            if ua and ua not in uas:
                uas.append(ua)
        findings.append(
            Finding(
                rule_id="WEB_SCANNER_UA",
                title="Security-scanner tooling detected from {}".format(ip),
                severity="medium",
                category="rule",
                description=(
                    "{} request(s) from {} used a known scanning tool "
                    "user-agent: {}.".format(
                        len(rows), ip, "; ".join(uas[:3]) or "unknown"
                    )
                ),
                recommendation=(
                    "Reconnaissance of your application is underway. "
                    "Rate-limit or block the source, keep software and "
                    "plugins patched, and check what those scans found."
                ),
                count=len(rows),
                src_ip=None if ip == NO_IP else ip,
                evidence=make_evidence(rows),
                metrics={"distinct_user_agents": len(uas)},
            )
        )
    return findings


def detect_dir_scan(records):
    """High 404 ratio from one IP = directory/file enumeration."""
    by_ip = defaultdict(list)
    for record in records:
        if record.status is not None and record.src_ip:
            by_ip[record.src_ip].append(record)
    findings = []
    for ip, rows in by_ip.items():
        if len(rows) < DIR_SCAN_MIN_REQUESTS:
            continue
        nf = sum(1 for r in rows if r.status == 404)
        if nf / len(rows) < DIR_SCAN_404_RATIO:
            continue
        paths = {r.path for r in rows if r.path}
        findings.append(
            Finding(
                rule_id="WEB_DIR_SCAN",
                title="Directory/file enumeration scan from {}".format(ip),
                severity="high",
                category="rule",
                description=(
                    "{} requests from {} of which {} returned 404 ({}%), "
                    "across {} distinct paths - consistent with content "
                    "discovery tooling.".format(
                        len(rows), ip, nf, int(100 * nf / len(rows)), len(paths)
                    )
                ),
                recommendation=(
                    "Rate-limit or block the source, ensure no sensitive "
                    "paths returned content, and compare the discovered "
                    "paths against what you actually expose."
                ),
                count=nf,
                src_ip=ip,
                evidence=make_evidence([r for r in rows if r.status == 404]),
                metrics={"requests": len(rows), "not_found": nf, "unique_paths": len(paths)},
            )
        )
    return findings


# --------------------------------------------------------------------------
# syslog / system rules
# --------------------------------------------------------------------------

def detect_syslog_threats(records):
    findings = []
    for rule_id, rx, severity, title, recommendation in SYSLOG_THREATS:
        rows = [r for r in records if rx.search(r.raw or "")]
        if not rows:
            continue
        ips = []
        for r in rows:
            ip = r.src_ip
            if ip and ip not in ips:
                ips.append(ip)
        desc = "{} line(s) match the pattern for: {}.".format(len(rows), title.lower())
        if ips:
            desc += " Source IPs: {}.".format(", ".join(ips[:5]))
        findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                category="rule",
                description=desc,
                recommendation=recommendation,
                count=len(rows),
                evidence=make_evidence(rows),
                metrics={"lines": len(rows)},
            )
        )
    return findings


# --------------------------------------------------------------------------
# network rules
# --------------------------------------------------------------------------

def detect_port_scan(records):
    by_ip = defaultdict(set)
    for record in records:
        if record.port and record.src_ip:
            by_ip[record.src_ip].add(record.port)
    findings = []
    for ip, ports in by_ip.items():
        if len(ports) < PORT_SCAN_MIN_PORTS:
            continue
        sample = sorted(ports)[:20]
        findings.append(
            Finding(
                rule_id="NET_PORT_SCAN",
                title="Port scanning activity from {}".format(ip),
                severity="high",
                category="rule",
                description=(
                    "{} contacted {} different destination ports - "
                    "consistent with a port scan. Ports seen: {}.".format(
                        ip, len(ports), ", ".join(str(p) for p in sample)
                    )
                ),
                recommendation=(
                    "Block or rate-limit the source at the firewall, make "
                    "sure only intended ports are reachable, and verify "
                    "nothing answered on unexpected ports."
                ),
                count=len(ports),
                src_ip=ip,
                evidence=make_evidence(
                    sorted(
                        (r for r in records if r.src_ip == ip and r.port in ports),
                        key=lambda r: r.line_no,
                    )
                ),
                metrics={"unique_ports": len(ports)},
            )
        )
    return findings


def detect_cleartext(records):
    by_service = defaultdict(list)
    for record in records:
        if record.port in CLEARTEXT_PORTS:
            service = CLEARTEXT_PORTS[record.port]
            detail = "port {}".format(record.port)
        else:
            m = CLEARTEXT_RE.search(record.raw or "")
            if not m:
                continue
            service = m.group(0).upper()
            detail = "protocol reference"
        by_service[(service, detail)].append(record)
    findings = []
    for (service, detail), rows in by_service.items():
        ips = []
        for r in rows:
            if r.src_ip and r.src_ip not in ips:
                ips.append(r.src_ip)
        findings.append(
            Finding(
                rule_id="NET_CLEARTEXT",
                title="Cleartext protocol usage ({})".format(service),
                severity="medium",
                category="rule",
                description=(
                    "{} log line(s) show {} traffic ({}). Credentials and "
                    "data on these protocols are sent unencrypted. "
                    "Source IPs: {}.".format(
                        len(rows), service, detail, ", ".join(ips[:5]) or "unknown"
                    )
                ),
                recommendation=(
                    "Replace Telnet/FTP with SSH/SFTP, disable the cleartext "
                    "service if it is unused, and check whether any "
                    "credentials used over it appear elsewhere."
                ),
                count=len(rows),
                evidence=make_evidence(rows),
                metrics={"service": service},
            )
        )
    return findings


ALL_RULES = (
    detect_brute_force,
    detect_auth_compromise,
    detect_sql_injection,
    detect_xss,
    detect_path_traversal,
    detect_rce,
    detect_sensitive_paths_high,
    detect_sensitive_paths_med,
    detect_scanner_uas,
    detect_dir_scan,
    detect_syslog_threats,
    detect_port_scan,
    detect_cleartext,
)
