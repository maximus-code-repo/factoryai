"""Remediation knowledge base.

Maps every rule ID to concrete remediation steps and links to authoritative
references (OWASP, MITRE ATT&CK, NIST, CWE) so users can learn more about
the issue and how to fix it. The engine attaches these to each finding.
"""

MITRE = "https://attack.mitre.org/techniques/{}/"


def _ref(label, url):
    return {"label": label, "url": url}


RULE_KNOWLEDGE = {
    # ------------------------------------------------ authentication
    "AUTH_BRUTE_FORCE": {
        "steps": [
            "Block or rate-limit the source IP at the firewall or reverse proxy.",
            "Enable account lockout thresholds and exponential backoff on repeated failures.",
            "Require MFA for the targeted accounts.",
            "Review the targeted accounts for any successful logins from the same source.",
            "For SSH, disable password authentication in favor of public keys.",
        ],
        "references": [
            _ref("MITRE ATT&CK T1110: Brute Force", MITRE.format("T1110")),
            _ref("MITRE ATT&CK T1110.001: Password Guessing", MITRE.format("T1110/001")),
            _ref("NIST SP 800-63B: Digital Identity Guidelines (throttling)", "https://pages.nist.gov/800-63-3/sp800-63b.html"),
            _ref("Mozilla OpenSSH security guidelines", "https://infosec.mozilla.org/guidelines/openssh.html"),
        ],
    },
    "AUTH_COMPROMISE": {
        "steps": [
            "Treat this as an active intrusion: start your incident-response process and preserve the log files.",
            "Disable the affected accounts, revoke their sessions and tokens, and force credential resets.",
            "Review every action taken by those sessions (commands run, files accessed, outbound connections).",
            "Hunt for persistence: new local users, SSH authorized_keys entries, cron jobs, new services.",
            "Determine what data those accounts could reach and check for signs of access or exfiltration.",
        ],
        "references": [
            _ref("MITRE ATT&CK T1078: Valid Accounts", MITRE.format("T1078")),
            _ref("MITRE ATT&CK T1110: Brute Force", MITRE.format("T1110")),
            _ref("NIST SP 800-61 Rev. 3: Incident Handling Guide", "https://csrc.nist.gov/pubs/sp/800/61/r3/final"),
        ],
    },
    # ------------------------------------------------ web attacks
    "WEB_SQLI": {
        "steps": [
            "Confirm the affected parameters are handled with parameterized queries or an ORM; never concatenate SQL.",
            "Check database logs for the queries that actually ran, and look for data being read or modified.",
            "Apply least-privilege database permissions to the application account.",
            "Add input validation or a WAF rule for the attack patterns.",
            "Patch the framework or CMS if the requests target a known vulnerable component.",
        ],
        "references": [
            _ref("OWASP: SQL Injection", "https://owasp.org/www-community/attacks/SQL_Injection"),
            _ref("OWASP Cheat Sheet: SQL Injection Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"),
            _ref("OWASP Top 10 A03:2021 - Injection", "https://owasp.org/Top10/A03_2021-Injection/"),
            _ref("CWE-89: SQL Injection", "https://cwe.mitre.org/data/definitions/89.html"),
        ],
    },
    "WEB_XSS": {
        "steps": [
            "Apply context-aware output encoding wherever the affected parameters are rendered.",
            "Deploy a Content-Security-Policy response header to blunt inline-script execution.",
            "Validate or sanitize input on the affected fields.",
            "If the payload was served to other users, investigate for stored XSS and potentially affected sessions.",
        ],
        "references": [
            _ref("OWASP: Cross-Site Scripting (XSS)", "https://owasp.org/www-community/attacks/xss/"),
            _ref("OWASP Cheat Sheet: XSS Prevention", "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
            _ref("MDN: Content Security Policy", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"),
            _ref("CWE-79: Cross-site Scripting", "https://cwe.mitre.org/data/definitions/79.html"),
        ],
    },
    "WEB_TRAVERSAL": {
        "steps": [
            "Reject path segments like ../ and their encodings; canonicalize paths and verify they stay inside the intended root.",
            "Map user input to a whitelist of files or IDs instead of raw filesystem paths.",
            "Run the application under a least-privileged OS account with no access outside its data directory.",
            "Check whether any traversal request returned content (HTTP 200) and what was readable.",
        ],
        "references": [
            _ref("OWASP: Path Traversal", "https://owasp.org/www-community/attacks/Path_Traversal"),
            _ref("CWE-22: Path Traversal", "https://cwe.mitre.org/data/definitions/22.html"),
            _ref("MITRE ATT&CK T1083: File and Directory Discovery", MITRE.format("T1083")),
        ],
    },
    "WEB_RCE": {
        "steps": [
            "Refactor the affected feature so no shell is invoked with user input; use parameterized subprocess APIs.",
            "Search host audit logs for the injected commands (whoami, cat, wget, curl, nc) actually executing.",
            "If any command executed, treat the host as compromised: isolate it, rotate its credentials, and rebuild if needed.",
            "Patch the framework or CMS the requests target.",
        ],
        "references": [
            _ref("OWASP: Command Injection", "https://owasp.org/www-community/attacks/Command_Injection"),
            _ref("CWE-78: OS Command Injection", "https://cwe.mitre.org/data/definitions/78.html"),
            _ref("MITRE ATT&CK T1059: Command and Scripting Interpreter", MITRE.format("T1059")),
        ],
    },
    "WEB_SENSITIVE_HIGH": {
        "steps": [
            "Remove the files from the web root and deny access at the web server; assume anything served is public.",
            "Rotate every credential, API key, and database password found in the exposed files.",
            "Add pre-commit and CI secret scanning so credentials never reach a web root again.",
            "Check logs for other requesters of the same paths to gauge exposure.",
        ],
        "references": [
            _ref("OWASP Top 10 A05:2021 - Security Misconfiguration", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
            _ref("MITRE ATT&CK T1552.001: Credentials in Files", MITRE.format("T1552/001")),
            _ref("CWE-200: Exposure of Sensitive Information", "https://cwe.mitre.org/data/definitions/200.html"),
        ],
    },
    "WEB_SENSITIVE_MED": {
        "steps": [
            "Ensure admin, backup, and config paths return 404 or sit behind authentication.",
            "Delete stale backup files (.bak, .sql, archives) from the web root.",
            "Rate-limit or challenge clients that generate heavy 404 volumes.",
            "Keep CMS software and plugins updated; these paths are probed for known exploits.",
        ],
        "references": [
            _ref("OWASP Top 10 A05:2021 - Security Misconfiguration", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
            _ref("MITRE ATT&CK T1595: Active Scanning", MITRE.format("T1595")),
        ],
    },
    "WEB_SCANNER_UA": {
        "steps": [
            "Block or rate-limit the source; scanner traffic is usually automated pre-attack reconnaissance.",
            "Compare the paths the scanner requested against what you actually expose, and patch anything outdated.",
            "Consider a WAF or bot-management rule for known scanner signatures.",
        ],
        "references": [
            _ref("MITRE ATT&CK T1595: Active Scanning", MITRE.format("T1595")),
            _ref("MITRE ATT&CK T1595.002: Vulnerability Scanning", MITRE.format("T1595/002")),
        ],
    },
    "WEB_DIR_SCAN": {
        "steps": [
            "Rate-limit or temporarily lock out clients that generate repeated 404s.",
            "Confirm none of the enumerated paths returned content they should not have.",
            "Disable directory listing and return uniform error pages so probing gains less information.",
        ],
        "references": [
            _ref("MITRE ATT&CK T1595: Active Scanning", MITRE.format("T1595")),
            _ref("OWASP Top 10 A05:2021 - Security Misconfiguration", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
        ],
    },
    # ------------------------------------------------ syslog / system
    "SYS_BREAKIN": {
        "steps": [
            "Investigate the source host and block it if it has no business connecting.",
            "Check whether any login from that source succeeded.",
            "Disable root SSH logins; prefer key-based authentication.",
            "Fix reverse-DNS for your own hosts to reduce these warnings for legitimate clients.",
        ],
        "references": [
            _ref("MITRE ATT&CK T1110.001: Password Guessing", MITRE.format("T1110/001")),
            _ref("Mozilla OpenSSH security guidelines", "https://infosec.mozilla.org/guidelines/openssh.html"),
        ],
    },
    "SYS_SUDO_ABUSE": {
        "steps": [
            "Review the sudoers policy and apply least privilege: named commands, not ALL.",
            "Determine whether any of the attempts succeeded, and check session logs for that account.",
            "If the account may be compromised, disable it and force a credential reset.",
        ],
        "references": [
            _ref("MITRE ATT&CK T1548.003: Sudo and Sudo Caching", MITRE.format("T1548/003")),
            _ref("CIS Benchmarks (secure configuration guides)", "https://www.cisecurity.org/cis-benchmarks"),
        ],
    },
    "SYS_NEW_USER": {
        "steps": [
            "Verify the account matches an approved change request.",
            "If unexpected, disable the account and review its groups, shell, and SSH keys.",
            "Check the sessions that account has opened, and hunt for other persistence on the host.",
        ],
        "references": [
            _ref("MITRE ATT&CK T1136: Create Account", MITRE.format("T1136")),
            _ref("MITRE ATT&CK T1136.001: Local Account", MITRE.format("T1136/001")),
        ],
    },
    "SYS_ROOT_SESSION": {
        "steps": [
            "Confirm the session was expected maintenance by an authorized administrator.",
            "Prefer sudo with per-command rules over direct root shells.",
            "Alert on root sessions so each one gets acknowledged.",
        ],
        "references": [
            _ref("MITRE ATT&CK T1078: Valid Accounts", MITRE.format("T1078")),
            _ref("CIS Benchmarks (secure configuration guides)", "https://www.cisecurity.org/cis-benchmarks"),
        ],
    },
    # ------------------------------------------------ network
    "NET_PORT_SCAN": {
        "steps": [
            "Block the source at the perimeter firewall.",
            "Verify only intended services are reachable from outside, and close or filter the rest.",
            "Scan your own perimeter regularly so you know your exposure before an attacker does.",
        ],
        "references": [
            _ref("MITRE ATT&CK T1046: Network Service Discovery", MITRE.format("T1046")),
            _ref("MITRE ATT&CK T1595.002: Vulnerability Scanning", MITRE.format("T1595/002")),
        ],
    },
    "NET_CLEARTEXT": {
        "steps": [
            "Replace Telnet and FTP with SSH and SFTP.",
            "Disable the cleartext service entirely if nothing needs it.",
            "Rotate credentials that traveled over the cleartext service; assume they were captured.",
        ],
        "references": [
            _ref("MITRE ATT&CK T1557: Adversary-in-the-Middle", MITRE.format("T1557")),
            _ref("CIS Benchmarks (secure configuration guides)", "https://www.cisecurity.org/cis-benchmarks"),
            _ref("Mozilla OpenSSH security guidelines", "https://infosec.mozilla.org/guidelines/openssh.html"),
        ],
    },
    # ------------------------------------------------ anomalies
    "ANOM_VOLUME": {
        "steps": [
            "Identify the host: monitoring agent, search crawler, or compromised machine.",
            "If it is authorized, document it so future reports can dismiss it; otherwise rate-limit or block it.",
            "Inspect what the requests actually did, not just how many there were.",
        ],
        "references": [
            _ref("OWASP: Automated Threats to Web Applications", "https://owasp.org/www-project-automated-threats-to-web-applications/"),
            _ref("MITRE ATT&CK T1498: Network Denial of Service", MITRE.format("T1498")),
        ],
    },
    "ANOM_ERROR_RATE": {
        "steps": [
            "Review which paths the client requested: active probing, or a broken link and misconfigured integration.",
            "Fix application errors if the paths are legitimate.",
            "Rate-limit noisy or hostile clients.",
        ],
        "references": [
            _ref("MITRE ATT&CK T1595.002: Vulnerability Scanning", MITRE.format("T1595/002")),
            _ref("OWASP Top 10 A05:2021 - Security Misconfiguration", "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
        ],
    },
    "ANOM_HOURLY": {
        "steps": [
            "Correlate the spike with scheduled jobs or change-management records before assuming an attack.",
            "Review which accounts and source IPs were active during those hours.",
            "Alert on off-hours privileged activity so spikes get a human decision.",
        ],
        "references": [
            _ref("MITRE ATT&CK T1078: Valid Accounts", MITRE.format("T1078")),
            _ref("NIST SP 800-61 Rev. 3: Incident Handling Guide", "https://csrc.nist.gov/pubs/sp/800/61/r3/final"),
        ],
    },
    "ANOM_SPIKE": {
        "steps": [
            "Pull the requests from the spike minute and identify what they targeted.",
            "Add rate limiting if the traffic is automated; check upstream impact if it is load-related.",
            "Look for tool signatures in the spike (user agents, requested paths).",
        ],
        "references": [
            _ref("OWASP: Automated Threats to Web Applications", "https://owasp.org/www-project-automated-threats-to-web-applications/"),
            _ref("MITRE ATT&CK T1498: Network Denial of Service", MITRE.format("T1498")),
        ],
    },
    "ANOM_CRAWLER": {
        "steps": [
            "Decide whether this crawler is authorized (search engine, partner, internal tooling).",
            "Enforce robots.txt and rate limits for everything else.",
            "Check whether the crawler discovered paths it should not have found.",
        ],
        "references": [
            _ref("MITRE ATT&CK T1595: Active Scanning", MITRE.format("T1595")),
            _ref("OWASP: Automated Threats to Web Applications", "https://owasp.org/www-project-automated-threats-to-web-applications/"),
        ],
    },
}
