"""Statistical anomaly detection.

These detectors do not match attack signatures; they look for source IPs,
time windows, or behaviors that are extreme outliers compared to the rest
of the log. They use robust statistics (median and median absolute
deviation) because a classic mean/std z-score is masked by the very
outlier you are hunting.
"""

from collections import Counter, defaultdict
from statistics import median

from .models import Finding, make_evidence

MAD_SCALE = 0.6745       # makes MAD comparable to a standard z-score
MZ_THRESHOLD = 3.5      # modified z-score at which we flag (Iglewicz-Hoaglin)
RATIO_THRESHOLD = 5.0    # fallback when MAD collapses to zero
MAX_PER_DETECTOR = 3    # cap findings so one weird IP doesn't flood the report


def _robust_outliers(counts, min_population, min_value, min_multiple=1.0,
                     ratio_threshold=RATIO_THRESHOLD):
    """Return [(key, value, metrics)] for values far outside the population.

    A value must exceed max(min_value, median * min_multiple) and then:
    - score a modified z >= MZ_THRESHOLD when MAD > 0, or
    - be at least ratio_threshold times the median when MAD is 0 but the
      median is not, or
    - simply exceed min_value when both MAD and the median are 0 (e.g. error
      counts where most peers have none).
    """
    if len(counts) < min_population:
        return []
    values = list(counts.values())
    med = median(values)
    mad = median([abs(v - med) for v in values])
    out = []
    for key, value in counts.items():
        if value < max(min_value, med * min_multiple):
            continue
        if mad > 0:
            score = MAD_SCALE * (value - med) / mad
            if score >= MZ_THRESHOLD:
                out.append((key, value, {"median": med, "mad": mad,
                                         "robust_z": round(score, 1)}))
        elif med > 0 and value >= ratio_threshold * med:
            out.append((key, value, {"median": med,
                                     "ratio_vs_median": round(value / med, 1)}))
        elif med == 0 and value >= min_value:
            out.append((key, value, {"median": 0, "absolute": value}))
    return sorted(out, key=lambda item: -item[1])[:MAX_PER_DETECTOR]


def _finding(rule_id, title, severity, description, recommendation, records,
             count, metrics, src_ip=None):
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category="anomaly",
        description=description,
        recommendation=recommendation,
        count=count,
        src_ip=src_ip,
        evidence=make_evidence(records),
        metrics=metrics,
    )


def detect_volume_anomaly(records):
    """A source IP producing an extreme share of all requests."""
    counts = Counter(r.src_ip for r in records if r.src_ip)
    flagged = _robust_outliers(counts, min_population=5, min_value=15)
    findings = []
    for ip, value, metrics in flagged:
        findings.append(
            _finding(
                "ANOM_VOLUME",
                "Unusual request volume from {}".format(ip),
                "medium",
                "{} generated {} requests, far above the median of {} per "
                "source IP. This can be a crawler, a monitoring host, or a "
                "compromised machine.".format(
                    ip, value, metrics["median"]
                ),
                "Identify the host. If it is legitimate (monitoring, "
                "indexing) document it; otherwise investigate what the "
                "traffic actually does.",
                [r for r in records if r.src_ip == ip],
                value,
                metrics,
                src_ip=ip,
            )
        )
    return findings


def detect_error_rate_anomaly(records):
    """A source IP generating an extreme number of HTTP error responses."""
    per_ip = defaultdict(lambda: {"requests": 0, "errors": 0, "rows": []})
    for record in records:
        if record.src_ip and record.status is not None:
            bucket = per_ip[record.src_ip]
            bucket["requests"] += 1
            bucket["rows"].append(record)
            if record.status >= 400:
                bucket["errors"] += 1
    candidates = {
        ip: b["errors"]
        for ip, b in per_ip.items()
        if b["requests"] >= 10
    }
    flagged = _robust_outliers(candidates, min_population=5, min_value=10)
    findings = []
    for ip, errors, metrics in flagged:
        bucket = per_ip[ip]
        findings.append(
            _finding(
                "ANOM_ERROR_RATE",
                "Unusually high error rate from {}".format(ip),
                "medium",
                "{} produced {} HTTP error responses out of {} requests, "
                "versus a median of {} errors per IP. Probing, scraping "
                "gone wrong, or a misconfigured client.".format(
                    ip, errors, bucket["requests"], metrics["median"]
                ),
                "Check what the client was requesting. If it was probing, "
                "block or rate-limit it; if the paths look legitimate, fix "
                "what is erroring.",
                bucket["rows"],
                errors,
                metrics,
                src_ip=ip,
            )
        )
    return findings


def detect_hourly_anomaly(records):
    """An hour-of-day bucket far outside the log's normal hourly volume."""
    rows = [r for r in records if r.timestamp]
    if len(rows) < 50:
        return []
    hour_counts = Counter(r.timestamp.hour for r in rows)
    if len(hour_counts) < 4:
        return []  # too narrow a time span to talk about "unusual hours"
    flagged = _robust_outliers(
        hour_counts, min_population=4, min_value=5, min_multiple=2.0,
        ratio_threshold=3.0,
    )
    if not flagged:
        return []
    off_hours = [h for h, _, _ in flagged if h < 6 or h >= 22]
    day_hours = [h for h, _, _ in flagged if 6 <= h < 22]
    hour_str = lambda hours: ", ".join("{:02d}:00".format(h) for h in hours)
    if off_hours:
        findings = [
            _finding(
                "ANOM_HOURLY",
                "Activity spike during off-hours",
                "medium",
                "Traffic between {} is far above the median for this log "
                "({} vs {} per hour). Off-hours spikes are worth a look: "
                "they are often batch jobs, but also exports and staging "
                "by attackers.".format(
                    hour_str(off_hours),
                    max(c for _, c, _ in flagged),
                    flagged[0][2]["median"],
                ),
                "Correlate the spike with the accounts and source IPs "
                "active then. Confirm it is a scheduled job; otherwise "
                "investigate the sessions involved.",
                [r for r in rows if r.timestamp.hour in off_hours],
                sum(c for h, c, _ in flagged if h in off_hours),
                {"hours": hour_str(off_hours)},
            )
        ]
        return findings
    findings = [
        _finding(
            "ANOM_HOURLY",
            "Unusual traffic spike at {}".format(hour_str([h])),
            "low",
            "Traffic in this hour is far above the median for this log "
            "({} vs {} per hour).".format(c, metrics["median"]),
            "Check what drove the spike - a campaign, a crawler, or an "
            "incident - before assuming it is benign.",
            [r for r in rows if r.timestamp.hour == h],
            c,
            metrics,
        )
        for h, c, metrics in flagged[:1]
    ]
    return findings


def detect_traffic_spikes(records):
    """A single minute far outside the log's per-minute volume."""
    rows = [r for r in records if r.timestamp]
    if len(rows) < 100:
        return []
    buckets = Counter(
        r.timestamp.replace(second=0, microsecond=0) for r in rows
    )
    if len(buckets) < 30:
        return []
    flagged = _robust_outliers(
        buckets, min_population=30, min_value=10, min_multiple=3.0
    )
    findings = []
    for minute, count, metrics in flagged:
        findings.append(
            _finding(
                "ANOM_SPIKE",
                "Traffic spike at {}".format(minute.isoformat()),
                "medium" if count >= 5 * metrics["median"] else "low",
                "{} requests in a single minute ({}), versus a median of {} "
                "per minute in this log.".format(
                    count, metrics, metrics["median"]
                ),
                "Short, sharp spikes are typical of automated tools or "
                "retry storms. Pull the requests in this minute and check "
                "what was targeted.",
                [r for r in rows
                 if r.timestamp.replace(second=0, microsecond=0) == minute],
                count,
                metrics,
            )
        )
    return findings


def detect_crawler(records):
    """One IP touching an extreme number of distinct URLs."""
    paths_by_ip = defaultdict(set)
    for record in records:
        if record.src_ip and record.path:
            paths_by_ip[record.src_ip].add(record.full_url() or record.path)
    counts = {ip: len(paths) for ip, paths in paths_by_ip.items()}
    flagged = _robust_outliers(counts, min_population=5, min_value=30)
    findings = []
    for ip, unique_paths, metrics in flagged:
        findings.append(
            _finding(
                "ANOM_CRAWLER",
                "High URL diversity from {}".format(ip),
                "medium",
                "{} requested {} distinct URLs, versus a median of {} per "
                "source IP - consistent with a crawler, scraper, or content "
                "discovery scan.".format(ip, unique_paths, metrics["median"]),
                "Decide whether this crawler is authorized. If not, "
                "rate-limit it and check whether it found anything it "
                "should not have.",
                [r for r in records if r.src_ip == ip],
                unique_paths,
                metrics,
                src_ip=ip,
            )
        )
    return findings


ALL_ANOMALIES = (
    detect_volume_anomaly,
    detect_error_rate_anomaly,
    detect_hourly_anomaly,
    detect_traffic_spikes,
    detect_crawler,
)
