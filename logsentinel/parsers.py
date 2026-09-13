"""Parsers that turn raw log text into normalized Record objects.

Supported formats:
- Apache / Nginx access logs (combined and common log format)
- Syslog / auth.log style lines (RFC 3164 and ISO-8601 timestamps)
- CSV (auto-detects and maps common column names)
- JSON (a single object/array or newline-delimited JSON)
- Plain text fallback (every line kept, best-effort IP/timestamp extraction)

Every input line always becomes a Record so no evidence is lost; lines that
do not match the detected layout are kept as plain-text records.
"""

import csv
import io
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from .models import ParseResult, Record

MAX_LINES = 1_000_000

IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

SYSLOG_RE = re.compile(
    r"^(?P<ts>(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?))\s+"
    r"(?P<host>\S+)\s+(?P<program>[\w./-]+?)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

ISO_TS_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)

SYSLOG_USER_RES = (
    re.compile(r"\bfor (?:invalid user )?(\w+) from\b", re.I),
    re.compile(r"\binvalid user (\w+) from\b", re.I),
    re.compile(r"\buser=(\S+)", re.I),
)

CSV_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%d/%b/%Y:%H:%M:%S %z",
    "%d/%b/%Y:%H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
)


# --------------------------------------------------------------------------
# column-name mapping for CSV and JSON inputs
# --------------------------------------------------------------------------

def _norm_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(name).lower())


_CANON_CANDIDATES = {
    "src_ip": ("ip", "srcip", "sourceip", "clientip", "remoteaddr", "ipaddress",
               "src", "attackerip", "sourceaddress", "clientaddress", "originip", "peerip"),
    "timestamp": ("timestamp", "time", "date", "datetime", "eventtime", "ts",
                  "createdat", "logtime", "eventdate", "generatedtime"),
    "user": ("user", "username", "userid", "account", "login", "usr", "subjectusername"),
    "event": ("event", "message", "msg", "description", "action", "eventtype",
              "details", "summary", "text", "log"),
    "method": ("method", "requestmethod", "httpmethod", "verb"),
    "path": ("path", "url", "uri", "requesturi", "endpoint", "resource",
             "request", "target", "file", "page"),
    "query": ("query", "querystring", "params", "search"),
    "status": ("status", "statuscode", "responsecode", "httpstatus",
               "resultcode", "result", "code"),
    "ua": ("useragent", "ua", "agent", "browser"),
    "host": ("host", "hostname", "server", "destip", "dstip",
             "destinationip", "targetip", "dst", "destination"),
    "port": ("port", "destport", "dstport", "destinationport", "dport",
             "targetport", "serviceport"),
}


def _map_columns(headers) -> dict:
    """Map canonical field names to the index/key of the best-matching column.

    Two passes: exact normalized matches first (so 'dstip' is not stolen by
    the generic 'ip' candidate), then substring matches for anything still
    unmapped (so 'Timestamp (UTC)' still maps).
    """
    norms = {i: _norm_name(h) for i, h in enumerate(headers)}
    mapping = {}
    used = set()
    for canonical, candidates in _CANON_CANDIDATES.items():
        cand_norms = {_norm_name(c) for c in candidates}
        for i, n in norms.items():
            if i not in used and n and n in cand_norms:
                mapping[canonical] = i
                used.add(i)
                break
    for canonical, candidates in _CANON_CANDIDATES.items():
        if canonical in mapping:
            continue
        cand_norms = {_norm_name(c) for c in candidates}
        for i, n in norms.items():
            if i in used or not n:
                continue
            if any(len(c) >= 3 and c in n for c in cand_norms):
                mapping[canonical] = i
                used.add(i)
                break
    return mapping


# --------------------------------------------------------------------------
# timestamp helpers (all records use naive UTC datetimes)
# --------------------------------------------------------------------------

def _to_naive_utc(dt: datetime) -> datetime:
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


_MONTHS = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
            "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}


def _parse_rfc3164(ts_str: str) -> datetime:
    """Parse 'Sep  9 02:13:00'; syslog omits the year, so assume the current
    one and step back a year if that would put the timestamp in the future.
    Parsed manually because yearless strptime is deprecated."""
    parts = ts_str.split()
    if len(parts) != 3:
        raise ValueError("unrecognized RFC 3164 timestamp: {!r}".format(ts_str))
    month = _MONTHS.get(parts[0][:3].lower())
    if month is None:
        raise ValueError("unknown month: {!r}".format(parts[0]))
    day = int(parts[1])
    hh, mm, ss = (int(x) for x in parts[2].split(":"))
    now = datetime.now()
    dt = datetime(now.year, month, day, hh, mm, ss)
    if dt > now + timedelta(days=1):
        dt = dt.replace(year=now.year - 1)
    return dt


def _parse_iso(ts_str: str) -> datetime:
    s = ts_str.strip()
    if s.endswith(("Z", "z")):
        s = s[:-1] + "+00:00"
    m = re.search(r"([+-]\d{2})(\d{2})$", s)
    if m:  # offsets like +0200 (no colon) are rejected by older fromisoformat
        s = s[: m.start()] + m.group(1) + ":" + m.group(2)
    return _to_naive_utc(datetime.fromisoformat(s))


def _parse_apache_ts(ts_str: str) -> Optional[datetime]:
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            return _to_naive_utc(datetime.strptime(ts_str, fmt))
        except ValueError:
            continue
    return None


def _parse_timestamp(value) -> Optional[datetime]:
    """Best-effort timestamp parsing for CSV/JSON fields."""
    s = str(value).strip()
    if not s:
        return None
    m = ISO_TS_RE.search(s)
    if m:
        try:
            return _parse_iso(m.group(0))
        except ValueError:
            pass
    if re.fullmatch(r"\d{10}(\d{3})?", s):  # epoch seconds or milliseconds
        n = int(s)
        return datetime.fromtimestamp(
            n / (1000.0 if len(s) == 13 else 1.0), tz=timezone.utc
        ).replace(tzinfo=None)
    for fmt in CSV_TS_FORMATS:
        try:
            return _to_naive_utc(datetime.strptime(s, fmt))
        except ValueError:
            continue
    return None


# --------------------------------------------------------------------------
# format detection
# --------------------------------------------------------------------------

def detect_format(filename: str, text: str) -> str:
    """Detect the log format from the file extension and content."""
    name = (filename or "").lower()
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return "text"
    if name.endswith((".jsonl", ".ndjson")):
        return "json"
    if name.endswith(".json"):
        return "json"
    if name.endswith(".csv"):
        return "csv"

    stripped = lines[0].lstrip()
    if stripped.startswith(("{", "[")):
        return "json"

    head = lines[:50]
    if sum(1 for ln in head if APACHE_RE.match(ln)) >= (len(head) + 1) // 2:
        return "apache"
    if sum(1 for ln in head if SYSLOG_RE.match(ln)) >= (len(head) + 1) // 2:
        return "syslog"

    if len(lines) >= 2 and any(ln.count(d) >= 2 for ln in lines[:10] for d in (",", ";", "\t")):
        counts = {len(ln.split(",")) for ln in lines[:10]}
        if len(counts) == 1 and next(iter(counts)) >= 3:
            return "csv"
    return "text"


# --------------------------------------------------------------------------
# per-format parsers (each returns (records, structured_count))
# --------------------------------------------------------------------------

def _plain_record(raw: str, line_no: int) -> Record:
    ip_m = IPV4_RE.search(raw)
    ts_m = ISO_TS_RE.search(raw)
    timestamp = None
    if ts_m:
        try:
            timestamp = _parse_iso(ts_m.group(0))
        except ValueError:
            timestamp = None
    return Record(
        raw=raw,
        line_no=line_no,
        timestamp=timestamp,
        src_ip=ip_m.group(0) if ip_m else None,
        event=raw,
    )


def _split_request(request: str):
    """Split 'GET /path?query HTTP/1.1' into (method, path, query)."""
    parts = request.split(" ")
    if len(parts) >= 2 and parts[0].isupper() and parts[0].isalpha():
        method = parts[0]
        target = parts[1]
        path, _, query = target.partition("?")
        return method, path, query
    return None, None, None


def _record_from_apache(m, raw: str, line_no: int) -> Record:
    request = m.group("request") or ""
    method, path, query = _split_request(request)
    user = m.group("user")
    user = user if user and user != "-" else None
    record = Record(
        raw=raw,
        line_no=line_no,
        timestamp=_parse_apache_ts(m.group("ts")),
        src_ip=m.group("ip"),
        user=user,
        event=request or None,
        method=method,
        path=path,
        query=query or None,
        status=int(m.group("status")),
        ua=m.group("ua"),
    )
    if m.group("referer"):
        record.extra["referer"] = m.group("referer")
    return record


def _parse_apache(text: str):
    records, structured = [], 0
    for line_no, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        m = APACHE_RE.match(raw)
        if m:
            records.append(_record_from_apache(m, raw, line_no))
            structured += 1
        else:
            records.append(_plain_record(raw, line_no))
    return records, structured


def _record_from_syslog(m, raw: str, line_no: int) -> Record:
    ts_raw = m.group("ts")
    timestamp = None
    try:
        timestamp = _parse_iso(ts_raw) if ts_raw[0].isdigit() else _parse_rfc3164(ts_raw)
    except ValueError:
        timestamp = None
    msg = m.group("msg")
    ip_m = IPV4_RE.search(msg)
    user = None
    for rx in SYSLOG_USER_RES:
        um = rx.search(msg)
        if um:
            user = um.group(1)
            break
    # netfilter-style logs carry the destination port as DPT=<n>;
    # this is a service port, unlike sshd's 'port N' client source port.
    port_m = re.search(r"\bDPT=(\d+)", msg)
    record = Record(
        raw=raw,
        line_no=line_no,
        timestamp=timestamp,
        src_ip=ip_m.group(0) if ip_m else None,
        user=user,
        event=msg,
        host=m.group("host"),
        port=int(port_m.group(1)) if port_m else None,
    )
    record.extra["program"] = m.group("program")
    return record


def _parse_syslog(text: str):
    records, structured = [], 0
    for line_no, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        m = SYSLOG_RE.match(raw)
        if m:
            records.append(_record_from_syslog(m, raw, line_no))
            structured += 1
        else:
            records.append(_plain_record(raw, line_no))
    return records, structured


def _assign(record: Record, canonical: str, value: str) -> None:
    if canonical == "timestamp":
        record.timestamp = _parse_timestamp(value)
    elif canonical == "status":
        m = re.search(r"\d+", value)
        if m:
            record.status = int(m.group())
    elif canonical == "port":
        m = re.search(r"\d+", value)
        if m:
            record.port = int(m.group())
    elif canonical == "method":
        record.method = value.strip().upper()
    elif canonical == "path":
        method, path, query = _split_request(value)
        if method:  # the cell held a full request line like "GET /x HTTP/1.1"
            record.method = method
            record.path = path
            record.query = query or None
        else:
            path, _, query = value.partition("?")
            record.path = path
            record.query = query or None
    elif canonical == "query":
        record.query = value
    else:
        setattr(record, canonical, value)


def _parse_csv(text: str):
    sample = text[:8192]
    delimiter = ","
    try:
        delimiter = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
    except csv.Error:
        pass
    rows = [
        row for row in csv.reader(io.StringIO(text), delimiter=delimiter)
        if any(cell.strip() for cell in row)
    ]
    if not rows:
        return [], 0
    header = [c.strip() for c in rows[0]]
    mapping = _map_columns(header)
    records = []
    for offset, row in enumerate(rows[1:], 1):
        record = Record(raw=delimiter.join(row), line_no=offset)
        for canonical, idx in mapping.items():
            if idx >= len(row):
                continue
            value = row[idx].strip()
            if value and value != "-":
                _assign(record, canonical, value)
        for i, name in enumerate(header):
            if i not in mapping.values() and i < len(row) and row[i].strip():
                record.extra[name] = row[i].strip()
        records.append(record)
    return records, len(records)


def _flatten(obj: dict) -> dict:
    """Flatten one level of nesting so {'client': {'ip': ...}} becomes findable."""
    flat = {}
    for key, value in obj.items():
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                flat["{}.{}".format(key, sub_key)] = sub_value
        else:
            flat[key] = value
    return flat


def _record_from_obj(obj, line_no: int, raw: Optional[str]) -> Record:
    if not isinstance(obj, dict):
        text = raw if raw is not None else json.dumps(obj, ensure_ascii=False)
        return _plain_record(text, line_no)
    flat = _flatten(obj)
    record = Record(
        raw=raw if raw is not None else json.dumps(obj, ensure_ascii=False),
        line_no=line_no,
    )
    keys = list(flat.keys())
    # _map_columns returns positional indices; translate to the actual keys.
    index_map = _map_columns(keys)
    mapping = {canonical: keys[idx] for canonical, idx in index_map.items()}
    for canonical, key in mapping.items():
        value = flat.get(key)
        if value is None:
            continue
        s = str(value).strip()
        if s and s != "-":
            _assign(record, canonical, s)
    for key, value in flat.items():
        if key not in mapping.values() and not isinstance(value, (dict, list)):
            record.extra[key] = value
    return record


def _parse_json(text: str):
    stripped = text.lstrip()
    if stripped.startswith("[") or (stripped.startswith("{") and "\n" not in stripped.strip()):
        data = json.loads(text)  # whole-file JSON (array or single object)
        items = data if isinstance(data, list) else [data]
        raws = [None] * len(items)
    else:
        items, raws = [], []
        for line_no, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            items.append(json.loads(line))  # raises -> caller falls back
            raws.append(line)
    records = [
        _record_from_obj(obj, index, raw)
        for index, (obj, raw) in enumerate(zip(items, raws), 1)
    ]
    return records, len(records)


def _parse_text(text: str):
    records = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        if raw.strip():
            records.append(_plain_record(raw, line_no))
    return records, len(records)


# --------------------------------------------------------------------------
# public entry point
# --------------------------------------------------------------------------

def parse_text(filename: str, text: str) -> ParseResult:
    """Parse raw log text into normalized records, auto-detecting the format."""
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        raise ValueError(
            "File has more than {:,} lines; split it before analysis.".format(MAX_LINES)
        )
    nonempty = [ln for ln in lines if ln.strip()]
    if not nonempty:
        return ParseResult(
            fmt="text", records=[], total_lines=0,
            warnings=["The file contained no readable log lines."],
        )

    fmt = detect_format(filename, text)
    warnings = []
    try:
        if fmt == "json":
            records, structured = _parse_json(text)
        elif fmt == "csv":
            records, structured = _parse_csv(text)
        elif fmt == "apache":
            records, structured = _parse_apache(text)
        elif fmt == "syslog":
            records, structured = _parse_syslog(text)
        else:
            records, structured = _parse_text(text)
    except Exception as exc:  # malformed for the detected format -> plain text
        warnings.append(
            "{} parsing failed ({}); treated the file as plain text.".format(fmt, exc)
        )
        fmt = "text"
        records, structured = _parse_text(text)
        return ParseResult(fmt, records, len(lines), structured, warnings)

    if fmt in ("apache", "syslog") and structured < len(nonempty):
        warnings.append(
            "{} line(s) did not match the {} layout; they were kept as "
            "plain-text records.".format(len(nonempty) - structured, fmt)
        )
    return ParseResult(fmt, records, len(lines), structured, warnings)
