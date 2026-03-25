"""
Log Ingestion & Preprocessing Pipeline
Supports Apache access logs and syslog formats.
"""

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class LogEntry:
    raw: str
    source: str        # 'apache' or 'syslog'
    timestamp: str
    level: str
    message: str


APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

SYSLOG_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\d+) (?P<time>\S+) \S+ '
    r'(?P<process>\S+?)(\[[\d]+\])?: (?P<message>.+)'
)


def parse_apache(line: str) -> LogEntry | None:
    m = APACHE_PATTERN.match(line.strip())
    if not m:
        return None
    status = m.group("status")
    level = "ERROR" if status.startswith("5") else \
            "WARN"  if status.startswith("4") else "INFO"
    return LogEntry(
        raw=line.strip(),
        source="apache",
        timestamp=m.group("time"),
        level=level,
        message=f'{m.group("request")} -> {status}'
    )


def parse_syslog(line: str) -> LogEntry | None:
    m = SYSLOG_PATTERN.match(line.strip())
    if not m:
        return None
    msg = m.group("message")
    level = "ERROR" if "error" in msg.lower() else \
            "WARN"  if "warn"  in msg.lower() else "INFO"
    return LogEntry(
        raw=line.strip(),
        source="syslog",
        timestamp=f'{m.group("month")} {m.group("day")} {m.group("time")}',
        level=level,
        message=msg
    )


def ingest(path: str) -> list[LogEntry]:
    """
    Ingest a log file. Auto-detects Apache vs syslog format.
    Skips malformed lines gracefully.
    """
    entries: list[LogEntry] = []
    lines = Path(path).read_text(errors="replace").splitlines()

    if not lines:
        return entries

    # Detect format from first non-empty line
    first = next((l for l in lines if l.strip()), "")
    is_apache = bool(APACHE_PATTERN.match(first))

    parser = parse_apache if is_apache else parse_syslog

    for line in lines:
        if not line.strip():
            continue
        entry = parser(line)
        if entry:
            entries.append(entry)

    return entries
