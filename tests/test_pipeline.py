"""
Pytest Test Suite
Covers ingestion, edge cases, malformed inputs, and heuristic detection.
"""

import pytest
from src.ingestion import ingest, parse_apache, parse_syslog, LogEntry
from src.rag import RAGDetector


# ─── Fixtures ────────────────────────────────────────────────────────────────

VALID_APACHE = (
    '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] '
    '"GET /apache_pb.gif HTTP/1.0" 200 2326'
)

ERROR_APACHE = (
    '10.0.0.1 - - [11/Oct/2000:08:00:00 -0700] '
    '"POST /login HTTP/1.1" 500 512'
)

WARN_APACHE = (
    '192.168.1.1 - - [12/Oct/2000:09:00:00 -0700] '
    '"GET /secret HTTP/1.1" 403 128'
)

VALID_SYSLOG = (
    "Oct 11 22:14:15 myhost sshd[12345]: Accepted password for user from 192.168.1.1"
)

ERROR_SYSLOG = (
    "Oct 11 22:14:20 myhost kernel: error reading disk sector 0x1234"
)


# ─── Ingestion Tests ─────────────────────────────────────────────────────────

class TestApacheParser:
    def test_valid_entry(self):
        entry = parse_apache(VALID_APACHE)
        assert entry is not None
        assert entry.source == "apache"
        assert entry.level == "INFO"
        assert "200" in entry.message

    def test_error_status(self):
        entry = parse_apache(ERROR_APACHE)
        assert entry is not None
        assert entry.level == "ERROR"

    def test_warn_status(self):
        entry = parse_apache(WARN_APACHE)
        assert entry is not None
        assert entry.level == "WARN"

    def test_malformed_line(self):
        assert parse_apache("this is not a log line") is None

    def test_empty_line(self):
        assert parse_apache("") is None

    def test_partial_line(self):
        assert parse_apache("127.0.0.1 - -") is None


class TestSyslogParser:
    def test_valid_entry(self):
        entry = parse_syslog(VALID_SYSLOG)
        assert entry is not None
        assert entry.source == "syslog"
        assert entry.level == "INFO"

    def test_error_detection(self):
        entry = parse_syslog(ERROR_SYSLOG)
        assert entry is not None
        assert entry.level == "ERROR"

    def test_malformed_line(self):
        assert parse_syslog("random garbage text") is None

    def test_empty_line(self):
        assert parse_syslog("") is None


class TestIngest:
    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.log"
        f.write_text("")
        result = ingest(str(f))
        assert result == []

    def test_all_malformed(self, tmp_path):
        f = tmp_path / "bad.log"
        f.write_text("bad line\nanother bad line\n!!!\n")
        result = ingest(str(f))
        assert result == []

    def test_mixed_valid_invalid(self, tmp_path):
        f = tmp_path / "mixed.log"
        f.write_text(VALID_APACHE + "\nbad line\n" + ERROR_APACHE + "\n")
        result = ingest(str(f))
        assert len(result) == 2

    def test_apache_format_detection(self, tmp_path):
        f = tmp_path / "apache.log"
        f.write_text(VALID_APACHE + "\n" + ERROR_APACHE + "\n")
        result = ingest(str(f))
        assert all(e.source == "apache" for e in result)

    def test_syslog_format_detection(self, tmp_path):
        f = tmp_path / "syslog.log"
        f.write_text(VALID_SYSLOG + "\n" + ERROR_SYSLOG + "\n")
        result = ingest(str(f))
        assert all(e.source == "syslog" for e in result)


# ─── Heuristic Fallback Tests ─────────────────────────────────────────────────

class TestHeuristicFallback:
    def _make_entry(self, level: str) -> LogEntry:
        return LogEntry(
            raw="raw log", source="apache",
            timestamp="now", level=level, message="test"
        )

    def _detector(self):
        # RAGDetector without a store — we call _heuristic_fallback directly
        return RAGDetector.__new__(RAGDetector)

    def test_no_anomaly(self):
        d = self._detector()
        result = d._heuristic_fallback([self._make_entry("INFO")])
        assert result["anomaly_detected"] is False
        assert result["severity"] == "LOW"

    def test_warning_anomaly(self):
        d = self._detector()
        result = d._heuristic_fallback([self._make_entry("WARN")])
        assert result["anomaly_detected"] is True
        assert result["severity"] == "MEDIUM"

    def test_error_anomaly(self):
        d = self._detector()
        result = d._heuristic_fallback([self._make_entry("ERROR")])
        assert result["anomaly_detected"] is True
        assert result["severity"] == "HIGH"

    def test_error_takes_priority_over_warn(self):
        d = self._detector()
        entries = [self._make_entry("WARN"), self._make_entry("ERROR")]
        result = d._heuristic_fallback(entries)
        assert result["severity"] == "HIGH"

    def test_suspicious_entries_listed(self):
        d = self._detector()
        e = self._make_entry("ERROR")
        result = d._heuristic_fallback([e])
        assert e.raw in result["suspicious_entries"]
