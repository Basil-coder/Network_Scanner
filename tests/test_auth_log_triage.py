"""Synthetic, offline unit and CLI tests for SSH authentication triage."""

from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from soc.auth_log_triage import (
    MAX_BYTES, TriageError, analyze, load_events, main, parse_line, parse_timestamp,
)


def line(kind="Failed password", ip="192.0.2.10", time="2026-10-31T10:00:00Z", user="test"):
    if kind == "Failed password":
        msg = f"Failed password for {user} from {ip} port 2222 ssh2"
    elif kind == "invalid":
        msg = f"Failed password for invalid user {user} from {ip} port 2222 ssh2"
    elif kind == "Accepted publickey":
        msg = f"Accepted publickey for {user} from {ip} port 2222 ssh2"
    else:
        msg = f"Accepted password for {user} from {ip} port 2222 ssh2"
    return f"{time} server sshd[123]: {msg}\n"


class ParsingTests(unittest.TestCase):
    def test_failure(self):
        self.assertEqual(parse_line(line().strip(), 1)[3], "failure")

    def test_invalid_user_failure(self):
        self.assertEqual(parse_line(line("invalid").strip(), 1)[3], "failure")

    def test_accepted_password(self):
        self.assertEqual(parse_line(line("Accepted password").strip(), 1)[3], "success")

    def test_accepted_publickey(self):
        self.assertEqual(parse_line(line("Accepted publickey").strip(), 1)[3], "success")

    def test_ignores_non_ssh(self):
        self.assertIsNone(parse_line("2026-10-31T10:00:00Z server cron[1]: hello", 1))

    def test_ignores_unrelated_sshd(self):
        self.assertIsNone(parse_line("2026-10-31T10:00:00Z server sshd[1]: Disconnected", 1))

    def test_ipv6_canonical(self):
        self.assertEqual(parse_line(line(ip="2001:0db8::1").strip(), 1)[2], "2001:db8::1")

    def test_bad_ip(self):
        with self.assertRaisesRegex(TriageError, "invalid source IP"):
            parse_line(line(ip="not-an-ip").strip(), 1)

    def test_scoped_ipv6(self):
        with self.assertRaisesRegex(TriageError, "scoped IP"):
            parse_line(line(ip="fe80::1%eth0").strip(), 1)

    def test_naive_time(self):
        with self.assertRaisesRegex(TriageError, "requires timezone"):
            parse_line(line(time="2026-10-31T10:00:00").strip(), 1)

    def test_invalid_time(self):
        with self.assertRaisesRegex(TriageError, "invalid ISO"):
            parse_line(line(time="not-a-date").strip(), 1)

    def test_utc_conversion(self):
        stamp = parse_timestamp("2026-10-31T12:00:00+02:00", 1)
        self.assertEqual(stamp, datetime(2026, 10, 31, 10, tzinfo=timezone.utc))

    def test_malformed_supported_message_rejected(self):
        with self.assertRaisesRegex(TriageError, "malformed supported"):
            parse_line("2026-10-31T10:00:00Z host sshd[1]: Failed password for user", 1)


class AnalysisTests(unittest.TestCase):
    def analyze_lines(self, lines, **kwargs):
        events = [parse_line(value.strip(), n) for n, value in enumerate(lines, 1)]
        return analyze([e for e in events if e], len(lines), **kwargs)

    def test_burst(self):
        report = self.analyze_lines([line(time=f"2026-10-31T10:00:{n:02d}Z") for n in range(5)])
        self.assertEqual([a["type"] for a in report["alerts"]], ["failure_burst"])
        self.assertEqual(report["alerts"][0]["failure_count"], 5)

    def test_success_after_failures(self):
        report = self.analyze_lines([line(time=f"2026-10-31T10:00:{n:02d}Z") for n in range(3)] + [line("Accepted password", time="2026-10-31T10:00:04Z")])
        self.assertEqual([a["type"] for a in report["alerts"]], ["success_after_failures"])

    def test_no_alert(self):
        report = self.analyze_lines([line(), line("Accepted password")])
        self.assertFalse(report["alerts"])

    def test_expired_window(self):
        report = self.analyze_lines([line(time="2026-10-31T10:00:00Z") for _ in range(4)] + [line(time="2026-10-31T10:11:00Z")])
        self.assertFalse(report["alerts"])

    def test_inclusive_window(self):
        report = self.analyze_lines([line(time="2026-10-31T10:00:00Z") for _ in range(4)] + [line(time="2026-10-31T10:10:00Z")])
        self.assertEqual(len(report["alerts"]), 1)

    def test_out_of_order(self):
        times = ["10:00:04", "10:00:01", "10:00:02", "10:00:00", "10:00:03"]
        report = self.analyze_lines([line(time=f"2026-10-31T{t}Z") for t in times])
        self.assertEqual(report["alerts"][0]["timestamp_utc"], "2026-10-31T10:00:04Z")

    def test_separate_sources(self):
        report = self.analyze_lines([line(ip="192.0.2.10") for _ in range(3)] + [line(ip="192.0.2.11") for _ in range(3)])
        self.assertFalse(report["alerts"])

    def test_duplicate_burst_suppressed(self):
        report = self.analyze_lines([line() for _ in range(20)])
        self.assertEqual(len(report["alerts"]), 1)

    def test_duplicate_success_suppressed(self):
        report = self.analyze_lines([line() for _ in range(3)] + [line("Accepted password") for _ in range(3)])
        self.assertEqual(len(report["alerts"]), 1)

    def test_redaction(self):
        report = self.analyze_lines([line(ip="192.0.2.20") for _ in range(5)], redact_ips=True)
        self.assertEqual(report["alerts"][0]["source_ip"], "source-1")
        self.assertTrue(report["ip_redacted"])

    def test_ignored_line_counts(self):
        report = analyze([parse_line(line().strip(), 1)], 3)
        self.assertEqual(report["ignored_lines"], 2)

    def test_invalid_window(self):
        with self.assertRaises(TriageError):
            analyze([], 0, window_minutes=0)

    def test_invalid_threshold(self):
        with self.assertRaises(TriageError):
            analyze([], 0, failure_threshold=1)

    def test_invalid_success_threshold(self):
        with self.assertRaises(TriageError):
            analyze([], 0, success_after_failures=0)


class FileAndCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "synthetic.log"

    def write(self, text):
        self.path.write_text(text, encoding="utf-8")

    def test_load_events(self):
        self.write("irrelevant\n" + line())
        events, count = load_events(self.path)
        self.assertEqual((len(events), count), (1, 2))

    def test_empty_file(self):
        self.write("")
        self.assertEqual(load_events(self.path), ([], 0))

    def test_invalid_utf8(self):
        self.path.write_bytes(b"\xff\n")
        with self.assertRaisesRegex(TriageError, "UTF-8"):
            load_events(self.path)

    def test_too_many_lines(self):
        self.path.write_bytes(b"x\n" * 100001)
        with self.assertRaisesRegex(TriageError, "100000 lines"):
            load_events(self.path)

    def test_missing_file(self):
        with self.assertRaisesRegex(TriageError, "cannot stat"):
            load_events(self.path)

    def test_custom_failure_threshold(self):
        self.write(line() * 3)
        output = io.StringIO()
        with redirect_stdout(output):
            code = main([str(self.path), "--failure-threshold", "3", "--format", "json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["alerts"][0]["type"], "failure_burst")

    def test_long_line(self):
        self.write("x" * 4097)
        with self.assertRaisesRegex(TriageError, "4096"):
            load_events(self.path)

    def test_reject_symlink(self):
        target = Path(self.temp.name) / "target"
        target.write_text("ok")
        self.path.symlink_to(target)
        with self.assertRaisesRegex(TriageError, "regular file"):
            load_events(self.path)

    def test_reject_directory(self):
        with self.assertRaisesRegex(TriageError, "regular file"):
            load_events(Path(self.temp.name))

    def test_size_limit(self):
        self.write("")
        with patch.object(Path, "lstat") as mocked:
            real = self.path.stat()
            mocked.return_value = type("Stat", (), {"st_mode": real.st_mode, "st_size": MAX_BYTES + 1})()
            with self.assertRaisesRegex(TriageError, "16 MiB"):
                load_events(self.path)

    def test_json_cli_alert_exit(self):
        self.write("".join(line() for _ in range(5)))
        output = io.StringIO()
        with redirect_stdout(output):
            code = main([str(self.path), "--format", "json", "--fail-on-alert"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())["alerts"][0]["type"], "failure_burst")

    def test_text_cli_no_alert_exit(self):
        self.write(line())
        output = io.StringIO()
        with redirect_stdout(output):
            code = main([str(self.path)])
        self.assertEqual(code, 0)
        self.assertIn("Alerts: 0", output.getvalue())

    def test_invalid_cli_exit(self):
        self.write(line())
        errors = io.StringIO()
        with redirect_stderr(errors):
            code = main([str(self.path), "--window-minutes", "0"])
        self.assertEqual(code, 2)
        self.assertIn("window-minutes", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
