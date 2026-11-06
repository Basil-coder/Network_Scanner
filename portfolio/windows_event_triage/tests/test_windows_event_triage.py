import tempfile
import unittest
from pathlib import Path
from windows_event_triage import parse_rows, analyze

class TriageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "events.csv"

    def write(self, text):
        self.path.write_text(text, encoding="utf-8")
        return self.path

    def test_detection_and_sorting(self):
        text = "timestamp,event_id,account,source_ip\n"
        for n in [2, 0, 1]:
            text += f"2026-11-01T10:0{n}:00Z,4625,alice,192.0.2.10\n"
        text += "2026-11-01T10:04:00Z,4624,alice,192.0.2.10\n"
        report = analyze(parse_rows(self.write(text)), threshold=3)
        self.assertEqual([a["type"] for a in report["alerts"]], ["repeated_failed_logons", "success_after_failures"])
        self.assertEqual(report["events_processed"], 4)

    def test_lockout(self):
        data = "timestamp,event_id,account,source_ip\n2026-11-01T10:00:00+02:00,4740,bob,-\n"
        report = analyze(parse_rows(self.write(data)))
        self.assertEqual(report["alerts"][0]["type"], "account_lockout")
        self.assertEqual(report["alerts"][0]["timestamp"], "2026-11-01T08:00:00+00:00")

    def test_old_failure_not_correlated(self):
        text = "timestamp,event_id,account,source_ip\n2026-11-01T10:00:00Z,4625,a,192.0.2.1\n2026-11-01T11:00:00Z,4624,a,192.0.2.1\n"
        self.assertEqual(analyze(parse_rows(self.write(text)))["alerts"], [])

    def test_different_source_not_correlated(self):
        text = "timestamp,event_id,account,source_ip\n2026-11-01T10:00:00Z,4625,a,192.0.2.1\n2026-11-01T10:01:00Z,4624,a,192.0.2.2\n"
        self.assertEqual(analyze(parse_rows(self.write(text)))["alerts"], [])

    def test_reject_missing_header(self):
        with self.assertRaisesRegex(ValueError, "header"):
            parse_rows(self.write("timestamp,event_id\n"))

    def test_reject_naive_timestamp(self):
        with self.assertRaisesRegex(ValueError, "timezone"):
            parse_rows(self.write("timestamp,event_id,account,source_ip\n2026-11-01T10:00:00,4625,a,192.0.2.1\n"))

    def test_reject_invalid_ip(self):
        with self.assertRaisesRegex(ValueError, "line 2"):
            parse_rows(self.write("timestamp,event_id,account,source_ip\n2026-11-01T10:00:00Z,4625,a,invalid\n"))

    def test_reject_unsupported_id(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            parse_rows(self.write("timestamp,event_id,account,source_ip\n2026-11-01T10:00:00Z,4688,a,192.0.2.1\n"))

    def test_reject_malformed_row(self):
        with self.assertRaisesRegex(ValueError, "malformed"):
            parse_rows(self.write("timestamp,event_id,account,source_ip\n2026-11-01T10:00:00Z,4625,a\n"))

    def test_reject_invalid_threshold(self):
        with self.assertRaisesRegex(ValueError, "threshold"):
            analyze([], threshold=1)

    def test_reject_symlink(self):
        target = self.write("timestamp,event_id,account,source_ip\n")
        link = Path(self.tmp.name) / "link.csv"
        link.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            parse_rows(link)

    def test_reject_duplicate_header(self):
        with self.assertRaisesRegex(ValueError, "header"):
            parse_rows(self.write("timestamp,event_id,account,source_ip,account\n"))

if __name__ == "__main__":
    unittest.main()
