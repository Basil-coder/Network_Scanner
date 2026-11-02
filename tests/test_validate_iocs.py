"""Offline synthetic tests for the IOC validator."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ioc.validate_iocs import InvalidIndicator, canonical, main, validate_feed


class IOCValidationTests(unittest.TestCase):
    def test_supported_types(self):
        examples = {
            ("ipv4", "203.0.113.9"): "203.0.113.9",
            ("ipv6", "2001:0db8::1"): "2001:db8::1",
            ("domain", "EXAMPLE.COM."): "example.com",
            ("sha256", "AB" * 32): "ab" * 32,
            ("url", "https://EXAMPLE.COM:443/a?q=1"): "https://example.com/a?q=1",
            ("url", "http://[2001:db8::1]:80"): "http://[2001:db8::1]/",
        }
        for (kind, value), expected in examples.items():
            with self.subTest(kind=kind, value=value):
                self.assertEqual(canonical(kind, value), expected)

    def test_invalid_values(self):
        cases = [
            ("ipv4", "2001:db8::1"), ("ipv6", "203.0.113.1"),
            ("ipv4", "192.168.001.1"), ("ipv6", "fe80::1%eth0"), ("domain", "localhost"),
            ("domain", "bad_name.test"), ("domain", "-bad.test"),
            ("domain", "bücher.example"), ("sha256", "abcd"),
            ("url", "file:///etc/passwd"), ("url", "http://user:pass@example.com"),
            ("url", "http://example.com:99999"), ("url", "http://example.com:0"), ("url", "http://example.com\\@evil.test"),
            ("url", "http://example.com/#frag"), ("url", "http://localhost"),
            ("url", "https://example.com/a b"), ("url", "https://example.com/\n"),
            ("ipv4", ""), ("domain", "a" * 64 + ".test"),
            ("sha256", "z" * 64), ("unknown", "example.com"),
        ]
        for kind, value in cases:
            with self.subTest(kind=kind, value=value):
                with self.assertRaises(InvalidIndicator):
                    canonical(kind, value)

    def test_wrong_types(self):
        for kind, value in [(None, "a.test"), ("domain", None), ("domain", 42), ("domain", []), (12, "a.test")]:
            with self.subTest(kind=kind, value=value):
                with self.assertRaises(InvalidIndicator):
                    canonical(kind, value)

    def test_duplicate_normalization_and_invalid_reasons(self):
        rows = [
            '{"type":"domain","value":"EXAMPLE.COM"}',
            '{"type":"domain","value":"example.com."}',
            '{"type":"ipv4","value":"203.0.113.1"}',
            '{"type":"sha256","value":"bad"}',
            '{"type":"domain","type":"ipv4","value":"203.0.113.1"}',
            '{"type":"url","value":"http://example.com"}',
            '{"type":"url","value":"http://example.com:80/"}',
            '{"type":"domain","value":"a.test","extra":true}',
            '{"type":"domain","value":"a.test","extra":NaN}',
            'not-json',
            '',
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.jsonl"
            path.write_text("\n".join(rows) + "\n", encoding="utf-8")
            report = validate_feed(path)
        self.assertEqual(report["total_lines"], 11)
        self.assertEqual(report["valid_unique"], 3)
        self.assertEqual(report["duplicate_count"], 2)
        self.assertEqual(report["invalid_count"], 6)
        self.assertEqual(report["duplicates"], [{"line": 2, "first_line": 1}, {"line": 7, "first_line": 6}])
        self.assertEqual([x["line"] for x in report["invalid"]], [4, 5, 8, 9, 10, 11])

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "empty.jsonl"
            path.write_bytes(b"")
            self.assertEqual(validate_feed(path)["valid_unique"], 0)

    def test_invalid_utf8(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_bytes(b"\xff\n")
            self.assertEqual(validate_feed(path)["invalid_count"], 1)

    def test_reject_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "target"
            target.write_text("", encoding="utf-8")
            link = Path(tmp) / "link"
            link.symlink_to(target)
            with self.assertRaises(InvalidIndicator):
                validate_feed(link)

    def test_reject_file_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "large"
            with path.open("wb") as handle:
                handle.truncate(4 * 1024 * 1024 + 1)
            with self.assertRaises(InvalidIndicator):
                validate_feed(path)

    def test_reject_long_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "long"
            path.write_bytes(b"x" * 4097)
            self.assertEqual(validate_feed(path)["invalid_count"], 1)

    def test_cli_exit_codes_and_no_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "feed.jsonl"
            path.write_text('{"type":"domain","value":"example.com"}\n', encoding="utf-8")
            out = io.StringIO()
            with patch("socket.socket", side_effect=AssertionError("network attempted")):
                with contextlib.redirect_stdout(out):
                    self.assertEqual(main([str(path), "--strict"]), 0)
            self.assertEqual(json.loads(out.getvalue())["valid_unique"], 1)
            path.write_text('{"type":"domain","value":"bad"}\n', encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main([str(path), "--strict"]), 1)
                self.assertEqual(main([str(path)]), 0)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(path) + ".missing"]), 2)


if __name__ == "__main__":
    unittest.main()
