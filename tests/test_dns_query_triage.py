import csv
import tempfile
import unittest
from pathlib import Path

from dns_query_triage import InputError, analyze, normalize_domain, main


class DnsTriageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'queries.csv'

    def write(self, rows):
        with self.path.open('w', newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(['client_ip', 'query'])
            w.writerows(rows)

    def test_normalize(self):
        self.assertEqual(normalize_domain(' WWW.Example.COM. '), 'www.example.com')

    def test_reject_malformed_domains(self):
        for value in ['x', 'a..example.com', '-x.example.com', 'a_example.com', 'x.example.com/path']:
            with self.subTest(value=value), self.assertRaises(InputError):
                normalize_domain(value)

    def test_empty(self):
        self.write([])
        self.assertEqual(analyze(self.path)['alerts'], [])

    def test_volume(self):
        self.write([('192.0.2.10', 'www.example.com')] * 3)
        report = analyze(self.path, threshold=3)
        self.assertEqual(report['alerts'][0]['count'], 3)
        self.assertEqual(report['rows'], 3)

    def test_subdomains(self):
        self.write([('192.0.2.10', f'part{i}.example.com') for i in range(4)])
        alerts = analyze(self.path, threshold=10, min_unique=4)['alerts']
        self.assertEqual(alerts[0]['unique_count'], 4)

    def test_duplicate_subdomain_not_counted_twice(self):
        self.write([('192.0.2.10', 'a.example.com')] * 4)
        self.assertEqual(analyze(self.path, threshold=10, min_unique=2)['alerts'], [])

    def test_client_isolation(self):
        self.write([('192.0.2.1', 'a.example.com'), ('192.0.2.2', 'b.example.com')])
        self.assertEqual(analyze(self.path, threshold=2, min_unique=2)['alerts'], [])

    def test_ipv6(self):
        self.write([('2001:db8::1', 'example.org')] * 2)
        self.assertEqual(analyze(self.path, threshold=2)['alerts'][0]['client_ip'], '2001:db8::1')

    def test_invalid_ip(self):
        self.write([('999.0.0.1', 'example.org')])
        with self.assertRaises(InputError):
            analyze(self.path)

    def test_bad_header(self):
        self.path.write_text('ip,query\n192.0.2.1,example.com\n')
        with self.assertRaises(InputError):
            analyze(self.path)

    def test_extra_column(self):
        self.path.write_text('client_ip,query\n192.0.2.1,example.com,extra\n')
        with self.assertRaises(InputError):
            analyze(self.path)

    def test_bad_thresholds(self):
        self.write([])
        with self.assertRaises(InputError):
            analyze(self.path, threshold=0)
        with self.assertRaises(InputError):
            analyze(self.path, min_unique=1)

    def test_size_limit(self):
        self.path.write_bytes(b'a' * 5_000_001)
        with self.assertRaises(InputError):
            analyze(self.path)

    def test_missing_file_exit(self):
        self.assertEqual(main([str(self.path)]), 2)

    def test_output(self):
        self.write([('192.0.2.10', 'example.org')])
        out = Path(self.tmp.name) / 'report.json'
        self.assertEqual(main([str(self.path), '--output', str(out)]), 0)
        self.assertIn('"rows": 1', out.read_text())


if __name__ == '__main__':
    unittest.main()
