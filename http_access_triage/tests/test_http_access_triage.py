import csv
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timedelta, timezone
from http_access_triage import load_events, analyze, parse_time


class HttpTriageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.file = Path(self.tmp.name) / 'events.csv'

    def write(self, rows, headers=('timestamp','client_ip','method','path','status')):
        with self.file.open('w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        return self.file

    def row(self, n=0, ip='192.0.2.5', path='/login', status='401'):
        return [(datetime(2026,1,1,tzinfo=timezone.utc)+timedelta(seconds=n)).isoformat(),ip,'POST',path,status]

    def test_login_failures_trigger(self):
        result=analyze(load_events(self.write([self.row(i) for i in range(5)])))
        self.assertEqual(result['alerts'][0]['signal'], 'authentication_failures')
        self.assertEqual(len(result['alerts']), 1)

    def test_server_errors_trigger(self):
        result=analyze(load_events(self.write([self.row(i,path='/health',status='503') for i in range(5)])))
        self.assertEqual(result['alerts'][0]['signal'], 'server_error_burst')

    def test_non_login_401_ignored(self):
        self.assertEqual(analyze(load_events(self.write([self.row(i,path='/profile') for i in range(5)])))['alerts'], [])

    def test_separate_ips(self):
        rows=[self.row(i,ip='192.0.2.1') for i in range(3)]+[self.row(i,ip='192.0.2.2') for i in range(3)]
        self.assertEqual(analyze(load_events(self.write(rows)))['alerts'], [])

    def test_time_window(self):
        self.assertEqual(analyze(load_events(self.write([self.row(i*301) for i in range(5)])))['alerts'], [])

    def test_reject_missing_header(self):
        with self.assertRaisesRegex(ValueError, 'headers'):
            load_events(self.write([],headers=('timestamp',)))

    def test_reject_duplicate_header(self):
        with self.assertRaisesRegex(ValueError, 'headers'):
            load_events(self.write([],headers=('timestamp','client_ip','method','path','status','status')))

    def test_reject_invalid_ip(self):
        with self.assertRaisesRegex(ValueError, 'row 2'):
            load_events(self.write([self.row(ip='bad')]))

    def test_reject_bad_status(self):
        with self.assertRaises(ValueError):
            load_events(self.write([self.row(status='999')]))

    def test_reject_naive_timestamp(self):
        with self.assertRaisesRegex(ValueError, 'timezone'):
            parse_time('2026-01-01T00:00:00')

    def test_reject_control_char_path(self):
        with self.assertRaises(ValueError):
            load_events(self.write([self.row(path='/log\nin')]))

    def test_reject_symlink(self):
        other=Path(self.tmp.name)/'link.csv'
        self.write([self.row()]); other.symlink_to(self.file)
        with self.assertRaises(ValueError): load_events(other)

    def test_reject_bad_threshold(self):
        with self.assertRaises(ValueError): analyze([],threshold=1)

    def test_query_string_not_retained(self):
        events=load_events(self.write([self.row(path='/login?token=secret')]))
        self.assertEqual(events[0][3], '/login')

    def test_unsorted_rows(self):
        rows=[self.row(i) for i in (4,2,3,1,0)]
        self.assertEqual(len(analyze(load_events(self.write(rows)))['alerts']),1)

    def test_rearm_after_window(self):
        rows=[self.row(i) for i in range(5)]+[self.row(400+i) for i in range(5)]
        self.assertEqual(len(analyze(load_events(self.write(rows)))['alerts']),2)


if __name__ == '__main__': unittest.main()
