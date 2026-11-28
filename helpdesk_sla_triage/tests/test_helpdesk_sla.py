import csv
import datetime as dt
import tempfile
import unittest
from pathlib import Path
from helpdesk_sla import InputError, audit, parse_time

NOW = parse_time('2026-11-14T12:00:00Z')
HEAD = ['ticket_id', 'opened_at', 'priority', 'status', 'updated_at']


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'tickets.csv'

    def write(self, rows, header=HEAD):
        with self.path.open('w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(header)
            writer.writerows(rows)

    def row(self, ticket='T-1', opened='2026-11-14T06:00:00Z', priority='P1', status='open', updated='2026-11-14T07:00:00Z'):
        return [ticket, opened, priority, status, updated]

    def test_overdue(self):
        self.write([self.row()])
        r = audit(self.path, NOW)
        self.assertEqual(r['findings'][0]['classification'], 'overdue')
        self.assertEqual(r['findings'][0]['age_hours'], 6)

    def test_approaching(self):
        self.write([self.row(opened='2026-11-14T08:30:00Z', updated='2026-11-14T08:31:00Z')])
        self.assertEqual(audit(self.path, NOW)['findings'][0]['classification'], 'approaching')

    def test_healthy(self):
        self.write([self.row(opened='2026-11-14T11:00:00Z', updated='2026-11-14T11:00:00Z')])
        self.assertEqual(audit(self.path, NOW)['findings'], [])

    def test_closed_excluded(self):
        self.write([self.row(status='closed')])
        self.assertEqual(audit(self.path, NOW)['findings'], [])

    def test_duplicate_id(self):
        self.write([self.row(), self.row()])
        with self.assertRaises(InputError): audit(self.path, NOW)

    def test_invalid_id(self):
        self.write([self.row(ticket='a@b')])
        with self.assertRaises(InputError): audit(self.path, NOW)

    def test_future_open(self):
        self.write([self.row(opened='2026-11-15T00:00:00Z', updated='2026-11-15T00:00:00Z')])
        with self.assertRaises(InputError): audit(self.path, NOW)

    def test_update_before_open(self):
        self.write([self.row(updated='2026-11-14T05:00:00Z')])
        with self.assertRaises(InputError): audit(self.path, NOW)

    def test_naive_timestamp(self):
        with self.assertRaises(InputError): parse_time('2026-11-14T12:00:00')

    def test_bad_priority(self):
        self.write([self.row(priority='P9')])
        with self.assertRaises(InputError): audit(self.path, NOW)

    def test_bad_status(self):
        self.write([self.row(status='unknown')])
        with self.assertRaises(InputError): audit(self.path, NOW)

    def test_bad_header(self):
        self.write([self.row()], header=['name'] + HEAD[1:])
        with self.assertRaises(InputError): audit(self.path, NOW)

    def test_extra_column(self):
        self.write([self.row() + ['extra']])
        with self.assertRaises(InputError): audit(self.path, NOW)

    def test_missing_column(self):
        self.write([self.row()[:-1]])
        with self.assertRaises(InputError): audit(self.path, NOW)

    def test_empty_file(self):
        self.path.write_text('')
        with self.assertRaises(InputError): audit(self.path, NOW)

    def test_symlink_rejected(self):
        self.write([self.row()])
        link = Path(self.temp.name) / 'link.csv'
        link.symlink_to(self.path)
        with self.assertRaises(InputError): audit(link, NOW)

    def test_limit(self):
        self.path.write_bytes(b'x' * 2_000_001)
        with self.assertRaises(InputError): audit(self.path, NOW)

    def test_timezone_conversion(self):
        self.assertEqual(parse_time('2026-11-14T14:00:00+02:00'), NOW)

    def test_invalid_utf8(self):
        self.path.write_bytes(b'\xff')
        with self.assertRaises(InputError): audit(self.path, NOW)

    def test_order(self):
        self.write([self.row(ticket='T-2', priority='P2', opened='2026-11-14T02:00:00Z'), self.row(ticket='T-1')])
        self.assertEqual([x['ticket_id'] for x in audit(self.path, NOW)['findings']], ['T-1', 'T-2'])


if __name__ == '__main__': unittest.main()
