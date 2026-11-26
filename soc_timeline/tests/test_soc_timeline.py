import csv
import tempfile
import unittest
from pathlib import Path
from soc_timeline import read_events, report, parse_time

FIELDS=['event_id','timestamp','source','event_type','ip','asset']

def row(eid, time, kind='login_failure', source='auth', ip='192.0.2.8', asset='lab-host'):
    return dict(zip(FIELDS,[eid,time,source,kind,ip,asset]))

class TriageTests(unittest.TestCase):
    def load(self, rows, fields=FIELDS):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'events.csv'
            with p.open('w',newline='') as f:
                writer=csv.DictWriter(f,fieldnames=fields)
                writer.writeheader()
                writer.writerows(rows)
            return read_events(p)

    def test_correlation(self):
        rows=[row(str(i),f'2026-11-18T10:0{i}:00Z') for i in range(3)]
        rows.append(row('success','2026-11-18T10:04:00Z','login_success'))
        out=report(self.load(rows))
        self.assertEqual(len(out['findings']),1)
        self.assertEqual(out['findings'][0]['event_ids'],['0','1','2','success'])
    def test_outside_window(self):
        rows=[row(str(i),f'2026-11-18T10:0{i}:00Z') for i in range(3)]
        rows.append(row('s','2026-11-18T11:00:00Z','login_success'))
        self.assertFalse(report(self.load(rows))['findings'])
    def test_distinct_asset(self):
        rows=[row(str(i),f'2026-11-18T10:0{i}:00Z') for i in range(3)]
        rows.append(row('s','2026-11-18T10:04:00Z','login_success',asset='other'))
        self.assertFalse(report(self.load(rows))['findings'])
    def test_naive_timestamp_rejected(self):
        with self.assertRaisesRegex(ValueError,'offset'):
            parse_time('2026-11-18T10:00:00')
    def test_duplicate_id_rejected(self):
        with self.assertRaisesRegex(ValueError,'duplicate'):
            self.load([row('a','2026-11-18T10:00:00Z'),row('a','2026-11-18T10:01:00Z')])
    def test_invalid_ip_rejected(self):
        with self.assertRaisesRegex(ValueError,'line 2'):
            self.load([row('a','2026-11-18T10:00:00Z',ip='not-an-ip')])
    def test_invalid_source_pair(self):
        with self.assertRaisesRegex(ValueError,'combination'):
            self.load([row('a','2026-11-18T10:00:00Z',source='firewall')])
    def test_timezone_normalization(self):
        self.assertEqual(parse_time('2026-11-18T12:00:00+02:00').isoformat(),'2026-11-18T10:00:00+00:00')
    def test_empty_csv(self):
        self.assertEqual(report(self.load([]))['event_count'],0)
    def test_invalid_threshold(self):
        with self.assertRaises(ValueError):report([],failure_threshold=1)
    def test_deterministic_sort(self):
        rows=[row('b','2026-11-18T10:00:00Z'),row('a','2026-11-18T10:00:00Z')]
        self.assertEqual([e['event_id'] for e in self.load(rows)],['a','b'])
    def test_missing_header(self):
        with self.assertRaisesRegex(ValueError,'exactly'):
            self.load([],FIELDS[:-1])

    def test_success_resets_subthreshold_failures(self):
        rows=[row('a','2026-11-18T10:00:00Z'),row('b','2026-11-18T10:01:00Z'),row('c','2026-11-18T10:02:00Z','login_success'),row('d','2026-11-18T10:03:00Z'),row('e','2026-11-18T10:04:00Z','login_success')]
        self.assertFalse(report(self.load(rows))['findings'])

    def test_equal_timestamp_is_not_precedence(self):
        rows=[row(str(i),'2026-11-18T10:00:00Z') for i in range(3)]
        rows.append(row('s','2026-11-18T10:00:00Z','login_success'))
        self.assertFalse(report(self.load(rows))['findings'])

    def test_window_boundary_inclusive(self):
        rows=[row(str(i),f'2026-11-18T10:0{i}:00Z') for i in range(3)]
        rows.append(row('s','2026-11-18T10:10:00Z','login_success'))
        self.assertEqual(len(report(self.load(rows))['findings']),1)

if __name__=='__main__': unittest.main()
