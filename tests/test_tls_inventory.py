import csv
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from tls_inventory import analyze, parse_time, validate_host

NOW = datetime(2026, 11, 10, tzinfo=timezone.utc)


def sample(tmp_path, rows, header=('hostname','port','not_after_utc','issuer')):
    p = tmp_path / 'certs.csv'
    with p.open('w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)
    return p


def test_statuses_and_sort(tmp_path):
    p = sample(tmp_path, [
        ('a.example','443','2026-11-09T00:00:00Z','CA'),
        ('b.example','443','2026-11-25T00:00:00Z','CA'),
        ('c.example','443','2027-01-01T00:00:00Z','CA')])
    r = analyze(p, NOW)
    assert r['counts'] == {'expired':1,'expiring':1,'ok':1}
    assert [x['status'] for x in r['certificates']] == ['expired','expiring','ok']


def test_exact_boundary(tmp_path):
    p = sample(tmp_path, [('a.example','443','2026-12-10T00:00:00Z','CA')])
    assert analyze(p, NOW)['counts']['expiring'] == 1


def test_duplicate_normalized_host(tmp_path):
    p = sample(tmp_path, [('A.Example','443','2026-12-10T00:00:00Z','CA'),('a.example','443','2026-12-11T00:00:00Z','CA')])
    with pytest.raises(ValueError, match='duplicate'):
        analyze(p, NOW)

@pytest.mark.parametrize('port', ['0','65536','-1','443.0',' 443'])
def test_bad_ports(tmp_path, port):
    with pytest.raises(ValueError):
        analyze(sample(tmp_path, [('a.example',port,'2026-12-10T00:00:00Z','CA')]), NOW)

@pytest.mark.parametrize('host', ['bad_host','-abc.example','abc..example','', 'a'*64+'.example'])
def test_bad_hosts(host):
    with pytest.raises(ValueError):
        validate_host(host)


def test_ipv6():
    assert validate_host('2001:db8::1') == '2001:db8::1'

@pytest.mark.parametrize('value', ['2026-11-10','2026-11-10T00:00:00+02:00','nonsense'])
def test_bad_timestamp(value):
    with pytest.raises(ValueError):
        parse_time(value)


def test_bad_header(tmp_path):
    with pytest.raises(ValueError, match='headers'):
        analyze(sample(tmp_path, [], header=('hostname','port')), NOW)


def test_bad_csv_row(tmp_path):
    with pytest.raises(ValueError, match='malformed'):
        analyze(sample(tmp_path, [('a.example','443','2026-12-10T00:00:00Z','CA','extra')]), NOW)


def test_symlink_rejected(tmp_path):
    p = sample(tmp_path, [])
    link = tmp_path / 'link.csv'
    link.symlink_to(p)
    with pytest.raises(ValueError, match='non-symlink'):
        analyze(link, NOW)


def test_cli_json(tmp_path):
    p = sample(tmp_path, [('example.test','443','2026-11-11T00:00:00Z','Synthetic CA')])
    script = Path(__file__).resolve().parents[1] / 'tls_inventory.py'
    proc = subprocess.run([sys.executable, str(script), str(p), '--as-of', '2026-11-10T00:00:00Z'],capture_output=True,text=True)
    assert proc.returncode == 0
    assert json.loads(proc.stdout)['counts']['expiring'] == 1


def test_cli_invalid(tmp_path):
    script = Path(__file__).resolve().parents[1] / 'tls_inventory.py'
    proc = subprocess.run([sys.executable, str(script), str(tmp_path/'missing.csv')],capture_output=True,text=True)
    assert proc.returncode == 2
