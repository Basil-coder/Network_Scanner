import csv
import sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from firewall_rule_audit import analyze, main

HEADER = ['rule_id','enabled','action','direction','protocol','source','destination','port']

def write(tmp_path, rows):
    p=tmp_path/'rules.csv'
    with p.open('w', newline='') as f:
        w=csv.writer(f);w.writerow(HEADER);w.writerows(rows)
    return p

def row(name='r1', enabled='true', action='allow', direction='inbound', protocol='tcp', source='any', destination='192.0.2.0/24', port='22'):
    return [name,enabled,action,direction,protocol,source,destination,port]

def test_exposed_ssh(tmp_path):
    r=analyze(write(tmp_path,[row()]))
    assert r['rules_checked']==1 and r['findings'][0]['severity']=='medium'

def test_unrestricted_rule(tmp_path):
    assert analyze(write(tmp_path,[row(protocol='any',destination='any',port='any')]))['findings'][0]['severity']=='high'

@pytest.mark.parametrize('change', [{'enabled':'false'},{'action':'deny'},{'direction':'outbound'},{'source':'198.51.100.0/24'},{'port':'443'}])
def test_no_findings(tmp_path,change):
    assert analyze(write(tmp_path,[row(**change)]))['findings']==[]

@pytest.mark.parametrize('change', [{'enabled':'maybe'},{'action':'drop'},{'direction':'sideways'},{'protocol':'ftp'},{'source':'not-an-ip'},{'port':'65536'},{'port':'100-20'},{'port':'0'}])
def test_invalid(tmp_path,change):
    with pytest.raises(ValueError): analyze(write(tmp_path,[row(**change)]))

def test_duplicate(tmp_path):
    with pytest.raises(ValueError,match='duplicate'): analyze(write(tmp_path,[row(),row()]))

def test_wrong_header(tmp_path):
    p=tmp_path/'bad.csv';p.write_text('x,y\n1,2\n')
    with pytest.raises(ValueError,match='header'): analyze(p)

def test_extra_columns(tmp_path):
    with pytest.raises(ValueError,match='column count'): analyze(write(tmp_path,[row()+['extra']]))

def test_missing_columns(tmp_path):
    with pytest.raises(ValueError,match='column count'): analyze(write(tmp_path,[row()[:-1]]))

def test_symlink(tmp_path):
    p=write(tmp_path,[row()]);link=tmp_path/'link.csv';link.symlink_to(p)
    with pytest.raises(ValueError,match='non-symlink'): analyze(link)

def test_size_limit(tmp_path):
    p=tmp_path/'large.csv';p.write_bytes(b'x'*2_000_001)
    with pytest.raises(ValueError,match='2 MB'): analyze(p)

def test_cli(tmp_path,capsys):
    p=write(tmp_path,[row()]); assert main([str(p)])==0
    assert 'rules_checked' in capsys.readouterr().out

def test_cli_error(tmp_path,capsys):
    assert main([str(tmp_path/'missing.csv')])==2
    assert 'error:' in capsys.readouterr().err

def test_icmp_port_rejected(tmp_path):
    with pytest.raises(ValueError,match='port must be any'): analyze(write(tmp_path,[row(protocol='icmp',port='22')]))

def test_documentation_ipv6(tmp_path):
    assert analyze(write(tmp_path,[row(source='2001:db8::/32')]))['findings']==[]
