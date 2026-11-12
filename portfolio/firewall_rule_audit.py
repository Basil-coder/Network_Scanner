"""Offline review of synthetic/exported firewall rule inventories; no network calls."""
import argparse
import csv
import ipaddress
import json
import sys
from pathlib import Path

FIELDS = ('rule_id', 'enabled', 'action', 'direction', 'protocol', 'source', 'destination', 'port')
MAX_BYTES = 2_000_000
MAX_ROWS = 10000


def parse_bool(value):
    if value.lower() in ('true', 'yes', '1'): return True
    if value.lower() in ('false', 'no', '0'): return False
    raise ValueError('enabled must be true/false, yes/no, or 1/0')


def parse_network(value):
    if value.lower() == 'any': return 'any'
    return str(ipaddress.ip_network(value, strict=False))


def parse_port(value, protocol):
    if protocol in ('icmp', 'any'):
        if value.lower() != 'any': raise ValueError('port must be any for ICMP/any protocol')
        return 'any'
    if value.lower() == 'any': return 'any'
    parts = value.split('-')
    if len(parts) not in (1, 2) or not all(p.isascii() and p.isdecimal() for p in parts):
        raise ValueError('port must be any, integer or inclusive range')
    nums = [int(p) for p in parts]
    if any(n < 1 or n > 65535 for n in nums) or nums != sorted(nums):
        raise ValueError('port outside 1-65535 or reversed range')
    return '-'.join(str(n) for n in nums)


def analyze(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_BYTES:
        raise ValueError('input must be a regular non-symlink CSV of at most 2 MB')
    findings, ids, count = [], set(), 0
    with p.open(encoding='utf-8-sig', newline='') as stream:
        reader = csv.DictReader(stream, strict=True)
        if reader.fieldnames is None or tuple(reader.fieldnames) != FIELDS:
            raise ValueError('CSV header must match: ' + ','.join(FIELDS))
        for line, row in enumerate(reader, start=2):
            count += 1
            if count > MAX_ROWS: raise ValueError('too many rows')
            if None in row or any(v is None for v in row.values()):
                raise ValueError(f'row {line}: incorrect column count')
            try:
                rid = row['rule_id'].strip()
                if not rid or len(rid) > 100 or rid in ids: raise ValueError('empty, oversized, or duplicate rule_id')
                ids.add(rid)
                enabled = parse_bool(row['enabled'].strip())
                action = row['action'].strip().lower()
                direction = row['direction'].strip().lower()
                protocol = row['protocol'].strip().lower()
                if action not in ('allow', 'deny') or direction not in ('inbound', 'outbound') or protocol not in ('tcp', 'udp', 'icmp', 'any'):
                    raise ValueError('unsupported action, direction or protocol')
                source = parse_network(row['source'].strip())
                destination = parse_network(row['destination'].strip())
                port = parse_port(row['port'].strip(), protocol)
            except ValueError as exc:
                raise ValueError(f'row {line}: {exc}') from exc
            if not enabled or action != 'allow' or direction != 'inbound': continue
            if source == 'any' and destination == 'any' and protocol == 'any':
                findings.append({'rule_id': rid, 'severity': 'high', 'reason': 'unrestricted inbound allow rule'})
            elif source == 'any' and protocol == 'tcp' and (port == 'any' or port in ('22', '3389', '445')):
                findings.append({'rule_id': rid, 'severity': 'medium', 'reason': 'broad inbound TCP access; review exposure and business need'})
    return {'rules_checked': count, 'findings': findings, 'note': 'Heuristic review of supplied inventory only; not proof of exposure or exploitability.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('csv_path')
    parser.add_argument('--output', help='Optional JSON report path')
    args = parser.parse_args(argv)
    try:
        report = analyze(args.csv_path)
        payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
        if args.output:
            Path(args.output).write_text(payload, encoding='utf-8')
        else:
            print(payload, end='')
    except (ValueError, OSError, UnicodeError, csv.Error) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
