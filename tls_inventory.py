"""Offline TLS certificate expiry inventory; never opens a network connection."""
import argparse
import csv
import ipaddress
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

HOST_RE = re.compile(r"(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\Z")
FIELDS = {"hostname", "port", "not_after_utc", "issuer"}
MAX_BYTES = 2_000_000
MAX_ROWS = 10_000


def parse_time(value):
    if not value.endswith('Z'):
        raise ValueError('timestamp must end in Z (UTC)')
    try:
        dt = datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError as exc:
        raise ValueError('invalid ISO 8601 UTC timestamp') from exc
    return dt


def validate_host(value):
    if not value or value != value.strip():
        raise ValueError('invalid hostname')
    try:
        ipaddress.ip_address(value)
        return value.lower()
    except ValueError:
        pass
    if not HOST_RE.fullmatch(value) or any(label.startswith('xn--') and len(label) <= 4 for label in value.split('.')):
        raise ValueError('invalid hostname')
    return value.lower()


def analyze(path, now, warn_days=30):
    if warn_days < 0 or warn_days > 3650:
        raise ValueError('warn-days must be 0..3650')
    p = Path(path)
    if not p.is_file() or p.is_symlink() or p.stat().st_size > MAX_BYTES:
        raise ValueError('input must be a regular non-symlink CSV <= 2 MB')
    results = []
    seen = set()
    with p.open('r', newline='', encoding='utf-8-sig') as fh:
        reader = csv.DictReader(fh, strict=True)
        if reader.fieldnames is None or set(reader.fieldnames) != FIELDS:
            raise ValueError('CSV headers must be hostname,port,not_after_utc,issuer')
        for line, row in enumerate(reader, start=2):
            if line > MAX_ROWS + 1:
                raise ValueError('too many rows')
            if None in row or any(v is None for v in row.values()):
                raise ValueError(f'row {line}: malformed CSV')
            try:
                host = validate_host(row['hostname'])
                port = int(row['port'])
                if not 1 <= port <= 65535 or str(port) != row['port']:
                    raise ValueError('invalid port')
                expiry = parse_time(row['not_after_utc'])
                issuer = row['issuer']
                if not issuer or len(issuer) > 200 or any(ord(c) < 32 for c in issuer):
                    raise ValueError('invalid issuer')
                key = (host, port)
                if key in seen:
                    raise ValueError('duplicate host and port')
                seen.add(key)
                remaining = (expiry - now).total_seconds() / 86400
                status = 'expired' if remaining < 0 else 'expiring' if remaining <= warn_days else 'ok'
                results.append({'hostname': host, 'port': port, 'not_after_utc': expiry.isoformat().replace('+00:00', 'Z'), 'issuer': issuer, 'days_remaining': round(remaining, 2), 'status': status})
            except ValueError as exc:
                raise ValueError(f'row {line}: {exc}') from exc
    return {'as_of_utc': now.isoformat().replace('+00:00', 'Z'), 'warning_days': warn_days, 'total': len(results), 'counts': {s: sum(r['status'] == s for r in results) for s in ('expired','expiring','ok')}, 'certificates': sorted(results, key=lambda r: (r['days_remaining'],r['hostname'],r['port']))}


def main(argv=None):
    parser = argparse.ArgumentParser(description='Analyze saved TLS expiry inventory CSV (no network)')
    parser.add_argument('csv_file')
    parser.add_argument('--warn-days', type=int, default=30)
    parser.add_argument('--as-of', help='UTC timestamp ending Z; defaults to current UTC')
    args = parser.parse_args(argv)
    try:
        now = parse_time(args.as_of) if args.as_of else datetime.now(timezone.utc)
        result = analyze(args.csv_file, now, args.warn_days)
    except (ValueError, OSError, csv.Error, UnicodeError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
