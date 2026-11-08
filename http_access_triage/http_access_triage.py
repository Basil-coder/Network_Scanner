"""Offline, bounded analysis of synthetic or exported HTTP access CSV logs."""
import argparse
import csv
import ipaddress
import json
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

REQUIRED = ('timestamp', 'client_ip', 'method', 'path', 'status')
MAX_BYTES = 8 * 1024 * 1024
MAX_ROWS = 50000
MAX_FIELD = 2048


def parse_time(value):
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError('invalid ISO 8601 timestamp') from exc
    if dt.tzinfo is None:
        raise ValueError('timestamp must include timezone')
    return dt.astimezone(timezone.utc)


def load_events(filename):
    path = Path(filename)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_BYTES:
        raise ValueError('input must be a regular non-symlink CSV <= 8 MiB')
    events = []
    with path.open('r', encoding='utf-8-sig', newline='') as handle:
        reader = csv.DictReader(handle, strict=True)
        if not reader.fieldnames or len(reader.fieldnames) != len(set(reader.fieldnames)) or not set(REQUIRED).issubset(reader.fieldnames):
            raise ValueError('missing or duplicate CSV headers')
        for lineno, row in enumerate(reader, start=2):
            if lineno > MAX_ROWS + 1:
                raise ValueError('too many CSV rows')
            if None in row or any(v is None or len(v) > MAX_FIELD for v in row.values()):
                raise ValueError(f'row {lineno}: malformed or oversized field')
            try:
                dt = parse_time(row['timestamp'])
                ip = str(ipaddress.ip_address(row['client_ip']))
                method = row['method'].upper()
                if method not in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'):
                    raise ValueError('unsupported method')
                status = int(row['status'])
                if str(status) != row['status'] or not 100 <= status <= 599:
                    raise ValueError('invalid HTTP status')
                route = row['path']
                if not route.startswith('/') or any(ord(ch) < 32 or ord(ch) == 127 for ch in route):
                    raise ValueError('invalid path')
            except (ValueError, TypeError) as exc:
                raise ValueError(f'row {lineno}: {exc}') from exc
            events.append((dt, ip, method, route.split('?', 1)[0], status))
    return sorted(events)


def analyze(events, *, threshold=5, window_seconds=300):
    if threshold < 2 or not 1 <= window_seconds <= 86400:
        raise ValueError('invalid threshold or window')
    windows = defaultdict(deque)
    alerts = []
    # Only one alert per (IP, signal) per rolling burst, to avoid noisy duplicates.
    active = set()
    for timestamp, ip, method, path, status in events:
        for key in tuple(active):
            queue = windows[key]
            while queue and (timestamp - queue[0]).total_seconds() > window_seconds:
                queue.popleft()
            if not queue:
                active.remove(key)
        signals = []
        if status in (401, 403) and path.lower() in ('/login', '/signin', '/api/login'):
            signals.append('authentication_failures')
        if status >= 500:
            signals.append('server_error_burst')
        for signal in signals:
            key = (ip, signal)
            queue = windows[key]
            while queue and (timestamp - queue[0]).total_seconds() > window_seconds:
                queue.popleft()
            queue.append(timestamp)
            if len(queue) >= threshold and key not in active:
                alerts.append({'signal': signal, 'client_ip': ip, 'count': len(queue), 'window_seconds': window_seconds, 'last_seen_utc': timestamp.isoformat()})
                active.add(key)
    return {'events_processed': len(events), 'alerts': alerts, 'note': 'Heuristic triage only; alerts do not establish malicious intent.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('csv_file')
    parser.add_argument('--threshold', type=int, default=5)
    parser.add_argument('--window-seconds', type=int, default=300)
    args = parser.parse_args(argv)
    try:
        result = analyze(load_events(args.csv_file), threshold=args.threshold, window_seconds=args.window_seconds)
    except (ValueError, OSError, UnicodeError, csv.Error) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
