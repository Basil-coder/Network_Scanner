"""Offline, deterministic correlation of sanitized SOC event exports."""
import argparse
import csv
import datetime as dt
import ipaddress
import json
from collections import defaultdict, deque
from itertools import groupby
from pathlib import Path

FIELDS = {'event_id', 'timestamp', 'source', 'event_type', 'ip', 'asset'}
ALLOWED_SOURCES = {'auth', 'firewall', 'integrity'}
ALLOWED_TYPES = {'login_failure', 'login_success', 'blocked_connection', 'file_changed'}
MAX_ROWS = 10000


def parse_time(value):
    value = value.strip()
    parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError('timestamp requires explicit UTC offset')
    return parsed.astimezone(dt.timezone.utc)


def read_events(path):
    events, seen = [], set()
    with open(path, newline='', encoding='utf-8-sig') as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None or set(reader.fieldnames) != FIELDS or len(reader.fieldnames) != len(FIELDS):
            raise ValueError('CSV must contain exactly: ' + ', '.join(sorted(FIELDS)))
        for line, row in enumerate(reader, start=2):
            if len(events) >= MAX_ROWS:
                raise ValueError('row limit exceeded')
            try:
                if None in row or any(v is None for v in row.values()):
                    raise ValueError('malformed CSV record')
                eid = row['event_id'].strip()
                if not eid or eid in seen or len(eid) > 64:
                    raise ValueError('empty, duplicate or oversized event_id')
                source, kind = row['source'].strip(), row['event_type'].strip()
                if source not in ALLOWED_SOURCES or kind not in ALLOWED_TYPES:
                    raise ValueError('unknown source or event type')
                if (source, kind) not in {('auth','login_failure'), ('auth','login_success'), ('firewall','blocked_connection'), ('integrity','file_changed')}:
                    raise ValueError('invalid source/event combination')
                ip = str(ipaddress.ip_address(row['ip'].strip())) if row['ip'].strip() else ''
                asset = row['asset'].strip()
                if not asset or len(asset) > 128 or any(ord(c) < 32 for c in asset):
                    raise ValueError('invalid asset')
                event = {'event_id':eid, 'timestamp':parse_time(row['timestamp']), 'source':source, 'event_type':kind, 'ip':ip, 'asset':asset}
                events.append(event)
                seen.add(eid)
            except (ValueError, TypeError) as exc:
                raise ValueError(f'CSV line {line}: {exc}') from exc
    return sorted(events, key=lambda e: (e['timestamp'], e['event_id']))


def analyze(events, window_minutes=10, failure_threshold=3):
    if not 1 <= window_minutes <= 1440 or not 2 <= failure_threshold <= 100:
        raise ValueError('invalid correlation thresholds')
    findings = []
    by_asset_ip = defaultdict(list)
    for event in events:
        if event['ip'] and event['event_type'] in ('login_failure', 'login_success'):
            by_asset_ip[(event['asset'], event['ip'])].append(event)
    for (asset, ip), group in sorted(by_asset_ip.items()):
        failures = deque()
        for timestamp, batch in groupby(group, key=lambda e: e['timestamp']):
            batch = list(batch)
            cutoff = timestamp - dt.timedelta(minutes=window_minutes)
            while failures and failures[0]['timestamp'] < cutoff:
                failures.popleft()
            successes = [e for e in batch if e['event_type'] == 'login_success']
            if successes:
                if len(failures) >= failure_threshold:
                    event = successes[0]
                    findings.append({'rule':'failures_followed_by_success', 'severity':'medium', 'asset':asset, 'ip':ip,
                                     'event_ids':[f['event_id'] for f in failures] + [event['event_id']],
                                     'observed_at':timestamp.isoformat(),
                                     'explanation':'Multiple authentication failures preceded a success from the same IP and asset within the window; investigate, not proof of compromise.'})
                failures.clear()
            else:
                failures.extend(batch)
    return sorted(findings, key=lambda f:(f['observed_at'],f['asset'],f['ip']))


def report(events, window_minutes=10, failure_threshold=3):
    timeline = [{**e, 'timestamp':e['timestamp'].isoformat()} for e in events]
    return {'schema_version':1, 'event_count':len(events), 'timeline':timeline,
            'findings':analyze(events, window_minutes, failure_threshold),
            'limitations':['Offline user-supplied data only; timestamps and source labels are not independently verified.',
                           'Correlation does not establish identity, malicious intent or compromise.',
                           'No geolocation, network requests or automatic containment.']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('csv_file', type=Path)
    parser.add_argument('--window-minutes', type=int, default=10)
    parser.add_argument('--failure-threshold', type=int, default=3)
    args=parser.parse_args()
    try:
        result=report(read_events(args.csv_file),args.window_minutes,args.failure_threshold)
    except (ValueError,OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
