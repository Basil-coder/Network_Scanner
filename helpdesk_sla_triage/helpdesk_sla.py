"""Offline, privacy-conscious helpdesk ticket SLA triage. Standard library only."""
import argparse
import csv
import datetime as dt
import json
import re
from pathlib import Path

UTC = dt.timezone.utc
FIELDS = {'ticket_id', 'opened_at', 'priority', 'status', 'updated_at'}
PRIORITY_HOURS = {'P1': 4, 'P2': 8, 'P3': 24, 'P4': 72}
STATUSES = {'open', 'in_progress', 'resolved', 'closed'}
MAX_BYTES = 2_000_000
MAX_ROWS = 10_000
ID_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z')


class InputError(ValueError):
    """Invalid ticket export."""


def parse_time(value):
    try:
        value = value.strip()
        if value.endswith('Z'):
            value = value[:-1] + '+00:00'
        result = dt.datetime.fromisoformat(value)
        if result.tzinfo is None or result.utcoffset() is None:
            raise ValueError('timezone required')
        return result.astimezone(UTC)
    except (ValueError, AttributeError) as exc:
        raise InputError('invalid timezone-aware ISO-8601 timestamp') from exc


def audit(path, now, thresholds=None):
    thresholds = thresholds or PRIORITY_HOURS
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_BYTES:
        raise InputError('input must be a regular non-symlink CSV at most 2 MB')
    findings = []
    seen = set()
    count = 0
    try:
        with path.open('r', encoding='utf-8-sig', newline='') as stream:
            reader = csv.DictReader(stream, strict=True)
            if reader.fieldnames is None or len(reader.fieldnames) != len(set(reader.fieldnames)) or set(reader.fieldnames) != FIELDS:
                raise InputError('CSV headers must be exactly: ' + ', '.join(sorted(FIELDS)))
            for line, row in enumerate(reader, 2):
                count += 1
                if count > MAX_ROWS:
                    raise InputError('too many rows')
                if None in row or any(v is None for v in row.values()):
                    raise InputError(f'row {line}: wrong column count')
                ticket = row['ticket_id'].strip()
                if not ID_RE.fullmatch(ticket) or ticket in seen:
                    raise InputError(f'row {line}: invalid or duplicate ticket ID')
                seen.add(ticket)
                priority = row['priority'].strip().upper()
                status = row['status'].strip().lower()
                if priority not in thresholds or status not in STATUSES:
                    raise InputError(f'row {line}: invalid priority or status')
                opened = parse_time(row['opened_at'])
                updated = parse_time(row['updated_at'])
                if updated < opened or opened > now or updated > now:
                    raise InputError(f'row {line}: inconsistent timestamps')
                if status in ('resolved', 'closed'):
                    continue
                age = (now - opened).total_seconds() / 3600
                limit = thresholds[priority]
                if age >= limit:
                    findings.append({'ticket_id': ticket, 'priority': priority, 'status': status,
                                     'age_hours': round(age, 2), 'threshold_hours': limit,
                                     'classification': 'overdue'})
                elif age >= 0.8 * limit:
                    findings.append({'ticket_id': ticket, 'priority': priority, 'status': status,
                                     'age_hours': round(age, 2), 'threshold_hours': limit,
                                     'classification': 'approaching'})
    except (UnicodeError, csv.Error) as exc:
        raise InputError('invalid UTF-8 or CSV data') from exc
    findings.sort(key=lambda x: (x['classification'] != 'overdue', PRIORITY_HOURS[x['priority']], x['ticket_id']))
    return {'schema_version': 1, 'evaluated_at': now.isoformat().replace('+00:00', 'Z'),
            'tickets_read': count, 'findings': findings,
            'note': 'Elapsed wall-clock time, not contractual business-hours SLA; no customer details processed.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('csv_file', help='local CSV export containing only approved non-PII fields')
    parser.add_argument('--now', required=True, help='timezone-aware ISO-8601 evaluation time, for reproducibility')
    parser.add_argument('--output', help='optional JSON report path; defaults to stdout')
    args = parser.parse_args(argv)
    try:
        report = audit(args.csv_file, parse_time(args.now))
        data = json.dumps(report, indent=2) + '\n'
        if args.output:
            Path(args.output).write_text(data, encoding='utf-8')
        else:
            print(data, end='')
    except (InputError, OSError) as exc:
        parser.exit(2, f'error: {exc}\n')


if __name__ == '__main__':
    main()
