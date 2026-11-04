#!/usr/bin/env python3
"""Offline DNS query CSV triage. No network access or DNS resolution."""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

MAX_BYTES = 5_000_000
MAX_ROWS = 50_000
DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z", re.ASCII)


class InputError(ValueError):
    pass


def normalize_domain(raw: str) -> str:
    name = raw.strip().lower().rstrip('.')
    if not DOMAIN.fullmatch(name):
        raise InputError("invalid ASCII DNS domain")
    return name


def analyze(path: Path, *, threshold: int = 10, min_unique: int = 8) -> dict:
    """Flag high-volume queries and many unique subdomains per base domain.

    The base-domain heuristic uses the last two labels and is NOT public-suffix
    aware; findings are triage leads, not proof of DNS tunneling.
    """
    if threshold < 1 or min_unique < 2:
        raise InputError("threshold must be >=1 and min-unique >=2")
    try:
        if path.stat().st_size > MAX_BYTES:
            raise InputError("CSV exceeds 5 MB limit")
        with path.open('r', encoding='utf-8-sig', newline='') as stream:
            reader = csv.DictReader(stream, strict=True)
            if not reader.fieldnames or set(reader.fieldnames) != {'client_ip', 'query'} or len(reader.fieldnames) != 2:
                raise InputError("CSV header must be client_ip,query")
            counts = Counter()
            subdomains = defaultdict(set)
            rows = 0
            for line, row in enumerate(reader, start=2):
                rows += 1
                if rows > MAX_ROWS:
                    raise InputError("CSV exceeds 50,000 rows")
                if None in row or any(value is None for value in row.values()):
                    raise InputError(f"row {line}: malformed CSV")
                try:
                    ip = str(ipaddress.ip_address(row['client_ip'].strip()))
                    domain = normalize_domain(row['query'])
                except (ValueError, AttributeError) as exc:
                    raise InputError(f"row {line}: invalid IP or domain") from exc
                counts[(ip, domain)] += 1
                labels = domain.split('.')
                if len(labels) > 2:
                    subdomains[(ip, '.'.join(labels[-2:]))].add(domain)
    except (OSError, UnicodeError, csv.Error) as exc:
        raise InputError(f"cannot read valid CSV: {type(exc).__name__}") from exc
    alerts = []
    for (ip, domain), count in sorted(counts.items()):
        if count >= threshold:
            alerts.append({'type': 'high_query_volume', 'client_ip': ip, 'domain': domain, 'count': count})
    for (ip, base), names in sorted(subdomains.items()):
        if len(names) >= min_unique:
            alerts.append({'type': 'unique_subdomain_burst', 'client_ip': ip, 'base_domain': base, 'unique_count': len(names)})
    return {'rows': rows, 'alerts': alerts, 'limitations': 'Heuristic only; last-two-label base domain is not public-suffix aware. No DNS resolution performed.'}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('csv_path', type=Path, help='Offline CSV with client_ip,query header')
    parser.add_argument('--threshold', type=int, default=10)
    parser.add_argument('--min-unique', type=int, default=8)
    parser.add_argument('--output', type=Path, help='Optional JSON report file')
    args = parser.parse_args(argv)
    try:
        report = analyze(args.csv_path, threshold=args.threshold, min_unique=args.min_unique)
        encoded = json.dumps(report, indent=2, sort_keys=True) + '\n'
        if args.output:
            args.output.write_text(encoded, encoding='utf-8')
        else:
            sys.stdout.write(encoded)
    except (InputError, OSError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
