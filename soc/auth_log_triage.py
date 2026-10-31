#!/usr/bin/env python3
"""Offline SSH authentication log triage for ISO-8601 syslog lines.

No network access, third-party packages, privileged operations or live scanning.
"""

from __future__ import annotations

import argparse
from collections import defaultdict, deque
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import stat
import sys

MAX_BYTES = 16 * 1024 * 1024
MAX_LINES = 100_000
MAX_EVENTS = 50_000
MAX_LINE_BYTES = 4096

SSH_LINE = re.compile(
    r"^(?P<timestamp>\S+)\s+\S+\s+sshd\[\d+\]:\s+(?P<message>.*)$"
)
FAILED = re.compile(
    r"^Failed password for (?:invalid user )?\S{1,64} from (?P<ip>\S+) port \d+(?: ssh2)?$"
)
ACCEPTED = re.compile(
    r"^Accepted (?:password|publickey) for \S{1,64} from (?P<ip>\S+) port \d+(?: ssh2)?$"
)


class TriageError(ValueError):
    """Input is unsupported, unsafe, or invalid."""


def parse_timestamp(value: str, line_number: int) -> datetime:
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TriageError(f"line {line_number}: invalid ISO-8601 timestamp") from exc
    if stamp.tzinfo is None or stamp.utcoffset() is None:
        raise TriageError(f"line {line_number}: timestamp requires timezone offset")
    return stamp.astimezone(timezone.utc)


def parse_line(line: str, line_number: int):
    match = SSH_LINE.fullmatch(line)
    if match is None:
        return None
    message = match.group("message")
    if message.startswith("Failed password"):
        kind = "failure"
        detail = FAILED.fullmatch(message)
    elif message.startswith("Accepted password") or message.startswith("Accepted publickey"):
        kind = "success"
        detail = ACCEPTED.fullmatch(message)
    else:
        return None
    if detail is None:
        raise TriageError(f"line {line_number}: malformed supported SSH authentication message")
    raw_ip = detail.group("ip")
    if "%" in raw_ip:
        raise TriageError(f"line {line_number}: scoped IP addresses are unsupported")
    try:
        source_ip = str(ipaddress.ip_address(raw_ip))
    except ValueError as exc:
        raise TriageError(f"line {line_number}: invalid source IP address") from exc
    stamp = parse_timestamp(match.group("timestamp"), line_number)
    return (stamp, line_number, source_ip, kind)


def load_events(path: Path):
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise TriageError(f"cannot stat input file: {exc.strerror}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise TriageError("input must be a regular file, not a symlink or special file")
    if metadata.st_size > MAX_BYTES:
        raise TriageError("input file exceeds 16 MiB limit")

    events = []
    total_lines = 0
    total_bytes = 0
    try:
        with path.open("rb") as stream:
            for line_number, raw in enumerate(stream, 1):
                total_lines = line_number
                total_bytes += len(raw)
                if total_bytes > MAX_BYTES:
                    raise TriageError("input exceeds 16 MiB while reading")
                if line_number > MAX_LINES:
                    raise TriageError("input exceeds 100000 lines")
                if len(raw) > MAX_LINE_BYTES:
                    raise TriageError(f"line {line_number}: exceeds 4096-byte limit")
                try:
                    line = raw.decode("utf-8").rstrip("\r\n")
                except UnicodeDecodeError as exc:
                    raise TriageError(f"line {line_number}: invalid UTF-8") from exc
                event = parse_line(line, line_number)
                if event is not None:
                    events.append(event)
                    if len(events) > MAX_EVENTS:
                        raise TriageError("input exceeds 50000 recognized events")
    except OSError as exc:
        raise TriageError(f"cannot read input file: {exc.strerror}") from exc
    return events, total_lines


def analyze(events, total_lines: int, *, window_minutes: int = 10,
            failure_threshold: int = 5, success_after_failures: int = 3,
            redact_ips: bool = False):
    if not (1 <= window_minutes <= 1440):
        raise TriageError("window-minutes must be between 1 and 1440")
    if not (2 <= failure_threshold <= 1000):
        raise TriageError("failure-threshold must be between 2 and 1000")
    if not (1 <= success_after_failures <= 1000):
        raise TriageError("success-after-failures must be between 1 and 1000")

    by_ip = defaultdict(list)
    for event in events:
        by_ip[event[2]].append(event)
    aliases = {ip: f"source-{i}" for i, ip in enumerate(sorted(by_ip), 1)}
    alerts = []
    for ip in sorted(by_ip):
        history = deque()
        seen_burst = False
        seen_success = False
        for when, line_number, _, kind in sorted(by_ip[ip], key=lambda item: (item[0], item[1])):
            while history and (when - history[0]).total_seconds() > window_minutes * 60:
                history.popleft()
            if kind == "failure":
                history.append(when)
                if len(history) >= failure_threshold and not seen_burst:
                    alerts.append({
                        "type": "failure_burst", "source_ip": aliases[ip] if redact_ips else ip,
                        "timestamp_utc": when.isoformat().replace("+00:00", "Z"),
                        "failure_count": len(history),
                    })
                    seen_burst = True
            elif len(history) >= success_after_failures and not seen_success:
                alerts.append({
                    "type": "success_after_failures", "source_ip": aliases[ip] if redact_ips else ip,
                    "timestamp_utc": when.isoformat().replace("+00:00", "Z"),
                    "failure_count": len(history),
                })
                seen_success = True
    alerts.sort(key=lambda a: (a["timestamp_utc"], a["type"], a["source_ip"]))
    return {
        "schema_version": 1,
        "total_lines": total_lines,
        "parsed_events": len(events),
        "ignored_lines": total_lines - len(events),
        "failed_logins": sum(event[3] == "failure" for event in events),
        "successful_logins": sum(event[3] == "success" for event in events),
        "window_minutes": window_minutes,
        "failure_threshold": failure_threshold,
        "success_after_failures": success_after_failures,
        "ip_redacted": redact_ips,
        "alerts": alerts,
    }


def build_parser():
    parser = argparse.ArgumentParser(description="Triage saved SSH auth logs offline (ISO-8601 format only)")
    parser.add_argument("log_file", type=Path, help="local UTF-8 log file (no symlinks)")
    parser.add_argument("--window-minutes", type=int, default=10)
    parser.add_argument("--failure-threshold", type=int, default=5)
    parser.add_argument("--success-after-failures", type=int, default=3)
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--redact-ips", action="store_true", help="replace IPs with source-1, source-2, ...")
    parser.add_argument("--fail-on-alert", action="store_true", help="exit 1 if alerts found (otherwise 0)")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        events, total_lines = load_events(args.log_file)
        result = analyze(events, total_lines, window_minutes=args.window_minutes,
                         failure_threshold=args.failure_threshold,
                         success_after_failures=args.success_after_failures,
                         redact_ips=args.redact_ips)
    except TriageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"SSH auth events: {result['parsed_events']} (ignored: {result['ignored_lines']})")
        print(f"Failures: {result['failed_logins']} | Successes: {result['successful_logins']}")
        print(f"Alerts: {len(result['alerts'])}")
        for alert in result["alerts"]:
            print(f"- {alert['timestamp_utc']} {alert['type']} source={alert['source_ip']} "
                  f"recent_failures={alert['failure_count']}")
    return 1 if args.fail_on_alert and result["alerts"] else 0


if __name__ == "__main__":
    sys.exit(main())
