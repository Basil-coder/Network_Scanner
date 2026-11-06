"""Offline triage of exported Windows Security Event CSV files."""
import argparse
import csv
import ipaddress
import json
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from pathlib import Path

ALLOWED_EVENTS = {4624, 4625, 4740}
REQUIRED = {"timestamp", "event_id", "account", "source_ip"}
MAX_BYTES = 5_000_000
MAX_ROWS = 50_000

def parse_time(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must contain timezone")
    return dt.astimezone(timezone.utc)

def parse_rows(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("input must be a regular, non-symlink file")
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("input exceeds 5 MB limit")
    results = []
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or len(reader.fieldnames) != len(set(reader.fieldnames)) or not REQUIRED.issubset(reader.fieldnames):
            raise ValueError("invalid CSV header; required: timestamp,event_id,account,source_ip")
        for line, row in enumerate(reader, 2):
            if line > MAX_ROWS + 1:
                raise ValueError("input exceeds row limit")
            if None in row or any(v is None for v in row.values()):
                raise ValueError(f"line {line}: malformed CSV row")
            try:
                event_id = int(row["event_id"])
                if event_id not in ALLOWED_EVENTS or str(event_id) != row["event_id"].strip():
                    raise ValueError("unsupported event ID")
                when = parse_time(row["timestamp"].strip())
                account = row["account"].strip()
                if not account or len(account) > 128:
                    raise ValueError("invalid account")
                ip = row["source_ip"].strip()
                if ip and ip != "-":
                    ip = str(ipaddress.ip_address(ip))
                else:
                    ip = None
            except (ValueError, OverflowError) as exc:
                raise ValueError(f"line {line}: {exc}") from exc
            results.append({"timestamp": when, "event_id": event_id, "account": account, "source_ip": ip})
    return sorted(results, key=lambda r: r["timestamp"])

def analyze(rows, threshold=5, window_minutes=10):
    if threshold < 2 or window_minutes < 1:
        raise ValueError("threshold must be >=2 and window_minutes >=1")
    failures = defaultdict(list)
    alerts = []
    window = timedelta(minutes=window_minutes)
    for row in rows:
        key = (row["account"], row["source_ip"])
        now = row["timestamp"]
        if row["event_id"] == 4625:
            failures[key].append(now)
            failures[key] = [t for t in failures[key] if now - t <= window]
            if len(failures[key]) == threshold:
                alerts.append({"type": "repeated_failed_logons", "account": key[0], "source_ip": key[1], "timestamp": now.isoformat(), "count": len(failures[key])})
        elif row["event_id"] == 4624:
            recent = [t for t in failures[key] if now - t <= window]
            if recent:
                alerts.append({"type": "success_after_failures", "account": key[0], "source_ip": key[1], "timestamp": now.isoformat(), "prior_failures": len(recent)})
        elif row["event_id"] == 4740:
            alerts.append({"type": "account_lockout", "account": key[0], "source_ip": key[1], "timestamp": now.isoformat()})
    return {"events_processed": len(rows), "alerts": alerts, "limitations": "Heuristic triage only; no maliciousness determination. Correlation requires matching account and source IP."}

def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline Windows Security CSV triage (no event collection or network access)")
    parser.add_argument("csv_file")
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window-minutes", type=int, default=10)
    args = parser.parse_args(argv)
    try:
        report = analyze(parse_rows(args.csv_file), args.threshold, args.window_minutes)
    except (ValueError, OSError, UnicodeError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True))

if __name__ == "__main__":
    main()
