# Offline Windows Security Event Triage

A standard-library Python tool for **offline** analysis of CSV exports of Windows Security events. It does not access Windows Event Viewer, connect to hosts, or scan a network. It supports **4625** (failed logon), **4624** (successful logon), and **4740** (account lockout). This is a SOC/IT troubleshooting demonstration, not an intrusion detector.

## Input contract

Create a UTF-8 CSV with header `timestamp,event_id,account,source_ip`. Timestamps must be ISO-8601 with an explicit timezone, e.g. `2026-11-01T10:00:00Z`. `source_ip` may be `-` if unavailable. The tool never reads an `.evtx` file directly. Convert only **authorized** event exports; do not commit real user names, host addresses, or logs.

Run from this directory:

```bash
python windows_event_triage.py sample_events.csv --threshold 3 --window-minutes 10
python -m unittest discover -s tests -v
```

## Detection logic

Events are sorted by normalized UTC timestamp. For each `(account, source_ip)` pair, the tool detects a threshold number of failed logons within a sliding time window, flags successful logons following recent failures from the **same pair**, and reports account lockouts. Output is JSON. Repeated-failures alerts fire when the threshold is first reached, not for every subsequent failure. Multiple successes can produce multiple alerts. Missing source IPs may group unrelated activity.

## Safety and limitations

Input is capped at 5 MB and 50,000 rows. Symlinks and malformed headers, rows, timestamps, IPs and event IDs are rejected. Alerts are heuristics, not proof of compromise. Windows logon types, workstation names, domain normalization, lockout correlation, and false-positive tuning are outside this minimal scope. Follow privacy rules when handling real event exports. No external dependencies or network access are required.

## Technical decisions

Standard library only, explicit event-ID allowlist, deterministic UTC sorting, keyed correlation, and synthetic tests using documentation-range IPs (`192.0.2.0/24`). The project is standalone and does not change the ARP scanner or require new dependencies. AI-assisted code; human review required.
