# Offline SOC Event Timeline

AI-assisted defensive Python 3.10+ lab. No dependencies, live network access or automated containment.

From this directory run:

    python soc_timeline.py examples/synthetic_events.csv
    python -m unittest discover -s tests -v

The CSV requires event_id,timestamp,source,event_type,ip,asset. Timestamps require an explicit offset. Events are sorted in UTC and duplicate IDs rejected. The tool accepts authentication, firewall and file integrity events, but only authentication events are correlated. Default rule: three failures preceding a success for the same asset/IP within ten minutes. Success resets the sequence; equal timestamps cannot establish precedence. The inclusive window uses a deque to expire old failures. Options: --window-minutes (1..1440), --failure-threshold (2..100).

The synthetic example yields six events and one investigation lead, not proof of compromise. Shared IPs, missing account identity, coarse timestamps and incomplete logs limit accuracy. Reports repeat input identifiers; use synthetic or sanitized data only. No paid services required.

Local archive regression suite: 15 tests passed on 2026-11-26; hosted CI and fresh GitHub checkout remain to be verified. Review before merging.
