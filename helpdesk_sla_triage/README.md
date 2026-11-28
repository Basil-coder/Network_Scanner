# Offline Helpdesk Ticket SLA Triage

AI-assisted defensive portfolio lab, Python 3.10+, standard library only. Prioritize aging unresolved tickets from sanitized CSV exports without contacting an ITSM system.

From this directory:

    python helpdesk_sla.py examples/synthetic_tickets.csv --now 2026-11-14T12:00:00Z
    python -m unittest discover -s tests -v

The required evaluation time makes results reproducible. CSV columns: ticket_id,opened_at,priority,status,updated_at. Use synthetic or approved pseudonymous IDs only. Timestamps must include an offset. Duplicate IDs, invalid statuses, inconsistent timestamps and malformed CSV are rejected. Input is limited to 2 MB and 10,000 rows.

Illustrative wall-clock thresholds: P1 4h, P2 8h, P3 24h, P4 72h. Unresolved tickets at 80% are approaching, at 100% overdue. Resolved/closed tickets are excluded. These are not contractual SLAs: business hours, holidays, pause states and escalation policies are not modeled. No automated escalation or external services. Output may contain internal ticket identifiers; handle accordingly.

Fresh extraction of the original local archive on 2026-11-28 passed 20 tests and reproduced one overdue and one approaching ticket from three synthetic records. Hosted CI remains unverified. Review before merging.
