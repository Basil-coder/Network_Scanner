# Offline SSH Authentication Log Triage

This standard-library-only Python 3.10+ utility analyzes **saved, local** SSH
`sshd` authentication logs. It detects bursts of failed logins from one source
and successful logins following repeated failures from that same source. It
never connects to a host, opens a network socket, scans a network, or modifies
input logs. This is a **triage aid**, not an intrusion detection system.

## Why this project exists

IT support and SOC analysts often need to review failed sign-ins and decide
whether to investigate a source IP further. This exercise demonstrates
structured log parsing, UTC normalization, validation, rolling time windows,
noise reduction, deterministic reporting, and automated tests.

## Supported input

An explicit UTF-8 **regular file** with ISO-8601, timezone-aware timestamps,
followed by a hostname, `sshd[PID]:`, and one of these messages:

- `Failed password for USER from IP port N ssh2`
- `Failed password for invalid user USER from IP port N ssh2`
- `Accepted password for USER from IP port N ssh2`
- `Accepted publickey for USER from IP port N ssh2`

For example, `2026-10-31T10:00:00Z lab sshd[123]: Failed password for demo from 192.0.2.10 port 2222 ssh2`.

**Not supported:** traditional RFC 3164 timestamps such as `Oct 31 10:00:00`,
PAM-only messages, rotated/compressed logs, Windows Event Log, journald binary
format, usernames containing whitespace, or arbitrary SSH event types. These
must be normalized by a trusted preprocessing step before using this tool.
Unrelated lines are counted as ignored; malformed lines that resemble a
supported authentication event are rejected instead of silently counted.

## Reproducible synthetic demonstration

From the repository root, create a synthetic file using only reserved
[documentation IP addresses](https://www.rfc-editor.org/rfc/rfc5737):

```bash
cat > /tmp/ssh-demo.log <<'EOF'
2026-10-31T10:00:00Z lab sshd[123]: Failed password for demo from 192.0.2.10 port 2222 ssh2
2026-10-31T10:00:01Z lab sshd[123]: Failed password for demo from 192.0.2.10 port 2222 ssh2
2026-10-31T10:00:02Z lab sshd[123]: Failed password for demo from 192.0.2.10 port 2222 ssh2
2026-10-31T10:00:03Z lab sshd[123]: Failed password for demo from 192.0.2.10 port 2222 ssh2
2026-10-31T10:00:04Z lab sshd[123]: Failed password for demo from 192.0.2.10 port 2222 ssh2
2026-10-31T10:00:05Z lab sshd[123]: Accepted password for demo from 192.0.2.10 port 2222 ssh2
EOF
python soc/auth_log_triage.py /tmp/ssh-demo.log --format json --redact-ips
```

Expected: one `failure_burst` alert (5 failures in 10 minutes) and one
`success_after_failures` alert (a success after at least 3 recent failures).
The redacted source is `source-1`. The CLI returns exit code `0` unless
`--fail-on-alert` is set, in which case alerts return `1`; invalid input or
configuration returns `2`.

```bash
python soc/auth_log_triage.py /tmp/ssh-demo.log --fail-on-alert
python soc/auth_log_triage.py --help
python -m unittest discover -s tests -p 'test_auth_log_triage.py' -v
```

## Detection logic and technical decisions

- Timestamps must carry a timezone offset; events are converted to UTC and
  sorted chronologically per source IP, with original line order breaking ties.
- Failures are tracked with a `deque` for a configurable **inclusive** sliding
  window (`--window-minutes`, default 10, range 1–1440).
- The first window with at least `--failure-threshold` failures (default 5)
  emits `failure_burst`. The first success preceded by at least
  `--success-after-failures` failures (default 3) within the same window emits
  `success_after_failures`.
- At most **one alert per source IP per alert type per file** is emitted to
  avoid output floods. This is deliberately a summary, not exhaustive event
  correlation. Multiple separate bursts from one IP will be collapsed.
- IPv4 and IPv6 are validated with `ipaddress`; no DNS lookups are made.
- Reports contain source IP, UTC alert time, and recent failure count, **not
  usernames**. `--redact-ips` replaces addresses with deterministic per-file
  aliases (`source-1`, etc.) for safe screenshots and portfolio examples.
- JSON output is deterministic and versioned (`schema_version: 1`) for future
  integration into local dashboards or ticket notes.

## Security and privacy boundaries

Input is capped at **16 MiB, 100,000 lines, 50,000 recognized events, and
4,096 bytes per line**. Symlinks, directories, invalid UTF-8, malformed
recognized messages, and invalid IPs/timestamps are rejected. The file is
opened locally and never uploaded. The file may change between validation and
read; this tool is not hardened against adversarial filesystem races.

Logs may contain usernames, internal IPs, hostnames, and sensitive incident
details. Use only authorized copies, keep them out of Git, and share only
synthetic or redacted reports. Even a redacted report may reveal activity
patterns. No sample production data is included.

**Important limitations:** multiple users behind one NAT can trigger an alert;
a success after failures does not prove account takeover; clock skew and
missing lines affect conclusions; successful public-key login may be normal;
and unsupported formats are ignored. Correlate with MFA, identity, asset,
change, and endpoint telemetry before drawing conclusions. Never treat an
alert as proof of compromise.

## Tests and disclosure

Tests use synthetic RFC 5737/3849 addresses and temporary files. No live SSH
sessions, network scans, privileged operations, external services, or real
incident data are required.

This feature was **AI-assisted** and is submitted for human review. It should
not be merged without examining the implementation and running the tests.
