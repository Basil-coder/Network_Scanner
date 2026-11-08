# Offline HTTP Access Log Triage

A standard-library-only, **offline** Python utility for defensive IT/SOC investigations. It parses a bounded CSV export of HTTP access logs and identifies (a) clusters of HTTP 401/403 responses on selected authentication endpoints and (b) bursts of HTTP 5xx responses. It **does not contact servers** or establish that traffic is malicious.

## Run

From the `http_access_triage` directory:

```bash
python http_access_triage.py examples/synthetic_access.csv --threshold 5 --window-seconds 300
python -m unittest discover -s tests -v
```

Requires Python 3.10+. CSV columns: `timestamp,client_ip,method,path,status`; timestamps must include a UTC offset (e.g. `2026-01-01T00:00:00Z`), and `client_ip` must be valid IPv4/IPv6. Use synthetic or appropriately authorized exports. Input limit: 8 MiB / 50,000 rows, field limit 2048 characters. Results are printed as JSON and include IP addresses; treat as potentially sensitive. Query parameters are discarded before analysis and never appear in output.

## Detection logic

- Authentication failures: five (configurable) HTTP 401/403 events on `/login`, `/signin`, or `/api/login` from one client IP within 300 seconds (configurable).
- Server errors: five HTTP 500–599 events from one client IP in the same window.
- Records are sorted by UTC timestamp, counted in a sliding window, and alert once per burst; a later distinct burst can alert again.
- A burst may be benign (broken client, deployment failure, load balancer, or proxy); investigate with change records and server logs. Source IP is not a user identity, especially behind NAT or reverse proxies.

## Design decisions / limitations

CSV is chosen to avoid ambiguous Apache/Nginx log dialects; export/normalize from the original log before running. The tool rejects malformed records rather than silently dropping evidence, rejects symlink input, and does not resolve DNS or perform scanning. It does not detect credential stuffing across distributed IPs, cannot verify whether an authentication attempt succeeded, and assumes `client_ip` is a trusted normalized field from the logging pipeline. 5xx bursts grouped by client IP may miss system-wide errors distributed among clients. For a real deployment, use rate baselines, proxy-aware attribution, retention policies, and approved redaction. Do not upload real access logs to public repositories.

## Test evidence

Run `python -m unittest discover -s tests -v` locally. The suite uses synthetic RFC 5737 documentation IPs and covers alert generation, false-positive avoidance, windows, validation, and privacy. No live requests are made. AI-assisted development; human review required before merge.
