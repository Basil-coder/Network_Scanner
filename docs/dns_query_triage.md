# Offline DNS Query Triage

This defensive Python standard-library tool analyzes **saved, authorized** DNS query CSV exports. It does not send packets, resolve names, query threat feeds, or access live networks. Use synthetic fixtures for demonstrations; real DNS logs may contain personal data.

## Input

UTF-8 CSV with exactly two headers: `client_ip,query`. For example:

```csv
client_ip,query
192.0.2.10,a.example.com
192.0.2.10,b.example.com
2001:db8::1,www.example.org
```

## Run

From the repository root:

```bash
python dns_query_triage.py examples/dns_queries.csv --threshold 3 --min-unique 3
python dns_query_triage.py examples/dns_queries.csv --output report.json
python -m unittest discover -s tests -v
```

The CLI produces deterministic JSON. `high_query_volume` flags a client repeatedly querying one name; `unique_subdomain_burst` flags many distinct names under the same two-label suffix. A nonzero exit code indicates invalid data or file errors. Limits: 5 MB input and 50,000 rows.

## Security and design decisions

- **Offline only:** no Scapy imports or network calls; all IP addresses are parsed locally.
- **Fail closed:** invalid IPs, invalid ASCII domains, malformed rows and unexpected CSV headers cause an error rather than silent omission.
- **No raw log reproduction:** JSON reports include client IPs and alerting domain names only, not every original query. Treat reports as sensitive and share only with authorization.
- **No false attribution:** counts are simple heuristics; high volume or many subdomains alone does not establish malicious DNS tunneling. The base-domain grouping uses the last two labels and is **not public-suffix aware** (e.g., `co.uk`); review results manually.
- **Operational use:** helps IT support teams spot noisy endpoints and gives junior SOC analysts an explainable first-pass triage queue. It is not an IDS, threat-intelligence feed, or detection guarantee.

## Testing

The unit suite covers volume thresholds, unique-subdomain counting, deduplication, client isolation, IPv6, malformed CSV, invalid input, size limits and JSON output. All examples use reserved documentation IP ranges.
