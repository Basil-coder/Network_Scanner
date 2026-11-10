# Offline TLS Certificate Expiry Inventory

Defensive IT/SOC troubleshooting tool that classifies **previously collected** certificate expiry metadata. It makes **no TLS connections, DNS requests, scans, or API calls**. Use only exported data from systems you administer or have permission to audit.

## CSV format

Exact headers: `hostname,port,not_after_utc,issuer`. Dates must be ISO 8601 UTC ending in `Z`. The tool does not collect certificate details or independently verify certificate trust chains.

```csv
hostname,port,not_after_utc,issuer
app.example.test,443,2026-11-09T00:00:00Z,Synthetic CA
portal.example.test,443,2026-11-25T00:00:00Z,Synthetic CA
service.example.test,8443,2027-02-01T00:00:00Z,Synthetic CA
```

## Run

```bash
python tls_inventory.py examples/tls_inventory_sample.csv --as-of 2026-11-10T00:00:00Z --warn-days 30
python tls_inventory.py examples/tls_inventory_sample.csv --warn-days 14
python -m pytest -q tests/test_tls_inventory.py
```

The JSON report sorts certificates by days remaining, then host and port. `expired` means the expiry instant has passed; `expiring` means the certificate expires in the next N days (inclusive); `ok` means outside the window. Exit code 2 indicates invalid input, not a partial success. All input is rejected if a row is malformed.

## Design decisions and limits

- Python standard library only; deliberately no network dependencies.
- Max 2 MB CSV and 10,000 records, strict headers and row validation, unique normalized hostname/port pairs, safe JSON output.
- Reject symlink input and control characters in issuer to reduce accidental data exposure or log injection.
- A hostname may be DNS-like or an IP address; no DNS resolution or hostname-to-certificate matching is attempted.
- Inventory is **not** proof that a live endpoint presents the listed certificate. Revocation, chain validation, SAN checks, self-signed status, and renewal ownership are out of scope.
- Timestamps are compared to a specified UTC instant for reproducible tests; fractional days are retained in output. Treat this as a renewal triage aid, not a compliance finding.

## Career demonstration

This project demonstrates safe offline asset inventory, certificate lifecycle monitoring, structured Python input validation, deterministic tests, JSON reporting, and operational prioritization for IT support, NOC and junior SOC roles.
