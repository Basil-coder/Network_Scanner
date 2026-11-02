# Offline IOC Feed Validator

Validate a **local JSON Lines** (JSONL) threat-intelligence feed before using it in a SOC triage workflow. This is a separate, network-free project from the ARP scanner, inventory drift detector, SHA-256 file integrity monitor, and SSH log triage utilities. Python 3.10+ and the standard library are sufficient.

## Supported indicators

Each UTF-8 line must contain **exactly** two JSON string fields, `type` and `value`. Supported types: `ipv4`, `ipv6`, `domain`, `url` (HTTP/HTTPS only), and `sha256`. Values are syntax-checked, normalized where safe, deduplicated by `(type, normalized_value)`, and returned in deterministic JSON. Duplicate and rejected line numbers are included. Invalid raw values are not echoed in error messages.

Synthetic sample (RFC 5737 example IP; not live threat intelligence):

```bash
cat > /tmp/sample-iocs.jsonl <<'EOF'
{"type":"domain","value":"EXAMPLE.COM."}
{"type":"domain","value":"example.com"}
{"type":"ipv4","value":"203.0.113.9"}
{"type":"sha256","value":"invalid-hash"}
EOF
python -m ioc.validate_iocs /tmp/sample-iocs.jsonl --strict
```

Output is JSON with `valid_unique: 2`, `duplicate_count: 1`, `invalid_count: 1`, the two normalized indicators, and line-number diagnostics. `--strict` exits **1** for any invalid or duplicate row; without it, the tool returns **0** after a readable feed. An unreadable/unsafe input file returns **2**. Redirect stdout to a local JSON file if needed; do not publish real IOC feeds or incident reports.

Run offline tests from the repository root:

```bash
python -m unittest discover -s tests -p 'test_validate_iocs.py' -v
python -m compileall -q ioc/validate_iocs.py tests/test_validate_iocs.py
```

## Design decisions and limits

- **No network operations:** no DNS, reputation API, HTTP, sockets, or active probing. This checks syntax and consistency, **not whether an IOC is malicious**.
- **Fail closed on ambiguous records:** reject duplicate JSON keys, non-finite JSON constants, unexpected fields, control characters, malformed ports, URL credentials and fragments, and unsupported types.
- **Conservative normalization:** IPs use Python `ipaddress`; domains are lowercased and may lose a terminal dot; SHA-256 is lowercased; URLs lowercase the host, remove default ports and use `/` for empty paths while preserving case-sensitive path/query. ASCII-only DNS names avoid Unicode lookalike ambiguity; punycode (`xn--`) labels are accepted but not independently decoded or verified.
- **Bounded local processing:** input must be a regular non-symlink file no larger than 4 MiB; maximum 20,000 lines and 4,096 bytes per line; indicator strings max 2,048 characters. All results are in memory. Do not run against attacker-writable paths: an adversary could replace a file between the metadata check and open (TOCTOU).
- **Operational context:** domain names must have at least two labels; local single-label names are rejected. Reserved/private IPs are syntactically valid (they may appear in internal investigations). URL fragments are not part of server requests and are rejected. No wildcard, CIDR, SHA-1/MD5, STIX, CSV, IDN Unicode, or threat scoring support.
- **Privacy:** reports include accepted indicators and may contain sensitive investigation details. Use synthetic data in commits and redact before sharing. This utility is a triage aid, not a production feed ingestion or detection engine.

AI-assisted implementation; human review is required before merging. No real feeds or network activity were used in the included tests.
