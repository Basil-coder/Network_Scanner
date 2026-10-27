# Offline inventory baseline and drift detection

This addition extends `Network_Scanner` with a **versioned JSON export** and a
**fully offline inventory comparison CLI**. It is intended for authorized
asset inventory, IT troubleshooting and SOC triage, not intrusion detection.

## Workflow

1. Confirm authorization and the intended IPv4 subnet. First check with
   `python network_scanner.py --subnet 192.0.2.0/24 --dry-run` (example only).
2. On a network you are authorized to inspect, capture an inventory with
   `sudo python network_scanner.py --subnet YOUR_CIDR --format json > baseline.json`.
3. Later, repeat into `current.json` on the **same** subnet.
4. Compare **without any network access**:

   ```bash
   python inventory_diff.py --before baseline.json --after current.json
   python inventory_diff.py --before baseline.json --after current.json --format json
   python inventory_diff.py --before baseline.json --after current.json --fail-on-change
   ```

For an entirely offline demonstration, create two synthetic JSON files:

`baseline.json`:

```json
{"schema_version":1,"subnet":"192.0.2.0/24","devices":[{"ip":"192.0.2.10","mac":"02:00:00:00:00:10"}]}
```

`current.json`:

```json
{"schema_version":1,"subnet":"192.0.2.0/24","devices":[{"ip":"192.0.2.10","mac":"02:00:00:00:00:11"},{"ip":"192.0.2.20","mac":"02:00:00:00:00:20"}]}
```

Output:

```text
Offline inventory comparison for 192.0.2.0/24
Added: 1 | Removed: 0 | MAC changed: 1
+ 192.0.2.20 02:00:00:00:00:20
~ 192.0.2.10 02:00:00:00:00:10 -> 02:00:00:00:00:11
```

`inventory_diff.py` exits **0** for a valid comparison (including changes),
**1** if changes exist and `--fail-on-change` is used, and **2** for invalid
input or incompatible subnets. The JSON report has `subnet`, `added`,
`removed`, and `mac_changed` fields.

## Design and limitations

- No network imports or socket operations occur in `inventory_diff.py`.
- JSON input must be UTF-8, schema version 1, at most 4 MiB and at most
  65,536 device rows. Duplicate IPs, malformed MACs, noncanonical or
  out-of-subnet IPv4 addresses, and subnet mismatches fail closed.
- MACs are case-normalized. Multiple IPs may legitimately share one MAC.
- ARP only observes devices that respond on the local layer-2 network at that
  time. Missing entries may reflect sleep, firewalls, VLANs or timing; MAC
  changes can reflect DHCP, interface replacement or spoofing. **Do not treat
  drift as proof of compromise.** Investigate and correlate with other logs.
- JSON snapshots contain potentially sensitive internal IP/MAC information.
  Store them privately, restrict access and retention, and **do not commit
  real inventories** to public GitHub repositories. Examples use RFC 5737
  documentation-only addresses and locally administered example MACs.
- No third-party libraries are required for the offline comparison. Actual
  ARP capture still requires Scapy and appropriate authorization/privileges.

## Offline tests

```bash
python -m unittest discover -s tests -v
```

Tests use synthetic addresses and a mocked scanner function. They do not
transmit packets or perform real scans. The scanner's default text output and
`--dry-run` behavior remain unchanged.

**Contribution disclosure:** This implementation and its tests were prepared
with AI assistance; review and verification remain the maintainer's
responsibility.
