# Network Scanner

A small Python CLI that discovers devices on an IPv4 subnet with ARP requests.
The target is selected explicitly in CIDR notation, and subnets larger than
`/16` are rejected to guard against accidental broad scans.

Only scan networks you own or have permission to test.

## Requirements

- Python 3.10 or newer
- Scapy 2.x (only needed for a real scan)
- Administrator/root privileges for raw network access during a real scan

Install the runtime dependency:

```bash
python -m pip install -r requirements.txt
```

## Usage

Start with a dry run. It validates and normalizes the subnet, reports the
number of target addresses, and exits without importing Scapy or sending any
packets:

```bash
python network_scanner.py --subnet 192.168.1.0/24 --dry-run
```

Example output:

```text
Dry run: would scan 192.168.1.0/24 (256 addresses); no packets sent.
```

After confirming the target and your authorization, run the scan with:

```bash
sudo python network_scanner.py --subnet 192.168.1.0/24
```

Use `python network_scanner.py --help` to see all options. IPv4 CIDR input is
required; malformed input, IPv6 networks, missing prefixes, and targets larger
than `/16` are rejected before any scan starts.

## Offline inventory drift reporting

Use `--format json` to export a versioned scan result and compare two saved
snapshots locally using `inventory_diff.py`. The comparison never scans or
contacts a network. See [INVENTORY.md](INVENTORY.md) for a fully synthetic
example, input validation, exit codes and privacy considerations.

## Tests

The automated tests use dependency injection and mocked Scapy objects. They do
not open sockets or send network packets, and Scapy is not required to run
them:

```bash
python -m unittest discover -s tests -v
```

![Network scanner example](https://user-images.githubusercontent.com/52016269/220776670-2a8e3575-c2b9-4113-8716-3e59588f41de.png)
