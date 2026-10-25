#!/usr/bin/env python3
"""Command-line IPv4 ARP network scanner."""

from __future__ import annotations

import argparse
import ipaddress
import sys
from collections.abc import Callable, Sequence
from typing import TypedDict


MAX_ADDRESSES = 65_536


class Device(TypedDict):
    """A device discovered by an ARP scan."""

    ip: str
    mac: str


ScanFunction = Callable[[ipaddress.IPv4Network], list[Device]]


def parse_subnet(value: str) -> ipaddress.IPv4Network:
    """Parse and validate an IPv4 subnet supplied in CIDR notation."""

    if "/" not in value:
        raise argparse.ArgumentTypeError(
            "subnet must use CIDR notation (for example, 192.168.1.0/24)"
        )

    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid subnet: {value!r}") from exc

    if not isinstance(network, ipaddress.IPv4Network):
        raise argparse.ArgumentTypeError("only IPv4 subnets are supported")

    if network.num_addresses > MAX_ADDRESSES:
        raise argparse.ArgumentTypeError(
            f"subnet contains {network.num_addresses:,} addresses; "
            f"the maximum is {MAX_ADDRESSES:,} (/16)"
        )

    return network


def scan_subnet(subnet: ipaddress.IPv4Network) -> list[Device]:
    """Discover devices with Scapy. Importing this module never sends packets."""

    # Keep Scapy lazy so validation, help, dry runs, and tests need no raw-socket
    # access (and can run even when the optional runtime dependency is absent).
    from scapy.all import ARP, Ether, srp

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(subnet))
    answered, _ = srp(packet, timeout=3, verbose=0)

    devices: list[Device] = []
    for _, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})

    return sorted(devices, key=lambda device: ipaddress.ip_address(device["ip"]))


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""

    parser = argparse.ArgumentParser(
        description="Discover devices on an IPv4 subnet with ARP requests."
    )
    parser.add_argument(
        "-s",
        "--subnet",
        required=True,
        type=parse_subnet,
        metavar="CIDR",
        help="IPv4 subnet to scan, up to /16 (for example, 192.168.1.0/24)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validate and display the target without sending packets",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    scan: ScanFunction | None = None,
) -> int:
    """Run the CLI and return its process exit code."""

    args = build_parser().parse_args(argv)
    subnet: ipaddress.IPv4Network = args.subnet

    if args.dry_run:
        print(
            f"Dry run: would scan {subnet.with_prefixlen} "
            f"({subnet.num_addresses:,} addresses); no packets sent."
        )
        return 0

    try:
        devices = (scan or scan_subnet)(subnet)
    except (ImportError, OSError) as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 1

    print(f"Available devices in {subnet.with_prefixlen}:")
    if not devices:
        print("No devices found.")
        return 0

    print(f"{'IP address':<16} MAC address")
    for device in devices:
        print(f"{device['ip']:<16} {device['mac']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
