#!/usr/bin/env python3
"""Compare two local ARP inventory snapshots without network access."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
MAX_DEVICES = 65_536
MAC_PATTERN = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\Z")


class InventoryError(ValueError):
    """An invalid or incompatible inventory snapshot."""


@dataclass(frozen=True)
class Snapshot:
    subnet: ipaddress.IPv4Network
    devices: dict[str, str]


def load_snapshot(path: Path) -> Snapshot:
    """Read a bounded, versioned JSON snapshot; reject ambiguous device data."""
    try:
        with path.open("rb") as source:
            raw = source.read(MAX_SNAPSHOT_BYTES + 1)
    except OSError as exc:
        raise InventoryError(f"cannot read {path}: {exc.strerror or exc}") from exc

    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise InventoryError(f"{path}: snapshot exceeds {MAX_SNAPSHOT_BYTES} bytes")
    try:
        data: Any = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise InventoryError(f"{path}: invalid UTF-8 JSON") from exc

    if not isinstance(data, dict) or set(data) != {"schema_version", "subnet", "devices"}:
        raise InventoryError(f"{path}: expected schema_version, subnet and devices")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise InventoryError(f"{path}: unsupported schema_version (expected 1)")
    if not isinstance(data["subnet"], str) or "/" not in data["subnet"]:
        raise InventoryError(f"{path}: subnet must be an IPv4 CIDR string")
    try:
        subnet = ipaddress.ip_network(data["subnet"], strict=True)
    except ValueError as exc:
        raise InventoryError(f"{path}: invalid canonical subnet") from exc
    if not isinstance(subnet, ipaddress.IPv4Network):
        raise InventoryError(f"{path}: IPv4 subnet required")

    rows = data["devices"]
    if not isinstance(rows, list) or len(rows) > MAX_DEVICES:
        raise InventoryError(f"{path}: devices must be a list of at most {MAX_DEVICES}")
    devices: dict[str, str] = {}
    for index, row in enumerate(rows):
        if not isinstance(row, dict) or set(row) != {"ip", "mac"}:
            raise InventoryError(f"{path}: invalid device at index {index}")
        ip, mac = row["ip"], row["mac"]
        if not isinstance(ip, str) or not isinstance(mac, str):
            raise InventoryError(f"{path}: device {index} requires string IP and MAC")
        try:
            address = ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError as exc:
            raise InventoryError(f"{path}: invalid IPv4 address at device {index}") from exc
        if str(address) != ip or address not in subnet:
            raise InventoryError(f"{path}: device {index} has noncanonical or out-of-subnet IP")
        if MAC_PATTERN.fullmatch(mac) is None:
            raise InventoryError(f"{path}: invalid MAC address at device {index}")
        if ip in devices:
            raise InventoryError(f"{path}: duplicate IP address {ip}")
        devices[ip] = mac.lower()
    return Snapshot(subnet, devices)


def compare(before: Snapshot, after: Snapshot) -> dict[str, Any]:
    """Classify changes by IP. MAC changes may reflect ordinary reassignment."""
    if before.subnet != after.subnet:
        raise InventoryError("snapshots have different subnets; comparison refused")

    def ordered(addresses: set[str]) -> list[str]:
        return sorted(addresses, key=ipaddress.IPv4Address)

    old, new = before.devices, after.devices
    added = [{"ip": ip, "mac": new[ip]} for ip in ordered(new.keys() - old.keys())]
    removed = [{"ip": ip, "mac": old[ip]} for ip in ordered(old.keys() - new.keys())]
    changed = [
        {"ip": ip, "before_mac": old[ip], "after_mac": new[ip]}
        for ip in ordered(old.keys() & new.keys())
        if old[ip] != new[ip]
    ]
    return {
        "subnet": str(before.subnet),
        "added": added,
        "removed": removed,
        "mac_changed": changed,
    }


def format_text(report: dict[str, Any]) -> str:
    """Create a deterministic, human-readable drift summary."""
    lines = [
        f"Offline inventory comparison for {report['subnet']}",
        f"Added: {len(report['added'])} | Removed: {len(report['removed'])} "
        f"| MAC changed: {len(report['mac_changed'])}",
    ]
    for row in report["added"]:
        lines.append(f"+ {row['ip']} {row['mac']}")
    for row in report["removed"]:
        lines.append(f"- {row['ip']} {row['mac']}")
    for row in report["mac_changed"]:
        lines.append(f"~ {row['ip']} {row['before_mac']} -> {row['after_mac']}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--before", type=Path, required=True, help="baseline JSON snapshot")
    parser.add_argument("--after", type=Path, required=True, help="new JSON snapshot")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--fail-on-change", action="store_true", help="return 1 if drift exists")
    args = parser.parse_args(argv)
    try:
        report = compare(load_snapshot(args.before), load_snapshot(args.after))
    except InventoryError as exc:
        print(f"Inventory error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(format_text(report))
    has_change = any(report[key] for key in ("added", "removed", "mac_changed"))
    return 1 if args.fail_on_change and has_change else 0


if __name__ == "__main__":
    raise SystemExit(main())
