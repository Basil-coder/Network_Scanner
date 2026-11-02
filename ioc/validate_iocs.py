#!/usr/bin/env python3
"""Validate a bounded, local JSONL feed of defensive indicators of compromise.

No DNS lookups, HTTP requests, sockets, or third-party packages are used.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

MAX_BYTES = 4 * 1024 * 1024
MAX_LINE_BYTES = 4096
MAX_RECORDS = 20000
DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
TYPES = ("ipv4", "ipv6", "domain", "url", "sha256")


class InvalidIndicator(ValueError):
    """A feed entry is invalid and should not be trusted downstream."""


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidIndicator("duplicate JSON key")
        result[key] = value
    return result


def reject_constant(_value: str) -> None:
    raise InvalidIndicator("non-finite JSON number")


def domain(value: str) -> str:
    if not value.isascii() or not value or len(value) > 253:
        raise InvalidIndicator("domain must be ASCII and at most 253 characters")
    normalized = value.lower().removesuffix(".")
    labels = normalized.split(".")
    if len(labels) < 2 or any(not DOMAIN_LABEL.fullmatch(x) for x in labels):
        raise InvalidIndicator("invalid DNS hostname labels")
    return normalized


def canonical(kind: str, value: str) -> str:
    if not isinstance(kind, str) or kind not in TYPES:
        raise InvalidIndicator("unsupported indicator type")
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise InvalidIndicator("indicator must be a nonempty string of at most 2048 characters")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise InvalidIndicator("control character in indicator")
    if kind in ("ipv4", "ipv6"):
        if "%" in value:
            raise InvalidIndicator("scoped IP addresses are not supported")
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise InvalidIndicator("invalid IP address") from exc
        if address.version != (4 if kind == "ipv4" else 6):
            raise InvalidIndicator("IP version does not match indicator type")
        return str(address)
    if kind == "domain":
        return domain(value)
    if kind == "sha256":
        if not SHA256.fullmatch(value):
            raise InvalidIndicator("SHA-256 must be exactly 64 hexadecimal characters")
        return value.lower()
    if not value.isascii() or "\\" in value or " " in value:
        raise InvalidIndicator("URL must be ASCII and contain no spaces or backslashes")
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise InvalidIndicator("URL requires http(s) and a hostname")
        if parsed.username is not None or parsed.password is not None:
            raise InvalidIndicator("URL credentials are not permitted")
        if parsed.fragment:
            raise InvalidIndicator("URL fragments are not permitted")
        hostname = parsed.hostname
        port = parsed.port  # Access validates malformed and out-of-range ports.
        if port == 0:
            raise InvalidIndicator("URL port must be between 1 and 65535")
        if hostname is None:
            raise InvalidIndicator("URL hostname missing")
        if "%" in hostname:
            raise InvalidIndicator("URL host cannot contain percent escapes or scope IDs")
        try:
            host_ip = ipaddress.ip_address(hostname)
        except ValueError:
            host = domain(hostname)
        else:
            host = f"[{host_ip}]" if host_ip.version == 6 else str(host_ip)
        if port is not None and port == (80 if parsed.scheme == "http" else 443):
            port = None
        netloc = host + (f":{port}" if port is not None else "")
        return urlunsplit((parsed.scheme, netloc, parsed.path or "/", parsed.query, ""))
    except ValueError as exc:
        if isinstance(exc, InvalidIndicator):
            raise
        raise InvalidIndicator("malformed URL or port") from exc


def validate_feed(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_BYTES:
            raise InvalidIndicator("input must be a regular non-symlink file of at most 4 MiB")
        with path.open("rb") as handle:
            data = handle.read(MAX_BYTES + 1)
    except OSError as exc:
        raise InvalidIndicator(f"cannot read input: {exc.strerror or 'I/O error'}") from exc
    if len(data) > MAX_BYTES:
        raise InvalidIndicator("input exceeds 4 MiB")
    lines = data.splitlines()
    if len(lines) > MAX_RECORDS:
        raise InvalidIndicator("input exceeds 20,000 lines")
    accepted: dict[tuple[str, str], int] = {}
    invalid: list[dict[str, object]] = []
    duplicates: list[dict[str, object]] = []
    for number, raw in enumerate(lines, 1):
        try:
            if len(raw) > MAX_LINE_BYTES:
                raise InvalidIndicator("line exceeds 4096 bytes")
            record = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                                parse_constant=reject_constant)
            if not isinstance(record, dict) or set(record) != {"type", "value"}:
                raise InvalidIndicator("expected object with only type and value")
            kind, value = record["type"], record["value"]
            normalized = canonical(kind, value)
            key = (kind, normalized)
            if key in accepted:
                duplicates.append({"line": number, "first_line": accepted[key]})
            else:
                accepted[key] = number
        except (UnicodeError, json.JSONDecodeError, InvalidIndicator) as exc:
            invalid.append({"line": number, "reason": str(exc) if isinstance(exc, InvalidIndicator)
                            else "invalid UTF-8 or JSON"})
    indicators = [{"type": kind, "value": value} for kind, value in sorted(accepted)]
    return {"schema_version": 1, "total_lines": len(lines), "valid_unique": len(indicators),
            "invalid_count": len(invalid), "duplicate_count": len(duplicates),
            "indicators": indicators, "invalid": invalid, "duplicates": duplicates}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline JSONL IOC validation; no network access")
    parser.add_argument("input", type=Path, help="local JSONL file containing type/value objects")
    parser.add_argument("--strict", action="store_true", help="exit 1 if invalid or duplicate entries")
    args = parser.parse_args(argv)
    try:
        report = validate_feed(args.input)
    except InvalidIndicator as exc:
        print(f"Input rejected: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return int(args.strict and (report["invalid_count"] or report["duplicate_count"]))


if __name__ == "__main__":
    raise SystemExit(main())
