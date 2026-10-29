#!/usr/bin/env python3
"""Offline, bounded SHA-256 file integrity baselines and drift checks.

Python 3.10+; standard library only. This is an investigation aid, not an IDS.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

SCHEMA_VERSION = 1
MAX_FILES = 10_000
MAX_DIRECTORIES = 10_000
MAX_DEPTH = 64
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_RELATIVE_PATH_CHARS = 1024
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


class IntegrityError(Exception):
    """A safe-to-display validation or filesystem failure."""


def _root_path(raw: str) -> Path:
    path = Path(raw).expanduser()
    if path.is_symlink():
        raise IntegrityError("the monitored root cannot be a symlink")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise IntegrityError(f"cannot access monitored root: {exc.strerror or exc}") from exc
    if not resolved.is_dir():
        raise IntegrityError("monitored root must be a directory")
    return resolved


def _external_manifest(root: Path, raw: str) -> Path:
    candidate = Path(raw).expanduser().resolve(strict=False)
    if candidate == root or root in candidate.parents:
        raise IntegrityError("manifest must be stored outside the monitored root")
    return candidate


def _valid_relpath(path: Any) -> bool:
    if not isinstance(path, str) or not path or len(path) > MAX_RELATIVE_PATH_CHARS:
        return False
    if path.startswith("/") or "\\" in path or any(ord(c) < 32 or ord(c) == 127 for c in path):
        return False
    parts = path.split("/")
    return all(part not in ("", ".", "..") for part in parts) and str(PurePosixPath(path)) == path


def _hash_regular_file(path: Path) -> tuple[int, str]:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise IntegrityError("not a regular file")
            if before.st_size > MAX_FILE_BYTES:
                raise IntegrityError(f"file exceeds {MAX_FILE_BYTES} byte limit")
            digest = hashlib.sha256()
            size = 0
            while block := stream.read(1024 * 1024):
                size += len(block)
                if size > MAX_FILE_BYTES:
                    raise IntegrityError(f"file exceeds {MAX_FILE_BYTES} byte limit")
                digest.update(block)
            after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns) or size != after.st_size:
                raise IntegrityError("file changed while hashing; retry with stable files")
            return size, digest.hexdigest()
    except OSError as exc:
        raise IntegrityError(f"cannot read file ({exc.strerror or exc})") from exc


def snapshot(root: Path) -> dict[str, Any]:
    """Collect a deterministic, strictly bounded snapshot. No network access."""
    files: list[dict[str, Any]] = []
    total = 0
    directories = 0

    def visit(folder: Path, depth: int) -> None:
        nonlocal total, directories
        directories += 1
        if directories > MAX_DIRECTORIES or depth > MAX_DEPTH:
            raise IntegrityError("directory count or nesting depth limit exceeded")
        try:
            with os.scandir(folder) as iterator:
                entries = sorted(iterator, key=lambda e: e.name)
        except OSError as exc:
            raise IntegrityError(f"cannot list directory: {exc.strerror or exc}") from exc
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            if not _valid_relpath(relative):
                raise IntegrityError("unsupported path name in monitored directory")
            try:
                if entry.is_symlink():
                    raise IntegrityError("symlinks are not supported; use a directory without symlinks")
                if entry.is_dir(follow_symlinks=False):
                    visit(path, depth + 1)
                elif entry.is_file(follow_symlinks=False):
                    if len(files) >= MAX_FILES:
                        raise IntegrityError(f"more than {MAX_FILES} files")
                    size, digest = _hash_regular_file(path)
                    total += size
                    if total > MAX_TOTAL_BYTES:
                        raise IntegrityError(f"total file size exceeds {MAX_TOTAL_BYTES} bytes")
                    files.append({"path": relative, "size": size, "sha256": digest})
                else:
                    raise IntegrityError("special files (devices, pipes, sockets) are not supported")
            except OSError as exc:
                raise IntegrityError(f"cannot inspect directory entry: {exc.strerror or exc}") from exc

    visit(root, 0)
    files.sort(key=lambda item: item["path"])
    return {"schema_version": SCHEMA_VERSION, "algorithm": "sha256", "files": files}


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_MANIFEST_BYTES + 1)
    except OSError as exc:
        raise IntegrityError(f"cannot read baseline: {exc.strerror or exc}") from exc
    if len(raw) > MAX_MANIFEST_BYTES:
        raise IntegrityError("baseline manifest exceeds size limit")
    def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result

    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_keys)
    except (UnicodeDecodeError, ValueError) as exc:
        raise IntegrityError("baseline must be valid UTF-8 JSON without duplicate keys") from exc
    if not isinstance(data, dict) or set(data) != {"schema_version", "algorithm", "files"}:
        raise IntegrityError("invalid baseline object keys")
    if type(data["schema_version"]) is not int or data["schema_version"] != SCHEMA_VERSION or data["algorithm"] != "sha256":
        raise IntegrityError("unsupported baseline schema or hash algorithm")
    records = data["files"]
    if not isinstance(records, list) or len(records) > MAX_FILES:
        raise IntegrityError("invalid baseline file list")
    seen: set[str] = set()
    total = 0
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "size", "sha256"}:
            raise IntegrityError("invalid baseline file record")
        name, size, digest = record["path"], record["size"], record["sha256"]
        if not _valid_relpath(name) or name in seen:
            raise IntegrityError("invalid or duplicate baseline path")
        if type(size) is not int or not 0 <= size <= MAX_FILE_BYTES:
            raise IntegrityError("invalid baseline file size")
        if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
            raise IntegrityError("invalid baseline SHA-256 digest")
        seen.add(name)
        total += size
        if total > MAX_TOTAL_BYTES:
            raise IntegrityError("baseline total file size exceeds limit")
    return data


def diff(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    old = {row["path"]: row for row in baseline["files"]}
    new = {row["path"]: row for row in current["files"]}
    return {
        "added": sorted(new.keys() - old.keys()),
        "removed": sorted(old.keys() - new.keys()),
        "modified": sorted(k for k in old.keys() & new.keys() if (old[k]["sha256"], old[k]["size"]) != (new[k]["sha256"], new[k]["size"])),
        "unchanged_count": sum(1 for k in old.keys() & new.keys() if (old[k]["sha256"], old[k]["size"]) == (new[k]["sha256"], new[k]["size"])),
    }


def save_manifest(path: Path, data: dict[str, Any], overwrite: bool = False) -> None:
    if path.exists() and not overwrite:
        raise IntegrityError("baseline already exists (use --overwrite to replace it)")
    if not path.parent.is_dir():
        raise IntegrityError("baseline parent directory does not exist")
    raw = (json.dumps(data, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    if len(raw) > MAX_MANIFEST_BYTES:
        raise IntegrityError("generated baseline exceeds manifest size limit")
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=path.parent, prefix=".integrity-", delete=False) as stream:
            temp_name = stream.name
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    except OSError as exc:
        raise IntegrityError(f"cannot save baseline: {exc.strerror or exc}") from exc
    finally:
        if temp_name is not None:
            try:
                Path(temp_name).unlink(missing_ok=True)
            except OSError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline SHA-256 file integrity baseline and drift checks")
    commands = parser.add_subparsers(dest="command", required=True)
    baseline = commands.add_parser("baseline", help="save a baseline manifest")
    baseline.add_argument("--root", required=True, help="directory of files to monitor")
    baseline.add_argument("--output", required=True, help="manifest JSON outside --root")
    baseline.add_argument("--overwrite", action="store_true", help="replace an existing manifest")
    check = commands.add_parser("check", help="compare current files with saved baseline")
    check.add_argument("--root", required=True)
    check.add_argument("--baseline", required=True, help="saved manifest JSON outside --root")
    check.add_argument("--format", choices=("text", "json"), default="text")
    check.add_argument("--fail-on-drift", action="store_true", help="exit 1 when drift is detected")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        root = _root_path(args.root)
        manifest = _external_manifest(root, args.output if args.command == "baseline" else args.baseline)
        if args.command == "baseline":
            data = snapshot(root)
            save_manifest(manifest, data, overwrite=args.overwrite)
            print(f"Baseline saved: {len(data['files'])} files (SHA-256).")
            return 0
        saved = load_manifest(manifest)
        changes = diff(saved, snapshot(root))
        if args.format == "json":
            print(json.dumps(changes, sort_keys=True))
        else:
            for kind in ("added", "removed", "modified"):
                print(f"{kind.capitalize()}: {len(changes[kind])}")
                for name in changes[kind]:
                    print(f"  {json.dumps(name, ensure_ascii=True)}")
            print(f"Unchanged: {changes['unchanged_count']}")
        return 1 if args.fail_on_drift and any(changes[k] for k in ("added", "removed", "modified")) else 0
    except IntegrityError as exc:
        print(f"Integrity check failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
