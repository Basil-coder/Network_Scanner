# Offline File Integrity Baseline & Drift Checker

A **defensive, standard-library-only** Python 3.10+ CLI for tracking changes in a *small, explicitly selected directory*. It creates a reproducible SHA-256 baseline and later reports files that were **added**, **removed**, or **modified**. It does not scan networks, upload data, or require elevated privileges.

## Quick start (synthetic files only)

From the repository root, on Linux/macOS:

```bash
mkdir -p /tmp/portfolio-integrity-demo
printf 'example=true\n' > /tmp/portfolio-integrity-demo/app.conf
python integrity/file_integrity.py baseline --root /tmp/portfolio-integrity-demo --output /tmp/portfolio-baseline.json
printf 'example=false\n' > /tmp/portfolio-integrity-demo/app.conf
python integrity/file_integrity.py check --root /tmp/portfolio-integrity-demo --baseline /tmp/portfolio-baseline.json --format json --fail-on-drift
# Exit status 1 indicates drift. 0 indicates no drift; 2 indicates an error.
```

The output is JSON with `added`, `removed`, `modified` (sorted relative file paths), and `unchanged_count`. Use `--format text` (default) for a human-readable report. On Windows, substitute a writable temporary folder and use `python` or `py`.

## How it works

1. `baseline` walks the chosen root without following symlinks, hashes regular files in 1 MiB blocks, and writes a versioned JSON manifest **outside** the monitored root. Existing baselines are protected unless `--overwrite` is supplied.
2. `check` validates the manifest schema and bounds, independently hashes the current files, and compares paths, sizes and SHA-256 values. No original file contents are stored in the baseline.
3. Ordering and manifest serialization are deterministic; no timestamps or host identifiers are included. Output is machine-readable for an incident investigation or offline CI job.

**Safety controls:** fail closed on symlinks, FIFOs, sockets and other special files; refuse noncanonical/unsafe manifest paths and duplicate records; cap inputs at 10,000 files, 10,000 directories, 64 levels of nesting, 16 MiB per file, 512 MiB total, and 4 MiB per manifest. The tool does not execute monitored files, make network connections, or traverse symlinks. Root and baseline must be separate directories. It uses only the Python standard library.

**Security limitations:** SHA-256 is for change detection, not authentication. An attacker who can edit both monitored files and the baseline can conceal changes; protect the baseline with independent access controls, ideally off-host. A modified file is **not evidence of malicious activity**. File names, sizes, and hashes can themselves be sensitive; don't commit real manifests or incident data. This is not a real-time monitor and is not hardened against hostile concurrent directory replacement or all filesystem races; use on a stable, trusted directory. Symlinks and special files are deliberately unsupported. The size limits make this suitable for small configuration or script directories, not entire drives.

## Offline verification

```bash
python -m unittest discover -s tests -p 'test_file_integrity.py' -v
python -m unittest discover -s tests -v
```

The tests use only temporary synthetic files, do not need Scapy, and do not send network traffic. Test coverage includes clean baselines, all three drift types, same-size content changes, deterministic ordering, unsafe paths, malformed JSON, file-size bounds, symlinks, and exit codes.

## Technical decisions / interview talking points

- **SHA-256 over file size/mtime alone:** detects same-size edits and avoids relying on mutable timestamps.
- **Relative paths and stable ordering:** make baselines portable across different absolute root locations and reproducible.
- **Explicit scope and strict caps:** reduce accidental reads of huge or sensitive trees and denial-of-service risk from untrusted manifests.
- **Fail-closed file types and validation:** avoid following symlinks outside the selected root and reject malformed/ambiguous baseline records.
- **Separation of baseline from watched directory:** avoids the manifest monitoring itself and makes independent protection possible.

**Portfolio disclosure:** This project was created with AI assistance and must receive human review before merging. Test results should only be claimed for commands actually executed; this documentation does not imply production deployment, live incident response, or external security certification.
