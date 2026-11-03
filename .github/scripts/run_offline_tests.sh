#!/usr/bin/env bash
set -euo pipefail

# This script is invoked inside a fresh Linux network namespace. pytest-socket
# adds a second Python-level guard against accidental socket use.
python -m compileall -q --invalidation-mode checked-hash .
python -m pytest \
  --quiet \
  --disable-warnings \
  --disable-socket \
  --allow-unix-socket \
  -p no:cacheprovider \
  tests
