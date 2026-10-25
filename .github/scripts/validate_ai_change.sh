#!/usr/bin/env bash
set -euo pipefail

base_sha="${1:?base SHA is required}"

if [[ "$(git rev-parse HEAD)" != "$base_sha" ]]; then
  echo "::error::Codex created a commit. The automation only accepts uncommitted workspace changes."
  exit 1
fi

# Intent-to-add makes newly created, still-untracked files visible to every
# subsequent git diff check without staging their contents.
git add -N -- .

if git diff --quiet "$base_sha" --; then
  echo "::error::Codex did not produce a meaningful change."
  exit 1
fi

git diff --check "$base_sha" --

mapfile -t changed_files < <(git diff --name-only --diff-filter=ACMR "$base_sha" --)
if (( ${#changed_files[@]} == 0 || ${#changed_files[@]} > 20 )); then
  echo "::error::Expected 1-20 added or modified files; found ${#changed_files[@]}."
  exit 1
fi

has_implementation=false
has_test=false
for path in "${changed_files[@]}"; do
  case "$path" in
    .github/*)
      echo "::error file=$path::Codex may not modify trusted automation files."
      exit 1
      ;;
    tests/test_*.py|tests/*_test.py)
      has_test=true
      ;;
    *.py)
      has_implementation=true
      ;;
  esac

  mode="$(git ls-files -s -- "$path" | awk '{print $1}')"
  if [[ "$mode" == "120000" || "$mode" == "160000" ]]; then
    echo "::error file=$path::Symlinks and submodules are not accepted from automated changes."
    exit 1
  fi
done

if [[ "$has_implementation" != "true" ]]; then
  echo "::error::The proposal must include a substantive Python implementation change."
  exit 1
fi
if [[ "$has_test" != "true" ]]; then
  echo "::error::The proposal must add or update a focused Python test."
  exit 1
fi

while IFS=$'\t' read -r added deleted path; do
  if [[ "$added" == "-" || "$deleted" == "-" ]]; then
    echo "::error file=$path::Binary changes are not accepted."
    exit 1
  fi
done < <(git diff --numstat "$base_sha" --)

changed_lines="$(git diff --numstat "$base_sha" -- | awk '{ added += $1; deleted += $2 } END { print added + deleted }')"
if (( changed_lines > 2000 )); then
  echo "::error::The ${changed_lines}-line patch is too large for an automated proposal."
  exit 1
fi

if git diff --summary "$base_sha" -- | grep -Eq 'mode change|create mode 120000|create mode 160000'; then
  echo "::error::Automated changes may not alter executable modes or introduce links/submodules."
  exit 1
fi

if git diff -U0 "$base_sha" -- | grep -E '^\+.*(AKIA[0-9A-Z]{16}|sk-(proj-)?[A-Za-z0-9_-]{20,}|BEGIN (RSA|OPENSSH|EC) PRIVATE KEY)' >/dev/null; then
  echo "::error::The proposed diff resembles a credential or private key."
  exit 1
fi

echo "Validated ${#changed_files[@]} changed file(s) and ${changed_lines} changed line(s)."
