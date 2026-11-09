#!/usr/bin/env bash
# Build-time only. Never guess a different direction for individual files.
set -euo pipefail

if (( $# < 2 )); then
  echo "usage: apply-source-patches.sh PATCH_BINARY PATCH_FILE..." >&2
  exit 2
fi
patch_binary=$1
shift

for patch_file in "$@"; do
  # This helper accepts unified source patches only, never an empty placeholder
  # that GNU patch would otherwise report as a successful no-op.
  if [[ ! -s "$patch_file" ]] || ! grep -q '^@@ ' "$patch_file"; then
    echo "Source patch is empty, missing or has no unified hunks: $patch_file" >&2
    exit 1
  fi
  # --batch --reverse alone may silently ignore -R on some files. --force
  # suppresses that heuristic; either the WHOLE forward or reverse patch fits.
  if "$patch_binary" --force --dry-run --fuzz=0 -p1 --input="$patch_file"; then
    "$patch_binary" --force --fuzz=0 -p1 --input="$patch_file"
  elif "$patch_binary" --force --reverse --dry-run --fuzz=0 -p1 --input="$patch_file"; then
    echo "Exact complete source patch already present: $patch_file"
  else
    echo "Source patch is incomplete or incompatible: $patch_file" >&2
    exit 1
  fi
done
