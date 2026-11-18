#!/usr/bin/env bash
# Bootstrap the shell from the same immutable lock as the release utilities.
# nix-shell prepends the shell's directory to PATH; /bin/bash would shadow
# pinned Python, QEMU and signing utilities with host binaries from /bin.
set -euo pipefail
if [ "$#" -eq 0 ]; then
  echo 'Usage: bash scripts/release-tools.sh COMMAND [ARG ...]' >&2
  exit 2
fi
release_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
release_shell=$(nix-build "$release_root/nix/release-tools.nix" -A releaseShell --no-out-link)
export NIX_BUILD_SHELL="$release_shell/bin/bash"
printf -v release_command '%q ' "$@"
exec nix-shell "$release_root/nix/release-tools.nix" --run "$release_command"
