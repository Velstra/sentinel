#!/usr/bin/env bash
# Evaluate every check without retaining all NixOS module graphs, and verify
# the interactive/override interfaces used when diagnosing a failing check.
set -euo pipefail

flake=${1:-.}
if (($#)); then
  shift
fi
nix_flags=(--no-write-lock-file --option eval-cache false "$@")

# Bound a complete evaluation so a regression fails instead of exhausting
# the build host. Callers can select tighter limits through the GC environment.
export GC_MAXIMUM_HEAP_SIZE=${GC_MAXIMUM_HEAP_SIZE:-14G}
export GC_FREE_SPACE_DIVISOR=${GC_FREE_SPACE_DIVISOR:-16}

nix flake check "$flake" --no-build --keep-going "${nix_flags[@]}"

nix eval --json "${flake}#checks.x86_64-linux.config-transaction" \
  "${nix_flags[@]}" --apply '
    test:
    assert test ? config && test ? driver && test ? driverInteractive && test ? nodes;
    assert builtins.attrNames test.nodes != [];
    {
      driver = test.driver.drvPath;
      interactive = test.driverInteractive.drvPath;
      scriptHash = builtins.hashString "sha256" test.config.testScript;
    }
  '

nix eval --json "${flake}#checks.x86_64-linux.console" \
  "${nix_flags[@]}" --apply '
    test:
    assert test ? overrideAttrs;
    assert (test.overrideAttrs (_: {})).drvPath == test.drvPath;
    { unchangedOverride = test.drvPath; }
  '
