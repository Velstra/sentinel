# What commit, confirm and save do

<a id="the-commit-model-runtime-apply"></a>

A configuration change reconciles running services without rebuilding or rebooting the OS.

<a id="undo-and-safety-nets"></a>

## Apply a reversible change

```text
set system hostname branch-a
compare
commit-confirm 2
```

Run these commands in a configuration session with a saved baseline. From a second session, verify management access. Run `confirm` before the timer expires, then `save` to keep the change across reboot. Without confirmation, the timer reapplies the saved baseline.

<a id="commit-vs-save"></a><a id="how-it-persists-across-reboot"></a>

## Choose the correct operation

| Operation | Effect |
|---|---|
| `compare` | Inspect pending changes before applying. |
| `commit` | Apply to running services. A future boot still reads the saved file. |
| `commit-confirm N` | Apply provisionally for N minutes, with a saved baseline for recovery. |
| `confirm`, then `save` | Cancel the CLI rollback timer, then persist the running configuration. |
| `discard` | Drop candidate edits that have not been committed. |
| `rollback N` | Apply and persist an archived revision. `0` is the newest. |

<a id="what-a-commit-reconciles"></a><a id="atomicity-and-rollback"></a><a id="privilege-path"></a>

## Recover a partial apply

Sentinel compiles the candidate before applying it and serializes concurrent applies. The firewall, routing and hostname stages track undo actions. A later service-stage failure can leave a mixed state. Read the failure, retain console access and restore a known saved revision. [Operator walkthrough](../operations/configure.md).

<a id="verifying-it"></a>

## Validate in a VM

```sh
nix build .#checks.x86_64-linux.commit -L
```

This check verifies live apply and persistence across reboot.
