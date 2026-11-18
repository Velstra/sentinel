# Use the configuration CLI

<a id="the-configuration-cli"></a>

Run `sentinel configure` on the appliance. Edits belong to a candidate until you apply them. A star in the prompt signals outstanding changes.

## Try a harmless edit

```text
set system hostname edge-lab
compare
discard
```

The diff shows the hostname change. Discarding it leaves the running configuration untouched. Use `?` or Tab after a path to discover the next field.

<a id="one-grammar"></a><a id="editing-the-candidate"></a><a id="applying--persisting"></a>

## Choose a command

| Command in the session | Result |
|---|---|
| `show`, `set`, `delete` | Inspect or edit the candidate. |
| `edit`, `up`, `top` | Move through the configuration tree. |
| `compare`, `discard` | Review or abandon pending edits. |
| `commit`, `save` | Apply to the running system, then persist across reboot. |
| `commit-confirm 2`, `confirm` | Apply provisionally with a two-minute window, then accept. Save explicitly for persistence. |
| `show system commit`, `compare N` | List saved revisions or compare against revision N. |
| `rollback N` | Apply and persist an archived revision. `0` is the newest. |

<a id="operational-commands-run-show--show"></a>

## Inspect the running appliance

```sh
sentinel show interfaces
sentinel show ip route
sentinel show ip bgp summary
sentinel show firewall statistics
sentinel show nat
```

At a configuration prompt, prefix operational commands with `run`. See [remote changes](../operations/configure.md) for a worked confirmation and recovery sequence.

## Read the applied configuration

`sentinel show configuration` reports the last successfully applied snapshot, or the saved configuration before the first live commit. It does not show another session's pending candidate. Treat configuration output as sensitive; use narrowed operational commands when sharing diagnostics. See [commit, confirm and save](../architecture/commit-model.md) for persistence and API differences.
