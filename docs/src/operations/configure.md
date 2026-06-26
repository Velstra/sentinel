# Configuring the appliance

`sentinel configure` is the VyOS/vtysh-style candidate session. You edit a
candidate, `compare` it, then `commit` (apply live) and/or `save` (persist).

## A session

```text
$ sentinel configure
sentinel# set system hostname fw-a
sentinel# set interface eth0 role wan
sentinel# set interface eth0 address dhcp
sentinel# compare
     system {
-        hostname sentinel
+        hostname fw-a
     }
sentinel# commit save
sentinel# exit
```

- **`commit`** applies the candidate to the running system (live).
- **`save`** persists it to `/var/lib/sentinel/appliance.toml`.
- **`commit save`** does both. See [the commit model](../architecture/commit-model.md).

## Completion (the vtysh feel)

- **`?`** or **Tab** shows suggestions **with descriptions**, one per line.
- At a value position that names an interface, completion offers the **real
  NICs** discovered from `/sys/class/net` (e.g. `set interface <Tab>` →
  `eth0`, `lo`, …) — so you complete against what the box actually has.
- Completion is context-aware: `show interfaces <Tab>` suggests interface names,
  not the same keywords as the level above.

## Operational `show` (outside configure)

From a plain shell, `sentinel show <what> [target]` reflects live system state:

```shell
sentinel show status
sentinel show interfaces [<iface>]   # scope to one NIC, vtysh-style
sentinel show routes
sentinel show neighbors
sentinel show config
sentinel show log
sentinel show version
```

## Off-box editing

`sentinel configure --no-apply` edits the candidate without touching the running
system — useful for preparing a config off the box or in CI. `compare` still
shows the diff against the saved config; `commit` in this mode is session-only.

## Discovered interfaces

Even before you assign anything, the real NICs show up in the config (VyOS-like),
so they're ready to reference. The minimal factory config has no interfaces of
its own; `show` in a fresh session lists what the hardware provides.
