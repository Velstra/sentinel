# Velstra Sentinel

**Velstra Sentinel** is a standalone, **immutable** firewall / router appliance
OS, built on the [Velstra Fabric](https://github.com/Velstra/fabric) eBPF/XDP
data plane and packaged with NixOS.

Where *Velstra Fabric* is the engine — an XDP firewall, router, load balancer,
and VXLAN/Geneve overlay with an HA control plane — **Sentinel is the appliance
on top**: an open-source firewall/router box, Rust-and-eBPF all the way down.

## What makes it an appliance

Sentinel is **not** a mutable system you SSH into and tweak. It is image-based
and immutable, the way real appliance OSes (Talos, VyOS, OPNsense) are:

- **Verified boot.** The Nix store ships on a **dm-verity**-protected partition
  whose root hash is sealed into a Unified Kernel Image (UKI). The kernel mounts
  `/nix/store` only if it matches — tamper detection at block level. Root is a
  volatile `tmpfs`; the one persistent partition holds the editable config.
- **Secure Boot.** The whole boot chain (systemd-boot + the UKI) is signed; the
  appliance ships PK/KEK/db enrollment payloads so the firmware enforces it.
- **A/B updates with auto-rollback.** Two store slots; an update writes the
  inactive one and systemd-boot's automatic boot assessment rolls back if the new
  slot fails to come up cleanly three times.
- **Runtime config apply — no rebuild, no reboot.** `sentinel configure` →
  `commit` applies firewall, hostname, and interface changes to the *running*
  system, fully airgapped. The OS image is fixed; only running services and the
  one persistent config partition change. (See
  [the commit model](architecture/commit-model.md).)

## Where to start

- **Just want to build the images?** Jump to [Building images](building/images.md).
- **Want to understand how it boots and updates?** Read
  [The appliance model](architecture/overview.md).
- **Putting it on hardware?** See [Installing to disk](operations/install.md).

> **A note on the appendix.** The two *historical design notes* at the end
> (`Original OS design notes`, `Original commit-model notes`) describe an earlier
> **rebuild-on-commit** design that was investigated and **rejected**. They are
> kept for context only. The implemented model is the image + runtime-apply model
> documented in the Architecture chapters — when the two disagree, the
> Architecture chapters are authoritative.

## License

**AGPL-3.0-or-later** — a commercial license is available for organisations that
cannot use the AGPL. Contributions are under the project CLA to keep
dual-licensing possible.
