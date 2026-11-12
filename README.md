# Velstra Sentinel

Firewall and routing appliance with an immutable A/B OS, a CLI and an embedded
web console. Both interfaces manage the same `appliance.toml`.

## Build and install

Build host: x86_64 Linux with [Nix and flakes](docs/src/building/prerequisites.md).
Users only need the resulting ISO, not Nix.

```sh
git clone https://github.com/Velstra/sentinel.git
cd sentinel
nix build .#sentinel-iso --out-link result-iso
```

Boot `result-iso/iso/velstra-sentinel-installer.iso`, follow the installer,
then eject the ISO and reboot. Installation erases the selected disks.
Source builds use development signing keys, not production trust.

For QEMU or Proxmox, follow the [VM quickstart](docs/src/operations/quickstart.md).
For a development VM instead of the installed image:

```sh
nix run .#vm
```

## Use

On the installed appliance:

```sh
sentinel show interfaces
sentinel show version
sentinel config check /var/lib/sentinel/appliance.toml
sentinel configure
```

Use `set`, `commit` and `save` in the configuration session.
The [CLI guide](docs/src/handbook/cli.md) explains the workflow.
The [quickstart configuration](examples/quickstart.cli) adds WAN DHCP, LAN,
NAT and HTTPS management; adapt its interface names before applying it.
Confirm provisional web changes with **Keep change**, or they roll back.

## Test and develop

Run these on a workstation, not on an installed appliance. Cargo builds need
Rust; UI tests additionally need Node.js and Chromium.

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

With Nix and writable `/dev/kvm`, run actual appliance VM checks:

```sh
nix build .#checks.x86_64-linux.quickstart .#checks.x86_64-linux.bootfallback -L
```

[Browser/UI tests](tests/console/README.md) ·
[Full test catalog](docs/src/reference/tests.md) ·
[Build outputs](docs/src/reference/flake-outputs.md)

## Documentation

[Install](docs/src/operations/install.md) ·
[Configuration](docs/src/operations/configure.md) ·
[Firewall/NAT](docs/src/handbook/firewall.md) ·
[Routing](docs/src/handbook/routing.md) ·
[HA](docs/ha-phase3.md) ·
[A/B updates](docs/src/operations/update.md)

## License

[AGPL-3.0-or-later](LICENSE). Commercial licensing is available; contributions
are covered by the project CLA.
