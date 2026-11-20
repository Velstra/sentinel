# Velstra Sentinel

<picture>
  <source media="(prefers-color-scheme: dark)" srcset=".github/brand/logo-on-dark.svg">
  <img src=".github/brand/logo.svg" alt="Velstra Sentinel" height="72">
</picture>

Sentinel is an open-source firewall and router for x86-64 UEFI machines. Test a policy change with a timed rollback, trace a hypothetical packet against the compiled configuration, and use witnessed HA when a former owner must stop forwarding after a partition.

**[Read the Sentinel operator guide](https://velstra.github.io/sentinel/)**

| Try it | What to verify |
|---|---|
| [Start a VM](https://velstra.github.io/sentinel/operations/quickstart.html) | Inspect two virtual NICs and log in with your installer-created account. |
| [Change a remote firewall](https://velstra.github.io/sentinel/operations/configure.html) | Confirm from a second session or allow rollback to the saved baseline. |
| [Trace a packet](https://velstra.github.io/sentinel/handbook/firewall.html#asking-before-you-send-packet-trace) | Identify the matching rule, translations and configured route. |
| [Evaluate HA](https://velstra.github.io/sentinel/operations/high-availability.html) | Check witness authority and standby readiness before failover. |
| [Stage an update](https://velstra.github.io/sentinel/operations/update.html) | Review the selected image and stage it on the inactive slot. |

## Build locally

On x86-64 Linux with Nix flakes:

```sh
git clone https://github.com/Velstra/sentinel.git
cd sentinel
nix build .#sentinel-iso --out-link result-iso
```

Boot `result-iso/iso/velstra-sentinel-installer.iso` in a UEFI VM with a new blank disk. Source images use development signing keys. For a disposable CLI evaluation use `nix run .#vm`. [Build prerequisites](https://velstra.github.io/sentinel/building/prerequisites.html)

## Test and contribute

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

[VM and browser test catalog](https://velstra.github.io/sentinel/reference/tests.html) · [Contribution terms](CONTRIBUTING.md) · [AGPL-3.0-or-later](LICENSE)

## Release status

Sentinel 1.0.0 is a release candidate under remediation. It has not been released: no `v1.0.0` tag exists, and the independent release audit of 2026-11-18/19 found blocking issues in both editions that are still being fixed (see the [changelog](CHANGELOG.md)). Do not treat any build of this tree as a production release. HA remains experimental. Review the [dataplane support matrix](docs/src/reference/dataplane-support.md) and [test evidence requirements](docs/src/reference/tests.md) before deployment. Development signing keys are not production trust identities.

Maintainers: [build, qualify and publish downloadable images](docs/releases.md).
