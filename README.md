# Velstra Sentinel

A standalone, **immutable** firewall / router appliance OS, built on the
[Velstra](https://github.com/Velstra/fabric) eBPF/XDP data plane.

Where [`Velstra Fabric`](https://github.com/Velstra/fabric) is the engine — an
XDP firewall, router, load balancer, and VXLAN/Geneve overlay with an HA control
plane — **Sentinel is the appliance on top**: an open-source firewall/router box,
Rust-and-eBPF all the way down.

**Not VyOS.** It is deliberately *not* a mutable system you SSH into and tweak.
Sentinel is **image-based and immutable**: the running OS is read-only, and the
whole box is described by one **declarative config** that the system reconciles
to atomically (closer in spirit to Talos than to VyOS/pfSense). You change the
appliance by changing its config and re-applying — never by editing live state.

> **Status: skeleton.** First slice: the **programmable, declarative CLI** —
> author/validate the appliance config, and talk to a Velstra controller over
> [`velstra-proto`](https://crates.io/crates/velstra-proto). The immutable OS
> image and the config→data-plane compiler build out from here.

## Try it

```shell
# Author the declarative config.
cargo run -- config init > appliance.toml          # commented starter
cargo run -- config check appliance.toml           # parse + validate
cargo run -- config show  appliance.toml           # normalized summary
cargo run -- config convert appliance.toml --to json  # TOML <-> JSON

# Talk to a running Velstra controller.
cargo run -- ports --controller http://127.0.0.1:50052
```

## Documentation

The full handbook — **how to build the images**, the appliance model (verified
boot, A/B updates, Secure Boot), and how to install/configure/update — lives in
[`docs/`](docs/) as an [mdBook](https://rust-lang.github.io/mdBook/):

```shell
nix run nixpkgs#mdbook -- serve docs   # live preview at http://localhost:3000
nix run nixpkgs#mdbook -- build docs   # static HTML in docs/book/

# the two build commands the handbook is built around:
nix build .#sentinel-image             # the flashable, signed appliance disk image
nix build .#sentinel-iso               # the live-boot installer ISO
```

It is published to GitHub Pages on push (see `.github/workflows/docs.yml`).
Historical design notes (the original `os.md` / `commit-model.md`) are preserved
in the book's appendix; the architecture chapters are authoritative where they
differ.

The config declares interfaces (with zone roles), addresses, and zone-to-zone
firewall rules; `ports` lists a controller's fabric ports over gRPC — the same
wire types the Velstra agent and CNI use.

## Architecture (intended)

```
        Sentinel (this repo) — appliance: config mgmt, admin API, OS image, HA
                │ velstra-proto (gRPC)
                ▼
        Velstra Fabric — data plane (XDP/eBPF) + control plane (controller/agent)
```

Sentinel depends on the shared Velstra crates from crates.io. Today that is
`velstra-proto`; the data-plane crates (`velstra-common`, `velstra-config`) join
once they leave their git-`aya` dependency behind and publish.

## License

**AGPL-3.0-or-later** — see [`LICENSE`](LICENSE). Like Velstra Fabric, the
product is copyleft; a commercial license is available for organisations that
cannot use the AGPL. Contributions are under the project CLA (to keep
dual-licensing possible).
