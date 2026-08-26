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

> **Status: working appliance, pre-1.0.** This is a substantial system
> (~80k lines of Rust across ~40 modules), not a skeleton, and most of it is
> exercised by the in-repo nixosTest suite. Implemented today:
>
> - **Config & apply** — the declarative config model and interactive `configure`
>   CLI (`commit` / `commit-confirm` / `rollback` / `save`), a timestamped config
>   archive with `rollback <N>` and `compare`, and a transactional apply that
>   unwinds already-applied steps in reverse on failure.
> - **Data plane** — the config→data-plane compiler driving the Velstra XDP
>   firewall, NAT (masquerade / DNAT / CGNAT / NPTv6), L4 load balancing, address
>   and port groups, per-rule rate limits, and QoS (CAKE / fq_codel).
> - **Immutable OS** — the A/B disk image with dm-verity boot and Secure Boot,
>   **LUKS2 data-partition encryption** (TPM2-sealed with a recovery passphrase),
>   an installer (CLI + interactive TUI) and a live-boot ISO first-boot wizard,
>   and a **signature-enforced update path** (a detached Ed25519 signature over
>   the release manifest verified under an operator-pinned public key; an image
>   whose signature or digest does not verify is refused).
> - **Management plane** — a **TLS-by-default** REST API and read-only web console
>   (a self-signed cert is minted and persisted on first boot and its public-key
>   pin printed for config-sync peers), a Prometheus `/metrics` endpoint, per-IP
>   and per-account login throttling, plus remote syslog and IPFIX flow export.
> - **Routing & VPN** — dynamic routing (BGP / OSPF / OSPFv3 / IS-IS / RIP / Babel
>   / VRRP / BFD via the Wren control plane), VPN (WireGuard / IPsec-IKEv2 /
>   OpenConnect), multi-WAN with health-checked failover, and PPPoE client **and**
>   server (the BNG / access-concentrator role).
> - **Services & security** — on-box PKI + ACME, intrusion detection (Suricata in
>   IDS mode, with enforcement through the eBPF blocklist), AAA (RADIUS / LDAP /
>   TOTP), a captive portal, and box services (DHCP, DNS, NTP, SNMP, LLDP, …).
>
> It also talks to a Velstra controller over
> [`velstra-proto`](https://crates.io/crates/velstra-proto) — today a single
> `ports` query, the first use of the shared wire types. **Most of the above is
> verified in the nixosTest VM suite; it is not yet validated end-to-end on
> physical hardware** — ACME live issuance and the TPM2-sealed unlock in
> particular exercise real boot/reachability paths a VM check cannot fully stand
> in for. Pre-1.0: config surface and defaults may still change.

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
