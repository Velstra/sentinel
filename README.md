# Velstra Sentinel

A standalone **firewall / router appliance** built on the
[Velstra](https://github.com/Velstra/fabric) eBPF/XDP data plane.

Where [`Velstra Fabric`](https://github.com/Velstra/fabric) is the engine — an
XDP firewall, router, load balancer, and VXLAN/Geneve overlay with an HA control
plane — **Sentinel is the product on top**: the turnkey appliance, in the shape
of VyOS or pfSense but Rust-and-eBPF all the way down. The appliance layer is
config management, an admin/control surface, an OS image, and box-level HA.

> **Status: skeleton.** This repo is just getting started. The first slice is a
> CLI that speaks the Velstra control-plane protocol
> ([`velstra-proto`](https://crates.io/crates/velstra-proto)) to a controller —
> proving the shared-protocol wiring across repos. Real appliance features build
> out from here.

## Try it

```shell
cargo run -- ports --controller http://127.0.0.1:50052
```

Point it at a running Velstra controller and it lists the fabric's ports over
gRPC — the same wire types the Velstra agent and CNI use.

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
