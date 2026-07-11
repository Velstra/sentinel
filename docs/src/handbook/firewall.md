# Firewall & NAT

Sentinel's firewall is **zone-based** and enforced in the eBPF/XDP data plane.
Every firewalled interface belongs to a *zone*; posture (stateful, ICMP,
default action) is set globally and overridden per zone; and `rule`s open
specific proto/port/source between zones. NAT (masquerade, port-forward,
NAT64, NPTv6) lives under `nat`.

## Zones & posture

A zone is just a name you assign to interfaces (`set interface eth0 zone wan`).
`firewall global` sets the defaults every zone inherits; `firewall zone <name>`
overrides them for one zone.

| Field (`global` / `zone <name>`) | Meaning |
|---|---|
| `default-action` | Default ingress action: `accept` / `drop` / `reject`. |
| `stateful` | Track flows so return traffic is allowed (`true`/`false`). |
| `block-icmp` | Drop inbound ICMP by default (`true`/`false`). |
| `log` | Log matched traffic by default (`true`/`false`). |
| `block <IP\|CIDR>` | Drop a source everywhere (`global`) or on one zone. |
| `description` | (zone only) free-text label. |

```text
set firewall global default-action drop        # deny by default
set firewall global stateful true
set firewall zone wan block-icmp true          # quiet on the WAN
set firewall zone lan default-action accept    # trust the LAN
```

## Rules

`firewall rule <name>` is a zone-to-zone allow/deny. A rule with a `proto` +
`port` is a specific service rule; a broad rule (`from`/`to`/`action` only)
sets a zone-pair posture.

| Field | Meaning |
|---|---|
| `from` / `to` | Source / destination zone. |
| `action` | `accept` / `drop` / `reject`. |
| `proto` | `tcp` / `udp`. |
| `port` | Destination port or range (`443`, `8000-8100`). |
| `source` | Source address/CIDR (default: any). |
| `source-group` / `port-group` | Match an [alias](#groups-aliases) instead. |
| `log` | Log packets matching this rule (`true`/`false`). |
| `schedule` | A time-based activation window (see below). |
| `description` / `disabled` | Label / administratively disable. |

```text
# Allow HTTPS from the WAN to a published service:
set firewall rule https-in from wan
set firewall rule https-in to lan
set firewall rule https-in proto tcp
set firewall rule https-in port 443
set firewall rule https-in action accept
```

### Time-based rules

A rule may carry a weekly local-time schedule; it is only in force while its
window is open (a systemd timer re-applies at the boundaries).

```text
set firewall rule guest-wifi from guest
set firewall rule guest-wifi proto tcp
set firewall rule guest-wifi port 0-65535
set firewall rule guest-wifi action accept
set firewall rule guest-wifi schedule days mon,tue,wed,thu,fri
set firewall rule guest-wifi schedule start 09:00
set firewall rule guest-wifi schedule end 17:00
```

## Groups (aliases)

Named address / port sets you reference from rules, so one edit updates every
rule that uses them.

```text
set firewall group address-group admins address 10.0.0.10,10.0.0.11
set firewall group port-group web port 80,443,8443

set firewall rule mgmt from lan
set firewall rule mgmt proto tcp
set firewall rule mgmt source-group admins
set firewall rule mgmt port-group web
set firewall rule mgmt action accept
```

## NAT

`nat` has four kinds of translation:

| Node | What it does |
|---|---|
| `source` | SNAT / masquerade a zone's outbound traffic (the classic WAN NAT). |
| `destination` | Inbound DNAT port-forward to an internal host. |
| `nat64` | Stateful IPv6→IPv4 translation (tayga) + DNS64 (unbound). |
| `npt66` | Stateless IPv6 prefix translation (RFC 6296, checksum-neutral). |

### Source NAT (masquerade)

```text
set nat source wan-masq zone wan            # masquerade everything leaving wan
```

### Destination NAT (port-forward)

| Field | Meaning |
|---|---|
| `zone` | Ingress zone (the public side). |
| `proto` | `tcp` / `udp`. |
| `port` | Public destination port. |
| `to` | Internal target `ip` or `ip:port`. |
| `hairpin` | NAT reflection — reach the service via the public IP from inside. |

```text
set nat destination web zone wan
set nat destination web proto tcp
set nat destination web port 443
set nat destination web to 10.0.0.10:8443
set nat destination web hairpin true
```

### NAT64 / NPTv6

```text
set nat nat64 enabled true
set nat nat64 prefix 64:ff9b::/96
set nat nat64 pool 100.64.0.0/24
set nat nat64 interface eth1
set nat nat64 dns64 true
```

`npt66` maps an internal ULA prefix to a delegated external prefix statelessly —
configured per interface via `[nat.npt66]` (internal ↔ external `/48`s); see
`show nat`.
