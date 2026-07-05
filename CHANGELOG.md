# Changelog

## [0.1.0] — 2026-07-05

First tagged release of the Sentinel immutable firewall/router appliance.

### Included
- Named zones + per-zone posture, VLANs, firewall (address/port groups,
  port ranges, per-rule log, source-CIDR, reject), NAT (masquerade + DNAT
  port-forwards).
- WireGuard (C1); DHCPv4 + RA/SLAAC + DNS (dnsmasq: forwarding, host-
  overrides, blocklists) + NTP (C7); dual-stack IPv6 + DHCPv6-PD.
- Bridges + bonding, per-interface MTU/MAC (C14 part); full routing CLI
  (BGP/OSPF/OSPFv3/IS-IS/RIP/RIPng/Babel/VRRP/static).
- **PPPoE client + TCP-MSS clamping (C5)** — real WAN uplinks.
- **QoS / traffic shaping (C8)** — per-interface CAKE / fq_codel.
- Verified boot / A-B / secure boot / atomic commit with commit-confirm,
  config archive, rollback-N, diff (C21).

### Not yet included (roadmap)
- IPsec (C2), multi-WAN (C6), stateful HA (C9), IDS/IPS (C11), REST/Web UI
  + AAA (C12), signed update channel (C13), PKI/ACME (C19), and the rest of
  the C-track parity list.
