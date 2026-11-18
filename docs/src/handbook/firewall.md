# Firewall, NAT and packet tracing

<a id="firewall--nat"></a>

Use the trace command to explain the configured outcome for a packet. Use live counters and logs to investigate actual traffic. Configuration examples run inside `sentinel configure`.

## Asking before you send (packet trace)

For example, determine whether a guest on `lan0` can reach SSH on a DMZ server. Replace interface names and addresses with ones from your configuration.

```text
sentinel trace --in lan0 tcp 10.0.0.200 10.9.0.10 22
```

With a matching guest-deny rule, the important result can look like this:

```text
verdict:   drop (no-ssh-from-guests)
```

Read the ingress zone, route, NAT translations and matched rule above the verdict. The model uses compiled configuration. Established connection state, dynamic routes and current multi-WAN health require live inspection. The web console exposes the same walk under **Policy → Packet trace**.

## Zones & posture

Assign interfaces to zones before using zone-specific defaults. Set the global default and override only the zones that need a different policy.

```text
set firewall global default-action drop        # deny by default
set firewall global stateful true
set firewall zone wan block-icmp true          # quiet on the WAN
set firewall zone lan default-action accept    # trust the LAN
```

## Rules

Scope each rule to the intended ingress and destination before applying it. This example scopes SSH to the management subnet and the firewall itself.

```text
set firewall rule mgmt-ssh from mgmt
set firewall rule mgmt-ssh to firewall
set firewall rule mgmt-ssh source 192.0.2.0/24
set firewall rule mgmt-ssh proto tcp
set firewall rule mgmt-ssh port 22
set firewall rule mgmt-ssh action accept
```

### The destination zone

For a port rule targeting a zone, verify the destination against that zone’s configured subnets. Use the packet trace to inspect the matched rule.

### Rate limits

Cap newly admitted flows per second with `limit`. Set `burst` to allow a short peak.

```text
set firewall rule ssh-in from wan
set firewall rule ssh-in proto tcp
set firewall rule ssh-in port 22
set firewall rule ssh-in action accept
set firewall rule ssh-in limit 5
set firewall rule ssh-in burst 10
```

### Time-based rules

A weekly schedule uses the appliance’s local timezone. Check the clock and the rule’s active window when troubleshooting.

```text
set firewall rule guest-wifi from guest
set firewall rule guest-wifi proto tcp
set firewall rule guest-wifi port 0-65535
set firewall rule guest-wifi action accept
set firewall rule guest-wifi schedule days mon,tue,wed,thu,fri
set firewall rule guest-wifi schedule start 09:00
set firewall rule guest-wifi schedule end 17:00
```

### ICMP message types

Use a typed ICMP or ICMPv6 rule when only specific messages should be allowed. Keep required path-MTU and neighbor-discovery traffic in the policy.

```text
# Answer pings from the management network, and nowhere else.
set firewall rule ping-mgmt from mgmt
set firewall rule ping-mgmt to firewall
set firewall rule ping-mgmt proto icmp
set firewall rule ping-mgmt icmp-type echo-request
set firewall rule ping-mgmt action accept

# Path MTU discovery has to work, whatever else is refused.
set firewall rule pmtu from wan
set firewall rule pmtu proto icmpv6
set firewall rule pmtu icmp-type packet-too-big
set firewall rule pmtu action accept
```

## Blocking by country (GeoIP)

Country codes select prefixes in the GeoIP database included in the appliance image. Review coverage and freshness before relying on a geographic rule.

```text
set firewall zone wan geoip-block CN,RU
```

## Source validation (anti-spoofing)

Source-validation mode controls which incoming source addresses the zone will admit. Check routing symmetry before choosing strict mode.

```text
set firewall zone wan source-validation strict
```

## IPv6 and extension headers

Check both address families when testing an interface policy. A family-specific source prefix only matches within that family.

## Groups (aliases)

Name frequently reused address, interface or port sets and refer to the group from rules.

### Some of a zone, not all of it

An interface group selects specific links within a zone. Use it to limit a rule to those ingress ports.

```text
set firewall group interface-group trusted interface eth0,eth1
set firewall rule ssh-trusted from lan
set firewall rule ssh-trusted proto tcp
set firewall rule ssh-trusted port 22
set firewall rule ssh-trusted action accept
set firewall rule ssh-trusted interface-group trusted
```

### Devices, not addresses

A MAC group matches link-layer addresses on its local segment. Use it for classification; a MAC address does not authenticate the device.

```text
set firewall group mac-group printers mac aa:bb:cc:dd:ee:ff,aa:bb:cc:dd:ee:01
set firewall rule no-printers from lan
set firewall rule no-printers source-mac-group printers
set firewall rule no-printers action drop
```

### Domain groups

A domain group resolves configured DNS names to addresses. Recheck the resolved addresses when a service changes its endpoints.

```text
set firewall group domain-group trackers domain ads.example.com,metrics.example.net

set firewall rule no-trackers from lan
set firewall rule no-trackers proto tcp
set firewall rule no-trackers port 443
set firewall rule no-trackers action drop
set firewall rule no-trackers destination-group trackers
```

## Protocols a rule can match

Select the protocol before adding transport-specific fields such as ports. Use CLI completion to inspect the accepted protocol names.

```
set firewall rule ping from wan
set firewall rule ping proto icmp
set firewall rule ping action accept
```

## NAT

Use source NAT for outbound masquerading and destination NAT for a published service. Verify the translated address and port with the packet trace before rolling out a forwarding rule.

### Source NAT (masquerade)

Source masquerading can use the WAN interface’s current IPv4 address, including a DHCP lease.

```text
set nat source wan-masq zone wan            # masquerade everything leaving wan
```

#### Deterministic CGNAT

A deterministic block maps an internal address to a known port range. Check pool size and subscriber capacity before applying the design.

```text
set nat source wan-masq zone wan
set nat source wan-masq cgnat-block-size 512      # ports per internal address
set nat source wan-masq cgnat-base-port 32768     # optional; this is the default
```

### Destination NAT (port-forward)

Specify the external zone, protocol and service port together with the internal destination. Use the packet trace to inspect the translation.

```text
set nat destination web zone wan
set nat destination web proto tcp
set nat destination web port 443
set nat destination web to 10.0.0.10:8443
set nat destination web hairpin true
```

### NAT64 / NPTv6

NAT64 translates between address families using its configured prefix and pool. NPTv6 translates between IPv6 prefixes. Use the mode appropriate for the addressing plan.

```text
set nat nat64 enabled true
set nat nat64 prefix 64:ff9b::/96
set nat nat64 pool 100.64.0.0/24
set nat nat64 interface eth1
set nat nat64 dns64 true
```

## Load-balanced services

Define a VIP, protocol, port and backend pool. Inspect the translation for a connection to the VIP.

```text
set load-balancer web zone wan
set load-balancer web vip 203.0.113.10
set load-balancer web proto tcp
set load-balancer web port 443
set load-balancer web backend 10.0.0.11:8443
set load-balancer web backend 10.0.0.12
```

## Seeing what is on the wire

Query the live flow table and per-flow counters to see traffic already observed by the dataplane.

```text
show flows                 # the live state table, with per-flow packets/bytes
show top-talkers           # hosts ranked by the volume attributed to them
```

## SYN-flood protection (SYN proxy)

Enable SYN proxy only for the TCP service ports that need it and verify normal connections to each protected service.

```text
set firewall syn-protect 443
set firewall syn-protect 8080 mss 1400
delete firewall syn-protect 443
```

## Application-layer gateways: there are none

The dataplane does not rewrite protocol payloads through application-layer gateways. Plan explicit application ports, passive endpoints or NAT traversal as appropriate.

## Groups whose members are decided elsewhere

Use a named group when rule membership comes from a published list or authenticated users. Keep ownership, refresh behavior and the consequences of an empty group explicit.

### Published lists

Reference a maintained feed from a named group. Confirm the source and refresh behavior before relying on its contents.

```text
set firewall group feed-group bogons url https://example.org/bogons.txt
set firewall rule drop-bogons source-group bogons
```

### People

User groups allow a policy to refer to authenticated identities rather than a fixed address list.

```text
set firewall group user-group admins user alice,bob
set firewall rule admin-ssh source-group admins
```

## One rule for both protocols

Use `tcp_udp` when TCP and UDP intentionally share a rule and port.

```text
set firewall rule dns-in proto tcp_udp
set firewall rule dns-in port 53
```

## Which rules are doing anything

Inspect rule-hit counters while generating ordinary application traffic. Use the trace for the configuration decision behind a specific packet.

```text
show firewall hits
```

## What was already refused (firewall log)

Read the firewall log for recent decisions. A counter reason can be shared by several rules; use a trace to identify candidate matches.

```text
show firewall log            # the last fifty lines
show firewall log 500        # a deeper read, up to 5000
show firewall log since 6h   # a period instead of a count
```

## A packet the filter cannot parse

Inspect the configured default for unparseable traffic and check drop counters before changing it. An explicit fail-closed posture drops packets the dataplane cannot classify.

## Stateful tracking and idle deadlines

Choose connection-tracking timeouts for the expected workload. Check existing flows before shortening their idle lifetime.

```text
set firewall global conntrack tcp-syn 30
set firewall global conntrack tcp-established 86400
set firewall global conntrack tcp-closing 30
set firewall global conntrack udp 30
set firewall global conntrack udp-stream 180
set firewall global conntrack icmp 10
```

## Check the result

```sh
sentinel show firewall statistics
sentinel show firewall log
sentinel show nat
```

Generate normal application traffic on an isolated test segment. Compare the counters and logs with the simulated decision.
