# Firewall, NAT and packet tracing

<a id="firewall--nat"></a>

Use the trace command to explain the configured outcome for a packet. Use live counters and logs to investigate actual traffic. Configuration examples run inside `sentinel configure`.

Read the [support matrix and conformance gate](../reference/dataplane-support.md) for what the data plane is qualified to do and its known limits (IPv6 fragments are not translated, the SYN proxy is port-scoped and IPv4-only). Routed traffic currently uses kernel forwarding plus TC egress, not an established-flow XDP redirect fast path.

## Asking before you send (packet trace)

For example, determine whether a guest on `lan0` can reach SSH on a DMZ server. Replace interface names and addresses with ones from your configuration.

```text
sentinel trace --in lan0 tcp 10.0.0.200 10.9.0.10 22
```

With a matching guest-deny rule, the important result can look like this:

```text
verdict:   drop (no-ssh-from-guests)
```

The standalone command reads the saved configuration by default. To test a proposed TOML file before applying it, pass the same packet to the candidate. JSON exposes the verdict, deciding rule and intermediate steps for comparison:

```sh
sentinel trace --config ./candidate.toml --json --in lan0 tcp 10.0.0.200 10.9.0.10 22
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

`block-icmp` refuses new inbound ICMP, such as a ping from the internet, even where a rule accepts ICMP. Answers still arrive: the echo reply to a ping the firewall or a LAN host sent, and an ICMP error about a tracked connection — packet-too-big and fragmentation-needed included, so path-MTU discovery keeps working. Outbound ICMP is not affected. IPv6 neighbour discovery and MLD always pass on every zone, whatever its default action, rules or `block-icmp` say; without them no IPv6 neighbour on that link resolves. A zone needs no ICMPv6 rule for IPv6 to work.

IPv4 packets with options are refused on stateful zones: a TCP or UDP packet whose IPv4 header carries options cannot be tracked, proxied or translated, so a stateful zone drops it rather than judging it without state (RFC 7126 practice). A stateless zone still judges it by its rules.

An IPv4 address rule applies to IPv4 only and an IPv6 address rule to IPv6 only. A rule that names no address applies to both families unless `family` limits it.

## Rules

Scope each rule to the intended ingress and destination before applying it. This example scopes SSH from the management zone to the firewall's own addresses. `firewall` is not a reserved name: declare a zone that means "this appliance" by marking it local, once.

```text
set firewall zone firewall local true
set firewall rule mgmt-ssh from mgmt
set firewall rule mgmt-ssh to firewall
set firewall rule mgmt-ssh proto tcp
set firewall rule mgmt-ssh port 22
set firewall rule mgmt-ssh action accept
```

A rule's `from` zone is where the packet **arrives**. A rule without `direction` applies to arriving traffic only; `direction out` makes it a rule about traffic leaving through that zone's links, including traffic this appliance sends, and `direction both` applies it to both. So `from wan proto tcp port 25 action drop` keeps SMTP out without stopping LAN hosts from sending mail.

Zone policy IDs are derived from the zone name, so adding, removing or renaming one zone no longer resets the connections of the others. The first commit after upgrading from an image that numbered zones by their sorted names changes every ID once and resets connection state once; on an HA pair, the two members report "policy differs" while they run different images during a rolling upgrade.

A rule without `proto` is not a rule the data plane carries: `from lan action accept` sets zone `lan`'s default to accept. It cannot be narrowed, so `source`, `destination`, groups, `family`, `direction` and `log` on it are refused, and so is the rule itself when the zone sets `default-action` explicitly (the zone's setting decides). Give the rule a `proto` (and a `port` for TCP/UDP) to narrow it.

Two rules on the same zone, protocol, port and address hold one verdict in the data plane. The stricter wins (`reject`, then `drop`, then `accept`), so a `drop` for one port inside an accepted range works in either order, and `sentinel trace` reports the same rule. Where the winner's `family` or `direction` does not cover the other rule's, `config check` says which part is not enforced.

### The destination zone

For a port rule targeting a zone, verify the destination against that zone’s configured subnets. Use the packet trace to inspect the matched rule.

A **local** zone is matched against the addresses the appliance holds while it runs: static addresses, DHCP and DHCPv6 leases, SLAAC addresses, and a VRRP address while this member holds it. A DHCP management port is therefore reachable by `to firewall` rules, and the rule never widens to other destinations. `sentinel trace` knows only the configured addresses and says so when a destination could be a run-time address.

A destination zone binds its configured connected prefixes, not the eventual outgoing interface. Routed prefixes behind that zone are not automatically included. A source-constrained port rule matches one address end, so its `to` label is not also enforced; broad rules set ingress posture rather than a destination restriction. Read every advisory and verify the actual destination match.

New or changed unsafe destination-zone deny rules are refused by admission; this does not retroactively make unchanged legacy policy safe. Accept-rule advisories remain nonfatal. Use explicit destination matches for management isolation rather than assuming a zone label is an egress ACL.

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

A weekly schedule uses the appliance’s local timezone. Check the clock and the rule’s active window when troubleshooting. The rule set is re-applied at every window boundary and whenever the clock is stepped (for example when NTP first synchronises after boot) or the time zone changes.

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

A zone's blocklist and GeoIP countries name **sources**: they refuse what a listed address sends in through the zone, and nothing else. `zone wan geoip-block XX` stops hosts in XX connecting in, and stops their packets to connections they started; it does not stop LAN hosts reaching addresses in XX, and the answers to those connections are let back in. An address added to a blocklist loses the connections it opened at once, but keeps answering ones that were opened towards it. On a zone with `stateful false` there is no connection to answer, so a listed address cannot answer anything either. There is no outbound blocklist in this release: to keep the inside from reaching listed addresses, write `direction out` rules for the protocols and ports concerned. The global blocklist (`set firewall blocklist`) works the same way on every zone. Every zone's policy carries its own copy of the global blocklist and global GeoIP countries, so a global entry costs one data-plane entry per zone plus one; `config check` refuses a configuration whose total exceeds the data plane's 262,144 entries per address family.

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

Each connection gets its own public source port. Ports are scarce only between connections to the **same** remote address and port: each such endpoint has the whole 32768-port range (32768–65535) of the public address to itself, and connections to different endpoints never compete. The total number of connections is limited by the state tables, not by ports.

A new connection examines a fixed window of 128 candidate ports, so opening it costs the same no matter how busy the box has been. If all 128 are taken, the opening packet is dropped and counted as `egress_nat_no_candidate` in `sentinel show firewall statistics`; the client's retransmission tries again. How often that happens depends on how full that one endpoint's range is:

| Concurrent connections to one remote ip:port, per public address | Share of the range | New connections refused |
| ---: | ---: | ---: |
| up to ~29,500 | 90 % | none measurable |
| ~31,100 | 95 % | about 0.15 % |
| ~32,400 | 99 % | about 27 % |

So plan for roughly **31,000 concurrent connections from one public address to one remote ip:port**. No NAT can exceed 32,768. A closed connection keeps its port for the closing timeout (30 s by default), so a single public address sustains roughly a thousand connections per second from fresh client ports to one remote service. When `egress_nat_no_candidate` grows, the remedy is more public addresses. In 1.0 masquerade translates to the one address of each uplink and has no address pool, so in practice that means spreading the traffic over another masquerading uplink. Logical expiry does not guarantee immediate physical reclamation; do not infer a supported connection limit from configured map sizes.

#### Deterministic CGNAT

A deterministic block maps an internal address to a known port range. Check pool size and subscriber capacity before applying the design.

```text
set nat source wan-masq zone wan
set nat source wan-masq cgnat-block-size 512      # ports per internal address
set nat source wan-masq cgnat-base-port 32768     # optional; this is the default
```

### Destination NAT (port-forward)

Specify the external zone, protocol and service port together with the internal destination. Use the packet trace to inspect the translation. A port-forward is `tcp`, `udp` or `tcp_udp`. Hairpin reflection needs a static IPv4 address on the external zone; on a DHCP or PPPoE uplink `config check` warns that it has no effect.

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

Define a VIP, protocol (`tcp`, `udp` or `tcp_udp`), port and backend pool. Inspect the translation for a connection to the VIP.

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

Enable SYN proxy only for the TCP service ports that need it and verify normal connections to each protected service. A protected port is proxied on the zones that admit it: a zone with an accept rule for that TCP port on arriving traffic, a TCP port-forward of it, or a load balancer on it. Connections other zones open to that port elsewhere — your LAN clients' outbound HTTPS under `syn-protect 443` — are not proxied, and a hairpin reflection does not count as admitting it. Proxied connections lose window scaling, SACK and timestamps. When no zone admits the port that way (the service sits behind a zone whose default action accepts), the proxy answers every IPv4 SYN to that port arriving on any zone, and `config check` says so. `config check` names the zones a port is proxied on. IPv6 is not SYN-proxied in 1.0: the SYN proxy protects IPv4 only. Where a protected port is reachable over IPv6 (a zone with an IPv6 address whose rules admit it, or any IPv6 zone when the port is proxied everywhere), `config check` names those zones.

```text
set firewall syn-protect 443
set firewall syn-protect 8080 mss 1400
delete firewall syn-protect 443
```

A protected port can sit behind a port-forward, including one that changes the port (`port 8080 to 192.0.2.10:80` with `syn-protect 8080`), and servers that speak first (SMTP, FTP, POP, IMAP, SSH) work through the proxy. The proxy keeps one record per proxied connection, and the agent removes it once no live connection state (firewall or NAT) claims it any more, checked over two complete passes of the state tables; idle connections keep theirs however many others come and go.

Two consequences of that lifetime:

- **A client reusing a source port too soon.** After a connection ends, its record stays until two passes after its connection state is gone: at once after a reset, after the closing timeout (`set firewall global conntrack tcp-closing`, 30 s by default) after a normal close. One pass takes about one second per 65,536 entries of the firewall state table (`sentinel show firewall capacity` lists its size), so a few seconds on a small box and a few minutes on one sized for millions of connections. A new connection from the same client address and port, inside that window, to a protected service whose server uses the same port (the same service, or another one forwarded to that port) is not admitted, and its own attempts keep the old record claimed while they last; the client's next attempt after that succeeds.
- **Half-closed connections after an HA failover.** A proxied connection that one side had half-closed (sent its FIN while the other kept sending) is treated as closing with the ordinary closing timeout instead of the longer half-close allowance, because the FIN history does not replicate. If it then idles longer than that, the new active member ends it. Fully open connections are not affected.

## Application-layer gateways: there are none

The dataplane does not rewrite protocol payloads through application-layer gateways. Plan explicit application ports, passive endpoints or NAT traversal as appropriate.

## Groups whose members are decided elsewhere

Use a named group when rule membership comes from a published list or authenticated users. Keep ownership, refresh behavior and the consequences of an empty group explicit.

### Published lists

Reference a maintained feed from a named group. Confirm the source and refresh behavior before relying on its contents.

```text
set firewall group feed-group bogons url https://example.org/bogons.txt
set firewall rule drop-bogons from wan
set firewall rule drop-bogons source-group bogons
set firewall rule drop-bogons proto tcp
set firewall rule drop-bogons port 22,443
set firewall rule drop-bogons action drop
```

A feed group is matched by port rules, so it needs a `proto` (and ports for TCP/UDP); a feed cannot block a source on every protocol at once — use the zone `blocklist` for that. Each feed member is one data-plane entry per port and protocol, so keep port sets narrow. Every commit and every refresh checks the merged feed against the data plane's capacity and keeps the running policy, with an error, if it no longer fits.

### People

User groups allow a policy to refer to authenticated identities rather than a fixed address list.

```text
set firewall group user-group admins user alice,bob
set firewall rule admin-ssh from lan
set firewall rule admin-ssh source-group admins
set firewall rule admin-ssh proto tcp
set firewall rule admin-ssh port 22
set firewall rule admin-ssh action accept
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

`log` decides what reaches this log. On a zone or as the firewall-wide
default (`set firewall zone <zone> log true`, `set firewall global log true`)
it records every packet the firewall drops or rejects, with the reason. On a
rule (`set firewall rule <name> log true`) it records that rule's drops, and
for an accepting rule each new flow it admits. Packets of flows already
admitted are never logged, however busy the link: forwarding, NAT and
tunnelling are counted (`show firewall statistics`), not logged.

The journal is rationed: the agent writes at most a burst of 100 such lines
and then 10 a second, and for every 10 s in which it held lines back one
`suppressed N data-plane log record(s)` warning says how many. The drop
counters still count every packet, and `show firewall statistics` reports the
held-back total as `log_lines_suppressed`. A flood of logged drops therefore
costs log lines, never the firewall's speed or the rest of the journal.

The console's live view is a different stream: on a logging zone or policy it
shows every packet, accepted ones included. It is bounded and lossy — under
load it skips packets — and it never reaches the journal.

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

## Inspect state-map occupancy

```text
show firewall states
show firewall capacity
show firewall counters
show firewall events
```

Rule capacity is checked before anything is applied: each rule trie holds 8,192 entries (every port of a range, every group member and each protocol of `tcp_udp` is one entry), 127 rate-limited entries fit in total, and the blocklist holds 262,144 entries per address family across all zones. `config check` names the map, the count and the rules that fill it.

`capacity` counts raw `CONNTRACK`, `FW_FLOWS` and `SYN_FLOWS` entries, including expired entries. It is not an active-connection count or supported limit. A complete consistent sample warns at 80%; failed/changing samples report `unknown` and include sampling age. Matching scans remain non-atomic, so `observed-below-threshold` is not a health guarantee. Eviction counts are unavailable, and old agents report the query unavailable.

## Check the result

```sh
sentinel show firewall statistics
sentinel show firewall log
sentinel show nat
```

Generate normal application traffic on an isolated test segment. Compare the counters and logs with the simulated decision.
