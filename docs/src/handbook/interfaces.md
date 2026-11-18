# Interfaces and addressing

<a id="interfaces"></a>

Set addresses and zones on the discovered device names. Keep the serial console or a separately connected management port available before moving a live link into a zone.

## Common fields

Inspect the discovered NIC names before assigning zones, addresses or MTU. For a WAN using DHCP and a statically addressed LAN:

```text
set interface eth0 zone wan
set interface eth0 address dhcp
set interface eth1 zone lan
set interface eth1 address 10.0.0.1/24
set interface eth1 address6 2001:db8:0:1::1/64
```

## Zoned links stay down until the firewall has them

Sentinel holds a zoned data interface down until the dataplane attaches. Inspect the reason with `sentinel show interfaces`. Restore the dataplane from the serial console or independent management path before treating a held port as a cabling problem.

### Keep a way in that does not depend on the data plane

Keep a local or serial console, or a physically independent management interface, while changing dataplane attachment.

## VLANs (802.1Q / QinQ)

A tagged subinterface can infer its parent and VLAN from a name such as `eth1.20`. Set the protocol explicitly for an 802.1ad service tag.

```text
set interface eth1.20 zone iot          # infers parent eth1, vlan 20
set interface eth1.20 address 10.0.20.1/24
```

## Virtual interface types

Set the interface type and its required parent or members. Take one end-to-end hop at a time when building bridges, bonds, tagged interfaces or tunnels.

### Bridges & bonds

Use a bridge to join L2 ports. Use a bond to group physical links into one logical interface; configure the switch to match its mode.

```text
set interface br0 type bridge
set interface br0 member eth1
set interface br0 member eth2
set interface br0 zone lan
set interface br0 address 10.0.0.1/24

set interface bond0 type bond
set interface bond0 bond-mode 802.3ad      # or active-backup, balance-rr, …
set interface bond0 member eth3
set interface bond0 member eth4
```

### Tunnels

Configure the tunnel’s local and remote endpoints and the address of the resulting link. Verify underlay reachability first.

```text
set interface gre1 type gre
set interface gre1 local 203.0.113.1
set interface gre1 remote 198.51.100.1
set interface gre1 key 42                  # gre/gretap only
set interface gre1 zone tunnel
set interface gre1 address 10.255.0.1/30
```

## PPPoE (VDSL / fibre)

Set the physical parent and provision the ISP-assigned authentication values. Place the zone and address settings on the appropriate logical interface.

```text
set interface wan0 type pppoe
set interface wan0 parent eth0             # the raw NIC the session runs over
set interface wan0 zone wan
set interface wan0 pppoe username user@isp
set interface wan0 pppoe password <isp-password>
set interface wan0 mtu 1492
```

## IPv6 addressing & prefix delegation

Request a delegated prefix on the upstream link, assign a downstream subnet, and verify the advertised prefix on a LAN client.

```text
set interface wan0 address6 dhcp
set interface wan0 pd-from wan0            # request a prefix on the WAN
set interface eth1 pd-from wan0            # …carve a /64 for the LAN
set interface eth1 pd-subnet 1
```

## Serving the LAN: DHCP & Router Advertisements

Configure the DHCP pool and router advertisements on the LAN interface. Reserve the appliance’s own address outside the dynamic pool.

```text
set interface eth1 dhcp-server enable
set interface eth1 dhcp-server pool-offset 100
set interface eth1 dhcp-server pool-size 100
set interface eth1 dhcp-server dns 10.0.0.1
set interface eth1 dhcp-server static-mapping printer mac 52:54:00:aa:bb:cc ip 10.0.0.5

set interface eth1 router-advert enable
set interface eth1 router-advert prefix 2001:db8:0:1::/64
```

## Egress QoS (bufferbloat)

Set the shaper bandwidth from the measured uplink rate. Test latency with background traffic before and after applying CAKE.

```text
set interface wan0 qos discipline cake
set interface wan0 qos bandwidth 100mbit
set interface wan0 qos rtt internet
```

## MACsec

Configure the parent, peer identity and matching keys on both ends. Provision unique keys through the site’s credential procedure. Use CLI completion under `set interface <name>` for the required MACsec fields.

## Clamping TCP MSS

Use an explicit MSS or the path-MTU mode on an encapsulated path. Confirm large TCP transfers work as well as small probes.

```text
set interface tun0 mss 1360
set interface tun0 mss pmtu
```

## Offload

Inspect NIC driver capabilities before setting per-interface offloads. Verify the active state after applying.

```text
set interface eth0 offload gro true
set interface eth0 offload rxhash true
```

## Router advertisements

Configure the advertised prefix, preference and lifetimes on the downstream link.

```text
set interface eth0 router-advert enable
set interface eth0 router-advert prefix 2001:db8:1::/64
set interface eth0 router-advert managed true
set interface eth0 router-advert dhcp6-pool start 2001:db8:1::1000
set interface eth0 router-advert dhcp6-pool end   2001:db8:1::2000
```

## DHCP reservations

Associate a stable client MAC with a reserved address and confirm the client renews the intended lease.

```text
set interface eth0 dhcp-server static-mapping printer mac 00:11:22:33:44:55
set interface eth0 dhcp-server static-mapping printer ip 10.0.0.9
```

## NIC hardware

Apply only settings supported by the specific NIC and driver. Verify the resulting link settings on the appliance.

```text
set interface eth3 ethernet speed 1000
set interface eth3 ethernet duplex full
set interface eth3 ethernet rx-ring 4096
set interface eth3 ethernet tx-ring 4096
set interface eth3 ethernet rx-usecs 50
set interface eth3 ethernet adaptive-tx true
```

## Bridge detail

Configure the bridge and member-specific VLAN behavior together. Confirm tagged and untagged endpoints reach the expected segment.

```text
set interface br0 bridge stp true
set interface br0 bridge priority 4096
set interface br0 bridge hello-time 2
set interface br0 bridge max-age 20
set interface br0 bridge forward-delay 15
set interface br0 bridge ageing-time 300
set interface br0 bridge igmp-snooping true
set interface br0 bridge igmp-querier true
```

### As a port of a bridge

Set port-specific bridge behavior on the member while keeping the logical L3 address on the bridge.

```text
set interface eth5 bridge-port cost 100
set interface eth5 bridge-port priority 32
set interface eth5 bridge-port learning false
```

## Bond detail

Match LACP or static bond parameters on both the appliance and the connected switch.

```text
set interface bond0 bond hash-policy layer3+4
set interface bond0 bond lacp-rate fast
set interface bond0 bond min-links 2
set interface bond0 bond primary eth3
set interface bond0 bond mii-interval 100
set interface bond0 bond arp-interval 2000
set interface bond0 bond arp-target 10.0.0.1
```

## Cellular (`wwan`)

Set the modem connection profile and APN supplied by the carrier. Use a management path independent of the cellular link while testing.

```text
set interface wwan0 type wwan
set interface wwan0 zone wan
set interface wwan0 address dhcp
set interface wwan0 wwan apn internet
set interface wwan0 wwan ip-type ipv4v6
```

### What is not verified here

Stubbed modem tests validate configuration rendering. Check registration, carrier addressing and reconnection with the actual modem.

## Wireless

Choose the radio role and the local regulatory settings. Validate connectivity with the physical adapter and intended client.

```text
set interface wlan0 type wireless
set interface wlan0 zone lan
set interface wlan0 address 10.0.10.1/24
set interface wlan0 wireless mode access-point
set interface wlan0 wireless ssid velstra
set interface wlan0 wireless country DE
set interface wlan0 wireless channel 6
set interface wlan0 wireless band n
set interface wlan0 wireless wpa mode wpa2+wpa3
set interface wlan0 wireless wpa passphrase <pre-shared-key>
```

### What is not here

Radio settings depend on hardware, firmware, driver and regulatory support. A rendered configuration does not validate RF behavior.

## Route-based IPsec (`vti`)

Pair the VTI interface with its IPsec connection, then route the protected subnet over the interface.

```text
set interface vti0 type vti
set interface vti0 vti-key 42
set interface vti0 zone vpn
set interface vti0 address 10.255.0.1/30
set interface vti0 mss pmtu
```

## Per-link IPv4 and IPv6 behaviour

Apply family-specific settings on the intended interface. Verify both addresses and effective routes after the change.

```text
set interface eth0 ip disable-forwarding true
set interface eth0 ip proxy-arp true
set interface eth0 ip arp-cache-timeout 30
set interface eth0 ipv6 disable-forwarding true
set interface eth0 ipv6 no-link-local true
set interface eth0 ipv6 dad-transmits 2
set interface eth0 ipv6 accept-dad 2
```

### The ARP block

Configure ARP behavior only where the link topology requires it; verify neighbor resolution from both sides.

```text
set interface eth0 ip arp-filter true      # only answer for an address on this link
set interface eth0 ip arp-ignore true      # the reply half of the same rule
set interface eth0 ip arp-announce true    # source from an address on the target's subnet
set interface eth0 ip arp-accept true      # learn from gratuitous ARP (faster failover)
```

## DHCP client options

Configure client options on the interface that requests the lease; verify the values actually returned by the server.

```text
set interface wan0 address dhcp
set interface wan0 dhcp client-id mac
set interface wan0 dhcp host-name fw
set interface wan0 dhcp vendor-class-id sentinel
set interface wan0 dhcp user-class residential
set interface wan0 dhcp no-default-route true
set interface wan0 dhcp default-route-distance 210
set interface wan0 dhcp reject 192.0.2.9
```

## Port mirroring

Select source and monitor ports explicitly. Verify the monitor receives the expected traffic without disturbing normal forwarding.

```text
set interface eth1 mirror-ingress mon0
set interface eth1 mirror-egress mon0
```

## Check the result

```sh
sentinel show interfaces
sentinel show ipv6 route
```

Match the observed names, addresses and link states to your intended topology. Verify tagging on both ends before changing a trunk.
