# Worked configurations

<a id="example-configurations"></a>

Use a disposable VM for these examples. Check NIC names, peer addresses and ownership of the saved configuration before applying them to any appliance.

## Home / SOHO router {#soho}

Start with an installed VM and the admin account created by the installer. The [quickstart](../operations/quickstart.md) applies a WAN DHCP client, a LAN address, a DHCP pool, DNS, masquerading and a LAN-only HTTPS listener. Preview the complete candidate with `compare` before applying.

## Branch office with a site-to-site VPN {#branch}

For an IKEv2 connection, match the peer identity, local and remote subnets, and security policy at both ends. The [IPsec recipe](vpn.md#ipsec-site-to-site-ikev2) shows the configuration.

```sh
sentinel show vpn ipsec sas
sentinel show ip route
```

After negotiation, verify the security association and a connection from one protected subnet to the other.

## Dynamic-routing core (OSPF) {#ospf}

Assume both ends of a directly connected, addressed transit link belong to the backbone area. On this router:

```text
set protocols router-id 10.255.0.1
set protocols ospf interface eth1 area 0.0.0.0
set protocols ospf network-type point-to-point
compare
```

Match area, timers and network type on the peer. After applying, inspect `sentinel show ip ospf neighbors` and `sentinel show ip route`.

## Active/standby HA pair {#ha-pair}

For forwarding authority during a partition, use the [witness-backed HA runbook](../operations/high-availability.md). In this design, two members share a witness and the previous owner is fenced when its lease expires. A VRRP virtual address by itself does not establish that the old node stopped forwarding.

```sh
sentinel show ha
sentinel show vrrp
```

Check authority, readiness and the advertised VIP separately.
