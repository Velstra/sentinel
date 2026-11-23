# Network services

<a id="services"></a>

A LAN resolver and time server on `eth1`:

```text
set services dns upstream 9.9.9.9,1.1.1.1
set services dns serve-on eth1
set services ntp upstream pool.ntp.org
set services ntp serve-on eth1
compare
commit-confirm 2
```

Bind every service to the intended interfaces and addresses, and substitute your own resolvers, networks and credentials for the lab values.

## DNS (LAN resolver)

```text
set services dns upstream 9.9.9.9,1.1.1.1
set services dns serve-on eth1
set services dns host-override nas.home 10.0.0.5
set services dns blocklist ads.example.com
```

## Encrypted DNS upstreams

```text
set services dns upstream 9.9.9.9
set services dns secure-upstream tls://dns.quad9.net
set services dns secure-upstream https://dns.quad9.net/dns-query
```

## Who may ask, and what is never asked

`allow-from` limits the clients; `dont-query` names domains never forwarded upstream.

```text
set services dns allow-from 10.0.0.0/8,fd00::/8
set services dns dont-query 168.192.in-addr.arpa
```

## NTP server

Confirm the appliance clock is synchronized before serving it.

```text
set services ntp upstream pool.ntp.org
set services ntp serve-on eth1
```

## LLDP, SNMP, mDNS

Trusted interfaces only; a collector should reach only what it needs.

```text
set services lldp enable true
set services snmp community <read-only-community>
set services snmp allow 10.0.0.0/24
set services mdns interface eth1,eth2
```

## Web console

Keep working local access while changing HTTPS settings.

```text
set services web enable true
set services web port 8443
set services web listen-address 10.0.0.1
```

### TLS

The console and API share the management certificate. Validate its identity from a trusted path before sending credentials.

```text
set services web tls-cert /var/lib/sentinel/pki/web/fullchain.pem
set services web tls-key  /var/lib/sentinel/pki/web/key.pem
```

## SSH log level

```text
set services ssh loglevel VERBOSE
```

## Dynamic DNS

Provider, hostname and a scoped provider credential go under `services dyndns`. Check the DNS answer after the uplink address changes.

## DHCP relay

```text
set services dhcp-relay interface eth1,eth0     # client + upstream links
set services dhcp-relay server  10.0.100.10     # IPv4 upstream (uses the link's giaddr)
set services dhcp-relay server6 2001:db8:100::10 # IPv6 upstream (or ff05::1:3, the relay multicast)
```

## UDP broadcast relay

Relay only the required UDP port between the selected segments.

```text
set services broadcast-relay wol port 9
set services broadcast-relay wol interface lan
set services broadcast-relay wol interface guest
```

## Reverse proxy / L7 load balancer

```text
set services reverse-proxy web port 443
set services reverse-proxy web certificate site-cert
set services reverse-proxy web backends 10.0.0.10:8080,10.0.0.11:8080
```

## Remote syslog

```text
set services syslog target 10.0.0.9
set services syslog target logs.example.com port 6514
set services syslog target logs.example.com proto tcp
set services syslog target logs.example.com level warning
```

## Syslog facilities

```text
set services syslog target 10.0.0.9 facility auth,local7
```

## Alert notifications

Send a test notification after configuring.

```text
set services alerts webhook https://hooks.example.com/sentinel
set services alerts mail to noc@example.com
set services alerts mail relay smtp.example.com
set services alerts mail user fw@example.com
set services alerts mail password <secret>
```

## Flow export (IPFIX)

```text
set services flow-export collector 10.0.0.50:4739
set services flow-export interval 30
set services flow-export domain 7
```

## Intrusion detection

```mermaid
flowchart LR
  traffic([Traffic on the<br/>monitored interface]) --> ids[IDS]
  ids --> alerts[show ids alerts]
  ids -->|only with block-on-alert| block[Block]
```

### It detects, it does not block

Blocking is off by default. Watch alerts on the normal workload first.

### Reading alerts

```text
show ids                  # what is watched, and whether the detector runs
show ids alerts           # the 20 most recent
show ids alerts 100
```

### Acting on an alert

Review alert quality before enabling `block-on-alert`, and keep critical management addresses in the configured exclusion list.

### Refusing a server by name (SNI)

Needs a visible server name in the handshake; encrypted or absent names are not matched.

```text
set services ids interface eth0
set services ids block-on-alert true
set services ids sni-block example.com
```

## Captive portal

Bind the portal to a guest zone, with a unique local passphrase from your credential process.

### What holds the zone

The portal applies to the designated guest zone. Check that address assignment, DNS and the portal itself work before admission.

### How a device finds the page

DHCP can advertise the portal URI with option 114, for clients that implement captive-portal discovery.

### Seeing it

```text
show portal
show portal sessions
```

### What a portal is not

Admission is not device authentication: a MAC address is only a local identifier.

## Port mapping (NAT-PMP)

Enable only on a trusted client zone.

```text
set services port-mapping zone lan
set services port-mapping wan-zone wan
set services port-mapping max-lifetime 7200
```

### What a mapping is

Each live mapping has an owner and an expiration; check them on the appliance.

### What is refused

```text
show port-mapping
clear port-mapping            # close every mapping hosts opened
clear port-mapping tcp 51820  # or just one
```

### NAT-PMP, not UPnP

Clients that need UPnP IGD need another integration.

## Check the result

```sh
sentinel show interfaces
sentinel show version
```

From an authorized LAN client, query the resolver and open the HTTPS address. Check the clock before trusting TLS expiry or log timestamps.
