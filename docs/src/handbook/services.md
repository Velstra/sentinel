# Network services

<a id="services"></a>

Bind management and LAN services to the intended interfaces and addresses. Examples use lab endpoints: substitute the actual resolver, management networks and credentials before applying.

## DNS (LAN resolver)

Bind the resolver to the trusted LAN and set explicit upstream servers. Check the result from a client on that interface.

```text
set services dns upstream 9.9.9.9,1.1.1.1
set services dns serve-on eth1
set services dns host-override nas.home 10.0.0.5
set services dns blocklist ads.example.com
```

## NTP server

Select upstream clocks and restrict client service to the intended links. Confirm the appliance clock is synchronized.

```text
set services ntp upstream pool.ntp.org
set services ntp serve-on eth1
```

## LLDP, SNMP, mDNS

Limit discovery and monitoring to trusted interfaces. Verify that the intended collector can reach only the services it requires.

```text
set services lldp enable true
set services snmp community <read-only-community>
set services snmp allow 10.0.0.0/24
set services mdns interface eth1,eth2
```

## Web console

Bind the management listener to the intended address and port. Retain working local access while changing HTTPS settings.

```
set services web enable true
set services web port 8443
set services web listen-address 10.0.0.1
```

### TLS

The console and API share the management certificate. Validate its identity from a trusted path before sending credentials.

```
set services web tls-cert /var/lib/sentinel/pki/web/fullchain.pem
set services web tls-key  /var/lib/sentinel/pki/web/key.pem
```

## Dynamic DNS

Set the provider, hostname and provider-specific credential under `services dyndns`. Use a scoped provider credential and verify the DNS answer after the uplink address changes.

## DHCP relay

Set the client-facing and upstream interfaces, and the address of the authoritative DHCP server.

```text
set services dhcp-relay interface eth1,eth0     # client + upstream links
set services dhcp-relay server  10.0.100.10     # IPv4 upstream (uses the link's giaddr)
set services dhcp-relay server6 2001:db8:100::10 # IPv6 upstream (or ff05::1:3, the relay multicast)
```

## Reverse proxy / L7 load balancer

Configure the listening port, certificate and backend endpoints. Test the certificate and the response from each application backend.

```text
set services reverse-proxy web port 443
set services reverse-proxy web certificate site-cert
set services reverse-proxy web backends 10.0.0.10:8080,10.0.0.11:8080
```

## Remote syslog

Send logs to a collector with the required transport, port and facility policy. Check receipt on the collector.

```text
set services syslog target 10.0.0.9
set services syslog target logs.example.com port 6514
set services syslog target logs.example.com proto tcp
set services syslog target logs.example.com level warning
```

## Alert notifications

Select the event destination and deliver a test notification using your organization’s approved channel.

```text
set services alerts webhook https://hooks.example.com/sentinel
set services alerts mail to noc@example.com
set services alerts mail relay smtp.example.com
set services alerts mail user fw@example.com
set services alerts mail password <secret>
```

## UDP broadcast relay

Relay only the required UDP port between the selected segments; verify that unrelated broadcasts stay local.

```text
set services broadcast-relay wol port 9
set services broadcast-relay wol interface lan
set services broadcast-relay wol interface guest
```

## Intrusion detection

Select the monitored interface and inspect IDS events before enabling any automatic blocking. Maintain a site-specific exception list for management systems.

### It detects, it does not block

IDS alerts can be used for monitoring without enabling automated blocking. Observe expected workload first.

### Reading alerts

Inspect recent IDS events and their timestamps; forward relevant events to your log collector.

```
show ids                  # what is watched, and whether the detector runs
show ids alerts           # the 20 most recent
show ids alerts 100
```

### Acting on an alert

Review normal traffic and alert quality before enabling `block-on-alert`. Keep critical management addresses in the configured exclusion list.

## Flow export (IPFIX)

Send IPFIX accounting records to the configured collector and verify that it observes the expected interfaces and flows.

```text
set services flow-export collector 10.0.0.50:4739
set services flow-export interval 30
set services flow-export domain 7
```

### Refusing a server by name (SNI)

An SNI match requires a visible server name in the handshake. Review encrypted or absent names when assessing coverage.

```text
set services ids interface eth0
set services ids block-on-alert true
set services ids sni-block example.com
```

## Captive portal

Bind the portal to a guest zone and provision a unique local passphrase through your credential process. Check the portal and the list of authenticated sessions from the operator console.

### What holds the zone

The portal applies to the designated guest zone. Verify pre-admission access to address assignment, DNS and the portal itself.

### How a device finds the page

DHCP can advertise the captive-portal URI using option 114. Test with a client that implements captive-portal discovery.

### Seeing it

Read the current portal sessions and compare with a freshly admitted test client.

```text
show portal
show portal sessions
```

### What a portal is not

Portal admission is not device authentication. Treat a MAC address as a local identifier.

## Port mapping (NAT-PMP)

Enable NAT-PMP only on a trusted client zone, then constrain mapping lifetime and the external zone.

```text
set services port-mapping zone lan
set services port-mapping wan-zone wan
set services port-mapping max-lifetime 7200
```

### What a mapping is

Check the live NAT-PMP mapping, its owner and expiration on the appliance.

### What is refused

Inspect the current mappings before clearing one. Scope administrative removal to the intended mapping.

```text
show port-mapping
clear port-mapping            # close every mapping hosts opened
clear port-mapping tcp 51820  # or just one
```

### NAT-PMP, not UPnP

This service uses NAT-PMP. Clients requiring UPnP IGD need another integration.

## Encrypted DNS upstreams

Choose TLS or HTTPS upstreams that your resolver trusts and can reach. Check resolution during a normal query.

```text
set services dns upstream 9.9.9.9
set services dns secure-upstream tls://dns.quad9.net
set services dns secure-upstream https://dns.quad9.net/dns-query
```

## Who may ask, and what is never asked

Bind the resolver on the intended interfaces and constrain the allowed client networks.

```text
set services dns allow-from 10.0.0.0/8,fd00::/8
set services dns dont-query 168.192.in-addr.arpa
```

## Syslog facilities

Send only the selected facilities to a restricted collector or retain the full stream on your primary log service.

```text
set services syslog target 10.0.0.9 facility auth,local7
```

## SSH log level

Select an appropriate OpenSSH log level and verify a test connection appears in the authentication log.

```text
set services ssh loglevel VERBOSE
```

## Check the result

```sh
sentinel show interfaces
sentinel show version
```

From an authorized LAN client, query the chosen resolver and open the configured HTTPS address. Verify the appliance clock before relying on TLS expiry or log timestamps.
