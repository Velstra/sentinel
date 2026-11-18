# VPN and certificates

<a id="vpn--pki"></a>

Choose the tunnel type first. Assign addresses, routing policy and firewall zones explicitly; a successful handshake alone does not establish forwarding to a protected subnet.

## IPsec (site-to-site, IKEv2)

Configure the two IKEv2 endpoints and matching protected subnets. Provision independent site credentials through an approved local process.

```text
set vpn ipsec branch local 203.0.113.1
set vpn ipsec branch remote 198.51.100.1
set vpn ipsec branch local-subnet 10.0.0.0/24
set vpn ipsec branch remote-subnet 10.1.0.0/24
set vpn ipsec branch psk <pre-shared-key>
```

### Route-based tunnels (VTI)

Bind a VTI to its IPsec tunnel and install routes over the VTI for the remote networks.

```text
set interface vti0 type vti
set interface vti0 vti-key 42
set interface vti0 zone vpn
set interface vti0 address 10.255.0.1/30
set interface vti0 mss pmtu

set vpn ipsec branch local 203.0.113.1
set vpn ipsec branch remote 198.51.100.1
set vpn ipsec branch psk <pre-shared-key>
set vpn ipsec branch vti vti0

set protocols static 10.1.0.0/24 dev vti0
```

## WireGuard

Define the logical interface, local tunnel address, peer public key and allowed prefixes. Confirm the peer endpoint can be reached through the underlay.

```text
set interface wg0 type wireguard
set interface wg0 zone vpn
set interface wg0 address 10.9.0.1/24
set vpn wireguard wg0 private-key generate
set vpn wireguard wg0 listen-port 51820
set vpn wireguard wg0 peer <peer-pubkey> allowed-ips 10.9.0.2/32
set vpn wireguard wg0 peer <peer-pubkey> endpoint peer.example.com:51820
set vpn wireguard wg0 peer <peer-pubkey> keepalive 25
```

## OpenConnect (road-warrior)

Set the VPN server certificate, client address pool, DNS and permitted routes. Provision a separate credential for each intended user.

```text
set vpn openconnect certificate vpn-cert
set vpn openconnect pool 10.99.0.0/24
set vpn openconnect zone vpn
set vpn openconnect dns 10.0.0.1
set vpn openconnect routes 10.0.0.0/24
set vpn openconnect user alice password <secret>
```

## PKI

Create a local CA and issue a certificate with the intended subject, alternate names and usage. Review issuance and expiration with `sentinel show pki`. For a public ACME service, use the separately documented ACME path.

```text
set pki ca lab-ca common-name "Lab CA"
set pki certificate vpn-cert ca lab-ca
set pki certificate vpn-cert common-name vpn.example.com
set pki certificate vpn-cert subject-alt-name DNS:vpn.example.com
set pki certificate vpn-cert usage server
```

### ACME issuance

Use a reachable challenge host and check the certificate’s names and expiry after issuance. For an internal CA, distribute the issuing CA through your own trust policy.

```text
set firewall rule acme-challenge from wan
set firewall rule acme-challenge action accept
set firewall rule acme-challenge proto tcp
set firewall rule acme-challenge port 80
```

## Which VPNs this appliance carries, and which it will not

Choose WireGuard for a key-based peer, IKEv2 for IPsec interoperability or OpenConnect for a compatible TLS remote-access client.

## Check the result

```sh
sentinel show vpn ipsec sas
sentinel show pki
sentinel show ip route
```

For IPsec, inspect the active security associations and verify the remote subnet from an authorized client. Check certificate expiry for TLS-based services.
