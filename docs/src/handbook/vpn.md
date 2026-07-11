# VPN & PKI

`vpn` configures site-to-site and road-warrior tunnels; `pki` is the on-box
certificate manager (a local CA and ACME/Let's Encrypt) that the TLS-based
services draw on.

## IPsec (site-to-site, IKEv2)

`vpn ipsec <name>` is a strongSwan IKEv2 tunnel.

| Field | Meaning |
|---|---|
| `local` / `remote` | This box's / the peer's IKE endpoint (IPv4). |
| `local-subnet` / `remote-subnet` | Protected subnets (IPv4 CIDR). |
| `psk` | Pre-shared key (secret). |
| `ike-version` | `1` or `2` (default 2). |
| `ike-proposal` / `esp-proposal` | Cipher proposals (default `aes256-sha256-modp2048`). |
| `local-id` / `remote-id` | IKE identities (default = the addresses). |
| `start-action` | `start` (initiate at load), `trap` (on first packet), `none` (responder). |

```text
set vpn ipsec branch local 203.0.113.1
set vpn ipsec branch remote 198.51.100.1
set vpn ipsec branch local-subnet 10.0.0.0/24
set vpn ipsec branch remote-subnet 10.1.0.0/24
set vpn ipsec branch psk <pre-shared-key>
```

## WireGuard

A WireGuard tunnel is an [`interface type wireguard`](interfaces.md#virtual-interface-types)
plus its keys and peers under `vpn wireguard <ifname>`.

| Field | Meaning |
|---|---|
| `private-key` | The tunnel private key, or `generate` for a fresh keypair. |
| `listen-port` | The UDP listen port. |
| `peer <pubkey> allowed-ips` | CIDRs routed to this peer. |
| `peer <pubkey> endpoint` | The peer's public `host:port`. |
| `peer <pubkey> keepalive` | Persistent-keepalive seconds. |
| `peer <pubkey> preshared-key` | Optional pre-shared key. |

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

A TLS-based AnyConnect-compatible server that traverses any middlebox.

| Field | Meaning |
|---|---|
| `certificate` | TLS server identity — a `pki certificate` name. |
| `port` | TCP/UDP listen port (default 443). |
| `pool` | Client address pool (IPv4 CIDR). |
| `dns` / `routes` | Resolver(s) / split-tunnel subnets pushed to clients. |
| `default-route` | Full tunnel: push a default route. |
| `zone` | Firewall zone for the server's tun interface. |
| `user <name> password <pw>` | A client login. |

```text
set vpn openconnect certificate vpn-cert
set vpn openconnect pool 10.99.0.0/24
set vpn openconnect zone vpn
set vpn openconnect dns 10.0.0.1
set vpn openconnect routes 10.0.0.0/24
set vpn openconnect user alice password <secret>
```

## PKI

`pki` mints the certificates the TLS services (OpenConnect, reverse proxy, the
management API) use — from a local CA or via ACME.

| Node | Fields |
|---|---|
| `ca <name>` | `common-name`, `organization`, `key-type` (ec/rsa), `validity-days`. |
| `certificate <name>` | `ca` (a local CA name or `acme`), `common-name`, `subject-alt-name` (`DNS:host`/`IP:addr`), `key-type`, `usage` (server/client), `validity-days`. |
| `acme` | `email`, `directory-url`, `challenge` (http-01/dns-01), `agree-tos`. |

```text
# A local CA + a server cert signed by it:
set pki ca lab-ca common-name "Lab CA"
set pki certificate vpn-cert ca lab-ca
set pki certificate vpn-cert common-name vpn.example.com
set pki certificate vpn-cert subject-alt-name DNS:vpn.example.com
set pki certificate vpn-cert usage server

# Or a public cert via Let's Encrypt:
set pki acme email admin@example.com
set pki acme agree-tos true
set pki certificate site-cert ca acme
set pki certificate site-cert common-name www.example.com
```

`show pki` lists CAs and issued certs with their expiry.
