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

### ACME issuance

A locally-signed certificate is right for a VPN, where both ends are yours. It is
useless for anything a person points a browser at — the management API, the
reverse proxy — because nothing trusts it. `ca = "acme"` obtains a real one.

**Issuance is a job, not part of the commit.** Obtaining a certificate talks to a
server and waits for it to call back, and it fails for reasons the config cannot
fix: a name that does not point here yet, port 80 unreachable, the directory down.
So the commit records what is wanted and `sentinel-acme.service` does the work,
run by a daily timer with a randomised delay. Renewal is the same code path, and
starts 30 days before expiry — so a fortnight of failures still leaves room.

An apply also asks for one run immediately, because a fresh box otherwise has no
certificate until the timer's first tick while everything reports success.

**Port 80 has to be reachable.** The http-01 challenge is fetched back over it
from outside; if no zone admits `tcp/80`, the commit says so and `show pki`
repeats it, rather than letting the failure surface in a timer weeks later:

```text
set firewall rule acme-challenge from wan action accept proto tcp port 80
```

**Refused at commit**, because each would otherwise fail hours later inside a
timer with nobody watching: issuing without `agree-tos` (the protocol has no way
to), `challenge dns-01` (it needs provider credentials Sentinel does not model),
and a `common-name` that is an address (a public CA issues for names, which is
what the challenge is fetched over). An `IP:` subject-alt-name is dropped rather
than refused — passing it would fail the whole order, including the names that
were fine.

An obtained certificate lands in the same store as a locally-signed one, under
the same filenames, so the reverse proxy, the OpenConnect server and `show pki`
never learn where it came from — which is what makes `ca = "acme"` a one-word
change.

```text
sentinel show pki      # …and whether renewal is actually scheduled
```

`nix build .#checks.x86_64-linux.acme -L` verifies the whole exchange against
[Pebble](https://github.com/letsencrypt/pebble), a real RFC 8555 server: the
appliance registers, orders, serves the challenge on :80, and Pebble fetches it
back — so a certificate coming out the far end proves the exchange, not merely
that the client ran.

## Which VPNs this appliance carries, and which it will not

Three are supported and are the answer to essentially every case: **WireGuard**
for site-to-site and for people, **IPsec IKEv2** where the other end is
equipment that speaks IPsec and nothing else, and **OpenConnect** for a
road-warrior on a network that only lets TLS out.

Two are deliberately absent:

- **PPTP — never.** Its authentication and encryption (MS-CHAPv2, MPPE) are
  broken in the sense that matters: recovering the key is a service you can buy.
  Carrying it would let someone configure a tunnel that reads as protection and
  is not.
- **L2TP/IPsec — no.** It is IKEv2's transport with more moving parts and worse
  throughput, for the sake of clients that all now speak IKEv2 anyway. If you
  need an IPsec road-warrior, use IKEv2; if you need to traverse a hostile
  middlebox, use OpenConnect, which was built for it.

**OpenVPN is a possible addition, not a commitment.** It is a reasonable
protocol with a large installed base, and the case for it is compatibility with
an existing deployment rather than any property WireGuard lacks. It will be
built if that case is made, and not as a matter of course.
