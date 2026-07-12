# System & management

The `system` tree holds host-wide identity and the management surfaces —
who can log in, and how the box syncs to an HA peer. SSH daemon tuning lives
next door under `services ssh`.

## Hostname

```text
set system hostname fw-a
```

The hostname is applied live on commit and shown in the prompt.

## Login accounts

`system login <user>` defines a local account, VyOS-style. Accounts are
created on commit (the built-in `admin` always exists); each carries any number
of SSH public keys and an optional pre-hashed login password.

| Command | Meaning |
|---|---|
| `set system login <user> ssh-key <openssh-key>` | An OpenSSH public key allowed to log in as this user (repeatable). |
| `set system login <user> hashed-password <hash>` | A crypt(3) hash (`$6$…`) for console + sudo — never a plaintext password. |

The password is for the console and `sudo`; **SSH stays key-only** unless you
also enable password auth on the daemon (below). Generate a hash off-box:

```text
$ mkpasswd -m sha-512        # or: openssl passwd -6

admin@fw-a# set system login alice ssh-key ssh-ed25519 AAAAC3Nz…I alice@laptop
admin@fw-a# set system login alice ssh-key ssh-ed25519 AAAAC3Nz…J alice@phone
admin@fw-a# set system login alice hashed-password $6$xsalt$hash…
```

## SSH daemon

`services ssh` tunes the OpenSSH daemon itself. It is on and key-only by
default; the keys come from `system login` above.

| Field | Meaning |
|---|---|
| `enable` | Run the SSH daemon (`true`/`false`; default `true`). |
| `port` | TCP port sshd listens on (default 22). |
| `listen-address` | Restrict sshd to one local address (default: all). |
| `password-authentication` | Allow password logins over SSH (default `false`, key-only). |

```text
set services ssh port 2222
set services ssh listen-address 10.0.0.1
```

## HA config sync

`system config-sync` keeps a high-availability pair in step: on every `commit`,
the running config is pushed to each configured peer, which applies and
persists it. It rides the box's own management API (bearer-token authenticated),
so it needs no extra daemon — a declarative analog of pfSense's XMLRPC sync.

| Field | Meaning |
|---|---|
| `peer` | A peer firewall to push to — `host` or `host:port` (default port 8080, repeatable). |
| `secret` | The shared bearer token both peers present. Setting it also arms this box's receiving API. |

A *received* sync never re-pushes, so a pair never loops. Configure the shared
secret on both nodes; point the active node at the standby:

```text
# On the standby (arms its receiving API):
set system config-sync secret <shared-token>

# On the active node (pushes on every commit):
set system config-sync secret <shared-token>
set system config-sync peer 10.0.0.2
```

> Config sync copies the **whole** config, including interface addresses and the
> peer list — appropriate when the pair is symmetric. Pair it with
> [VRRP](routing.md#vrrp) for the virtual IP and you have a full
> active/standby firewall. See the [HA pair example](examples.md#ha-pair).

`config-sync` scales past a pair: `peer` is repeatable, so an active node can push
to two or more standbys (a full mesh, each node listing the others). Only the
interactive `commit` pushes — a received sync never re-pushes — so a cluster of
any size never loops. There is no designated primary and no merge, so drive edits
from **one** node (last write wins), exactly like pfSense.

## HA conntrack sync

VRRP alone hands the virtual IP to a standby on failover, but the standby has
never seen the active node's flows — so every established, NAT'd connection breaks
the moment the IP moves. `system conntrack-sync` fixes that: it mirrors the eBPF
conntrack table to the HA peers (a *pfsync*-analog). The data plane binds a UDP
socket, pushes its live conntrack entries to each peer every interval, and applies
the entries a peer pushes — so whichever node VRRP promotes already holds the flow
table and the connections survive.

| Field | Meaning |
|---|---|
| `listen` | Local bind endpoint for peer state — `host` or `host:port` (default port `5429`). Defaults to `0.0.0.0:5429`. |
| `peer` | A peer firewall to push conntrack state to — `host` or `host:port` (default port `5429`, repeatable). |
| `interval` | Seconds between pushes (default `1`). |

```text
# Symmetric HA pair — each node pushes to the other:
# On fw1 (10.0.0.2):
set system conntrack-sync peer 10.0.0.3
# On fw2 (10.0.0.3):
set system conntrack-sync peer 10.0.0.2
```

Like config-sync, `peer` is repeatable, so a three-or-more node cluster is a full
mesh: each node pushes its table to every other, and whichever one becomes master
already has the state. `listen` defaults to `0.0.0.0:5429`, so setting a `peer` is
enough to enable both directions.

> **Trust the link.** The sync stream is unauthenticated (like pfsync), so it must
> run over a trusted or dedicated sync segment — a peer that can reach the socket
> can inject conntrack (hence NAT) state. Gate the port with a firewall rule, or
> put the sync on its own zone. Together **VRRP + config-sync + conntrack-sync**
> make a complete stateful active/standby (or active/active-capable) HA cluster;
> see the [HA pair example](examples.md#ha-pair).
