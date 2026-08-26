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
| `set system login <user> totp <base32-secret>` | A one-time-code secret. The account then needs a code as well as a password. |

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


## A second factor

An account with a `totp` secret must give a six-digit code as well as its
password. RFC 6238, thirty-second steps, one step of tolerance either side so a
code typed as it rolls over still works.

```text
set system login alice totp generate
```

`generate` makes the secret, prints the `otpauth://` URI a QR code encodes, and
prints **the code that is current right now**. Check the phone agrees before you
walk away: somebody who enrolled the wrong account finds out here rather than at
the next sign-in, locked out.

The code is checked **after** the password and never instead of it, so a wrong
password and a wrong code are the same refusal from outside — there is nothing to
probe.

Two places it deliberately does not apply. The **serial console** has no second
factor: it is the port you reach for when the network this box manages is the
thing that is broken. **SSH** has none either — that belongs to sshd's own
configuration, not here.

## Where a password is checked

`system aaa` says where a password is checked when it is not checked here. A
local account list is a shadow account list: it has to be kept alongside the real
one, and it is the one nobody remembers to remove somebody from.

**The order is deliberate and not configurable: local first, then the servers in
the order given.** A box whose directory is unreachable must still be enterable
by the account written on it — and that is precisely the moment the directory is
likely to be unreachable.

### RADIUS

| Field | Meaning |
|---|---|
| `secret` | The shared secret (required). |
| `port` | Server port (default 1812). |
| `timeout` | Seconds to wait (default 3). A login is a person waiting. |

```text
set system aaa radius 10.0.0.50 secret a-shared-secret
set system aaa radius 10.0.0.50 timeout 2
```

PAP only. CHAP would hide the password from the wire but needs the server to
hold it in plaintext, which is the worse trade. RFC 2865 hides the password with
MD5 against the shared secret — **that is not encryption in any modern sense**,
so a RADIUS server belongs on a segment you already trust.

### LDAP

A **simple bind as the user**, not search-then-bind: searching first needs a
service account whose password would then live on the firewall.

| Field | Meaning |
|---|---|
| `base-dn` | Where the accounts live (required). The bind DN is `<user-attribute>=<username>,<base-dn>`. |
| `user-attribute` | The attribute naming an account (default `uid`; Active Directory usually wants `sAMAccountName`). |
| `tls` | `ldaps` (default), `starttls`, or `none`. |
| `port` | Default 636 for `ldaps`, else 389. |
| `timeout` | Seconds to wait (default 5). |

```text
set system aaa ldap dir.example.com base-dn ou=people,dc=example,dc=com
set system aaa ldap dir.example.com user-attribute sAMAccountName
```

`starttls` demands the upgrade and **fails rather than falling back** to
plaintext — falling back would defeat asking for it. `none` is allowed, because
a directory on a wire you already control is a real deployment, but `commit`
says out loud that the bind password crosses in the clear.

The username is escaped into the DN (RFC 4514). It lands inside
`uid=<here>,ou=…`, so a name containing a comma would not be a name any more —
it would be a different DN, chosen by whoever typed it.

### TACACS+

The third of the trio, for shops whose AAA lives on a TACACS+ server
(RFC 8907). The appliance speaks the ASCII authentication flow — it asks
whether this username and password are good, over TCP. Authorization and
accounting are not implemented: an appliance login needs a yes or a no, and
what an account may do here is decided by its group, not by the server.

| Field | Meaning |
|---|---|
| `secret` | The shared secret (required). |
| `port` | Server port (default 49, TCP). |
| `timeout` | Seconds to wait (default 3). A login is a person waiting. |

```text
set system aaa tacacs 10.0.0.49 secret a-shared-secret
set system aaa tacacs 10.0.0.49 timeout 2
```

RFC 8907 XORs the packet body against an MD5 chain over the shared secret —
the RFC itself calls that **obfuscation, not encryption** — so a TACACS+
server belongs on a segment you already trust, exactly like a RADIUS server.

When more than one kind of server is configured, they are consulted in a fixed
order — RADIUS, then LDAP, then TACACS+ — after the local account list, and
the first server that answers decides. A refusal names the protocol that
refused, so with three kinds configured you know which one to look at.

### Who gets in, and what they may do

A directory account still needs a local `system login` entry naming its group —
**unless** `default-group` is set:

```text
set system aaa default-group operators
```

Without that rule, configuring one server would hand management access to
everybody in the directory.

Three answers are told apart, and the difference matters. A server that
**rejects** has answered, and no other server is asked. A server that cannot be
**reached** has not answered, so the next is tried; if none answers at all, the
sign-in fails with "no authentication server answered" rather than "wrong
password". Treating an unreachable directory as a bad password locks everybody
out at exactly the moment the network is already broken.

## The serial console

```text
set system console device ttyS0
set system console speed 115200
```

The port somebody reaches for when the network is the thing that is broken, so
the baud rate is not cosmetic: it is the difference between a login prompt and a
screen of noise.

## How far back you can roll

```text
set system commit-revisions 100
```

How many past revisions the archive keeps. A policy, not a constant: a box
changed twice a year wants a longer memory than one changed twice a day. Unset
leaves the appliance default.

## A history of the box itself

```text
set system metrics enable true
```

Live counters answer "what is happening". They cannot answer "was this
happening at three in the morning last Tuesday", which is the question people
actually arrive with.

Off by default — a box with a small or read-mostly disk should not start writing
to it because a graph might be nice. When it is on, a sampler runs once a minute
and writes into a **ring per series**: the size on disk is decided when the file
is created and never changes, so a history cannot fill a partition.

Three resolutions, all fed from the same sampler run:

| Resolution | Step | Span |
|---|---|---|
| `minute` | 60 s | a day |
| `quarter` | 15 min | a month |
| `day` | 24 h | two years |

```text
show history                          # what is kept, and how far back
show history iface.eth0.rx            # the rates
show history gauge.sessions day       # a coarser view
```

**Counters are stored raw and rates derived when read.** A counter that was
reset — an interface that went away and came back, a reboot — reads lower than
the one before it, and the honest answer is a *gap*, not the enormous spike that
treating the wrap as a delta would draw. A hole the box was switched off for is
not averaged across either.

A `gauge.` series is a level rather than a total, so it comes back as it was
stored: deriving a rate from the number of connections would draw the change in
it, which nobody wants to look at.

The console's **History** view draws these, and draws a gap as a gap.

## Keyboard, locale and timezone

```text
set system keyboard de
set system locale de_DE.UTF-8
set system timezone Europe/Berlin
```

`keyboard` is the layout of the physical and serial consoles. It comes first of
the three for a practical reason: everything an operator types at the console
goes through it, and a passphrase entered on the wrong layout is a box that
cannot be unlocked. An SSH session brings its own layout and is unaffected.

`timezone` matters more on a firewall than on a desktop. Every log line, every
firewall hit, every certificate expiry and every scheduled rule is stamped with
it, and correlating an incident across two boxes whose clocks read different
zones is a reliable way to lose an hour. Unset leaves UTC in place, which is the
safe answer if you are not sure.

The zone is checked against `/usr/share/zoneinfo` on this machine rather than
against a list compiled into the appliance: the set of zones moves with tzdata,
and a built-in list would eventually refuse a zone that exists — at commit, on a
box you are already logged into.

All three apply on commit and survive a reboot. A keymap this image does not
ship draws a warning rather than failing the commit: the firewall rules in the
same commit matter more than the console layout.

## When the clock cannot be trusted

A zone only decides how the time is *written down*. Whether it is right at all is
a separate question, and one the box will not stay quiet about: a firewall that
boots with its clock years slow routes and filters exactly as usual while every
log timestamp is wrong, every certificate expiry is judged against a date that
has not happened, and every scheduled rule opens its window on the wrong day.

`show version` says so on its `clock:` line, and `show status` repeats it — but
only while it is true, so a healthy box carries no extra line:

```text
clock:      2021-01-14 03:22:57 UTC — NOT synchronised: no time source has set
            this clock, so log timestamps, certificate expiry and time-based
            rules are all unreliable
```

The judgement is the kernel's own clock-discipline flag, which the time daemon
clears once it has actually reached a server — the same signal `timedatectl`
reports, so the two never disagree. A reading that also looks implausible (it is
earlier than a file this appliance itself wrote) is quoted alongside as
corroboration; it is never the reason on its own, because a clock can be wrong
while synchronised and right while unsynchronised.

Nothing is corrected automatically. Point the box at a time source
([NTP](services.md)) — an appliance that silently moved its own clock would turn
a fault you can see into one you cannot.
