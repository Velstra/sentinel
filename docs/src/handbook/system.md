# System & management

The `system` tree holds host-wide identity and the management surfaces —
who can log in, and how the box syncs to an HA peer. SSH daemon tuning lives
next door under `services ssh`.

## Persistent logs

Installed images retain `/var/log` on the data partition. The journal is bounded
to 128 MiB, keeps 256 MiB free and expires entries after 14 days. Before an
update or when diagnosing an earlier boot:

```sh
journalctl --list-boots --merge
journalctl --merge -u velstra.service -u wren.service
```

`--merge` includes retained logs from earlier machine IDs on an unprovisioned,
stateless test VM. It does not retrieve logs from remote cluster members.

## Hostname

```text
set system hostname fw-a
```

The hostname is applied live on commit and shown in the prompt.

## Login accounts

`system login <user>` defines a local account. Accounts are created on commit;
each carries SSH public keys and an optional login password.

| Command | Meaning |
|---|---|
| `set system login <user> ssh-key <openssh-key>` | An OpenSSH public key allowed to log in as this user (repeatable). |
| `set system login <user> password <password>` | Hash a new local password with yescrypt; do not put plaintext commands in shell history or scripts. |
| `set system login <user> hashed-password <hash>` | Import a supported crypt(3) hash, never a plaintext password. |
| `set system login <user> totp <base32-secret>` | A one-time-code secret. The account then needs a code as well as a password. |

**SSH stays key-only** unless you also enable password auth on the daemon
(below). A local `read-write` group grants administrator access, including
passwordless sudo; read-only and ordinary ungrouped users do not receive it.
The configured, ungrouped built-in `admin` retains bootstrap administrator
access in both CLI and API; explicitly assigning it a read-only group removes
that exception. This does not grant administrator access to other ungrouped
accounts. Removing a managed account locks it, removes its managed SSH keys and
administrator group, and terminates its existing login sessions and user jobs.
Homes are not deleted. Demotion also expires old sessions. Use another
administrator or a recovery console when removing or demoting your own account.

New local passwords use yescrypt cost 5 (16 MiB), with a random salt. Existing
MD5-, SHA-256- and SHA-512-crypt hashes remain verifiable by the API; there is no
automatic rehash. The OS/PAM policy is unchanged: imported MD5 and SHA-256 hashes
do not grant password-based SSH/console access. Reset those passwords to yescrypt
before relying on OS login. The API's compatibility helper does not weaken the
system-wide crypt policy. Rotate legacy local passwords to migrate them. Imported yescrypt costs
are bounded (up to 32 MiB), and passwords must be 8–511 bytes with no NUL or line
break. These limits apply to local Unix/API accounts. Rendered OpenConnect VPN
credentials also use cost-5 yescrypt, but retain their existing non-empty
password-length compatibility. The root-private runtime credential file reuses
an unchanged password's validated hash; a legacy SHA-512 hash migrates on apply.
OpenConnect tunnel/restart acceptance still needs the final image's VM results.
To import a hash generated off-box, use an interactive password prompt:

```text
$ mkpasswd --method=yescrypt --rounds=5

admin@fw-a# set system login alice ssh-key ssh-ed25519 AAAAC3Nz…I alice@laptop
admin@fw-a# set system login alice ssh-key ssh-ed25519 AAAAC3Nz…J alice@phone
admin@fw-a# set system login alice hashed-password $y$j9T$<salt>$<digest>
```

The persistent, root-private `/var/lib/sentinel/login-accounts.json` registry
keeps each managed local UID stable across boots and reserves retired UIDs.
Retired `admin` accounts are not silently recreated with bootstrap privileges.
When upgrading an appliance without this registry, only currently configured
accounts are adopted: manually review Unix users removed before the upgrade.
Do not delete the registry to reset an account; corruption or UID drift fails
closed. These lifecycle changes still require the final image's VM login/SSH
acceptance results before release qualification.

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

A listen address selects the destination IP, not an allowed ingress interface.
Linux can deliver traffic arriving on another interface to that local IP. An
unzoned management NIC is deliberately unfiltered; its address is **not** an
implicit management-only boundary. The same applies to the Web console's listen
address and HA's receiving management API.

For example, deny SSH and HTTPS to management address `10.0.0.1` from an existing
`lan` zone, while keeping direct access on the separate management NIC and
forwarding to other hosts on those ports:

```text
set firewall rule deny-lan-management from lan
set firewall rule deny-lan-management proto tcp
set firewall rule deny-lan-management port 22,8080
set firewall rule deny-lan-management destination 10.0.0.1/32
set firewall rule deny-lan-management family ipv4
set firewall rule deny-lan-management action drop
commit-confirm 2
```

Use the actual service ports and management IP. Repeat for **each untrusted
ingress zone** and every exposed management address; IPv6 needs a separate rule
with `family ipv6` and the exact host `/128`. Use a destination match, not a broad
`to` rule or a combined source/destination rule. Verify both management access
and the intended denial before `confirm` and `save`; keep a local recovery
console. This is opt-in network policy, not automatic interface isolation.

## HA config sync

HA is **experimental**. Fenced pairing has witness and witnessless `two-node`
modes with different partition behavior; neither is equivalent to legacy VRRP
plus config sync. Follow the current [HA pairing and recovery guide](ha.md)
before using `sentinel ha pair <peer-endpoint>`. The token is read from stdin
with `--secret-stdin`, or prompted for without echo. Pairing authenticates the
first TLS connection before sending the bearer and records both member profiles
in canonical `appliance.toml`. Review the guide's known failure modes and retain
an independent management/console recovery path.

`system config-sync` delivers desired policy through the management API. CLI
commits and API updates queue a durable revision, with retries for an unavailable
peer; a received revision never queues a reverse push. Apply and persist share
one transaction lock. Paired revisions materialize the explicit peer identity,
including management/control endpoints and interface addresses, then validate and
apply the complete peer-adjusted document. New static links need their peer facts
in `system.ha.peer-identity` rather than an inferred address.

| Field | Meaning |
|---|---|
| `peer` | Receiver endpoint, `host` or `host:port` (default port 8080). Leased HA uses exactly one peer. |
| `secret` | Shared machine enrollment credential. It also enables the receiving HTTPS API. |
| `peer-fingerprint` | Base64 SHA-256 management TLS public-key pin. Pairing records the authenticated peer pin. |

The receiving API always honors `services.web.listen-address` and `port`, even
when `services.web.enable = false`. A secret alone leaves the default listener
on `127.0.0.1:8080`; it does not expose every address. Set a reachable control
address explicitly on **each** peer before remote synchronization or pairing.
Address binding is not ingress-interface isolation; apply the explicit
management ACL above where required.

Outside leased HA, legacy config sync can target multiple receivers. It preserves
the receiver's web listen address/port and existing local address/identity facts;
other web settings, including TLS, remain synchronized policy. A new static interface must
already have its receiver facts declared. Drive changes from one node to avoid
competing desired states. Legacy VRRP/config-sync alone does not provide the
witness's split-brain fencing guarantees.

Before upgrading an existing legacy-sync pair, reconcile outstanding changes
and verify delivery on both members, then upgrade both to the same reviewed
version. The new endpoint-aware shared revision can reject a queued old base as
a conflict. Preserve its outbox and receive-journal evidence for recovery; never
delete participation fences to force an otherwise refused first synchronization.

## HA conntrack sync

Conntrack sync requires an explicit 32–1024-byte `system.config-sync.secret`
and at least one state peer. Sentinel derives the authenticated state credential
from that secret; it never selects unauthenticated UDP, invents a credential or
widens a management bind. The explicitly configured secret activates the shared
API with the listener settings above, including in state-only configurations.
Config sync uses HTTPS for policy delivery;
conntrack sync uses mutually authenticated framed TCP for flow state. They are
separate services.

The TCP transport uses a default 50ms poll interval. It transfers complete snapshots, updates and
deletions for NAT, dual-stack firewall and SYN-proxy splice state. Kernel reads
are batched; configuration/policy generations fence incompatible state. Leased HA
also binds every transfer to the current witness authority. A former master
imports authoritative successor state before preemption; an incomplete map
installation does not advertise readiness.

WireGuard promotion uses the shared long-term VPN identity and authenticated
learned public endpoints to initiate new handshakes. Ephemeral kernel session keys
are not copied. The dedicated control tunnel remains member-specific and needs
an independent declared underlay outside the fenced data links.

| Field | Meaning |
|---|---|
| `listen` | Local state endpoint, numeric `IP:port` in leased HA (default port `5429`). |
| `peer` | Explicit state receiver endpoint. At least one is required; leased HA requires exactly one. |
| `interval` | Optional poll interval in seconds; omit it in leased mode to use 50ms. |

Legacy unsigned UDP and listen-only state replication are disabled. Before
upgrading, [migrate both members or remove the old state-sync block](ha.md#migrate-legacy-state-sync)
deliberately; an incompatible saved configuration is rejected, not downgraded.
Authenticated TCP protects integrity, not confidentiality: use an isolated HA
network or a dedicated control WireGuard tunnel when flow metadata must remain
private. Credential validation and transport selection alone do not establish
successful HA flow-failover qualification.

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

Newly generated secrets contain 160 bits (32 base32 characters). Treat the
printed secret and URI as credentials; do not put them in screenshots or issue
attachments.

The code is checked **after** the password and never instead of it, so a wrong
password and a wrong code are the same refusal from outside — there is nothing to
probe.

An accepted code's counter is durably consumed before issuing a session, so it
cannot be reused on that appliance after an API restart or reboot while its
persistent state is retained. Wait for the next 30-second code for another
login. The private replay state fails closed if corrupt or unwritable; deleting
it is not a safe login workaround. This protection is **per appliance**, not a
cluster-global replay guarantee. Keep time synchronized on every member.

Two places it deliberately does not apply. The **serial console** has no second
factor: it is the port you reach for when the network this box manages is the
thing that is broken. **SSH** has none either — that belongs to sshd's own
configuration, not here.

## Web sign-in limits

Sign-in attempts share an origin budget: ten attempts in a ten-minute window
trigger a 15-minute lockout for subsequent attempts. IPv6 addresses in the
same /64 share that budget. A separate account
budget permits 30 attempts in a ten-minute window, across origins.

The account limit also blocks a correct password from another origin. Someone
targeting a known account can therefore temporarily deny web access; keep an
independent SSH or serial recovery path. Successful sign-in clears both budgets.
These limits are held in memory and reset when the API restarts; they are not
cluster-wide or persistent protection.

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

The client uses PAP with a mandatory Message-Authenticator (attribute 80,
HMAC-MD5). The server must include a valid Message-Authenticator in every
Access-Accept and Access-Reject; missing, duplicate or invalid authenticators
are refused. There is no legacy unsigned-response downgrade. Configure the
RADIUS server accordingly before relying on it for access.

RADIUS/UDP password hiding and integrity checks do not provide modern transport
confidentiality. Use an isolated trusted network or a protected tunnel; do not
expose this exchange on an untrusted network.

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
