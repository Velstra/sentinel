# Sentinel 1.0.0 release notes

Sentinel 1.0.0 is the first release of the appliance with a stable configuration
language, signed A/B image updates and a qualified firewall and NAT data plane. It
follows 0.4.2 and replaces the 1.0.0 candidate of 2026-10-26, which was never
released. Everything that changed is listed in the
[changelog](https://github.com/Velstra/sentinel/blob/main/CHANGELOG.md); this page
says what an operator has to know **before** upgrading.

The release closes the findings of the independent 1.0.0 release audit of
2026-11-18/19. Finding identifiers (`DP-…`, `CTRL-…`, `HA-…`, `IMG-…`, `PROV-…`)
are cited where they explain a change.

## Before you upgrade

1. **Check the saved configuration with the 1.0.0 CLI first.** Export it from the
   box and run `sentinel config check appliance.toml` with the 1.0.0 CLI off-box,
   or stage the update and read the trial boot's report. 1.0.0 refuses several
   configurations that earlier releases accepted (list below).
2. **Plan one outage per HA pair** (next section). An HA upgrade is not hitless.
3. **Rotate a weak config-sync secret** before you upgrade, with
   `sentinel ha secret generate`, on both members.
4. **Keep console or out-of-band access** for the first boot. The update keeps the
   previous image as the fallback slot; do not bless the new slot before you have
   checked management access and forwarding.

## Upgrade warnings

### HA pairs: one failover outage and one state reset per upgrade

Zone policy identifiers are now stable hashes of the zone name instead of the
zone's alphabetical rank (DP-13), and a rule without `direction` now compiles as an
ingress rule (DP-15). Both are part of the shared-policy digest that decides
whether the standby is ready. While the two members run different versions:

- the standby reports `not ready: policy differs`, and conntrack sync refuses its
  sessions (safely; nothing wrong is installed);
- the switch-over to the upgraded member is therefore an **outage with loss of
  every established connection**, not a warm failover. Expect it once per upgrade;
- after the upgrade, the **first commit** reloads the data plane once with fresh
  state, because the stored policy identifiers change. Make that first commit in
  the same maintenance window.

Upgrade in this order, and do not leave a pair half-upgraded:

1. upgrade the standby and let it boot and bless its slot;
2. fail over to it (the outage above);
3. upgrade the old primary;
4. commit once on the active member.

**Never fail back onto a member that is not yet upgraded.** A masqueraded
connection owned by a 1.0 member does not survive a takeover by a pre-1.0 peer:
the older allocator looks for its public port in a different place and breaks the
connection. The other direction is covered: connections the older member owns
survive the switch-over to the upgraded one (`checks.ha-napt-mixed-version`). While the versions differ, do not change
accounts, AAA, update channels, SSH, console, BGP `update-source` or PPPoE
`local-address` on either member ([HA handbook](handbook/ha.md#mixed-versions-during-an-upgrade)).

### Configurations 1.0.0 refuses

`sentinel config check`, `commit` and `save` refuse these. What happens at boot is
stated per item.

| Change | Refused | At boot |
|---|---|---|
| Port forward or load balancer with a protocol other than `tcp`, `udp` or `tcp_udp`; two load-balancer services on one zone, protocol and port (DP-18) | yes | the saved file fails validation (see below) |
| A data-plane table over its capacity: more than 8,192 rule-trie entries (a rule without an address counts once in each source trie), more than 127 rate-limited rules, a global blocklist that exceeds 262,144 entries once copied into every zone, MAC rules, forwards, SYN proxy entries (DP-17, DP-29, PERF-03) | yes | boots the last-known-good or management-only configuration and says so |
| A rule without `proto` that also names a source, destination, group, family, direction, ICMP type or `log`, or that a zone's explicit `default-action` overrides (DP-14) | yes | the qualifier, or the inert rule, is removed and reported |
| Control characters (tab, CR, NEL, U+2028/2029) in any string, and malformed values in fields that reach daemon configuration files: SSH log level, DHCP host-name, bond hash policy and LACP rate, dynamic-DNS login and password, NTP `allow-from`, PPPoE subscribers and client password, update subscription key, sysctl keys, DNS TXT records (CTRL-02, -03, -08, -13, -16 to -18, -29) | yes | the setting or service is switched off with an error line; the rest boots |
| A config-sync secret shorter than 32 bytes or guessable (CTRL-01) | every change is refused until it is rotated | boots and keeps pairing; warns at every apply |
| A `drop`/`reject` rule with a non-local `to` zone, when the rule, a zone or an interface changes | yes | unchanged rules still load |

**If the saved file fails validation at the first boot of 1.0.0**, there is no
last-known-good file yet (1.0.0 records it after its first healthy boot), so
`sentinel-boot` fails. The trial boot then fails its health assessment and the
loader returns to the previous image after its counted attempts. Fix the
configuration on the old image and stage the update again.

### Packet handling that changed

- **IPv4 options (DP-34):** TCP and UDP packets whose IPv4 header carries options
  are dropped on stateful zones; they cannot be tracked, proxied or translated.
  Stateless zones still judge them by their rules.
- **Rule direction (DP-15):** a rule without `direction` matches arriving traffic
  only. `from wan proto tcp port 25 action drop` no longer stops LAN hosts sending
  mail. Use `direction both` for the old meaning.
- **Blocklists and GeoIP name sources (DP-15):** a zone or global blocklist and
  `geoip-block` refuse what a listed address sends in, and nothing else. They no
  longer stop LAN hosts reaching a listed address, and the answers to such
  connections are let back in. There is no outbound blocklist in 1.0: to keep the
  inside from reaching listed addresses, write `direction out` rules.
- **SYN proxy scope (DP-31):** `syn-protect` proxies a port only on the zones that
  admit it (an accept rule, a port-forward or a load balancer), so LAN clients'
  outbound connections to that port are no longer proxied. A port that no zone
  admits that way stays proxied everywhere, and `config check` says so.
- **IPv4 rules no longer match IPv6 (DP-11):** a rule on `0.0.0.0/…` used to apply
  to all IPv6 traffic as well. If IPv6 was blocked only by such a rule, it now
  passes. Review the IPv6 policy.
- **`block-icmp` (DP-10):** refuses new inbound ICMP only. Echo replies and ICMP
  errors about tracked connections (packet-too-big included) pass, outbound ICMP is
  not affected, and IPv6 neighbour discovery and MLD always pass on every zone.
- **RELATED ICMP is delivered (DP-10, DP-21):** a UDP probe to a closed port now
  receives its port-unreachable at once; IPv6 path-MTU discovery works.
- **Fail-closed zones (DP-22):** non-IP EtherTypes other than ARP, 802.1Q/802.1ad,
  PPPoE, LLDP, EAPOL, slow protocols and MACsec are dropped.
- **TCP state (DP-03, DP-08, DP-25, DP-37):** out-of-window RSTs are ignored;
  XMAS, NULL, FIN-only and out-of-state packets are dropped on stateful zones;
  non-SYN TCP no longer creates NAT state.
- **Duplicate rules (DP-30):** two rules on one zone, protocol, port and address
  hold the stricter verdict in the data plane, as `sentinel trace` reports.
- **NAT (DP-04, DP-05, DP-23):** GRE, ESP, SCTP and 6in4 are masqueraded instead of
  leaking the private source; AH, ICMP timestamp and ICMP with options are dropped
  at WAN egress; IPv4 fragments are translated; hairpin NAT rewrites the client
  port. A new masqueraded connection examines a fixed window of 128 candidate
  ports, so the connection rate no longer collapses after an ICMP echo or a
  port-forward (DP-26, PERF-02).

### Credentials and management

- The config-sync secret is no longer a full-access API bearer (CTRL-01, CTRL-07).
  On the first apply, an API token file equal to the secret is replaced by a fresh
  random token. Scripts that used the secret as a bearer receive `401`/`403`; use
  `/var/lib/sentinel/api-token`.
- Config sync no longer carries accounts, groups, AAA, update channels and keys,
  SSH, the console, BGP `update-source` or PPPoE `local-address` (CTRL-09, CTRL-10).
  Configure them on each member.
- `save` writes the committed running configuration and refuses while the session
  has uncommitted edits (CTRL-14). Scripts of the form `set …; save` must commit
  first.
- An IPsec pre-shared key containing a backslash is now written escaped, so the
  effective key changes; set it again on the peer (CTRL-29).
- Staging an unversioned local update proof (a signed digest or a raw
  signature) requires `--allow-downgrade`; use the release's signed manifest
  instead. No slot can be written during an unblessed trial boot (CTRL-11,
  CTRL-26).
- **Self-hosted update channels:** signed channel metadata must carry a
  freshness policy (channel, architecture, sequence number, issue and expiry
  time, at most 14 days apart). 1.0.0 refuses metadata without one, a
  sequence lower than one it has seen, and a sequence reused for different
  bytes, so a channel must be re-signed at least every 14 days.
- `save` never confirms a pending `commit-confirm`: while one is pending,
  every write, `save` included, is refused until you `confirm` or the trial
  reverts.
- An operator in `wheel` who opens `sentinel configure` on the box now gets one
  root session through `sudo` (one `configure` entry in the sudo log) instead
  of one sudo call per step; commits take seconds instead of half a minute.
  Accounts outside `wheel` and `--no-apply` sessions keep their own
  privileges, so a `--no-apply` save cannot replace the box's root-owned
  configuration.

### State survives an agent restart

Sentinel now asks the data plane to persist its hooks and state tables
(`[state] persist = true`, DP-12, DP-27): an agent restart, crash or reconfigure
keeps enforcing and keeps NAT sessions, and zoned links are no longer held down
while it restarts. Connection-state tables are sized from the box's memory and
hold at least 16,384 connections, so a larger box
uses more kernel memory for them than before (DP-06). The SYN proxy's table is
sized for one record per connection, so the tables' layout changed: the **first
agent restart after the upgrade starts with fresh state** instead of adopting the
pinned tables (pinned state never survives the upgrade's reboot either).

## Known limitations

- **SYN proxy and source-port reuse.** The proxy's record of a connection is
  removed by the agent once no live connection state claims it, two passes of the
  state tables after that state is gone (seconds on a small box, minutes on one
  sized for millions of connections). A client that reconnects from the same
  address and port to the same protected service inside that window is not
  admitted until it retries after it ([firewall handbook](handbook/firewall.md)).

- **IPv6 is not SYN-proxied in 1.0.** The SYN proxy protects IPv4 only (DP-35).
  Where a protected port is reachable over IPv6, `config check` names the zones.
  IPv6 SYN proxying is planned for 1.1.
- **Masquerade port ceiling per remote endpoint.** One public address carries
  about **31,000 concurrent connections to one remote ip:port**; beyond that new
  connections are refused and counted in `egress_nat_no_candidate`
  (`show firewall statistics`). No NAT can exceed 32,768 per public address and
  endpoint; a closed connection holds its port for the closing timeout (30 s), so
  one address sustains roughly a thousand new connections per second from fresh
  client ports to one service. Masquerade in 1.0 uses the one address of each
  uplink and has no address pool, so the remedy is another masquerading uplink
  ([firewall handbook](handbook/firewall.md)).
- **Rule capacity.** At most 8,192 rule-trie entries per address family; a
  larger rule set is refused at `config check` and `commit` with the capacity
  named, and a saved file over the limit boots the last-known-good configuration.
- **No bulk removal of the global blocklist.** `delete firewall global block`
  takes one entry; there is no command to clear a large blocklist at once in 1.0.
  Remove entries in one batch session and commit once.
- **IPv4 options** in TCP and UDP are refused on stateful zones (DP-34, above).
  Traffic that needs them must cross a zone with `stateful false`; other
  protocols (IGMP router-alert, for example) are not affected.
- No outbound blocklist (DP-15, above). IPv6 is not NAT-translated for fragments;
  IPv4 fragments that arrive before the first fragment are dropped (DP-05).
- A NIC that strips 802.1Q tags in hardware makes the parent's zone judge VLAN
  traffic under native XDP (DP-22). Turn `offload rxvlan` off on such a parent.
- `hairpin true` on a DHCP or PPPoE WAN does nothing yet (DP-39; `commit` warns).
- NIC names follow PCI slots; give zoned NICs an `hw-id` (PROV-04; `config check`
  warns).
- A commit interrupted by SIGKILL, out-of-memory or power loss is not rolled back
  (CTRL-15 covers signals, I/O errors and panics).
- HA remains experimental: its VM checks cover election, failover with state
  and the masquerade and SYN-proxy failovers, not every partition or
  witness-loss case. Rolling upgrades are not hitless (above), and the witness
  is a single point of authority by design.
- **HA with WireGuard steps a lagging clock forward on takeover.** Both members
  answer WireGuard peers with one identity, and a peer accepts a handshake only
  with a newer timestamp than the last. A member whose wall clock fell behind
  (a hypervisor pause or migration) therefore steps it forward to its
  predecessor's after taking the VIPs and before reconfiguring WireGuard, and
  tunnels follow the takeover in about a second. A small helper with only
  `CAP_SYS_TIME` takes the step, not Wren. The step is forward-only and logged.
  It is refused beyond 10 minutes, beyond 60 seconds when both clocks claim NTP
  synchronisation, when this member is NTP-synchronised and its predecessor is
  not, and beyond 10 minutes of steps in one boot. Wren cannot forge the
  predecessor's reading the helper acts on. Then tunnels may stall until NTP corrects the clock, and
  `sentinel show health` reports `ha-clock-behind-peer`. Run NTP on both
  members ([HA handbook](handbook/ha.md)).
- **Kernel CVEs without a 6.12.y fix.** 1.0.0 ships Linux 6.12.118. Of the
  181 High/Critical kernel matches the image scan reports, the kernel CNA's
  per-branch records show 109 already fixed on 6.12.y and 3 not present in 6.12;
  **51 affect 6.12 and have no 6.12.y fix yet**, and **18 have no kernel.org
  CNA record**. These 69 are listed one by one in the release gate's
  kernel baseline (`scripts/cve-waivers.json`), not accepted as a count, and
  none has been checked against the appliance's kernel configuration yet.
  40 of the 51 are fixed in the 6.18 LTS line, which is evaluated with the
  NixOS 26.11 base roll.

## Verification

See the qualification record for this release in the changelog's 1.0.0 entry
and the [test catalogue](reference/tests.md).
