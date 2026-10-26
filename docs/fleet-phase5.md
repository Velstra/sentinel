# Optional fleet management

A node remains fully functional without a controller. With no `[fleet]` section,
`sentinel-fleet.timer` is stopped, no controller request is made, and local CLI,
API, routing, forwarding and HA continue independently. Enabling/disabling fleet
is an idempotent live reconciliation; it requires no reboot.

Fleet uses an outbound HTTPS check-in. There is no additional listening socket
on the appliance. The controller queues commands for the next check-in, including
a request to collect telemetry. Every mutation is Ed25519-signed separately from
the mutual TLS transport. A controller can request a provisional application,
then explicitly confirm its exact revision or request recovery. Successful
check-ins never renew the confirmation deadline or confirm implicitly.

## Provision and enable

Provision a client certificate and private key for this node, the controller's
CA certificate, and a private enrollment-token file under
`/var/lib/sentinel/fleet/`. Keep the directory owned by root and writable by
nobody else (0700), and the client key and token owned by root with mode 0600.
A `file:` enrollment token must name a file directly in that directory; any other
path is refused at commit, and the file is opened without following a symlink at
the directory or the file. (The token is sent to `controller-url`, so a reference
that could name any root-owned private file would let whoever sets those two
fields post that file to a server of their choosing.) The controller must map the client certificate identity to the enrolled
node ID and validate the bearer credential. Client certificates are issued by
your controller/PKI; the hook does not mint a controller-trusted identity itself.

On the controller, derive the configured signing public key from its independent
Ed25519 command-signing private key:

```sh
openssl pkey -in fleet-command-signing.key -pubout -outform DER \
  | tail -c 32 | base64 -w0
```

Set the resulting public value through **System → Fleet enrollment**, or the
configuration CLI. The complete TOML shape is:

```toml
[fleet]
controller-url = "https://fleet.example.com"
node-id = "edge-a"
enrollment-token = "file:/var/lib/sentinel/fleet/enrollment-token"
ca-certificate = "/var/lib/sentinel/fleet/controller-ca.pem"
client-certificate = "/var/lib/sentinel/fleet/client.pem"
client-key = "/var/lib/sentinel/fleet/client.key"
# Set signing-key to the base64 public value obtained above before applying.
poll-interval = 5
# flow-telemetry = true   # opt in to per-flow detail; see "Telemetry" below
```

`signing-key` is required; a partial identity is rejected. The interval accepts
1–300 seconds and defaults to five. The token can also be specified inline; the
read API and human-readable configuration view redact it. Client private PEM
bytes never belong in `appliance.toml`. CA and certificate paths are absolute;
normal TLS chain, host-name/IP and validity checks are mandatory. HTTP, URL
credentials, query strings, fragments, redirects and ambient curl configuration
are not accepted: curl runs with `--disable` and an empty environment, so
`~/.curlrc`, `HTTPS_PROXY`/`ALL_PROXY`, `SSLKEYLOGFILE` and
`CURL_CA_BUNDLE`/`SSL_CERT_FILE` have no effect. Proxies are not supported. A request has a ten-second bound and responses are capped at
2 MiB. An unavailable controller cannot hold the configuration lock during its
request or block boot/forwarding.

For diagnostics, run `sentinel fleet-poll` and inspect
`journalctl -u sentinel-fleet.service`. The durable per-config state is
`/var/lib/sentinel/.appliance.toml.fleet.json` (0600); it records the high-water
sequence and the accepted/refused operation outcome, never the proposed TOML or
enrollment token. Corrupt state fails closed rather than resetting replay
protection. Removing fleet stops the timer/service and retains this record.
Changing enrollment trust locally starts a new sequence namespace.

## Controller protocol v1

The node sends `POST <controller-url>/api/v1/sentinel/check-in`, authenticating
with its provisioned mTLS identity and an `Authorization: Bearer` header. The
request body is JSON:

- `protocol`: `1`.
- `node`: the stable enrolled `node-id`.
- `nonce`: a new unpredictable 64-character hexadecimal challenge.
- `revision`: canonical SHA-256 revision of the current desired document.
- `sequence`, `result`: the last consumed command and its outcome.
- `transaction`: the same pending/completed state as the local transaction API.
- `telemetry`: null, or the snapshot requested on the preceding check-in.

The controller replies `{"command": null}` when idle, or
`{"command": {"payload": "BASE64", "signature": "BASE64"}}`. Both encodings use
standard padded base64. The decoded payload is UTF-8 JSON containing a positive
`sequence` and an `operation`. Unknown fields/actions are refused. The signature
is Ed25519 over these exact bytes, concatenated without JSON canonicalization:

```text
UTF8("Velstra Sentinel Fleet command v1") || 0x00 ||
UTF8(node) || 0x00 || UTF8(request.nonce) || 0x00 || decoded_payload
```

The payload operations are:

```json
{"sequence":1,"operation":{"action":"telemetry"}}
{"sequence":2,"operation":{"action":"apply","expected_revision":"current-revision","toml":"complete desired TOML"}}
{"sequence":3,"operation":{"action":"confirm","id":"pending-transaction-id","revision":"pending-revision"}}
{"sequence":4,"operation":{"action":"revert","id":"pending-transaction-id"}}
```

Each new command must have a higher sequence. An exact duplicate of the latest
consumed payload is idempotent; a conflicting payload at that sequence or an
older command is rejected. The high-water mark is flushed before side effects,
including commands that subsequently fail schema/CAS checks. After a lost
acknowledgement, inspect `result` and `transaction` on reconnect. If the node
reports an interrupted `processing` outcome, use those actual transaction
facts and issue a new sequence; do not assume an operation was applied.

`apply` uses the normal complete `Appliance` schema and CAS against
`expected_revision`. It cannot change the **local-only trust settings**; a
revision that differs from the running configuration in any of them is refused
with a message naming each section, and nothing is applied:

- `[fleet]` — enrollment, controller URL, signing key, telemetry opt-in;
- `[[system.login]]`, `[[system.group]]`, `[system.aaa]` — accounts, SSH keys,
  password hashes, TOTP secrets, permissions, RADIUS/LDAP/TACACS servers and
  secrets;
- `[update]` — channel URLs, pinned public keys, subscription keys (the channel
  key also verifies local images);
- `[system.ha]`, `[system.ha-witness]`, `[system.config-sync]`,
  `[system.conntrack-sync]` — pairing identity, witness secret, sync peers,
  secret and pinned fingerprint;
- `[services.ssh]`, `[services.web]`, `[system.console]` — how the local
  operator reaches the box.

A controller must send these sections exactly as the node has them. Changing
them is a local management act. Policy — rules, zones, NAT, interfaces,
routing, VPN tunnels, DNS/DHCP and other services — remains fleet-managed. The independent commit-confirm worker and
watchdog protect address, port, TLS, VLAN, routing and firewall changes. Wait for
`transaction.pending.ready`, verify reachability, then sign a separate `confirm`
for that identity and revision. Without it, the previous saved and working state
returns automatically, including across process death or reboot. Expired/stale
confirmations cannot resurrect a revision. Confirmed changes enter the ordinary
HA configuration outbox; provisional revisions are not replicated.

Fleet enrollment is member-local. HA pairing/config sync preserve each node's
own identity, private-file paths and token. A source's fleet credential is not
included in shared configuration deliveries.

## Telemetry and verification

A signed `telemetry` command requests the following check-in's snapshot. By
default it carries **counters only**: the conntrack total, rule counters, HA
authority, Wren routes and neighbors, VPN handshakes and cumulative interface
counters, with `"flow_detail": false`. Nothing in it names a client. Per-flow
detail — the sampled connection states, the NAT flow table and the top talkers,
all lists of endpoint addresses — is sent only when the node's operator sets
`set fleet flow-telemetry true`; being part of `[fleet]`, a controller cannot
turn it on for itself. Source failures are
explicit; interface rates may be unknown on this one-shot sample, so the
controller derives rates from successive cumulative counters. Fleet never drains
the packet-event ring: the local API remains its sole streaming consumer.

`nix build .#checks.x86_64-linux.fleet -L` boots an appliance and a real TLS
controller fixture. It checks client-certificate authentication, wrong CA/token,
private key permissions, signed telemetry without stolen ring events and
without flow detail until opted in, bad signatures/challenges/targets, a signed
revision adding a login refused, replay across reboot, live apply, explicit
confirm, controller-outage rollback, local edits and return to standalone
operation.
`tests/fleet/controller.py` is solely that disposable test peer; it is not a
production fleet controller. The existing API PR-CI check includes this VM.
