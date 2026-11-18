# Optional fleet management

An enrolled node checks in over outbound HTTPS using mutual TLS. Signed controller requests can ask for telemetry or a provisional configuration change. Local forwarding and management continue when the controller is unreachable.

## Enroll a node

Provision a controller CA, a client certificate and private key, and an enrollment-token file under `/var/lib/sentinel/fleet/`. Keep the directory root-owned (0700) and the private key and token accessible only by root (0600). Keep the controller’s command-signing private key separate from its transport credentials.

In **System → Fleet enrollment**, enter the controller URL, node ID, local credential paths and the base64 Ed25519 signing public key. A representative configuration is:

```toml
[fleet]
controller-url = "https://fleet.example.com"
node-id = "edge-a"
enrollment-token = "file:/var/lib/sentinel/fleet/enrollment-token"
ca-certificate = "/var/lib/sentinel/fleet/controller-ca.pem"
client-certificate = "/var/lib/sentinel/fleet/client.pem"
client-key = "/var/lib/sentinel/fleet/client.key"
signing-key = "<base64-ed25519-public-key>"
poll-interval = 5
```

Replace all example values with your enrolled identity. The server name must match the trusted certificate. Keep per-flow telemetry disabled unless it is required.

## Verify check-in

```sh
sentinel fleet-poll
journalctl -u sentinel-fleet.service
```

Confirm the enrolled node ID at the controller. A check-in does not implicitly confirm a pending revision. Removing fleet configuration stops polling and preserves the local appliance.

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


## Verify the implementation

Run `cargo test --workspace --locked` in the checkout and the fleet check for your revision on a KVM build host.
