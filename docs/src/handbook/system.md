# System and management

<a id="system--management"></a>

Use the console when introducing new authentication methods. Verify a new administrator session before removing an existing working access path.

## Security boundaries

Read the [authentication and synchronization reference](../reference/authentication.md) before changing accounts, AAA, TOTP or HA transport. It covers privilege revocation, password compatibility, persistent replay protection, sign-in lockouts and legacy-sync migration.

A management listen address does not restrict ingress interfaces. Test explicit destination ACLs from every untrusted segment. HA is experimental; policy sync and flow-state sync are distinct authenticated services, not proof of failover readiness.

## Hostname

Change the hostname in the candidate, review it and apply it. Confirm a temporary remote change before persisting it.

```text
set system hostname fw-a
```

## Login accounts

Provision each administrator’s own SSH public key; keep the private key on that administrator’s device. The example assumes an account named `alice`.

```text
set system login alice ssh-key <public-key>
```

Use the complete public-key line in place of the placeholder. Test login from a second session before altering the original account.

## SSH daemon

Restrict the SSH listener to the management address and use the intended port. Test a separate administrator login.

```text
set services ssh port 2222
set services ssh listen-address 10.0.0.1
```

## HA config sync

Shared configuration and per-member identities must stay distinct. Use the [HA mode and enrollment runbook](../operations/high-availability.md) for two-member enrollment and peer authority.

The receiver honors its local Web listener address and port even with the interactive Web UI disabled. A secret alone leaves the default loopback listener; explicitly configure a reachable control address on each member. Preserve receiver-local identity and review the [legacy revision migration](../reference/authentication.md#ha-config-sync) before upgrading.

## HA conntrack sync

A standby needs compatible policy and current replicated state for an established flow to continue. Check replica readiness on both members before a maintenance failover.

State replication requires an explicit 32–1024-byte config-sync secret and at least one state peer. Unsigned UDP and listen-only replication are disabled. Authenticated framed TCP provides integrity, not confidentiality; isolate or encrypt the control link. [Migration and transport details](../reference/authentication.md#ha-conntrack-sync).

## A second factor

Enroll the user’s TOTP device and test it with a synchronized appliance clock before relying on it.

```text
set system login alice totp generate
```

## Where a password is checked

External authentication can use RADIUS, LDAP or TACACS+. Keep a tested local recovery account and apply authentication changes with a confirmation window.

### RADIUS

Configure the server address, timeout and a site-issued shared secret under `set system aaa radius`. Verify authentication and role mapping with a test account.

### LDAP

Configure the endpoint, base DN and TLS under `set system aaa ldap`. This is a simple bind as the authenticating user, not a service-account directory search. Verify certificate trust and local group mapping; do not silently fall back to plaintext.

### TACACS+

Configure the designated server and its shared secret under `set system aaa tacacs`. This integration authenticates users; it does not implement server-side TACACS+ authorization or accounting. Verify the locally configured group permissions as well as successful login.

### Who gets in, and what they may do

Check the group assigned to the account, including any configurable default for directory users.

```text
set system aaa default-group operators
```

## The serial console

Match the console device and speed to the attached terminal or BMC console.

```text
set system console device ttyS0
set system console speed 115200
```

## How far back you can roll

Set the archive retention to the number of configuration revisions your change process needs.

```text
set system commit-revisions 100
```

## A history of the box itself

Enable local metrics collection when trends over time are needed in addition to live counters.

```text
set system metrics enable true
```

## Keyboard, locale and timezone

Match the console keyboard, locale and timezone to the operating environment. Verify the layout before entering a sensitive credential.

```text
set system keyboard de
set system locale de_DE.UTF-8
set system timezone Europe/Berlin
```

## When the clock cannot be trusted

Check synchronization before investigating suspicious timestamps, certificate validity or time-based login failures.

```text
clock:      2021-01-14 03:22:57 UTC — NOT synchronised: no time source has set
            this clock, so log timestamps, certificate expiry and time-based
            rules are all unreliable
```

## Check the result

```sh
sentinel show version
sentinel show system commit
```

Check time synchronization before testing a time-based factor. Inspect revision history before restoring an older configuration.
