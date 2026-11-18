# System and management

<a id="system--management"></a>

Use the console when introducing new authentication methods. Verify a new administrator session before removing an existing working access path.

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

Shared configuration and per-member identities must stay distinct. Use the [witness-backed HA runbook](../operations/high-availability.md) for two-member enrollment and peer authority.

## HA conntrack sync

A standby needs compatible policy and current replicated state for an established flow to continue. Check replica readiness on both members before a maintenance failover.

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

Configure the directory endpoint, base DN and bind credentials under `set system aaa ldap`. Verify directory trust, the user lookup and role mapping.

### TACACS+

Configure the designated server and its shared secret under `set system aaa tacacs`. Test the intended authorization level as well as successful login.

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
