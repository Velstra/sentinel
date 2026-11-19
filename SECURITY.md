# Security

Report vulnerabilities privately through
[GitHub private vulnerability reporting](https://github.com/Velstra/sentinel/security/advisories/new).
Do not put credentials, private keys or sensitive appliance archives in public issues.

Include the affected version or commit, image SHA-256, configuration with secrets
removed, reproduction steps and observed impact. Reports about bundled dependencies
and image defaults are in scope, not only Sentinel's Rust code.

Before 1.0, security fixes target the current main branch. A passing source CI run
is not an image security assessment or a production release certification.

If credentials were exposed, replace the affected credentials first. Removing a
file from the latest commit does not remove it from Git history or existing clones.

## Management trust model

The appliance accepts three kinds of management bearer:

- the **machine token** (`/var/lib/sentinel/api-token`, root-only, random): full
  access, for the operator on the box;
- a **session** from signing in with an account: what its group grants, ended by
  idle time, lifetime, sign-out or any change to the account;
- the **config-sync secret**, presented by an HA or config-sync peer: read
  access, `PUT /api/v1/config-sync` and `POST /api/v1/ha/pair` (the latter
  only to enroll an unpaired member or repeat the applied pairing), nothing
  else.

A peer cannot change who manages the receiving member (accounts, groups, AAA,
update channels and keys, SSH, console stay local) and is not shown account or
directory secrets, but it does set the shared firewall, NAT, routing and VPN
policy, and it reads the shared policy secrets. **Whoever holds the config-sync secret, or controls one member,
controls the traffic policy of the pair.** Generate the secret with
`sentinel ha secret generate`; weak secrets are refused. The HA proof, sign-in
and bearer authentication are rate-limited per source, and pre-authentication
connections are capped per source and in total. Details:
[authentication reference](docs/src/reference/authentication.md),
[HA handbook](docs/src/handbook/ha.md).
