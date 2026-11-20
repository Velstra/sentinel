# Security

The full policy, including safe harbour, is at
<https://www.velstra.cloud/security>. This file is the short version for the
repository.

## Report a vulnerability

Report privately, never in a public issue, pull request or discussion:

- [GitHub private vulnerability reporting](https://github.com/Velstra/sentinel/security/advisories/new)
  (preferred), or
- email `security@velstra.cloud`, encrypted with our OpenPGP key
  (fingerprint `TODO(owner): key fingerprint`).

Include the affected version or commit, image SHA-256, configuration with
secrets removed, reproduction steps and observed impact. Reports about bundled
dependencies and image defaults are in scope, not only Sentinel's Rust code. Do
not put credentials, private keys or sensitive appliance archives in a report
you cannot control; if credentials were exposed, replace them first. Removing
a file from the latest commit does not remove it from Git history or existing
clones.

There is no bug-bounty program. We credit reporters unless asked not to.

## What happens next

- Acknowledgement within 3 business days.
- A first assessment (reproduced or not, severity, affected versions) within
  10 business days.
- A coordinated disclosure date agreed with you; we aim to publish within 90
  days of the report, sooner when a fix is ready or the issue is exploited.
- Advisories are published as GitHub security advisories on this repository,
  with a CVE ID requested through GitHub, and listed in `CHANGELOG.md`.
- Security fixes land in public Sentinel first. Enterprise LTS subscribers
  receive them as certified updates on their channel; no fix is held back for
  paying customers.

Good-faith research under the published policy is authorised: test your own
appliances or VMs, do not degrade update.velstra.cloud or access other
people's data, and give us reasonable time before publishing.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.0.x | Yes: security fixes on `main` and in the next 1.0.x community release |
| < 1.0 | No: upgrade to the latest 1.0.x release |

Enterprise LTS lines (`vX.Y.*-lts`) have a five-year support period per line;
see the [support policy](https://www.velstra.cloud/support#lifecycle). A
passing source CI run is not an image security assessment or a production
release certification.

## Cyber Resilience Act reporting

We follow Article 14 of the EU Cyber Resilience Act: an actively exploited
vulnerability in Sentinel, or a severe incident affecting its security, is
reported through the single reporting platform to the coordinating CSIRT and
ENISA with an early warning within 24 hours of becoming aware, a notification
within 72 hours, and a final report after a fix is available; affected users
are informed. Sentinel has no conformity assessment under the CRA and carries
no CE marking or security certification.

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
