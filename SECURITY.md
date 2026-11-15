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
