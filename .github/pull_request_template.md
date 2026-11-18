## Change

Describe the operator-visible change and link the issue. State what remains out
of scope, including any compatibility or migration limits.

## Verification

List the exact commands, source/input revisions and results. For image or packet
path changes, include the tested image/object hash and retained VM/packet
evidence. Distinguish executed passes from evaluation, skipped or pending tests.

## Review checklist

- [ ] A regression test reproduces the defect or demonstrates the feature.
- [ ] CLI, API and UI behavior is checked where affected; any untested path is named.
- [ ] Failure, rollback and invalid-input behavior is checked where affected.
- [ ] Documentation describes actual support and known limits without claiming release certification.
- [ ] No credentials, private keys, raw appliance images or sensitive QA artifacts are included.

For a security-sensitive fix, follow [SECURITY.md](../SECURITY.md) before opening
a public PR. Contribution terms are in [CONTRIBUTING.md](../CONTRIBUTING.md);
there is no separate administered CLA.
