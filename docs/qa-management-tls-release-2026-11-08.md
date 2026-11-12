# Automatic management TLS renewal and OS release metadata

## OSQA-008: preserve the key while renewing automatic certificates

Previously, automatic TLS initialization returned whenever both files existed.
Rebinding the listener to a new literal address therefore kept an old certificate
without that address's SAN. Renewal now reuses the original private key when a
required SAN is missing or fewer than30days remain. An intact suitable certificate
is unchanged. Lost or mismatched keys and corrupt identity files fail closed;
there is no silent replacement of a pinned identity. Explicit operator certificate
and key paths bypass automatic renewal entirely.

Identity files are single-link, caller-owned regular files, opened without
following symlinks. The parent must be caller-owned and not group/world writable.
A cross-process lock serializes issuance. Private files are0600 from creation.
The new certificate is checked for its public-key identity, SANs and validity
before atomic publication. New keys use atomic no-replace publication; a crash
after key publication recovers using that same key. Existing keys are never
rewritten by renewal, so config-sync's SPKI pin remains stable.

Six Rust tests cover rebind/idempotency, expiration-window renewal, missing or
mismatched key, corruption/name injection, symlink/hardlink refusal and concurrent
initialization. `tests/management_tls.py` additionally starts the real HTTPS API,
verifies certificate trust and the new hostname/address, rejects a wrong address,
checks the unchanged private key/SPKI and proves operator certificates are never
rewritten. It never disables TLS verification or applies host configuration.
The same integration test is `checks.x86_64-linux.management-tls`.

These local/Nix tests do not alone close OSQA-008 on the installed cloud cluster;
actual immutable-update and live-listener UI checks remain required.

## OSQA-168: do not confuse the binary version with the running OS release

`sentinel show version` now adds a `release:` line from the running system's
`/etc/os-release` `IMAGE_VERSION`. The System UI uses the existing CLI-backed
detail renderer, not a second version source. Missing, duplicated, oversized or
unsafe metadata is explicitly unknown. The file is parsed as bounded text, never
sourced as shell code. Unit tests cover valid quoted/unquoted release tokens and
malformed/injected/ambiguous values.

The release label is informational. The actual dm-verity identity, slot and
binary-path identities remain present and authoritative. A source-only pass is
not installed-image or complete-feature certification.

## Scoped installed-candidate follow-up

Standalone OpenStack C actually booted signed disposable QA4, SHA256
`66d60a48348e256d779f35e2bccfd67576b83bf23ff822cecb7d0828fa61014f`.
Installed verity/store partition bytes match that donor; automatic health
assessment makes slotA permanent without manual blessing. FallbackB and the
configuration, machine, SSH and TLS-key identities remain unchanged.

Real CLI commits and real GUI Stage/Validate/Apply/Keep operations each move the
management listener to the control address and back. Independent strict TLS
verification checks the actual CA and IP SAN and refuses a wrong IP. The private
key/SPKI stays unchanged; certificate bytes legitimately renew for the new SANs.
The GUI records five expected failed connections while its listener moves, not
an invented zero-network-error verdict. The original bind/config is restored.

The actual installed UI also displays the declared QA4 release. Its131-case
regression passes, including126Configuration-Validate-only parser proposals:
invalid proposals are never applied. The sanitized scoped receipt is retained
under the enterprise QA work directory as
`corrected-candidate-QA4-installed1137.json`; raw backups remain private.

These passes are limited to corrected C. They do not close the older pair,
physical-hardware or complete-feature requirements. A separate actual GUI
packet test exposed OSQA-170 inline port validation; its failed QA4 receipt is
retained. The shared validation fix has local and Nix browser regression tests,
but QA5 installed verification is a distinct subsequent gate.
