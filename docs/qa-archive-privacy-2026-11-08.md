# Configuration archive credential boundary (OSQA-011)

Scope: a local source fix and its regression tests. This is not a statement
that the frozen OpenStack image, physical appliances, or a production release
has been upgraded or certified. Original failing evidence remains retained.

## Defect and intended access

Archived appliance documents contain the same credentials as the current
document. The old direct write used default file permissions, and its sudo
fallback explicitly installed mode `0644` in a `0755` directory. A local user
outside the operator group could therefore read old API/HA and VPN credentials.

Revisions now use the canonical atomic configuration installer: mode `0640`,
group `wheel`, with a `0750` archive directory. On the appliance both directory
and files are root-owned. Off-box documents retain their parent owner's UID.
Operators who can already read the current configuration retain revision and
rollback access. This is an access restriction, **not encryption at rest**.

## Upgrade, staging and failure behavior

- The `sentinel-archive-protect` unit requires the persistent data mount and
  completes before the boot renderer, management API, SSH and user sessions.
  It does not parse the saved configuration, so malformed TOML cannot skip the
  privacy migration. A missing archive is a harmless no-op, not a new history.
- Existing regular files, including old interrupted temporary copies, are
  migrated too. Every archive write rechecks that boundary. The internal
  privileged helper never takes its parent's apply lock, avoiding a nested
  cross-process deadlock while a wheel operator saves.
- Directory/file opening and permission changes use no-follow descriptors.
  Symlinks, multiply-linked files, FIFOs and other non-regular entries are
  refused; migration does not recursively chmod unrelated targets. Such an
  archive blocks dependent login/management startup until an operator resolves
  it. No historical document is silently deleted as a repair.
- New copies reuse unpredictable exclusive atomic staging, not the old shared
  `.archive.toml.tmp`. The final descriptor's mode is set before secret bytes
  are written, preserving wheel read access even under `umask 077`.
- Archive failure remains a reported best-effort failure after a save, not a
  claim that a revision was recorded. Retention still removes only recognized
  revision files; protected interrupted copies are not silently pruned.

Restricting copies does not revoke a credential somebody already obtained.
Rotation of previously exposed production credentials requires its own
coordinated deployment/secret-store procedure. This change does not rotate keys
on the frozen cloud pair or on physical appliances.

## Reproducible checks

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --workspace
nix build .#checks.x86_64-linux.archive-privacy --max-jobs 1 --cores 4 -L
CONSOLE_TEST_FILE=archive.test.mjs tests/console/run.sh
```

The Rust regressions cover legacy and new modes, idempotent migration, absent
history, symlink/hardlink refusal, FIFO handling, listing and retention. The
KVM gate uses real root/API persistence, wheel/CLI commits under `umask 077`,
actual `nobody` and administrator open/read attempts, live hostname rollback,
retention and a cold boot. A second guest checks that a substituted archive
blocks dependent services without changing its unrelated target.

The real Chrome regression independently exercises CLI-to-UI visibility,
invalid Validate without persistence, valid Validate/Apply/Keep change, the UI
revision rollback button, and CLI rollback of a GUI-created revision. It checks
the actual local files and credential preservation, not just returned JSON.
Its local API uses `--no-apply`; only the KVM gate demonstrates live OS effects.
Neither gate by itself establishes complete HA, full feature or cloud-image
certification.
