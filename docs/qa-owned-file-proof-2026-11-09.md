# Fail-closed protected-file existence proof

The ordinary metadata query still uses `Path::try_exists()`: verified presence
is true, verified absence (including a dangling symlink) is false, and unknown
metadata state is an error. An already-root metadata error never retries as an
expression that could collapse that error to false.

Only a non-root PermissionDenied result may ask the same pinned Sentinel binary
for a privileged metadata proof. The hidden `owned-file-probe` command is
root-only, never escalates recursively, reads metadata only, and emits exactly
`true\n` or `false\n` after a successful query. Both booleans exit successfully.
Its caller requires success plus the entire exact five- or six-byte frame.
Exit 1, command-not-found 127, permission error, signal, process I/O error, or
unknown/extra output are errors, never absence. Child output is not copied into
error messages. Paths remain literal argv values after `--`; no shell is used.

This replaces ambiguous `sudo test -e` status handling. A sudo refusal and a
legitimate false test expression can both return 1, and stderr text is not a
reliable execution protocol. The existing `sentinel-self` helper deliberately
skips a plain self invocation, uses `sudo -n`, and captures output with closed
stdin. The accepted metadata frame is bounded to six bytes. The existing shared
process helper still collects its trusted pinned child's output; this change
does not introduce a general subprocess timeout or collection-memory limit.

Preserved caller Result propagation means an unknown protected journal cannot
qualify as a missing safe-apply transaction, empty HA outbox, first sync,
uninitialized replay state, or missing stored trust pin. This is an error/absence
distinction, not proof that a live HA operation or filesystem race is atomic.

Host regressions cover direct/root/non-root outcomes, metadata denial/I/O errors,
one probe, unsuccessful sudo/child statuses, exact typed framing, root-only child
dispatch, literal CLI paths, no-content diagnostics, and real missing/symlink
metadata behavior. A callback regression verifies unknown state cannot reach
an absence-dependent mutation at the Result boundary; it is not a native HA/API
execution claim. The isolated host runs do not validate an actual permitted or
denied sudo policy in a VM; that requires a subsequent disposable VM gate.

No change to global sudo policy, runtime packages, file permissions, protected
socket access, production signing keys, or cloud/DUT configuration is included.
