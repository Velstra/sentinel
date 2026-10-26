# Sentinel console interaction contract

Visual ownership is documented in DESIGN.md. This contract records the existing
staged settings workflow used by the connection timeout form.

| Capability | Canonical owner | Source of truth | Allowed variants | Verification |
|---|---|---|---|---|
| Form | settingsPanel, fieldGrid, fieldLines in src/webui.rs | CLI grammar in src/session.rs and bounds/defaults in src/config.rs | Edit; clear to restore default | tests/console/console.test.mjs |
| Toast | banner and showResult in src/webui.rs | Configure API response | Information; error; applied | tests/console/console.test.mjs |
| CRUD | stage, applyStaged and configure in src/webui.rs | appliance.toml through the management API | Validate without commit; commit and save; delete field | tests/console/console.test.mjs |

The form reads configuration through leaves/fieldsOf and stages the same
commands the CLI accepts. Stage changes only the local batch. Validate sends
that batch without committing. Apply sends it once with commit/save, displays
the server result and refreshes the form. Failed requests retain staged work;
successful commits clear it. Repeated Apply is guarded by the shared busy state.

For `firewall global conntrack`, all six values are idle seconds bounded to
1–604800 by the server. Empty fields delete the explicit override and restore
the model defaults. The exact defaults remain owned by ConntrackTimeouts in
src/config.rs; the console documents them through its shared default hints.
The form introduces no new permission, authentication or runtime-apply policy.

| Business source | UI consequence |
|---|---|
| docs/src/handbook/firewall.md | Connection state and timeout terminology |
| src/config.rs: ConntrackTimeouts | Bounds, defaults and persisted representation |
| src/session.rs: firewall global conntrack | Set/delete command semantics |
| Management API configure endpoint | Server validation and commit results |

The fields inherit shared labels, focus treatment, keyboard behavior, themes
and responsive layout. Tests must cover applying every timeout, invalid input,
reading persisted values, restoring defaults and complete CLI-field coverage.

Leased HA and the independent witness use the same settingsPanel/fieldGrid,
Stage, Validate, Apply and delete semantics on the existing HA page. Their
configuration and security rules remain owned by src/ha.rs, src/config.rs and
docs/ha-phase3.md. They do not introduce another apply or enrollment path;
initial pairing remains the authenticated `sentinel ha pair` operation.

HA identity JSON, witness credentials and the configuration-sync credential use
the shared secretWidget: a masked input with an associated label and a keyboard
accessible Show/Hide button. Values stay in the current form/staged batch and
are never included in the staged summary or browser storage. The CLI argument
encoder preserves identity JSON as one token. Unchanged fields, including a
server-redacted witness credential, are never replayed during another edit.
Server validation keeps rejected edits staged and leaves persisted state intact.

The member selector uses the established native select; its two choices accept
platform-owned popup geometry and keyboard behavior. Activation and preemption
reuse the existing switch primitive. All fields inherit existing tokens, themes,
responsive flow and focus styles. Browser tests cover all HA fields, identity
round trips, reveal controls, invalid election settings and credential retention.

Phase 4 extends the shared management lifecycle with a named, safe-apply
variant. A live form Apply validates its entire batch before accepting any
mutation. A rejected batch stays staged in full; it never partially applies.
Live API writes prepare a private durable journal and launch an independent
systemd worker. The candidate is provisional until the operator explicitly
selects **Keep change**. The default confirmation window is 60 seconds after
reconciliation; `services web confirm-timeout` owns the configured duration.
Polling status never confirms or extends that deadline. The global banner
survives navigation and is recovered from the server after reload. Revert is
also completed by the independent recovery service, since a reverse address,
port or TLS change can terminate the API connection. Off-box form emulation
(`--no-apply`) retains immediate save semantics; the document editor exercises
real journal/confirmation/expiry semantics without touching host networking.

| Capability | Canonical owner | Source of truth | Allowed variants | Verification |
|---|---|---|---|---|
| Safe Apply | safe_apply.rs, management.js lifecycle, existing busy/banner primitives | Durable pending journal and monotonic server deadline | Applying; awaiting confirmation; confirmed; reverting; expired/disconnected | Rust transaction/API tests, nix/management-test.nix, tests/console/management.test.mjs |
| TOML editor | management.js document adapter and shared management API | Appliance parser/validator and CAS revision | Explicitly reveal complete document; validate without mutation; provisional apply | API permission/CAS tests and real browser tests |
| Live events | telemetry.rs single collector and management.js tableRows/renderFlows | Agent packet ring, active rule IDs/names and counters | 512 retained events; 50 rows/page; action/search; pause | Collector tests, two-stream kernel VM, browser filters/pagination |
| Live dashboard | telemetry.rs and shared console table/card tokens | Kernel interface counters, agent HA/maps, Wren, WireGuard | Sampling; live; partial source errors; stale/disconnected | Collector rate/reset tests, VM and browser |

The full TOML document is available only to write-capable accounts and only
loaded after **Show configuration**. It includes real secrets so complete
revisions preserve keys. The initial editor is concealed; Hide clears its
contents, and sign-out clears every draft. Drafts and event filters remain in
memory, never in URLs or browser storage. Navigating preserves the TOML draft;
the existing unload guard protects it when leaving the document. Hide refuses
to discard dirty content. Apply and Validate preserve rejected text and use
`aria-invalid`/`aria-describedby` for the server's inline error.

The editor deliberately uses a side-by-side current/proposed document and a
server-generated diff after validation. It is another adapter to the same
Appliance model, with compare-and-swap protection against stale revisions.
The existing settingsPanel/Stage workflow remains the canonical form editor.
All assets are embedded into the Rust binary; this console has no separate
React application, Node dependency tree, or runtime asset host.

Telemetry is local to the selected appliance; peer views explicitly withhold
local measurements. Source failures remain unknown and visible rather than
becoming healthy zeros. Counter rates use measured elapsed time; resets create
an unknown sample. Standby sync age means elapsed time since its last complete
authenticated replica update. VCS2 does not acknowledge remote apply latency to
the Master, so that unmeasured quantity is explicitly described instead of
inventing a zero. The native action select accepts platform-owned popup and
keyboard behavior. Live event filters are intentionally transient because they
can contain sensitive addresses. Pagination and paused history are bounded;
packet history is diagnostic, not a lossless audit archive.

Fleet enrollment is an optional singleton on the existing System page. It uses
settingsPanel/fieldGrid, the staged Stage/Apply lifecycle and the shared secret
widget. The enrollment credential is masked with an accessible reveal control;
server-redacted credentials are never replayed while another field is edited.
Disconnect stages `delete fleet` and uses the ordinary commit-confirm path.
Rejected enrollment keeps the complete staged correction and the last working
configuration. Fleet client keys are private file references; private PEM bytes
never enter this form. No new theme, navigation, dialog or notification owner is
introduced. Verification: tests/console/fleet.test.mjs and nix/fleet-test.nix.
