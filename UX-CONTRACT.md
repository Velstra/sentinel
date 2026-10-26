# Sentinel console interaction contract

Visual ownership is documented in DESIGN.md. This contract records the existing
staged settings workflow used by the connection timeout form.

| Capability | Canonical owner | Source of truth | Allowed variants | Verification |
|---|---|---|---|---|
| Form | settingsPanel, fieldGrid, fieldLines in src/webui.rs | CLI grammar in src/session.rs and bounds/defaults in src/config.rs | Edit; clear to restore default | tests/console/console.test.mjs |
| Toast | banner and showResult in src/webui.rs | Configure API response | Information; error; applied | tests/console/console.test.mjs |
| CRUD | stage, applyStaged and configure in src/webui.rs | appliance.toml through the management API | Validate without commit; commit and save; delete field | tests/console/console.test.mjs |
| Select/Listbox | Native action select in React Flows | Telemetry packet actions | Platform popup and keyboard | ui/tests/management.test.tsx; tests/console/react.test.mjs |
| Scrollbar | Global application CSS in ui/src/style.css, using src/webui.rs tokens | Existing light/dark theme tokens | Bounded flow table and code panes | tests/console/react.test.mjs narrow/theme checks |

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
| Safe Apply | safe_apply.rs, ui/src/controller.ts lifecycle, existing busy/banner primitives | Durable pending journal and monotonic server deadline | Applying; awaiting confirmation; confirmed; reverting; expired/disconnected | Rust transaction/API tests, nix/management-test.nix, tests/console/management.test.mjs |
| TOML editor | ui/src/controller.ts document adapter and shared management API | Appliance parser/validator and CAS revision | Explicitly reveal complete document; validate without mutation; provisional apply | API permission/CAS tests and real browser tests |
| Live events | telemetry.rs single collector and ui/src/components.tsx Flows | Agent packet ring, active rule IDs/names and counters | 512 retained events; 50 rows/page; action/search; pause | Collector tests, two-stream kernel VM, browser filters/pagination |
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
The requested migration implements these management workflows with React and
TypeScript in ui/. The existing login, navigation and CLI-backed forms remain
the compatibility shell. All production assets, including React, are built with
a pinned npm lockfile and embedded into the Rust binary. Node is a build/test
dependency only; there is no runtime asset host.

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

## React management migration

| Capability | Canonical owner | Source of truth | Allowed variants | Verification |
|---|---|---|---|---|
| Form | ConfigEditor and Management in ui/src | Appliance::from_toml, CAS document endpoint | Reveal, validate, provisional apply, baseline reload preserving draft | ui/tests/management.test.tsx; tests/console/react.test.mjs |
| Select/Listbox | Native action select in Flows | Packet action from the telemetry collector | Platform-owned popup and keyboard behavior | React component and browser filter tests |
| Scrollbar | Global rules in ui/src/style.css, using the console tokens | Existing theme tokens | Flow table and code panes own only their bounded overflow | Browser narrow/theme checks |
| Toast | Existing banner/showResult via src/management.js adapter | Server transaction result | Applied, confirmed, restored, uncertain | Component and real API browser tests |
| CRUD | Shared Management controller | Document revision and durable transaction API | No optimistic commits; no automatic write retries | Component race/offline tests and management VM |

React owns the complete migrated view subtrees, not the shell's navigation or
CLI-form rendering. Shell writes publish their pending transaction to the same
controller. Polling is authenticated, recovers a pending banner after reload and
never confirms or renews a deadline. Async responses are invalidated on sign-out;
SSE readers, retry timers, full documents, paused packets and sensitive filters
are cleared. Draft changes remain in the shell's existing unload guard, and
in-app navigation preserves the draft without extra confirmation.

Tables render 50 rows per page from at most 512 retained events. Search is local,
so updates and clear are immediate; IME composition does not submit a mutation.
Action/search/page state stays in memory because it can include private addresses.
Unavailable source data remains unknown; switching to a peer withholds local
telemetry. HA Backup sync age is the age of its last authenticated baseline;
Master remote application latency remains explicitly unmeasured.

The editor's side-by-side diff uses bounded line comparison and the canonical
server diff after validation. A stale revision requires reloading the baseline
while keeping the proposed document. A lost write response blocks another Apply
until the pending transaction or baseline has been checked. Read-only identities
cannot load full documents. Validation errors retain the proposal and focus the
associated textarea. Hide refuses to discard a dirty draft.

Selecting a peer hides the full local document without discarding its local draft.
Returning to the local member restores the same draft and dirty state. Losing
write access or signing out clears revealed documents. Global confirmation
explains when a local member or write-capable identity must be selected.

## Navigation and everyday tasks

src/webui.rs::goto remains the sole destination owner. The React Host.navigate
adapter delegates overview cards and common tasks to it without issuing a write.
The workspace category stays selected when its child page is open; raw diagnostic
views are grouped under a native disclosure and open when selected. Search has
an explicit Clear action which restores focus and the full navigation.

Below 900px Menu is an inline, non-modal disclosure with aria-expanded and
aria-controls. It starts closed, removes hidden navigation from the tab order,
closes on destination selection and focuses the new page heading. Escape closes
it and returns focus to Menu; an open modal retains Escape ownership. Sign-out
resets the disclosure. The document remains the content scroll owner.

The overview never treats an absent measurement as zero or infers tunnel health
from a peer count. Handshake data and full source errors remain inspectable.
Technical source errors are deliberately folded, with visible unavailable text.
Blocked event filtering includes both drop and reject; presets preserve search
and reset/clamp pagination. Counts describe the bounded retained display, including
its paused snapshot. The editor's ordered guide explains the existing workflow;
validation, permissions, CAS and commit-confirm semantics remain server-owned.

Verification: ui/tests/management.test.tsx and tests/console/react.test.mjs cover
navigation destinations, combined blocked filtering, diagnostic reveal, mobile
menu/search/focus/escape and both themes. Full console coverage remains required.

Live packets has its own Policy destination (`flows`) using the same telemetry
controller. Firewall rules opens directly onto policy controls; the inspector
is no longer a large preamble above the rule editor. Both remain reachable from
the same category strip and the dashboard task links.

Destination navigation focuses the page heading and returns the document to the
top, so a long previous form cannot strand the next page below its heading. A
ResizeObserver derives --bar-h from the real header height (including narrow or
zoomed wrapping); drawers use that measured offset rather than covering controls.

Sign-out also clears the navigation query and configuration search matches before
the next identity can open the shell; no private address query survives a session.

The navigation search generation is invalidated on sign-out. Responses from an
older session or selected member cannot repopulate its search index.

The header is the sole rendered account-identity surface. Its existing read-only
badge is visible beside the account; the unused hidden sidebar identity and its
duplicate renderer were retired. Browser authentication checks assert actual
badge visibility rather than the absence of a hidden class on a hidden subtree.
