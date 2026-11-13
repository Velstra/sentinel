# Sentinel console interaction contract

Visual ownership is documented in DESIGN.md. This contract records the existing
staged settings workflow used by the connection timeout form.

| Capability | Canonical owner | Source of truth | Allowed variants | Verification |
|---|---|---|---|---|
| Form | settingsPanel, fieldGrid, fieldLines in src/webui.rs | CLI grammar in src/session.rs and bounds/defaults in src/config.rs | Edit; clear to restore default | tests/console/console.test.mjs |
| Toast | banner and showResult in src/webui.rs | Configure API response | Information; error; applied | tests/console/console.test.mjs |
| CRUD | stage, applyStaged and configure in src/webui.rs | appliance.toml through the management API | Validate without commit; commit and save; delete field | tests/console/console.test.mjs |
| Creation drawer | renderAddPanel/wireToggle in src/webui.rs | Existing staged CLI-object creation | Non-modal region; internal Cancel and Escape close without staging; restore trigger focus and retain local draft until refresh | tests/console/ux.test.mjs |
| Select/Listbox | Native action select in React Flows | Telemetry packet actions | Platform popup and keyboard | ui/tests/management.test.tsx; tests/console/react.test.mjs |
| Scrollbar | Global application CSS in ui/src/style.css, using src/webui.rs tokens | Existing light/dark theme tokens | Bounded flow table and code panes | tests/console/react.test.mjs narrow/theme checks |

The form reads configuration through leaves/fieldsOf and stages the same
commands the CLI accepts. Stage changes only the local batch. Validate sends
that batch without committing. Apply sends it once with commit/save, displays
the server result and refreshes the form. Failed requests retain staged work;
successful commits clear it. Repeated Apply is guarded by the shared busy state.

The header batch badge says **staged changes**, not **pending changes**. It
describes the local batch only; an empty batch never claims the independent
provisional network transaction has been confirmed. The React confirmation
banner remains the sole owner of its awaiting-confirmation state and deadline.

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

## Shared settings-control validation

Firewall port matches keep their text/list/range control. The shared bindField
validator rejects zero/out-of-range ports, malformed lists, reversed ranges and
over-wide ranges before Stage, preserving the value and focusing its associated
inline error. The range-size limit comes from config.rs MAX_PORT_RANGE, not an
independent UI constant. Valid comma-separated ports and ranges remain supported;
the actual appliance schema still owns final validation. This behavior applies
to creation drawers and edit dialogs (tests/console/ux.test.mjs, console-ux gate).

fieldGrid/bindField associates visible labels, helper text and inline errors
with each native/composite control. Required creation fields, integer bounds
and complete update URLs are checked before Stage/Add; the first invalid field
is revealed and focused, a form summary explains refusal, and entered values
remain available for correction. Blank optional values retain the existing
delete/default semantics. Appliance schema validation remains authoritative for
addresses, dependencies, credentials and full candidate commits.

Shared bindField blur feedback does not reflow an active pointer gesture.
pointerdown/up/cancel and window-blur own one deferred feedback queue; after
completed activation, queued errors use the same associated inline text.
Keyboard blur, input correction and explicit Add/Stage validation remain
immediate. A canceled gesture never activates an action. This prevents a newly
visible required-field error from moving the clicked target before release;
it does not waive validation, stage a command or add an alternate submit path.
Informational field hints use that same queue for native change and delayed
completion: a wrapping CIDR explanation must not move a physically held Add.
Stale values/detached controls cannot repaint the active form. The empty-policy
regression holds the real Add for 400ms, verifies stable geometry/no early
staging, then requires the ordinary release to stage exactly one valid rule.
Verification includes physically held Chrome mouse presses on desktop/mobile
and keyboard validation in tests/console/ux.test.mjs.

Object identifiers use specific labels where they are not arbitrary names:
destination/aggregate/authorised prefixes, neighbour IP addresses, WireGuard
public keys, TCP ports and numeric policy sequences. Sequence bounds follow
the CLI's u32 representation. Both inline object editors and the rule dialog
reuse fieldGrid validation; dialog headings provide their accessible names.

IPsec renders its configuration before reading operational SA diagnostics, so
a slow or unavailable daemon cannot block its repair form. The New tunnel
control, like every shared creation trigger, starts disabled with
data-config-loading. renderAddPanel owns both the disclosure binding and the
completed form; only then does it clear that initial readiness gate and
immediately reapply gateWrites. A separate hand-maintained startup handler list
must not make a rendered form unreachable. A failed
configuration read leaves creation disabled with an explanation. Other disabled
prerequisite/permission controls are never lifted by this owner. Local/remote
protected subnets are visible in the initial tunnel form; advanced route-based
binding and final cross-field validation remain owned by the existing model.
The independent diagnostic promise is not part of a form transaction: after
Validate/Apply has returned its real result, the shared busy controls recover
without waiting for SA observations. showInto retains its own pending/error
and generation guards; no observation is invented or silently treated healthy.
Its local-IKE address suggestions contain only IPv4 endpoints, as required by
the appliance schema. The shared local-address inventory remains dual-stack
for protocols that support it; arbitrary valid IPv4 endpoints remain typeable.

An absent prefix-list, route-map, WireGuard interface or DHCP server is an
explicit prerequisite-unavailable state, not a pending configuration read.
The shared object/form owner disables New with visible associated guidance,
retires the old handler/disclosure and clears its hidden panel when that parent
disappears. Selecting or naming a valid current parent rebinds the same owner
once and reapplies account/member gates. A stale picker option is never accepted
as a current parent. Draft-only name/picker changes synchronously reuse the last
genuine configuration read, so an old parent's handler is never offered during
an unnecessary fetch. Their rule Add uses the same draft-vocabulary refresh
without starting a configuration read; explicit Refresh still reads the backend.
Naming/selecting a parent alone stages no command; Discard retains its existing
local-batch meaning, and Refresh reconciles its vocabulary.
tests/console/empty-policy.mjs removes the real private-fixture parents and
exercises physical creation, native selection, discard/reload, disappearance,
real read-only login and admin recovery at actual 1440/390 CSS pixels. It does
not replace native fixed-image verification.

Switches activate on completed native button clicks, including keyboard and
assistive activation; canceled pointer gestures do not change the value.

Update signing keys use the shared field owner with a multiline textarea,
labelled public-Ed25519/file-reference guidance and inline format validation.
The same variant serves the default channel and named channel creation/editing;
other protocols' public-key controls are unchanged. Stage emits one quoted CLI
token, never literal command-separating newlines. CLI export and replay preserve
the public bytes; the model/setter/verifier share bounded RFC8410 Ed25519 SPKI
validation and canonical PEM formatting. Historical flattened public keys remain
usable without changing their material. File references are not read during
declarative validation or silently retargeted; the verifier bounds the actual
file read. Private/foreign/malformed keys are refused without echoing material.
OpenSSL remains responsible for signature verification. Browser regressions
cover physical paste, invalid-key refusal, actual backend validation and real
CLI-save-to-UI readback on desktop/mobile; these do not replace native OTA proof.
Quoted public-key exports are decoded only by the corresponding update-key
reader. File references preserve Unicode, repeated and trailing spaces through
Stage, CLI save/export/replay and UI refresh; changing another field never
replays an unchanged pin. Browser receipts assert the actual CSS viewport,
including 390px, rather than trusting Chromium's requested window size.

Suggestion controls are button disclosures, not authored ARIA comboboxes:
the trigger has a field-specific name and expanded/controls relationships,
ArrowDown enters suggestions, Escape closes and restores trigger focus, and
selection restores input focus. Arbitrary valid typed values remain possible.

Live command failures share the existing unavailable/technical-details visual
variant. Retry really repeats that read, busy state is exposed, and older
responses cannot overwrite a newer request for the same pane. Error output is
retained in a disclosure, not displayed as an empty/healthy protocol table.

Verification: tests/console/ux.test.mjs and tests/console/layout.test.mjs use real
Chromium against the disposable --no-apply API. The layout suite walks every
palette destination at 1440, 390 and 320 CSS pixels, checking labels, overlapping
grid fields, clipping outside deliberate scroll regions and document width.

Leased HA and the independent witness use the same settingsPanel/fieldGrid,
Stage, Validate, Apply and delete semantics on the existing HA page. Their
configuration and security rules remain owned by src/ha.rs, src/config.rs and
docs/ha-phase3.md. They do not introduce another apply or enrollment path;
initial pairing remains the authenticated `sentinel ha pair` operation.

The HA election-mode selector uses the same native select and staged form owner.
Witness mode remains the compatibility default; two-node mode exposes local and
peer heartbeat endpoints plus millisecond timing fields. The HA page explicitly
warns that complete heartbeat isolation can activate both members without a
witness. It never labels this as quorum-backed protection, infers independent
physical paths from VLANs, or enrolls a peer merely by changing the selector.
Mode, timing, control-link ancestry and credential checks remain server-owned in
src/config.rs, src/ha.rs and src/session.rs. Switching modes retains entered
values so rejected configurations can be corrected through the normal workflow.

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

Telemetry belongs to the selected appliance. Peer views use configured-member-only
read endpoints over the server's pinned config-sync transport, never direct
browser credentials or fallback local measurements. Source failures remain unknown and visible rather than
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
Unavailable source data remains unknown; switching members immediately clears
measurements, routes, chart history and paused packets and invalidates old reads.
HA Backup sync age is the age of its last authenticated baseline;
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
ResizeObserver and bounded animation-frame scroll/resize handling derive --bar-h
from the real header's viewport bottom, including the mobile brand row and
narrow/zoomed wrapping. Drawers use that offset before and after scrolling;
neither their identifier nor focused controls may hide beneath the header.

Sign-out also clears the navigation query and configuration search matches before
the next identity can open the shell; no private address query survives a session.

The navigation search generation is invalidated on sign-out. Responses from an
older session or selected member cannot repopulate its search index.

The header is the sole rendered account-identity surface. Its existing read-only
badge is visible beside the account; the unused hidden sidebar identity and its
duplicate renderer were retired. Browser authentication checks assert actual
badge visibility rather than the absence of a hidden class on a hidden subtree.

## System health observations

The existing local System details renderer also displays the declared running
OS `IMAGE_VERSION` via `sentinel show version` (`src/image.rs`, `src/main.rs`).
Unknown metadata is explicit; the Cargo binary version is not an OS-version
fallback. The release label supplements, never replaces, dm-verity and slot
identity. No alternate UI version source or write path is introduced.

ReactSystemHealth is the shared read-only diagnostic surface on the dashboard
(compact notices) and System page (complete observations). Its source is the
authenticated GET /api/v1/system/health endpoint in src/health.rs and src/api.rs.
Management owns the 15-second polling, duplicate/timeout guards and session/member
invalidation. Unknown, failed or stale probes never appear healthy; a peer view
reads that member's diagnostics through the pinned backend proxy. Sign-out clears observations and invalidates pending
responses. Read-only accounts may inspect and retry; Configure NTP navigates to
the existing services:resolution settingsPanel and grants no additional writes.
Clock synchronisation and optional LAN NTP serving remain distinct. Diagnostics
never reset the TPM, clear failed service state or change configuration.
Verification: ui/tests/health.test.tsx plus authenticated API and system-probe tests.

## Selected-member observation boundary

Management and Host.member own exact member identity, not merely a remote/local
flag. Dashboard, throughput, HA role, routing, packet events, rule counters and
system health all share this target. Local telemetry remains SSE; peer telemetry
polls authenticated full snapshots. One collector with a bounded ten-second idle
lease retains counter deltas between polls. Duplicate snapshots never renew
freshness. Unsupported/offline peers show unavailable, never local data. Member
and session changes abort requests and reject late frames, errors and 401s.

The full document, staged writes and confirmation transaction remain local;
switching members hides but does not discard a local draft. Configure NTP is
disabled in peer diagnostics with an explicit local-member explanation. The
compatibility System details disclosure is local-only and hidden for peers;
historical metrics explicitly require the local member rather than mislabeling
local history. These are read-only display boundaries, not new permissions.
Transport/membership/redaction policy is owned by src/api.rs and src/net.rs.
Verification: Rust pinned HTTPS two-router tests, ui/tests/management.test.tsx,
ui/tests/health.test.tsx and tests/console/react.test.mjs.

Legacy settings use the same local-write boundary: writeBlockReason owns the
account/context explanation, stage refuses peer drafts, and gateWrites gates
Stage/New/Edit/Delete/Apply and operational mutations even after asynchronous
redraws. Peer views retain existing local drafts without offering to apply them.
The persistent read-only notice describes disabled controls; returning local
restores only context-gated actions, not unrelated prerequisite-disabled buttons.
The server's authorization and the guarded local-only Apply remain authoritative.

configSyncState/configSyncBadge render the API's outbound delivery state in both
Stack and the member rail, independently of authenticated reachability. Delivered
means no local outbox changes await that peer; it does not certify bidirectional
model equality. Pending delivery, Conflict and Unknown remain distinct. Conflicts
offer comparison guidance, never an automatic force-overwrite/repair. Verification:
tests/console/peer.test.mjs uses real pinned peer reads and explicitly identified
presentation fixtures; native conflict and actual convergence require live HA tests.

The rail's native member button reserves its name row independently of the
delivery label. Role/status metadata wraps below, stays within the same hit
target and never truncates the primary identifier to make a badge fit. Keyboard
selection and all member/write boundaries remain unchanged. The peer suite
checks short/long identifiers, four delivery states, both themes and 1440, 390
and 320 CSS-pixel geometry, including native Enter activation after layout verification.

refreshCluster is the shared session-owned member-status read. Stack and the
rail render the SAME snapshot, including failure/unknown notices; refreshStack
delegates to that owner. Normal page navigation and Refresh renew both surfaces.
Concurrent reads coalesce, expose aria-busy and retain no independent green
delivery result when the snapshot fails. Selected-member revision reads have
separate epoch/token/member guards and cannot delay a later delivery refresh.
Sign-out aborts/invalidate member reads and clears member/revision DOM; a late
answer cannot repopulate either the signed-out or a later session. This changes
display freshness only, never delivery/conflict/permission semantics. The peer
browser suite drives the actual Refresh and Sign out controls, including delayed
responses and unavailable snapshots, rather than manually refreshing both panes.

## Update URL validation

The shared bindField owner captures update/default and named-channel ownership
when each form is built. Both forms accept only the https:// and file:// schemes
defined by src/config.rs and src/session.rs; offline file mirrors remain valid.
Invalid schemes retain the entered value and show an associated inline error
before Stage. Generic URL syntax checks and authoritative API/CLI validation
remain in place. This is a business-backed field variant, not a new form owner.

## Operational signed updates

SystemUpdates uses the canonical Panel, button, row, status and description-list
primitives. Updates owns a single local observation/admission lifecycle inside
Management. Check and explicit reviewed Stage call the durable update-jobs API;
configuration forms still stage their own safe-apply changes separately. Pending
configuration, local drafts, unknown permissions, remote members and stale status
withhold these actions. No source, trust, downgrade, reboot or retry override is
offered. Review pins the exact offer, generation and full mutation context; a
changed observation invalidates it. A lost POST is correlated by request ID in
retained jobs, never retried automatically. Polls are read-only, non-overlapping,
bounded and restricted to the visible System view. Member/session changes abort
and invalidate old replies. Worker interruption/write uncertainty stays distinct
from a staged image, and staging is never displayed as a successful boot.
Historical Stage descriptions use the job's boot ID versus the independently
observed current boot ID; they must not call an already assessed boot unbooted.
The Panel focus-ref variant is used only to return focus after inline review
closes while its original trigger is busy. It adds no visual or navigation owner.

Verification: ui/tests/updates.test.tsx, tests/console/updates.test.mjs and the
actual native-update VM probe (independent CLI/API worker, verified write and cold
boot). Workstation browser fixtures verify UI behavior, not native slot writes.
