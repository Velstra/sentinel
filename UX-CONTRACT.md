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
