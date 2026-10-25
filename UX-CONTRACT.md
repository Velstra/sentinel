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
