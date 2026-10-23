# Sentinel console behavior

The product contract is the CLI-backed configuration and authorization model in `src/webui.rs`, `src/api.rs`, `src/config.rs` and `src/repl.rs`.

| Capability | Canonical owner | Source of truth | Verification |
|---|---|---|---|
| Settings and secret inputs | `fieldWidget`, `fieldGrid`, `settingsPanel` in `src/webui.rs` | Field definitions and existing config | Console browser tests |
| Permissions | `src/api.rs` | Server identity and permission | API tests |
| Staged configuration | `stage`, `fieldLines` and Apply/Discard in `src/webui.rs` | CLI parser and candidate | Console and commit tests |
| Candidate validation | `validate_script` in `src/repl.rs`, `POST /api/v1/configure/validate` | Complete candidate materialization and domain validation | Rust, HTTP, console and appliance tests |
| Appearance and scrollbars | Inline stylesheet in `src/webui.rs` | DESIGN.md runtime ownership | Console browser tests |

Secret controls preserve values and existing staging semantics. Inputs use password masking by default, preserve label association and provide Show/Hide with an accessible state. Revealing and concealing a value has no backend side effect. Re-rendering a setting returns it to the masked state. SNMP communities are secrets; BGP community lists remain ordinary route attributes.

Validate checks the complete staged candidate without applying or saving it. The validation endpoint accepts only editing commands; commit, save, rollback and operational commands are refused. Validation failures retain staged changes and show the backend's reason. Apply uses the ordinary configuration execution path.

File-backed management tokens are read from their configured file for each request. Atomic credential replacement revokes the old key without restarting the API. Empty or missing files do not restore a cached key. An explicitly configured environment token retains its existing process-lifetime precedence. Read-only config responses redact routing and link-encryption keys as well as login and VPN secrets.
