---
version: alpha
name: Velstra Sentinel
description: Self-contained appliance console for network administrators.
colors:
  primary: "#2e96c4"
  background: "#0b0f14"
  surface: "#141a22"
  foreground: "#f4f8fb"
typography:
  sans:
    fontFamily: "system-ui, sans-serif"
  mono:
    fontFamily: "ui-monospace, monospace"
rounded:
  panel: "6px"
spacing:
  base: ".25rem"
components:
  button: {}
  form: {}
---

# Sentinel console design

The authenticated appliance console serves network administrators, including during incidents and on isolated networks. Preserve the compact Velstra identity and the existing configuration staging model.

The canonical runtime tokens, dark/light ramps, native font stacks, spacing, radii and motion live in `src/webui.rs`. Components consume those variables directly; the complete page is self-contained and fetches no fonts or styles externally.

`fieldWidget`, `fieldGrid` and `settingsPanel` own setting controls, labels, validation hints and staging. Extend these shared owners across configuration sections. Secrets start masked, with an explicitly named keyboard-accessible reveal control; revealing a value must not stage or change it. Tables show whether a secret is set without printing it.

The server remains the permission boundary. Read-only config redaction and write authorization belong to `src/api.rs`. Presentation masking does not replace either. Configuration edits remain candidates until Apply; Discard drops the candidate. Keep failures visible and retain entered values on refusal.

Use existing semantic colors with textual states, native labeled controls, clear focus and reduced-motion behavior. Keep extended help secondary. Dashboard counts must represent observed data, including truthful empty, unavailable and loading states.
