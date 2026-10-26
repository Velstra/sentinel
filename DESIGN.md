---
version: alpha
name: Velstra Sentinel console
description: Calm appliance overview with clear tasks and safely staged configuration.
colors:
  primary: '#4fb2dc'
  background: '#0b0f14'
  surface: '#141a22'
  text: '#e8edf2'
  success: '#10b981'
  danger: '#ef4444'
typography:
  sans:
    fontFamily: 'system-ui, -apple-system, IBM Plex Sans, Segoe UI, sans-serif'
  mono:
    fontFamily: 'JetBrains Mono, ui-monospace, SF Mono, Menlo, Consolas, monospace'
rounded:
  DEFAULT: '8px'
  card: '14px'
spacing:
  field-gap: '0.75rem'
  section-gap: '1.5rem'
omitted:
  - section: components
    reason: Shared component behavior is maintained in UX-CONTRACT.md and src/webui.rs.
---

# Sentinel console design

## Overview

The console is an operating panel for network administrators configuring a local
firewall, including during incident response. Configuration forms share the
same grammar and staged changes as the CLI. Preserve the existing compact
console identity when adding settings; use the established field and card
builders for existing settings. The requested React migration owns the live
dashboard, flow inspector, document editor and confirmation banner in ui/src;
it shares the console shell and visual language. The usability redesign extends
that system across navigation and settings: more readable body text, clearer
surface grouping and direct paths to everyday tasks.

The current product copy is English. No additional market or locale is implied
by this change. Product requirements come from README.md and the handbook;
configuration semantics come from src/config.rs and src/session.rs.

## Colors

The canonical runtime palette and light/dark theme overrides live in the
embedded stylesheet in src/webui.rs. The values above document its dark theme;
this file does not generate or override CSS. Signal blue marks interactions,
while green and red retain their status meanings. New forms inherit the shared
semantic CSS variables, including the light theme.

## Typography

Use the existing system-first sans stack for controls and headings. Use the
shared monospace stack for commands, addresses and technical output. Do not
fetch fonts or other assets from the internet at runtime.

## Layout

Use the shared cards, addpanel field grid and mask footer. The 248px desktop
rail presents workspace categories and folds raw diagnostic views under an
explicit disclosure. Below 900px the rail becomes a compact brand row with a
Menu button; closed navigation is absent from the tab order. The dashboard
starts with four honest, clickable operational summaries and common tasks.
Detailed system tables remain available in a separate disclosure. Forms stay in
normal document flow and use the existing responsive breakpoints. Timeouts
belong beside the global firewall posture, with seconds in every field label
and explicit bounds/default guidance above the form.

## Elevation & Depth

Inherit the existing tonal surfaces and borders. A settings addition does not
introduce new shadows, overlays or decorative panels.

## Shapes

Use 8px controls, 10px inset panes and 14px cards through the canonical
--radius-sm/md/lg tokens in src/webui.rs. This replaces the earlier 4px/6px
geometry across the console as one system decision. Pill-shaped state/filter
controls retain their semantic role. Body text is 15px; technical tables and
addresses retain the smaller utility scale.

## Components

The canonical CLI-form owner is settingsPanel/fieldGrid in src/webui.rs.
The migrated management workflows use the React components and shared controller
in ui/src/components.tsx and ui/src/controller.ts. Their runtime CSS in
ui/src/style.css consumes the existing console tokens without redefining them;
ui/dist is generated and embedded, never a second token owner. It owns
label association, dirty state, Stage actions and feedback. See UX-CONTRACT.md
for the staged editing contract. Connection timeout fields use this owner.

## Do's and Don'ts

Show real server values and documented defaults. Keep units explicit. Stage
only changed fields, and clear a value through the CLI's delete operation.
Keep rejected values out of persisted configuration. Never add direct DOM
persistence, an alternative Apply path, or new visual tokens for one form.

The dashboard's identifying feature is an instrument-like measured traffic panel
above the interface table: aggregate RX + TX, separate directional readouts and
a bounded forty-sample chart with quiet grid lines and a filled trace. The chart
appears only after two measured samples; unavailable values remain explicit. It uses the existing signal color, system
sans controls and monospace network data. Keep routing/VPN diagnostics readable
and literal. The flow table owns its bounded scroll region; the document editor
keeps normal page scrolling and collapses its two-column review to a single
column on narrow screens. Diff markers use both +/− text and existing status
colors. React panel headings use a shared divided header, readable status pills and
monospace protocol labels. Document panes use a file header with explicit
read-only and draft roles. These are visual variants of the existing tokens;
no external fonts, new palette or decorative animation is introduced.

The shared shell composition lives in ui/src/shell.css; ui/src/style.css owns
React workflow composition. Both consume the canonical Rust theme tokens and
are built into one offline asset. Technical source failures show an explicit
unavailable state with an expandable diagnostic rather than a wall of shell
errors. Filter presets label allowed and blocked packets; blocked includes both
drop and reject. The configuration guide explains Edit → Validate → Apply →
Confirm without adding an alternative mutation or validation path.

Global scrollbar thumb, track, hover and active roles are defined in ui/src/style.css
as aliases to the existing text, surface and brand tokens. They apply to all
application-owned overflow surfaces, with system colors in forced-color mode.
