---
version: alpha
name: Velstra Sentinel console
description: Dense appliance controls with staged, declarative configuration.
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
  DEFAULT: '4px'
  card: '6px'
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
builders rather than introducing another UI framework.

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

Use the existing cards, addpanel field grid and mask footer. Forms stay in
normal document flow and use the existing responsive breakpoints. Timeouts
belong beside the global firewall posture, with seconds in every field label
and explicit bounds/default guidance above the form.

## Elevation & Depth

Inherit the existing tonal surfaces and borders. A settings addition does not
introduce new shadows, overlays or decorative panels.

## Shapes

Use the existing 4px control and 6px card radii through their runtime tokens.

## Components

The canonical form owner is settingsPanel/fieldGrid in src/webui.rs. It owns
label association, dirty state, Stage actions and feedback. See UX-CONTRACT.md
for the staged editing contract. Connection timeout fields use this owner.

## Do's and Don'ts

Show real server values and documented defaults. Keep units explicit. Stage
only changed fields, and clear a value through the CLI's delete operation.
Keep rejected values out of persisted configuration. Never add direct DOM
persistence, an alternative Apply path, or new visual tokens for one form.
