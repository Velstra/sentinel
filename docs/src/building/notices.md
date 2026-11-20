# Third-party notices and source obligations

**Release requirement, not yet a delivered artifact.** The current image and
bundled console do not contain a complete verified third-party notices bundle.
A source SBOM is not a substitute for the licenses and notices required by the
actual shipped software. Do not claim this gap is closed by this page.

## Required inputs

Build the inventory from one reviewed release cohort:

- The exact image's Nix store closure, including kernel, bootloader, firmware,
  services and dynamically linked libraries.
- The Cargo lockfiles and source trees used for Sentinel, Fabric, Wren and the
  eBPF object. A host-only dependency tree can omit target-specific or embedded
  components.
- The locked npm tree **and actual console bundle**. Build-time dependencies
  are useful audit inputs, but do not assume every development dependency is
  shipped or that every bundled asset has an npm package record.
- Vendored source, generated protocol code, patches and copied static assets.

Use the installed SBOM and build provenance as inventory inputs, then reconcile
them with actual linked/embedded components. Package metadata alone may omit
copyrights, dual-license choices, additional NOTICE files and source obligations.

## Bundle acceptance

For every distributed component, record its name, exact version/source revision,
source URL, selected license expression, and hashes of the source license/notice
files. Copy those files from the reviewed source; do not synthesize copyright
holders or replace missing terms with a guessed SPDX label. Unknown/conflicting
licenses, missing mandatory texts and incompatible terms must fail release review.

The bundle must retain:

1. Full applicable license texts and upstream copyright/NOTICE material.
2. Component-to-text mappings, including the software embedded in the console
   and eBPF object.
3. The corresponding-source availability required by each applicable license,
   including modifications and build/install information where required.
4. The image SHA-256, source/input revisions and bundle hash in the release
   evidence. Keep the inventory deterministic and check for unaccounted files.

Before distributing, install the validated bundle in a documented read-only
image path, expose it from the console's legal/about surface, and publish the
matching source access information alongside the artifacts. Test access as an
ordinary operator on the built image and verify the bundle's hash after extraction.
Those image/UI delivery hooks and their regression tests are still outstanding.

## Licences of the first-party components

The image combines three first-party projects, each under its own licence, with
NixOS packages under theirs:

| Component | What ships in the image | Licence |
|---|---|---|
| Sentinel | the `sentinel` CLI, API and embedded console | AGPL-3.0-or-later |
| Fabric | the `velstra` data-plane agent | AGPL-3.0-or-later |
| Fabric eBPF object (`velstra-ebpf`) | the XDP/TC programs loaded into the kernel | GPL-2.0-or-later OR MIT |
| Wren | the `wren` routing daemon | GPL-2.0-or-later (its `wren-core` crate is Apache-2.0) |
| NixOS packages | kernel, systemd, OpenSSH, strongSwan, dnsmasq and the rest of the closure | each package's own licence, as recorded in its nixpkgs `meta.license` |

The Rust crates compiled into the three binaries were checked at the 8b6181 audit
and carry only permissive licences; no SSPL, BUSL, GPL-2.0-only or unknown licence
was found in the shipped dependency graphs.

## What a distributor must ship

Anyone who distributes the image, including a derived or commercial edition,
distributes all of the above and must meet each licence's terms. At least:

1. The licence texts of every component, including the AGPL-3.0, GPL-2.0, MIT,
   Apache-2.0 texts for the first-party components and the texts for the NixOS
   packages in the closure.
2. The corresponding source of every GPL- or AGPL-licensed component, or a
   written offer for it. For the first-party components that is the exact
   revisions pinned in `flake.lock` (Sentinel itself, `fabric` and `wren`). For
   NixOS packages it is the nixpkgs revision in `flake.lock` together with every
   patch or override applied on top of it — the patch files in this repository
   and any patches a derived edition adds (for example a security overlay).
3. The build and install information the licences require, which for this
   image is the flake and its lock file.
4. Because Sentinel and Fabric are AGPL, users who interact with a modified
   version over a network must be offered its corresponding source.

## Open legal question (needs counsel)

This page states licence facts, not legal advice. One question is unresolved and
needs a lawyer before a proprietary edition ships: **whether a proprietary
edition's additions constitute mere aggregation with Wren (GPL-2.0-or-later) and
with Fabric and Sentinel (AGPL-3.0-or-later)**, and **whether any contributor
agreement covers relicensing Wren's GPL code**. Wren and the agent run as
separate executables, which supports the aggregation reading, but that has been
checked only at the Nix packaging level, not by code review. Fabric commit
`0012f81` removed CLA enforcement and relicensing claims from that project, so
relicensing rights should not be assumed.

Sentinel's own terms are in [LICENSE](https://github.com/Velstra/sentinel/blob/main/LICENSE)
and [CONTRIBUTING.md](https://github.com/Velstra/sentinel/blob/main/CONTRIBUTING.md).
No separate CLA is administered. These documents neither establish ownership of
third-party contributions nor grant additional commercial relicensing rights;
resolve rights questions with the actual rights holders before relying on them.
