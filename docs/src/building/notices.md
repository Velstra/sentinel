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

Sentinel's own terms are in [LICENSE](https://github.com/Velstra/sentinel/blob/main/LICENSE)
and [CONTRIBUTING.md](https://github.com/Velstra/sentinel/blob/main/CONTRIBUTING.md).
No separate CLA is administered. These documents neither establish ownership of
third-party contributions nor grant additional commercial relicensing rights;
resolve rights questions with the actual rights holders before relying on them.
