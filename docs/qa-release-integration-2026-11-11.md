# Release candidate integration

This candidate combines the retained appliance checkpoint with the reviewed
signed-update staging, protected-file handling, installer signature cleanup,
radio unit correction and source-SBOM generation changes. Previously isolated
capacity and legacy-update fixture corrections are now part of the repository.

The installer preserves partition-table signatures until the final GPT
transaction and refuses conflicting whole-disk data/table signatures before
erasure. The update staging path uses the persistent state filesystem and
preserves signature, capacity, active-slot and downgrade checks. Radio retry
settings are emitted in systemd's Unit section.

The capacity observer opens the ESP before hashing its raw bytes, holding that
read-only directory descriptor for a coherent mounted observation. It retains
full partition/GPT/config/key comparisons, including a regression after natural
automount expiration. The legacy fixture verifies actual configured XDP and
ordinary automatic assessment before blessing both counted boots, and models
one stable virtual hardware UUID across the cold boot.

Public CI now runs the associated Python fixture regressions and emits a
standard CycloneDX source SBOM. An installed-image SBOM, vulnerability clearance
and image-bound runtime/hardware evidence remain separate release requirements.

The asynchronous operational OTA API revision remains outside this candidate
until its observation concurrency and live-configuration authorization gaps
are corrected. Prior tests of individual source slices do not qualify this
combined tree: fresh formatting, strict Clippy, workspace tests, fixture tests,
Nix evaluation and the relevant real VM/browser gates are required. No release
has been approved by creating this integration branch.
