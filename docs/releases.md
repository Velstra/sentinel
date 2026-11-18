# Releases

End users download an ISO, QCOW2 or compressed RAW disk from GitHub Releases.
They do not install Nix. Enterprise update bundles use the private update
gateway and R2, not public release assets.

## Run a candidate

After the workflow is merged and the prerequisites below are configured:

```sh
gh workflow run release-community.yml --ref main -f version=v1.0.0-rc.1 -F publish=false
gh run list --workflow release-community.yml
gh run watch RUN_ID --exit-status
```

The version's base must match `Cargo.toml`. Tag pushes build and test only.
A main-branch dispatch additionally requests production signing approval.
`publish=false` never creates a GitHub Release. A failed check blocks the
subsequent jobs; start a new run instead of reusing an earlier approval.

To publish, dispatch the same action with `-F publish=true`. This performs a
new complete qualification and requires independent environment approvals;
it does not promote an arbitrary old artifact. Existing tags must identify
the same commit. Existing releases are never overwritten.

## One-time prerequisites

- Configure distinct `community-signing`, `community-attestation` and
  `community-publish` environments with
  required reviewers, self-review disabled, administrator bypass disabled,
  and only branch `main` (optionally tag `v*`) allowed. The action verifies the
  reviewer/branch API configuration and a real independent human approval for
  the current run before loading keys or publishing. It does not infer an
  approval from a job merely having started (for example through bypass).
- Set repository `RELEASE_ARTIFACT_BYTE_BUDGET` to the reviewed maximum
  **per transfer**. The default is zero. Four large artifact copies can coexist
  for one day, in addition to check receipts. This is not an account-wide
  spending cap: check current storage usage and set a zero-spend billing budget
  before enabling the action. No giant Actions cache is created.
- Store `VELSTRA_DB_KEY_PEM` only in `community-signing`, and
  `VELSTRA_GPG_PRIVATE_KEY` only in `community-attestation`. Separate environment
  identities prevent an earlier approval from authorizing the later job.
  Use a dedicated release identity, not factory/test keys.
  The unattended GPG identity must be usable in the ephemeral job; use an
  independently reviewed external signer if policy requires hardware custody.
- Set public repository variables `VELSTRA_PK_CERT`, `VELSTRA_KEK_CERT`,
  `VELSTRA_DB_CERT`, their exact PEM-file SHA256 values as
  `VELSTRA_PK_CERT_SHA256`, `VELSTRA_KEK_CERT_SHA256`, `VELSTRA_DB_CERT_SHA256`,
  and the enrollment binaries as `VELSTRA_PK_AUTH_BASE64`,
  `VELSTRA_KEK_AUTH_BASE64`, `VELSTRA_DB_AUTH_BASE64`.
- Set public repository variables `VELSTRA_GPG_PUBLIC_KEY` and full uppercase
  `VELSTRA_GPG_FINGERPRINT`. Publish this fingerprint independently of the
  downloadable bundle. Review enrollment material against the real firmware
  identities. Private PK/KEK keys are **not** uploaded to Actions.

## What is verified

Every exported flake check runs in a separate KVM-capable job, with an explicit
run nonce rather than accepting a cached test result. No check-name allowlist
silently drops newly added tests. A 6-hour job timeout fails the release.

Build, firmware signing, packaging/VM execution, checksum signing and
publication use fresh separate runners. VM execution receives no private keys;
only the publication job has repository write permission. Transfers require
the same run, commit, immutable artifact ID and exact archive digest.

The production disk keeps Community's A/B layout. All three EFI executables
and enrollment files replace the factory identity. QCOW2 is compared against
the raw disk, the ISO's actual embedded disk is hashed, and the exact signed
disk must boot twice with Secure Boot and persistent boot blessing. The first
trial boot requires the product-health assessment before blessing. The second,
permanent boot verifies startup and the persisted boot entry; it does not claim
a second assessment that the boot-count generator does not schedule. The
published checksums cover every artifact, source SBOM and evidence file.
The full planned check catalog and every receipt's 24-hour freshness are
revalidated before checksum signing and again before publication.
Upload happens into a draft; every uploaded byte is downloaded and checked
before the release becomes visible. Failed uploads leave a draft for review.

## Explicit limitations

The current live ISO boot chain is **not Secure Boot authenticated**. Disable
Secure Boot to boot that installer, verify its signed download first, and
enroll the independently verified firmware identity for the installed system.
Signing the embedded disk does not sign the ISO's live kernel or root filesystem.

The source CycloneDX SBOM is not an OS CVE scan. Source regression fixtures are
not claimed to run every feature on the final disk. Hardware certification,
core-package vulnerability assessment and unresolved product findings remain
separate release decisions; this workflow does not waive them. Do not publish
a stable release while its readiness review has unresolved blockers.

Each GitHub Release asset must be smaller than 2 GiB. The action fails rather
than silently omitting an oversized ISO or distributing a truncated disk.
Large private Enterprise certification uses its separately protected pipeline,
full image SBOM/scanner gates and private R2 publication.
