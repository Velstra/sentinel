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
subsequent jobs. Failed regression checks may be run once more in the same run
([one re-run](#one-re-run-of-failed-regression-checks)); for anything else, or
a third attempt, start a new run instead of reusing an earlier approval.

To publish, dispatch the same action with `-F publish=true`. This performs a
new complete qualification and requires independent environment approvals
(or, in [single-operator mode](#single-operator-mode), the maintainer's own);
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
  A project with one maintainer uses
  [single-operator mode](#single-operator-mode) instead.
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

## Single-operator mode

The default is a two-person rule: each environment must forbid self-review,
and each approval must come from someone who did not start the run. A project
with one maintainer can never meet it. Setting the repository variable
`RELEASE_SINGLE_OPERATOR` to exactly `true` replaces it with this rule; any
other value, or no variable, keeps the two-person rule.

For each of `community-signing`, `community-attestation` and
`community-publish` the action then requires:

- exactly one required-reviewers rule naming at least one reviewer
  (self-review may be allowed);
- administrator bypass disabled;
- a wait timer of at least 30 minutes
  (`SINGLE_OPERATOR_MIN_WAIT_MINUTES` in `scripts/check_release_environment.py`);
- the same branch policies as above: `main`, optionally tag `v*`.

Each signing, attestation and publication job still requires a real
`approved` review of the current run in its own environment by a GitHub
`User` account. The maintainer may approve their own run, but the job having
started is never taken as an approval. The release body ends with
"Release approvals: single-operator mode (one maintainer, wait timer ≥ 30
min).", and each environment check writes the same line as a run annotation.

What it protects against: a stolen workflow-scoped or repository-write token
cannot release on its own. It cannot approve a deployment, and the wait timer
holds each protected job for at least 30 minutes, which gives the maintainer
time to reject the run or cancel it. Bypass is off, so an administrator
cannot start a waiting job past the review and the timer.

What it does not protect against: there is no second person. A compromised
maintainer account or a token with the maintainer's approval rights can
approve its own run; the wait timer only delays it, and only helps if the
maintainer notices the pending deployment. A repository administrator can
also edit the environments or the variable. Every protected job rechecks its
environment once it starts, so a timer removed while the job waits fails that
job, but a change reverted before the job starts is not seen. Watch
deployment-review notifications while single-operator mode is on.

To switch back, once a second maintainer exists, delete the variable
(`gh variable delete RELEASE_SINGLE_OPERATOR`) or set it to `false`, then
enable self-review prevention on all three environments and add the
independent reviewer. The next run enforces the two-person rule again;
the wait timers may stay.

## What is verified

Every exported flake check runs in a separate KVM-capable job, with an explicit
run nonce rather than accepting a cached test result. No check-name allowlist
silently drops newly added tests. A check whose build prints nothing for 30
minutes is taken for a hung runner: the build is killed and started once more
in the same job. A second stall, or any failure of the check itself, fails the
job; the job itself never retries a failed check. The check's receipt and the
release notes name every check that was retried. A regression job's 240-minute
timeout fails the release. A checkout that cannot reach github.com is retried
once after a two-minute pause.

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

## One re-run of failed regression checks

A run whose regression jobs failed may be continued once with GitHub's
**Re-run failed jobs** (`gh run rerun RUN_ID --failed`), which makes run
attempt 2. In that attempt:

- only regression jobs that *failed* in attempt 1 run again; one that was
  cancelled or timed out, or any other change, makes the release refuse;
- the plan, the build and every regression that passed come from attempt 1:
  the build is never repeated, and the release signs the attempt-1 build;
- sign, package, seal and publish run for the first time, so every
  environment approval is requested again;
- a regression job that fails again blocks the release; there is no attempt 3.
- GitHub may list a re-run job more than once in attempt 2; every entry must
  finish green, and the release notes say how many times attempt 2 ran it.

Before signing, and again before sealing and publishing, the workflow reads
from GitHub's job listings which job ran in which attempt and refuses anything
else. GitHub lists every carried-over job again in attempt 2, with a new ID,
so a job counts as carried over when its name, start, end and conclusion match
attempt 1. The packaged `source-checks.json` records each re-run check with its
first failure and the link to its attempt-1 log, and the release notes list
them: "Regression checks re-run once after a failure: CHECK (first failure:
...; attempt-1 log: ...)". Check receipts and the build are kept for one day,
so a re-run must reach packaging within a day of attempt 1; later, start a new
run.

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
