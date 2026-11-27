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
subsequent jobs. A failed job may be run again in the same run, up to run
attempt 3 ([re-runs](#re-runs-after-a-failure)); for anything else, start a
new run instead of reusing an earlier approval.

The regression checks, and only they, may run on self-hosted ephemeral
runners instead of GitHub's ([regression runners](#regression-runners)):

```sh
gh workflow run release-community.yml --ref main -f version=v1.0.0 -F publish=true \
  -f regression_runner=velstra-rel-LABEL
```

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
`approved` review in its own environment by a GitHub `User` account, one for
each time the job runs ([approvals](#re-runs-after-a-failure)). The maintainer may approve their own run, but the job having
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
release notes name every check that was retried. A regression job that hits
its 240-minute timeout fails (it may be [run again](#re-runs-after-a-failure)).
A checkout that cannot reach github.com is retried once after a two-minute
pause.

The image build, the installer ISO build and the exact-disk boot gate are
watched the same way: 30 minutes without output kills the build, which starts
once more in the same job (Nix keeps what it had finished). A second stall, or
any failure, fails the job. `image-evidence.json` records each retry under
`stall_retries`, and the release notes name the retried builds.

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

## Re-runs after a failure

A run whose jobs failed may be continued with GitHub's **Re-run failed jobs**
(`gh run rerun RUN_ID --failed`), which makes run attempt 2, and once more,
attempt 3. `scripts/release_attempts.py` reads from GitHub's job listings
which job ran in which attempt and refuses anything else:

- a job that *failed* (or timed out) may run again in the next attempt: a
  regression check, the build, or sign, package, seal and publish. A
  regression check thus runs at most twice more after its first failure. A
  cancelled job, or a plan that failed, makes the release refuse: start a new
  run;
- every job that passed is carried over unchanged into each later attempt and
  is never run again: the plan, a build that passed (the release signs that
  one), every passing regression, and sign, package or seal once they passed.
  GitHub lists a carried-over job again with a new ID, so it counts as carried
  over when its name, start, end and conclusion match its earlier entry;
- a release job that was only skipped, because an earlier one failed, runs for
  the first time;
- a job that fails in attempt 3 blocks the release; there is no attempt 4.
- GitHub may list a re-run job more than once. Every entry that got a runner
  must finish green, and at least one must. An entry that never got a runner
  is a phantom: it is ignored once the run has moved on to sign, which shows
  GitHub no longer waits for it, and always in an earlier attempt.

**Approvals.** Every run of sign, seal or publish needs an approval of its
own, given in the attempt that runs it; GitHub asks for it again whenever such
a job runs again. GitHub's review history for a run covers all its attempts and
says neither when nor in which attempt a review was given; a wait timer that
elapsed is listed as an approval by `github-actions[bot]`. So
`check_release_environment.py --approved` counts: the human approvals in the
job's environment must equal the number of times its job got a runner in this
run, the run now included. An approval from an earlier attempt can never stand
in for the run now. A rejected review closes the gate: its job fails without a
runner, makes no run, and may run again in the next attempt with a new
approval.

In the two-person mode each run's approval must come from someone who neither
dispatched the run nor started the attempt of that run; GitHub's run-attempt
records say who did. As the history does not say which approval belongs to
which run, the check requires that the approvers can be matched to the runs
that way. In [single-operator mode](#single-operator-mode) the maintainer
dispatches, approves and starts every re-run; only the count applies.

**Bytes.** Each job takes its input by artifact ID and digest from the job
before it, whichever attempt that one ran in: sign takes the build's, package
the signed disk, seal the tested release and publish the sealed one. Each
attempt uploads these under its own name (`...-attempt-N`), so a job that runs
again never meets its earlier upload and no artifact is ever replaced. The
check receipts keep their names: the receipt upload is a regression job's last
step, so a failed job never made one. The re-run package boot-tests the disk
under a new run nonce.

The packaged `source-checks.json` records each regression check run again,
with its first failure, the attempt it first failed in, the link to that log
and the attempts that ran it again; its receipt must come from the last of
them. Seal and publish compare that record with GitHub's listings, and take
the attempt that packaged the bundle from them. The release notes list every
job run again: "Regression checks re-run after a failure: CHECK (first
failure, attempt 1: ...; log: ...; ran again once in attempt 2 and passed)",
and "Release jobs re-run after a failure: JOB (first failure, attempt 2: ...;
log: ...; ran again in attempt 3)". Check receipts and the build are kept for
one day, so a re-run must reach packaging within a day of the checks; later,
start a new run.

## Regression runners

The dispatch input `regression_runner` chooses the runners of the regression
checks: `github` (the default, and always for tag pushes) keeps them on
GitHub-hosted `ubuntu-24.04`, at most 19 at a time. A label matching
`velstra-rel-[a-z0-9]{8,32}` runs them on `[self-hosted, linux, x64, LABEL]`,
self-hosted ephemeral runners registered for that run, at most 40 at a time.
The plan job validates the value and fails closed on anything else.

Plan, build, sign, package, seal and publish always run on GitHub-hosted
`ubuntu-24.04` (a workflow test enforces it), and every one of their release
commands refuses to run unless `RUNNER_ENVIRONMENT` is `github-hosted`. No
signing key, no signed byte and no release artifact reaches a self-hosted
runner. The regression job holds no secret: its token can only read the
repository (`permissions: contents: read`), and it writes nothing but its
check receipt.

What a self-hosted runner can do is lie about a regression result. The
receipts of self-hosted regressions are only as trustworthy as those runners:
each is ephemeral (one job, then discarded), exists only for the run, and is
reachable only through the run's own label, so no earlier job or other
workflow can have left anything on it. `source-checks.json` records the runner
class and label, seal and publish check that record against the plan's own
outputs, and the release notes say it: "Regression checks ran on self-hosted
ephemeral runners (runner label velstra-rel-...)".

A self-hosted runner must provide: Ubuntu 24.04 x86-64 with systemd and udev;
labels `self-hosted`, `linux`, `x64` and the run's label; `/dev/kvm` usable by
the job and the Nix build users; `git`, `curl`, `xz-utils` and `python3` 3.11
or newer; a clock kept by NTP; outbound HTTPS to github.com and its Actions
services, releases.nixos.org and cache.nixos.org; at least 4 vCPUs, 16 GB of
memory and 100 GB of disk. Either no Nix, and passwordless `sudo` for the
installer, or Nix 2.35.4 preinstalled as a multi-user daemon whose `nix.conf`
enables `nix-command flakes` and keeps the default system features
(`nixos-test benchmark big-parallel kvm`): the install step then does nothing.
The AppArmor user-namespace restriction must be lifted, or `sudo` allowed for
`sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`; the step needs no
`sudo` when it is already lifted. The job user need not be a trusted Nix
user; the daemon may then not honour the job's `--max-jobs` and `--cores`.

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
